// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "htool_gpio.h"

#include <fcntl.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <pthread.h>
#include <sys/wait.h>
#include <unistd.h>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

#include "htool.h"
#include "protocol/gpio_drive_strength.h"
#include "protocol/test/libhoth_device_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::InSequence;
using ::testing::InvokeWithoutArgs;
using ::testing::Return;

static struct libhoth_device* g_mock_dev = nullptr;
static const char* g_mock_config_path = nullptr;
static const char* g_mock_spi_name = nullptr;
static const char* g_mock_transport = "";
static bool g_mock_dry_run = false;
static bool g_signals_blocked_on_device_open = false;

extern "C" {
struct htool_invocation* htool_global_flags(void) { return nullptr; }
struct libhoth_device* htool_libhoth_device(void) {
  sigset_t current_mask;
  sigemptyset(&current_mask);
  if (pthread_sigmask(SIG_BLOCK, nullptr, &current_mask) == 0) {
    g_signals_blocked_on_device_open =
        (sigismember(&current_mask, SIGINT) == 1 &&
         sigismember(&current_mask, SIGTERM) == 1 &&
         sigismember(&current_mask, SIGHUP) == 1);
  }
  return g_mock_dev;
}
void htool_report_error(const char* /*cmd_name*/, libhoth_error /*err*/) {}
int htool_get_param_string(const struct htool_invocation* /*inv*/,
                           const char* name, const char** value) {
  if (std::strcmp(name, "config") == 0 && g_mock_config_path) {
    *value = g_mock_config_path;
    return 0;
  }
  if (std::strcmp(name, "spi") == 0 && g_mock_spi_name) {
    *value = g_mock_spi_name;
    return 0;
  }
  if (std::strcmp(name, "transport") == 0 && g_mock_transport) {
    *value = g_mock_transport;
    return 0;
  }
  return -1;
}
int htool_get_param_bool(const struct htool_invocation* /*inv*/,
                         const char* name, bool* value) {
  if (std::strcmp(name, "dry_run") == 0) {
    *value = g_mock_dry_run;
    return 0;
  }
  return -1;
}
}

TEST_F(LibHothTest, parse_spi_interface) {
  enum htool_spi_interface_id iface;
  EXPECT_EQ(htool_parse_spi_interface("spidev", &iface), HOTH_SUCCESS);
  EXPECT_EQ(iface, HTOOL_SPI_DEV);
  EXPECT_STREQ(htool_spi_interface_name(iface), "spidev");

  EXPECT_EQ(htool_parse_spi_interface("spihost0", &iface), HOTH_SUCCESS);
  EXPECT_EQ(iface, HTOOL_SPI_HOST0);
  EXPECT_STREQ(htool_spi_interface_name(iface), "spihost0");

  EXPECT_EQ(htool_parse_spi_interface("spihost1", &iface), HOTH_SUCCESS);
  EXPECT_EQ(iface, HTOOL_SPI_HOST1);
  EXPECT_STREQ(htool_spi_interface_name(iface), "spihost1");

  EXPECT_NE(htool_parse_spi_interface("spi_dev", &iface), HOTH_SUCCESS);
  EXPECT_NE(htool_parse_spi_interface("spihost2", &iface), HOTH_SUCCESS);
  EXPECT_NE(htool_parse_spi_interface("", &iface), HOTH_SUCCESS);
}

TEST_F(LibHothTest, parse_gpio_pad) {
  uint8_t pad = 0;
  EXPECT_EQ(htool_parse_gpio_pad("MIO0", &pad), HOTH_SUCCESS);
  EXPECT_EQ(pad, 0);
  EXPECT_STREQ(htool_gpio_pad_name(pad), "MIO0");

  EXPECT_EQ(htool_parse_gpio_pad("mio10", &pad), HOTH_SUCCESS);
  EXPECT_EQ(pad, 10);
  EXPECT_STREQ(htool_gpio_pad_name(pad), "MIO10");

  EXPECT_EQ(htool_parse_gpio_pad("MIO46", &pad), HOTH_SUCCESS);
  EXPECT_EQ(pad, 46);
  EXPECT_STREQ(htool_gpio_pad_name(pad), "MIO46");

  EXPECT_EQ(htool_parse_gpio_pad("DIO0", &pad), HOTH_SUCCESS);
  EXPECT_EQ(pad, LIBHOTH_GPIO_DIO_PAD_OFFSET + 0);
  EXPECT_STREQ(htool_gpio_pad_name(pad), "DIO0");

  EXPECT_EQ(htool_parse_gpio_pad("dio12", &pad), HOTH_SUCCESS);
  EXPECT_EQ(pad, LIBHOTH_GPIO_DIO_PAD_OFFSET + 12);
  EXPECT_STREQ(htool_gpio_pad_name(pad), "DIO12");

  EXPECT_EQ(htool_parse_gpio_pad("DIO15", &pad), HOTH_SUCCESS);
  EXPECT_EQ(pad, LIBHOTH_GPIO_DIO_PAD_OFFSET + 15);
  EXPECT_STREQ(htool_gpio_pad_name(pad), "DIO15");

  EXPECT_NE(htool_parse_gpio_pad("DIO16", &pad), HOTH_SUCCESS);
  EXPECT_NE(htool_parse_gpio_pad("MIO47", &pad), HOTH_SUCCESS);
  EXPECT_NE(htool_parse_gpio_pad("IOA0", &pad), HOTH_SUCCESS);
  EXPECT_NE(htool_parse_gpio_pad("INVALID", &pad), HOTH_SUCCESS);
}

TEST_F(LibHothTest, parse_gpio_drive_strength_config_valid) {
  const char* kConfig =
      "# Sample config\r\n"
      "spidev.clk = DIO12 ; inline comment\r\n"
      "spidev.cs = DIO13\r\n"
      "spidev.d0 = DIO6\r\n"
      "spidev.d1 = DIO7\r\n"
      "spidev.d2 = DIO8\r\n"
      "spidev.d3 = DIO9\r\n"
      "spidev.drive_strengths = 0, 1, 2, 3\r\n"
      "\r\n"
      "spihost0.clk = DIO14\n"
      "spihost0.cs = DIO15\n"
      "spihost0.d0 = DIO2\n"
      "spihost0.d1 = DIO3\n"
      "spihost0.d2 = DIO4\n"
      "spihost0.d3 = DIO5\n"
      "spihost0.drive_strengths = 0, 2, 3\n"
      "\n"
      "spihost1.clk = MIO0\n"
      "spihost1.cs = MIO1\n"
      "spihost1.d0 = MIO2\n"
      "spihost1.d1 = MIO3\n"
      "spihost1.d2 = MIO4\n"
      "spihost1.d3 = MIO5\n"
      "spihost1.drive_strengths = 1, 3\n";

  struct htool_gpio_drive_strength_config cfg;
  EXPECT_EQ(htool_parse_gpio_drive_strength_config_str(kConfig, &cfg),
            HOTH_SUCCESS);

  EXPECT_EQ(cfg.interfaces[HTOOL_SPI_DEV].pads[HTOOL_SPI_SIG_CLK],
            LIBHOTH_GPIO_DIO_PAD_OFFSET + 12);
  EXPECT_EQ(cfg.interfaces[HTOOL_SPI_DEV].pads[HTOOL_SPI_SIG_CS],
            LIBHOTH_GPIO_DIO_PAD_OFFSET + 13);
  EXPECT_EQ(cfg.interfaces[HTOOL_SPI_DEV].num_drive_strengths, 4u);
  EXPECT_EQ(cfg.interfaces[HTOOL_SPI_DEV].drive_strengths[3], 3u);

  EXPECT_EQ(cfg.interfaces[HTOOL_SPI_HOST0].pads[HTOOL_SPI_SIG_CLK],
            LIBHOTH_GPIO_DIO_PAD_OFFSET + 14);
  EXPECT_EQ(cfg.interfaces[HTOOL_SPI_HOST0].num_drive_strengths, 3u);

  EXPECT_EQ(cfg.interfaces[HTOOL_SPI_HOST1].pads[HTOOL_SPI_SIG_CLK], 0u);
  EXPECT_EQ(cfg.interfaces[HTOOL_SPI_HOST1].pads[HTOOL_SPI_SIG_CS], 1u);
  EXPECT_EQ(cfg.interfaces[HTOOL_SPI_HOST1].pads[HTOOL_SPI_SIG_D0], 2u);
  EXPECT_EQ(cfg.interfaces[HTOOL_SPI_HOST1].pads[HTOOL_SPI_SIG_D1], 3u);
  EXPECT_EQ(cfg.interfaces[HTOOL_SPI_HOST1].pads[HTOOL_SPI_SIG_D2], 4u);
  EXPECT_EQ(cfg.interfaces[HTOOL_SPI_HOST1].pads[HTOOL_SPI_SIG_D3], 5u);
  EXPECT_EQ(cfg.interfaces[HTOOL_SPI_HOST1].num_drive_strengths, 2u);
  EXPECT_EQ(cfg.interfaces[HTOOL_SPI_HOST1].drive_strengths[0], 1u);
  EXPECT_EQ(cfg.interfaces[HTOOL_SPI_HOST1].drive_strengths[1], 3u);
}

TEST_F(LibHothTest, parse_gpio_drive_strength_config_duplicate_keys_rejected) {
  const char* kDupSignalKey =
      "spidev.clk = DIO12\n"
      "spidev.cs = DIO13\n"
      "spidev.d0 = DIO6\n"
      "spidev.d1 = DIO7\n"
      "spidev.d2 = DIO8\n"
      "spidev.d3 = DIO9\n"
      "spidev.d3 = DIO1\n"
      "spidev.drive_strengths = 0, 3\n";

  struct htool_gpio_drive_strength_config cfg;
  testing::internal::CaptureStderr();
  EXPECT_NE(htool_parse_gpio_drive_strength_config_str(kDupSignalKey, &cfg),
            HOTH_SUCCESS);
  std::string err_out = testing::internal::GetCapturedStderr();
  EXPECT_EQ(err_out, "Config line 7: duplicate key 'spidev.d3'.\n");

  const char* kDupStrengthsKey =
      "spidev.clk = DIO12\n"
      "spidev.cs = DIO13\n"
      "spidev.d0 = DIO6\n"
      "spidev.d1 = DIO7\n"
      "spidev.d2 = DIO8\n"
      "spidev.d3 = DIO9\n"
      "spidev.drive_strengths = 0, 1\n"
      "spidev.drive_strengths = 2, 3\n";

  testing::internal::CaptureStderr();
  EXPECT_NE(htool_parse_gpio_drive_strength_config_str(kDupStrengthsKey, &cfg),
            HOTH_SUCCESS);
  err_out = testing::internal::GetCapturedStderr();
  EXPECT_EQ(err_out,
            "Config line 8: duplicate key 'spidev.drive_strengths'.\n");
}

TEST_F(LibHothTest,
       parse_gpio_drive_strength_config_incomplete_signals_rejected) {
  const char* kIncompleteSignals =
      "spihost1.clk = MIO0\n"
      "spihost1.cs = MIO1\n"
      "spihost1.d0 = MIO2\n"
      "spihost1.d1 = MIO3\n"
      "spihost1.drive_strengths = 0, 1\n";
  struct htool_gpio_drive_strength_config cfg;
  EXPECT_NE(
      htool_parse_gpio_drive_strength_config_str(kIncompleteSignals, &cfg),
      HOTH_SUCCESS);

  const char* kMissingDriveStrengths =
      "spihost1.clk = MIO0\n"
      "spihost1.cs = MIO1\n"
      "spihost1.d0 = MIO2\n"
      "spihost1.d1 = MIO3\n"
      "spihost1.d2 = MIO4\n"
      "spihost1.d3 = MIO5\n";
  EXPECT_NE(
      htool_parse_gpio_drive_strength_config_str(kMissingDriveStrengths, &cfg),
      HOTH_SUCCESS);

  const char* kMissingPads = "spihost1.drive_strengths = 0, 1\n";
  EXPECT_NE(htool_parse_gpio_drive_strength_config_str(kMissingPads, &cfg),
            HOTH_SUCCESS);
}

TEST_F(LibHothTest, parse_gpio_drive_strength_config_duplicate_pads_rejected) {
  const char* kDupSignalPads =
      "spihost1.clk = MIO0\n"
      "spihost1.cs = MIO1\n"
      "spihost1.d0 = MIO2\n"
      "spihost1.d1 = MIO2\n"
      "spihost1.d2 = MIO4\n"
      "spihost1.d3 = MIO5\n";
  struct htool_gpio_drive_strength_config cfg;
  testing::internal::CaptureStderr();
  EXPECT_NE(htool_parse_gpio_drive_strength_config_str(kDupSignalPads, &cfg),
            HOTH_SUCCESS);
  std::string err_out = testing::internal::GetCapturedStderr();
  EXPECT_EQ(err_out,
            "Config line 4: duplicate pad 'MIO2' assigned to both "
            "'spihost1.d0' and 'spihost1.d1'.\n");

  const char* kCrossInterfaceDupPad =
      "spidev.clk = DIO12\n"
      "spidev.cs = DIO13\n"
      "spidev.d0 = DIO6\n"
      "spidev.d1 = DIO7\n"
      "spidev.d2 = DIO8\n"
      "spidev.d3 = DIO9\n"
      "spidev.drive_strengths = 0, 1\n"
      "spihost0.clk = DIO12\n";
  testing::internal::CaptureStderr();
  EXPECT_NE(
      htool_parse_gpio_drive_strength_config_str(kCrossInterfaceDupPad, &cfg),
      HOTH_SUCCESS);
  err_out = testing::internal::GetCapturedStderr();
  EXPECT_EQ(err_out,
            "Config line 8: duplicate pad 'DIO12' assigned to both "
            "'spidev.clk' and 'spihost0.clk'.\n");
}

TEST_F(LibHothTest, parse_gpio_drive_strength_config_file_io) {
  std::string tmp_path = ::testing::TempDir() + "/gpio_sweep_test_" +
                         std::to_string(getpid()) + ".conf";
  const char* kBaseLines =
      "spidev.clk = DIO12\n"
      "spidev.cs = DIO13\n"
      "spidev.d0 = DIO6\n"
      "spidev.d1 = DIO7\n"
      "spidev.d2 = DIO8\n"
      "spidev.d3 = DIO9\n"
      "spidev.drive_strengths = 0, 1\n";
  FILE* fp = std::fopen(tmp_path.c_str(), "w");
  ASSERT_NE(fp, nullptr);
  std::fputs(kBaseLines, fp);
  std::fclose(fp);

  struct htool_gpio_drive_strength_config cfg;
  EXPECT_EQ(htool_parse_gpio_drive_strength_config_file(tmp_path.c_str(), &cfg),
            HOTH_SUCCESS);
  EXPECT_EQ(cfg.interfaces[HTOOL_SPI_DEV].pads[HTOOL_SPI_SIG_CLK],
            LIBHOTH_GPIO_DIO_PAD_OFFSET + 12);
  EXPECT_EQ(cfg.interfaces[HTOOL_SPI_DEV].num_drive_strengths, 2u);

  // 255-char final line without trailing newline should succeed (matching _str)
  std::string line_255 = "# " + std::string(253, 'a');
  ASSERT_EQ(line_255.size(), 255u);
  fp = std::fopen(tmp_path.c_str(), "w");
  ASSERT_NE(fp, nullptr);
  std::fputs(kBaseLines, fp);
  std::fputs(line_255.c_str(), fp);
  std::fclose(fp);
  EXPECT_EQ(htool_parse_gpio_drive_strength_config_file(tmp_path.c_str(), &cfg),
            HOTH_SUCCESS);

  // 256-char line should fail
  std::string line_256 = line_255 + "b";
  fp = std::fopen(tmp_path.c_str(), "w");
  ASSERT_NE(fp, nullptr);
  std::fputs(kBaseLines, fp);
  std::fputs(line_256.c_str(), fp);
  std::fclose(fp);
  EXPECT_NE(htool_parse_gpio_drive_strength_config_file(tmp_path.c_str(), &cfg),
            HOTH_SUCCESS);

  std::remove(tmp_path.c_str());

  // Non-existent file should fail
  EXPECT_NE(htool_parse_gpio_drive_strength_config_file(tmp_path.c_str(), &cfg),
            HOTH_SUCCESS);

  // Directory path should fail via ferror(fp)
  EXPECT_NE(htool_parse_gpio_drive_strength_config_file(
                ::testing::TempDir().c_str(), &cfg),
            HOTH_SUCCESS);
}

TEST_F(LibHothTest, spi_signal_role_names) {
  EXPECT_STREQ(htool_spi_signal_role_name(HTOOL_SPI_SIG_CLK), "clk");
  EXPECT_STREQ(htool_spi_signal_role_name(HTOOL_SPI_SIG_CS), "cs");
  EXPECT_STREQ(htool_spi_signal_role_name(HTOOL_SPI_SIG_D0), "d0");
  EXPECT_STREQ(htool_spi_signal_role_name(HTOOL_SPI_SIG_D1), "d1");
  EXPECT_STREQ(htool_spi_signal_role_name(HTOOL_SPI_SIG_D2), "d2");
  EXPECT_STREQ(htool_spi_signal_role_name(HTOOL_SPI_SIG_D3), "d3");
}

TEST_F(LibHothTest, parse_gpio_drive_strength_config_invalid_strength) {
  const char* kBadConfig =
      "spidev.clk = DIO12\n"
      "spidev.cs = DIO13\n"
      "spidev.d0 = DIO6\n"
      "spidev.d1 = DIO7\n"
      "spidev.d2 = DIO8\n"
      "spidev.d3 = DIO9\n"
      "spidev.drive_strengths = 0, 1, 4\n";
  struct htool_gpio_drive_strength_config cfg;
  testing::internal::CaptureStderr();
  EXPECT_NE(htool_parse_gpio_drive_strength_config_str(kBadConfig, &cfg),
            HOTH_SUCCESS);
  std::string err_out = testing::internal::GetCapturedStderr();
  EXPECT_NE(err_out.find("Config line 7: invalid drive strength '4'"),
            std::string::npos);

  // Missing '=' on line 2
  testing::internal::CaptureStderr();
  EXPECT_NE(htool_parse_gpio_drive_strength_config_str(
                "# comment\nspidev.clk DIO12\n", &cfg),
            HOTH_SUCCESS);
  err_out = testing::internal::GetCapturedStderr();
  EXPECT_NE(err_out.find("Config line 2: missing '=' delimiter"),
            std::string::npos);

  // Invalid pad on line 3
  testing::internal::CaptureStderr();
  EXPECT_NE(htool_parse_gpio_drive_strength_config_str(
                "\n\nspidev.clk = IOA0\n", &cfg),
            HOTH_SUCCESS);
  err_out = testing::internal::GetCapturedStderr();
  EXPECT_NE(err_out.find("Config line 3: invalid GPIO pad 'IOA0'"),
            std::string::npos);
}

TEST_F(LibHothTest, set_spi_interface_drive_strength_all_pads) {
  struct htool_spi_drive_strength_interface_config iface_cfg = {};
  iface_cfg.pads[HTOOL_SPI_SIG_CLK] = LIBHOTH_GPIO_DIO_PAD_OFFSET + 14;
  iface_cfg.pads[HTOOL_SPI_SIG_CS] = LIBHOTH_GPIO_DIO_PAD_OFFSET + 15;
  iface_cfg.pads[HTOOL_SPI_SIG_D0] = LIBHOTH_GPIO_DIO_PAD_OFFSET + 2;
  iface_cfg.pads[HTOOL_SPI_SIG_D1] = LIBHOTH_GPIO_DIO_PAD_OFFSET + 3;
  iface_cfg.pads[HTOOL_SPI_SIG_D2] = LIBHOTH_GPIO_DIO_PAD_OFFSET + 4;
  iface_cfg.pads[HTOOL_SPI_SIG_D3] = LIBHOTH_GPIO_DIO_PAD_OFFSET + 5;

  EXPECT_CALL(mock_, send(_, UsesCommand(HOTH_CMD_SET_GPIO_DRIVE_STRENGTH), _))
      .Times(6)
      .WillRepeatedly(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, send(_, UsesCommand(HOTH_CMD_GET_GPIO_DRIVE_STRENGTH), _))
      .Times(6)
      .WillRepeatedly(Return(LIBHOTH_OK));

  uint32_t dummy = 0;
  struct hoth_response_get_gpio_drive_strength get_resp = {.strength = 2};
  {
    InSequence seq;
    for (int i = 0; i < 6; ++i) {
      EXPECT_CALL(mock_, receive)
          .WillOnce(DoAll(CopyResp(&dummy, 0), Return(LIBHOTH_OK)));
      EXPECT_CALL(mock_, receive)
          .WillOnce(
              DoAll(CopyResp(&get_resp, sizeof(get_resp)), Return(LIBHOTH_OK)));
    }
  }

  testing::internal::CaptureStderr();
  EXPECT_EQ(htool_set_spi_interface_drive_strength(&hoth_dev_, &iface_cfg, 2),
            HOTH_SUCCESS);
  EXPECT_EQ(testing::internal::GetCapturedStderr(), "");

  // Unmapped signal should fail without sending host commands
  iface_cfg.pads[HTOOL_SPI_SIG_D3] = HTOOL_GPIO_PAD_UNMAPPED;
  EXPECT_NE(htool_set_spi_interface_drive_strength(&hoth_dev_, &iface_cfg, 2),
            HOTH_SUCCESS);
}

TEST_F(LibHothTest, set_spi_interface_drive_strength_readback_mismatch_warns) {
  struct htool_spi_drive_strength_interface_config iface_cfg = {};
  iface_cfg.pads[HTOOL_SPI_SIG_CLK] = LIBHOTH_GPIO_DIO_PAD_OFFSET + 14;
  iface_cfg.pads[HTOOL_SPI_SIG_CS] = LIBHOTH_GPIO_DIO_PAD_OFFSET + 15;
  iface_cfg.pads[HTOOL_SPI_SIG_D0] = LIBHOTH_GPIO_DIO_PAD_OFFSET + 2;
  iface_cfg.pads[HTOOL_SPI_SIG_D1] = LIBHOTH_GPIO_DIO_PAD_OFFSET + 3;
  iface_cfg.pads[HTOOL_SPI_SIG_D2] = LIBHOTH_GPIO_DIO_PAD_OFFSET + 4;
  iface_cfg.pads[HTOOL_SPI_SIG_D3] = LIBHOTH_GPIO_DIO_PAD_OFFSET + 5;

  EXPECT_CALL(mock_, send(_, UsesCommand(HOTH_CMD_SET_GPIO_DRIVE_STRENGTH), _))
      .Times(6)
      .WillRepeatedly(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, send(_, UsesCommand(HOTH_CMD_GET_GPIO_DRIVE_STRENGTH), _))
      .Times(6)
      .WillRepeatedly(Return(LIBHOTH_OK));

  uint32_t dummy = 0;
  struct hoth_response_get_gpio_drive_strength mismatch_resp = {.strength = 1};
  struct hoth_response_get_gpio_drive_strength match_resp = {.strength = 3};
  {
    InSequence seq;
    // First pad (clk: DIO14) reads back 1 instead of 3
    EXPECT_CALL(mock_, receive)
        .WillOnce(DoAll(CopyResp(&dummy, 0), Return(LIBHOTH_OK)));
    EXPECT_CALL(mock_, receive)
        .WillOnce(DoAll(CopyResp(&mismatch_resp, sizeof(mismatch_resp)),
                        Return(LIBHOTH_OK)));
    for (int i = 1; i < 6; ++i) {
      EXPECT_CALL(mock_, receive)
          .WillOnce(DoAll(CopyResp(&dummy, 0), Return(LIBHOTH_OK)));
      EXPECT_CALL(mock_, receive)
          .WillOnce(DoAll(CopyResp(&match_resp, sizeof(match_resp)),
                          Return(LIBHOTH_OK)));
    }
  }

  testing::internal::CaptureStderr();
  EXPECT_EQ(htool_set_spi_interface_drive_strength(&hoth_dev_, &iface_cfg, 3),
            HOTH_SUCCESS);
  std::string err_output = testing::internal::GetCapturedStderr();
  EXPECT_NE(err_output.find("Warning: clk (DIO14) drive strength readback "
                            "mismatch: expected 3, got 1"),
            std::string::npos);
}

TEST_F(LibHothTest, set_spi_interface_drive_strength_error_propagation) {
  struct htool_spi_drive_strength_interface_config iface_cfg = {};
  for (size_t s = 0; s < HTOOL_SPI_SIGNAL_COUNT; ++s) {
    iface_cfg.pads[s] = static_cast<uint8_t>(s);
  }

  EXPECT_CALL(mock_, send(_, UsesCommand(HOTH_CMD_SET_GPIO_DRIVE_STRENGTH), _))
      .WillOnce(Return(LIBHOTH_ERR_FAIL));

  EXPECT_NE(htool_set_spi_interface_drive_strength(&hoth_dev_, &iface_cfg, 2),
            HOTH_SUCCESS);
}

TEST_F(LibHothTest, get_and_restore_spi_interface_drive_strengths) {
  struct htool_spi_drive_strength_interface_config iface_cfg = {};
  for (size_t s = 0; s < HTOOL_SPI_SIGNAL_COUNT; ++s) {
    iface_cfg.pads[s] = static_cast<uint8_t>(s);
  }

  EXPECT_CALL(mock_, send(_, UsesCommand(HOTH_CMD_GET_GPIO_DRIVE_STRENGTH), _))
      .Times(6)
      .WillRepeatedly(Return(LIBHOTH_OK));

  struct hoth_response_get_gpio_drive_strength resps[6] = {
      {.strength = 0}, {.strength = 1}, {.strength = 2},
      {.strength = 3}, {.strength = 5}, {.strength = 7},
  };
  {
    InSequence seq;
    for (int i = 0; i < 6; ++i) {
      EXPECT_CALL(mock_, receive)
          .WillOnce(
              DoAll(CopyResp(&resps[i], sizeof(resps[i])), Return(LIBHOTH_OK)));
    }
  }

  uint8_t saved[HTOOL_SPI_SIGNAL_COUNT] = {};
  EXPECT_EQ(
      htool_get_spi_interface_drive_strengths(&hoth_dev_, &iface_cfg, saved),
      HOTH_SUCCESS);
  for (int i = 0; i < 6; ++i) {
    EXPECT_EQ(saved[i], resps[i].strength);
  }

  // Restore all 6 pads; even if one pad fails on SET, the remaining 5 pads are
  // SET and verified via GET.
  {
    InSequence seq;
    EXPECT_CALL(mock_,
                send(_, UsesCommand(HOTH_CMD_SET_GPIO_DRIVE_STRENGTH), _))
        .WillOnce(Return(LIBHOTH_ERR_FAIL));
    for (int i = 1; i < 6; ++i) {
      EXPECT_CALL(mock_,
                  send(_, UsesCommand(HOTH_CMD_SET_GPIO_DRIVE_STRENGTH), _))
          .WillOnce(Return(LIBHOTH_OK));
      EXPECT_CALL(mock_,
                  send(_, UsesCommand(HOTH_CMD_GET_GPIO_DRIVE_STRENGTH), _))
          .WillOnce(Return(LIBHOTH_OK));
    }
  }
  uint32_t dummy = 0;
  {
    InSequence seq;
    for (int i = 1; i < 6; ++i) {
      EXPECT_CALL(mock_, receive)
          .WillOnce(DoAll(CopyResp(&dummy, 0), Return(LIBHOTH_OK)));
      EXPECT_CALL(mock_, receive)
          .WillOnce(
              DoAll(CopyResp(&resps[i], sizeof(resps[i])), Return(LIBHOTH_OK)));
    }
  }

  EXPECT_NE(htool_restore_spi_interface_drive_strengths(&hoth_dev_, &iface_cfg,
                                                        saved),
            HOTH_SUCCESS);
}

namespace {

class ScopedStdinRedirect {
 public:
  explicit ScopedStdinRedirect(const std::string& content,
                               bool keep_write_open = false) {
    saved_stdin_fd_ = dup(STDIN_FILENO);
    int pipefd[2] = {-1, -1};
    if (pipe(pipefd) == 0) {
      if (!content.empty()) {
        ssize_t written = write(pipefd[1], content.data(), content.size());
        (void)written;
      }
      if (keep_write_open) {
        write_fd_ = pipefd[1];
      } else {
        close(pipefd[1]);
      }
      dup2(pipefd[0], STDIN_FILENO);
      close(pipefd[0]);
    }
  }

  void CloseWriteFd() {
    if (write_fd_ >= 0) {
      close(write_fd_);
      write_fd_ = -1;
    }
  }

  ~ScopedStdinRedirect() {
    CloseWriteFd();
    if (saved_stdin_fd_ >= 0) {
      dup2(saved_stdin_fd_, STDIN_FILENO);
      close(saved_stdin_fd_);
    }
  }

 private:
  int saved_stdin_fd_ = -1;
  int write_fd_ = -1;
};

struct SimulatedGpioDevice {
  uint8_t pad_strength[256] = {};
  uint16_t last_cmd = 0;
  uint8_t last_pad = 0;

  void InitSpidevDefaults() {
    std::memset(pad_strength, 0, sizeof(pad_strength));
    pad_strength[LIBHOTH_GPIO_DIO_PAD_OFFSET + 12] = 0;
    pad_strength[LIBHOTH_GPIO_DIO_PAD_OFFSET + 13] = 1;
    pad_strength[LIBHOTH_GPIO_DIO_PAD_OFFSET + 6] = 2;
    pad_strength[LIBHOTH_GPIO_DIO_PAD_OFFSET + 7] = 3;
    pad_strength[LIBHOTH_GPIO_DIO_PAD_OFFSET + 8] = 2;
    pad_strength[LIBHOTH_GPIO_DIO_PAD_OFFSET + 9] = 1;
  }

  void VerifySpidevRestored() const {
    EXPECT_EQ(pad_strength[LIBHOTH_GPIO_DIO_PAD_OFFSET + 12], 0);
    EXPECT_EQ(pad_strength[LIBHOTH_GPIO_DIO_PAD_OFFSET + 13], 1);
    EXPECT_EQ(pad_strength[LIBHOTH_GPIO_DIO_PAD_OFFSET + 6], 2);
    EXPECT_EQ(pad_strength[LIBHOTH_GPIO_DIO_PAD_OFFSET + 7], 3);
    EXPECT_EQ(pad_strength[LIBHOTH_GPIO_DIO_PAD_OFFSET + 8], 2);
    EXPECT_EQ(pad_strength[LIBHOTH_GPIO_DIO_PAD_OFFSET + 9], 1);
  }

  libhoth_error HandleSend(const void* request) {
    const auto* hdr = static_cast<const struct hoth_host_request*>(request);
    const auto* payload = static_cast<const uint8_t*>(request) + sizeof(*hdr);
    last_cmd = hdr->command;
    if (hdr->command == HOTH_CMD_SET_GPIO_DRIVE_STRENGTH) {
      const auto* req =
          reinterpret_cast<const struct hoth_request_set_gpio_drive_strength*>(
              payload);
      pad_strength[req->pad] = req->strength;
    } else if (hdr->command == HOTH_CMD_GET_GPIO_DRIVE_STRENGTH) {
      const auto* req =
          reinterpret_cast<const struct hoth_request_get_gpio_drive_strength*>(
              payload);
      last_pad = req->pad;
    }
    return LIBHOTH_OK;
  }

  libhoth_error HandleReceive(void* response, size_t* actual_size) const {
    struct {
      struct hoth_host_response hdr;
      uint8_t payload[1];
    } resp = {};
    size_t payload_len = 0;
    if (last_cmd == HOTH_CMD_GET_GPIO_DRIVE_STRENGTH) {
      payload_len = sizeof(struct hoth_response_get_gpio_drive_strength);
      resp.payload[0] = pad_strength[last_pad];
    }
    resp.hdr.struct_version = HOTH_HOST_RESPONSE_VERSION;
    resp.hdr.result = HOTH_RES_SUCCESS;
    resp.hdr.data_len = static_cast<uint16_t>(payload_len);
    resp.hdr.checksum = libhoth_calculate_checksum(&resp.hdr, sizeof(resp.hdr),
                                                   resp.payload, payload_len);
    size_t total = sizeof(resp.hdr) + payload_len;
    std::memcpy(response, &resp, total);
    *actual_size = total;
    return LIBHOTH_OK;
  }
};

class GpioSweepTest : public LibHothTest {
 protected:
  void SetUp() override {
    LibHothTest::SetUp();
    std::string dir_tmpl = ::testing::TempDir() + "/gpio_sweep_test_XXXXXX";
    ASSERT_NE(mkdtemp(&dir_tmpl[0]), nullptr);
    tmp_dir_ = dir_tmpl;
    cfg_path_ = tmp_dir_ + "/gpio_sweep_exit_test.conf";
    FILE* fp = std::fopen(cfg_path_.c_str(), "w");
    ASSERT_NE(fp, nullptr);
    std::fputs(
        "spidev.clk = DIO12\n"
        "spidev.cs = DIO13\n"
        "spidev.d0 = DIO6\n"
        "spidev.d1 = DIO7\n"
        "spidev.d2 = DIO8\n"
        "spidev.d3 = DIO9\n"
        "spidev.drive_strengths = 1, 2\n",
        fp);
    std::fclose(fp);

    g_mock_dev = &hoth_dev_;
    g_mock_config_path = cfg_path_.c_str();
    g_mock_spi_name = "spidev";
    g_mock_dry_run = false;
    g_mock_transport = "";
    g_signals_blocked_on_device_open = false;
    sim_.InitSpidevDefaults();
  }

  void TearDown() override {
    g_mock_dev = nullptr;
    g_mock_config_path = nullptr;
    g_mock_spi_name = nullptr;
    g_mock_dry_run = false;
    g_mock_transport = "";
    std::remove(cfg_path_.c_str());
    if (!tmp_dir_.empty()) {
      rmdir(tmp_dir_.c_str());
    }
    LibHothTest::TearDown();
  }

  void BindDefaultReceive() {
    EXPECT_CALL(mock_, receive)
        .WillRepeatedly(
            [this](struct libhoth_device*, void* resp, size_t, size_t* actual,
                   int) { return sim_.HandleReceive(resp, actual); });
  }

  void ExpectDefaultGetCalls(int count) {
    EXPECT_CALL(mock_,
                send(_, UsesCommand(HOTH_CMD_GET_GPIO_DRIVE_STRENGTH), _))
        .Times(count)
        .WillRepeatedly([this](struct libhoth_device*, const void* req,
                               size_t) { return sim_.HandleSend(req); });
  }

  void ExpectDefaultSetCalls(int count) {
    EXPECT_CALL(mock_,
                send(_, UsesCommand(HOTH_CMD_SET_GPIO_DRIVE_STRENGTH), _))
        .Times(count)
        .WillRepeatedly([this](struct libhoth_device*, const void* req,
                               size_t) { return sim_.HandleSend(req); });
  }

  std::string tmp_dir_;
  std::string cfg_path_;
  SimulatedGpioDevice sim_;
};

}  // namespace

TEST_F(GpioSweepTest, NormalCompletionRestoresPadsAndPrintsReadback) {
  ScopedStdinRedirect input("\n\n");
  ExpectDefaultGetCalls(24);
  ExpectDefaultSetCalls(18);
  BindDefaultReceive();

  testing::internal::CaptureStdout();
  EXPECT_EQ(htool_gpio_sweep(nullptr), 0);
  std::string out = testing::internal::GetCapturedStdout();

  EXPECT_TRUE(g_signals_blocked_on_device_open);
  size_t saved_pos = out.find(
      "Saved original GPIO drive strengths for spidev pads (clk [DIO12]=0, "
      "cs [DIO13]=1, d0 [DIO6]=2, d1 [DIO7]=3, d2 [DIO8]=2, d3 [DIO9]=1).");
  size_t step1_pos = out.find(
      "[1/2] Applied drive_strength=1 to spidev pads (clk [DIO12]=1, cs "
      "[DIO13]=1, d0 [DIO6]=1, d1 [DIO7]=1, d2 [DIO8]=1, d3 [DIO9]=1).");
  EXPECT_NE(saved_pos, std::string::npos);
  EXPECT_NE(step1_pos, std::string::npos);
  EXPECT_LT(saved_pos, step1_pos);
  sim_.VerifySpidevRestored();
}

TEST_F(GpioSweepTest, QuitCommandRestoresPads) {
  ScopedStdinRedirect input("q\n");
  ExpectDefaultGetCalls(18);
  ExpectDefaultSetCalls(12);
  BindDefaultReceive();

  EXPECT_EQ(htool_gpio_sweep(nullptr), 0);
  sim_.VerifySpidevRestored();
}

TEST_F(GpioSweepTest, EofAtPromptRestoresPads) {
  ScopedStdinRedirect input("");
  ExpectDefaultGetCalls(18);
  ExpectDefaultSetCalls(12);
  BindDefaultReceive();

  EXPECT_EQ(htool_gpio_sweep(nullptr), 0);
  sim_.VerifySpidevRestored();
}

TEST_F(GpioSweepTest, FailedSetMidSweepNamesPadAndRestoresPads) {
  ScopedStdinRedirect input("\n\n");
  ExpectDefaultGetCalls(14);
  {
    InSequence seq;
    ExpectDefaultSetCalls(2);
    EXPECT_CALL(mock_,
                send(_, UsesCommand(HOTH_CMD_SET_GPIO_DRIVE_STRENGTH), _))
        .WillOnce(Return(LIBHOTH_ERR_FAIL));
    ExpectDefaultSetCalls(6);
  }
  BindDefaultReceive();

  testing::internal::CaptureStderr();
  EXPECT_EQ(htool_gpio_sweep(nullptr), -1);
  std::string err_out = testing::internal::GetCapturedStderr();
  EXPECT_NE(err_out.find("Error: failed to set d0 (DIO6) to drive_strength=1"),
            std::string::npos);
  sim_.VerifySpidevRestored();
}

TEST_F(GpioSweepTest, SignalDuringSetRestoresPads) {
  ScopedStdinRedirect input("\n\n");
  ExpectDefaultGetCalls(18);
  {
    InSequence seq;
    ExpectDefaultSetCalls(5);
    EXPECT_CALL(mock_,
                send(_, UsesCommand(HOTH_CMD_SET_GPIO_DRIVE_STRENGTH), _))
        .WillOnce([this](struct libhoth_device*, const void* req, size_t) {
          std::raise(SIGINT);
          return sim_.HandleSend(req);
        });
    ExpectDefaultSetCalls(6);
  }
  BindDefaultReceive();

  EXPECT_EQ(htool_gpio_sweep(nullptr), -1);
  sim_.VerifySpidevRestored();
}

TEST_F(GpioSweepTest, SigintAtPromptRestoresPads) {
  ScopedStdinRedirect input("", /*keep_write_open=*/true);
  pid_t child = -1;
  ExpectDefaultGetCalls(18);
  {
    InSequence seq;
    ExpectDefaultSetCalls(5);
    EXPECT_CALL(mock_,
                send(_, UsesCommand(HOTH_CMD_SET_GPIO_DRIVE_STRENGTH), _))
        .WillOnce(
            [this, &child](struct libhoth_device*, const void* req, size_t) {
              child = fork();
              if (child == 0) {
                usleep(20000);
                kill(getppid(), SIGINT);
                _exit(0);
              }
              return sim_.HandleSend(req);
            });
    ExpectDefaultSetCalls(6);
  }
  BindDefaultReceive();

  EXPECT_EQ(htool_gpio_sweep(nullptr), -1);
  if (child > 0) {
    waitpid(child, nullptr, 0);
  }
  sim_.VerifySpidevRestored();
}

TEST_F(GpioSweepTest, SigintOnBackgroundThreadWakesPromptAndRestoresPads) {
  ScopedStdinRedirect input("", /*keep_write_open=*/true);
  std::thread bg_thread;
  ExpectDefaultGetCalls(18);
  {
    InSequence seq;
    ExpectDefaultSetCalls(5);
    EXPECT_CALL(mock_,
                send(_, UsesCommand(HOTH_CMD_SET_GPIO_DRIVE_STRENGTH), _))
        .WillOnce([this, &bg_thread](struct libhoth_device*, const void* req,
                                     size_t) {
          bg_thread = std::thread([]() {
            sigset_t unblocked;
            sigemptyset(&unblocked);
            sigaddset(&unblocked, SIGINT);
            pthread_sigmask(SIG_UNBLOCK, &unblocked, nullptr);
            usleep(20000);
            pthread_kill(pthread_self(), SIGINT);
            usleep(20000);
          });
          return sim_.HandleSend(req);
        });
    ExpectDefaultSetCalls(6);
  }
  BindDefaultReceive();

  EXPECT_EQ(htool_gpio_sweep(nullptr), -1);
  if (bg_thread.joinable()) {
    bg_thread.join();
  }
  sim_.VerifySpidevRestored();
}

TEST_F(GpioSweepTest, RestoreSetFailureReportsFailedPadAndAllOriginals) {
  ScopedStdinRedirect input("q\n");
  ExpectDefaultGetCalls(17);
  {
    InSequence seq;
    ExpectDefaultSetCalls(6);
    EXPECT_CALL(mock_,
                send(_, UsesCommand(HOTH_CMD_SET_GPIO_DRIVE_STRENGTH), _))
        .WillOnce(Return(LIBHOTH_ERR_FAIL));
    ExpectDefaultSetCalls(5);
  }
  BindDefaultReceive();

  testing::internal::CaptureStderr();
  EXPECT_EQ(htool_gpio_sweep(nullptr), -1);
  std::string err_out = testing::internal::GetCapturedStderr();
  EXPECT_NE(err_out.find("Error: failed to restore clk (DIO12) to original "
                         "drive_strength=0"),
            std::string::npos);
  EXPECT_NE(
      err_out.find("Original drive strengths to restore: clk (DIO12)=0, cs "
                   "(DIO13)=1, d0 (DIO6)=2, d1 (DIO7)=3, d2 (DIO8)=2, d3 "
                   "(DIO9)=1"),
      std::string::npos);
}

TEST_F(GpioSweepTest, RestoreReadbackMismatchCountsAsError) {
  ScopedStdinRedirect input("q\n");
  ExpectDefaultGetCalls(18);
  {
    InSequence seq;
    ExpectDefaultSetCalls(6);
    // Restore pad 0 (clk: DIO12): SET returns OK without updating sim_, so
    // subsequent GET reads back 1 instead of 0.
    EXPECT_CALL(mock_,
                send(_, UsesCommand(HOTH_CMD_SET_GPIO_DRIVE_STRENGTH), _))
        .WillOnce([this](struct libhoth_device*, const void* req, size_t) {
          const auto* hdr = static_cast<const struct hoth_host_request*>(req);
          sim_.last_cmd = hdr->command;
          return LIBHOTH_OK;
        });
    ExpectDefaultSetCalls(5);
  }
  BindDefaultReceive();

  testing::internal::CaptureStdout();
  testing::internal::CaptureStderr();
  EXPECT_EQ(htool_gpio_sweep(nullptr), -1);
  std::string out = testing::internal::GetCapturedStdout();
  std::string err_out = testing::internal::GetCapturedStderr();
  EXPECT_EQ(out.find("Restored original GPIO drive strengths"),
            std::string::npos);
  EXPECT_NE(err_out.find("Error: clk (DIO12) drive strength readback "
                         "mismatch: expected 0, got 1"),
            std::string::npos);
  EXPECT_NE(err_out.find("Error: failed to restore clk (DIO12) to original "
                         "drive_strength=0"),
            std::string::npos);
  EXPECT_NE(
      err_out.find("Original drive strengths to restore: clk (DIO12)=0, cs "
                   "(DIO13)=1, d0 (DIO6)=2, d1 (DIO7)=3, d2 (DIO8)=2, d3 "
                   "(DIO9)=1"),
      std::string::npos);
}

TEST_F(GpioSweepTest, SweepingSpidevOverSpidevTransportWarns) {
  g_mock_transport = "spidev";
  ScopedStdinRedirect input("q\n");
  ExpectDefaultGetCalls(18);
  ExpectDefaultSetCalls(12);
  BindDefaultReceive();

  testing::internal::CaptureStderr();
  EXPECT_EQ(htool_gpio_sweep(nullptr), 0);
  std::string err_out = testing::internal::GetCapturedStderr();
  EXPECT_EQ(err_out,
            "Warning: sweeping 'spidev' while communicating over '--transport "
            "spidev' may disrupt host communication.\n");
  sim_.VerifySpidevRestored();
}

TEST_F(GpioSweepTest,
       PipedOutputFlushesStdoutBeforeReadbackWarningAndMarksStepMismatch) {
  std::string out_path = tmp_dir_ + "/gpio_sweep_piped_out.log";
  std::fflush(stdout);
  std::fflush(stderr);

  pid_t pid = fork();
  ASSERT_GE(pid, 0);
  if (pid == 0) {
    FILE* reopened = std::freopen(out_path.c_str(), "w", stdout);
    if (!reopened || dup2(fileno(stdout), STDERR_FILENO) < 0) {
      _exit(2);
    }

    ScopedStdinRedirect input("q\n");
    ExpectDefaultGetCalls(18);
    {
      InSequence seq;
      // Step 1 pad 0 (clk: DIO12): SET returns OK without updating sim_ (stays
      // 0 instead of 1), triggering a readback warning on stderr.
      EXPECT_CALL(mock_,
                  send(_, UsesCommand(HOTH_CMD_SET_GPIO_DRIVE_STRENGTH), _))
          .WillOnce([this](struct libhoth_device*, const void* req, size_t) {
            const auto* hdr = static_cast<const struct hoth_host_request*>(req);
            sim_.last_cmd = hdr->command;
            return LIBHOTH_OK;
          });
      ExpectDefaultSetCalls(11);
    }
    BindDefaultReceive();

    int rc = htool_gpio_sweep(nullptr);
    sim_.VerifySpidevRestored();
    bool mock_ok = ::testing::Mock::VerifyAndClearExpectations(&mock_);
    std::fflush(stdout);
    std::fflush(stderr);
    bool ok = (rc == 0) && mock_ok && !::testing::Test::HasFailure();
    _exit(ok ? 0 : 1);
  }

  int status = 0;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);

  std::string combined;
  FILE* log_fp = std::fopen(out_path.c_str(), "r");
  if (log_fp) {
    char buf[512];
    size_t n = 0;
    while ((n = std::fread(buf, 1, sizeof(buf), log_fp)) > 0) {
      combined.append(buf, n);
    }
    std::fclose(log_fp);
  }
  std::remove(out_path.c_str());

  ASSERT_NE(log_fp, nullptr);
  ASSERT_TRUE(WIFEXITED(status)) << "Child output:\n" << combined;
  EXPECT_EQ(WEXITSTATUS(status), 0) << "Child output:\n" << combined;

  size_t saved_pos =
      combined.find("Saved original GPIO drive strengths for spidev pads");
  size_t warn_pos = combined.find(
      "Warning: clk (DIO12) drive strength readback mismatch: expected 1, "
      "got 0");
  size_t applied_pos = combined.find(
      "[1/2] Applied (with readback mismatch) drive_strength=1 to spidev "
      "pads (clk [DIO12]=0, cs [DIO13]=1, d0 [DIO6]=1, d1 [DIO7]=1, d2 "
      "[DIO8]=1, d3 [DIO9]=1).");
  EXPECT_NE(saved_pos, std::string::npos) << combined;
  EXPECT_NE(warn_pos, std::string::npos) << combined;
  EXPECT_NE(applied_pos, std::string::npos) << combined;
  EXPECT_LT(saved_pos, warn_pos) << combined;
  EXPECT_LT(warn_pos, applied_pos) << combined;
}

TEST_F(GpioSweepTest, DryRunStepOmitsReadbackValues) {
  g_mock_dry_run = true;
  ScopedStdinRedirect input("q\n");
  testing::internal::CaptureStdout();
  EXPECT_EQ(htool_gpio_sweep(nullptr), 0);
  std::string out = testing::internal::GetCapturedStdout();
  EXPECT_NE(
      out.find("[Dry Run] [1/2] Applied drive_strength=1 to spidev pads (clk "
               "[DIO12], cs [DIO13], d0 [DIO6], d1 [DIO7], d2 [DIO8], d3 "
               "[DIO9])."),
      std::string::npos);
}

