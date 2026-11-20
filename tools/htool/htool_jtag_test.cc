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

#include "htool_jtag.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "protocol/host_cmd.h"
#include "protocol/jtag.h"
#include "protocol/test/libhoth_device_mock.h"
#include "tools/common/htool_cmd.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;

namespace {

struct FakeParams {
  std::unordered_map<std::string, const char*> strings;
  std::unordered_map<std::string, uint32_t> u32s;
};

FakeParams* g_params = nullptr;
struct libhoth_device* g_mock_dev = nullptr;

class HtoolJtagTest : public LibHothTest {
 protected:
  void SetUp() override {
    g_mock_dev = &hoth_dev_;
    g_params = &params_;
  }

  void TearDown() override {
    g_params = nullptr;
    g_mock_dev = nullptr;
  }

  void ExpectTestBypass(std::vector<uint8_t>* captured_tdi) {
    EXPECT_CALL(mock_, send(_,
                            UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                        HOTH_PRV_CMD_HOTH_JTAG_OPERATION),
                            _))
        .WillOnce(Invoke([captured_tdi](struct libhoth_device*, const void* buf,
                                        size_t len) {
          const size_t offset = sizeof(struct hoth_host_request) +
                                sizeof(struct hoth_request_jtag_operation);
          EXPECT_EQ(len, offset + HOTH_JTAG_TEST_BYPASS_PATTERN_LEN);
          const auto* p = static_cast<const uint8_t*>(buf) + offset;
          captured_tdi->assign(p, p + HOTH_JTAG_TEST_BYPASS_PATTERN_LEN);
          return LIBHOTH_OK;
        }));
    EXPECT_CALL(mock_, receive)
        .WillOnce(DoAll(CopyResp(&resp_, sizeof(resp_)), Return(LIBHOTH_OK)));
  }

  int RunTestBypass(const char* tdi_bytes) {
    params_ = {};
    params_.u32s["clk_idiv"] = 47;
    params_.u32s["jtag_interface_id"] = 0;
    params_.strings["tdi_bytes"] = tdi_bytes;

    const char* verbs[] = {"jtag", JTAG_TEST_BYPASS_CMD_STR, nullptr};
    struct htool_cmd cmd = {};
    cmd.verbs = verbs;
    struct htool_invocation inv = {};
    inv.cmd = &cmd;
    return htool_jtag_run(&inv);
  }

  FakeParams params_;
  struct hoth_response_jtag_test_bypass_operation resp_ = {};
};

TEST_F(HtoolJtagTest, TestBypassParsesReadOnlyLiteral) {
  const char* const ro_tdi_bytes =
      "  0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 "
      "0x08 0x09 0x0a 0x0b 0x0c 0x0d 0x0e 0x0f "
      "0x10 0x11 0x12 0x13 0x14 0x15 0x16 0x17 "
      "0x18 0x19 0x1a 0x1b 0x1c 0x1d 0x1e 0x1f "
      "0x20 0x21 0x22 0x23 0x24 0x25 0x26 0x27 "
      "0x28 0x29 0x2a 0x2b 0x2c 0x2d 0x2e 0x2f "
      "0x30 0x31 0x32 0x33 0x34 0x35 0x36 0x37 "
      "0x38 0x39 0x3a 0x3b 0x3c 0x3d 0x3e  0x3f  ";

  std::vector<uint8_t> sent;
  ExpectTestBypass(&sent);
  EXPECT_EQ(RunTestBypass(ro_tdi_bytes), 0);
  ASSERT_EQ(sent.size(), HOTH_JTAG_TEST_BYPASS_PATTERN_LEN);
  for (size_t i = 0; i < HOTH_JTAG_TEST_BYPASS_PATTERN_LEN; ++i) {
    EXPECT_EQ(sent[i], i);
  }
}

TEST_F(HtoolJtagTest, TestBypassDefaultPatternReusable) {
  std::vector<uint8_t> first;
  std::vector<uint8_t> second;
  ExpectTestBypass(&first);
  EXPECT_EQ(RunTestBypass(""), 0);
  ExpectTestBypass(&second);
  EXPECT_EQ(RunTestBypass(""), 0);
  EXPECT_EQ(first.size(), HOTH_JTAG_TEST_BYPASS_PATTERN_LEN);
  EXPECT_EQ(first, second);
}

TEST_F(HtoolJtagTest, TestBypassRejectsInvalidInputs) {
  EXPECT_CALL(mock_, send).Times(0);

  std::string bytes63;
  for (size_t i = 0; i < HOTH_JTAG_TEST_BYPASS_PATTERN_LEN - 1; ++i) {
    bytes63 += "0x01 ";
  }

  for (const std::string& bad :
       {bytes63, bytes63 + "0x02 0x03", std::string("-1 ") + bytes63,
        std::string("0x100 ") + bytes63,
        std::string("0x01\t0x02 ") + bytes63}) {
    EXPECT_EQ(RunTestBypass(bad.c_str()), -1) << bad;
  }
}

}  // namespace

extern "C" {

int htool_get_param_string(const struct htool_invocation* inv, const char* name,
                           const char** value) {
  (void)inv;
  auto it = g_params->strings.find(name);
  if (it == g_params->strings.end()) return -1;
  *value = it->second;
  return 0;
}

int htool_get_param_u32(const struct htool_invocation* inv, const char* name,
                        uint32_t* value) {
  (void)inv;
  auto it = g_params->u32s.find(name);
  if (it == g_params->u32s.end()) return -1;
  *value = it->second;
  return 0;
}

struct libhoth_device* htool_libhoth_device(void) { return g_mock_dev; }

void htool_report_error(const char* cmd_name, libhoth_error err) {
  (void)cmd_name;
  (void)err;
}

}  // extern "C"
