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

#include "htool_i2c.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "protocol/host_cmd.h"
#include "protocol/i2c.h"
#include "protocol/test/libhoth_device_mock.h"
#include "tools/common/htool_cmd.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

namespace {

struct FakeParams {
  std::unordered_map<std::string, const char*> strings;
  std::unordered_map<std::string, uint32_t> u32s;
  std::unordered_map<std::string, bool> bools;
};

FakeParams* g_params = nullptr;
struct libhoth_device* g_mock_dev = nullptr;

MATCHER_P2(UsesCommandWithPayload, command, expected, "") {
  const auto* req = static_cast<const struct hoth_host_request*>(arg);
  const uint8_t* payload =
      static_cast<const uint8_t*>(arg) + sizeof(struct hoth_host_request);
  return req->command == command && req->data_len == expected.size() &&
         std::memcmp(payload, expected.data(), expected.size()) == 0;
}

class HtoolI2cTest : public LibHothTest {
 protected:
  void SetUp() override {
    g_mock_dev = &hoth_dev_;
    g_params = &params_;
  }

  void TearDown() override {
    g_params = nullptr;
    g_mock_dev = nullptr;
  }

  void ExpectCommand(uint16_t prv_cmd, const std::vector<uint8_t>& expected_req,
                     const void* resp, size_t resp_size) {
    EXPECT_CALL(mock_,
                send(_,
                     UsesCommandWithPayload(
                         HOTH_CMD_BOARD_SPECIFIC_BASE + prv_cmd, expected_req),
                     _))
        .WillOnce(Return(LIBHOTH_OK));
    EXPECT_CALL(mock_, receive)
        .WillOnce(DoAll(CopyResp(resp, resp_size), Return(LIBHOTH_OK)));
  }

  int RunEnableEndpoints(uint32_t ids_count, const char* byte_stream) {
    params_ = {};
    params_.u32s["ids_count"] = ids_count;
    params_.strings["byte_stream"] = byte_stream;
    struct htool_invocation inv = {};
    return htool_i2c_filtering_enable_endpoints(&inv);
  }

  int RunI2cWrite(uint32_t offset, const char* byte_stream) {
    params_ = {};
    params_.u32s["bus"] = 1;
    params_.u32s["frequency"] = 400;
    params_.u32s["address"] = 0x50;
    params_.u32s["offset"] = offset;
    params_.bools["no_stop"] = false;
    params_.strings["byte_stream"] = byte_stream;

    const char* verbs[] = {"i2c", I2C_WRITE_CMD_STR, nullptr};
    struct htool_cmd cmd = {};
    cmd.verbs = verbs;
    struct htool_invocation inv = {};
    inv.cmd = &cmd;
    return htool_i2c_run(&inv);
  }

  FakeParams params_;
};

TEST_F(HtoolI2cTest, FilteringEnableEndpointsParsesReadOnlyLiteral) {
  const std::vector<uint8_t> expected = {1, 0, 0, 0, 0x0a, 16, 8, 255};
  ExpectCommand(HOTH_PRV_CMD_ENABLE_I2C_ENDPOINTS_FOR_FILTERING, expected,
                expected.data(), expected.size());
  EXPECT_EQ(RunEnableEndpoints(1, "  0x0a  16 010  255  "), 0);
}

TEST_F(HtoolI2cTest, FilteringEnableEndpointsEmptyDefault) {
  const std::vector<uint8_t> expected = {0, 0, 0, 0};
  ExpectCommand(HOTH_PRV_CMD_ENABLE_I2C_ENDPOINTS_FOR_FILTERING, expected,
                expected.data(), expected.size());
  EXPECT_EQ(RunEnableEndpoints(0, ""), 0);
}

TEST_F(HtoolI2cTest, FilteringEnableEndpointsRejectsInvalidAndOverflow) {
  EXPECT_CALL(mock_, send).Times(0);

  for (const char* bad :
       {"0xzz", "0x100", "-1", "-0", "0x01\t0x02", "\t0x01"}) {
    EXPECT_EQ(RunEnableEndpoints(1, bad), -1) << bad;
  }
  EXPECT_EQ(RunEnableEndpoints(0, "0x01"), -1);
  EXPECT_EQ(RunEnableEndpoints(1, ""), -1);

  const size_t max_bytes =
      LIBHOTH_MAILBOX_SIZE - sizeof(struct hoth_host_request) -
      sizeof(struct hoth_request_enable_i2c_endpoints_for_filtering);
  std::string overflow;
  for (size_t i = 0; i <= max_bytes; ++i) {
    overflow += "1 ";
  }
  EXPECT_EQ(RunEnableEndpoints(1, overflow.c_str()), -1);
}

TEST_F(HtoolI2cTest, I2cWriteParsesReadOnlyLiteral) {
  struct hoth_request_i2c_transfer expected = {};
  expected.bus_number = 1;
  expected.speed_khz = 400;
  expected.dev_address = 0x50;
  expected.flags = I2C_BITS_WRITE;
  expected.size_write = 3;
  expected.arg_bytes[0] = 0x20;
  expected.arg_bytes[1] = 0xaa;
  expected.arg_bytes[2] = 0xbb;

  const auto* bytes = reinterpret_cast<const uint8_t*>(&expected);
  struct hoth_response_i2c_transfer resp = {};
  ExpectCommand(HOTH_PRV_CMD_HOTH_I2C_TRANSFER,
                std::vector<uint8_t>(bytes, bytes + sizeof(expected)), &resp,
                sizeof(resp));
  EXPECT_EQ(RunI2cWrite(/*offset=*/0x20, "  0xaa  0xbb  "), 0);
}

TEST_F(HtoolI2cTest, I2cWriteRejectsInvalidAndOverflow) {
  EXPECT_CALL(mock_, send).Times(0);

  for (const char* bad : {"-1", "-0", "0x100", "bad", "0x01\t0x02"}) {
    EXPECT_EQ(RunI2cWrite(UINT32_MAX, bad), -1) << bad;
  }

  std::string too_many;
  for (size_t i = 0; i < I2C_TRANSFER_DATA_MAX_SIZE_BYTES; ++i) {
    too_many += "0 ";
  }
  // 256 bytes plus an offset byte overflows the 256-byte transfer buffer.
  EXPECT_EQ(RunI2cWrite(/*offset=*/0x05, too_many.c_str()), -1);
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

int htool_get_param_bool(const struct htool_invocation* inv, const char* name,
                         bool* value) {
  (void)inv;
  auto it = g_params->bools.find(name);
  if (it == g_params->bools.end()) return -1;
  *value = it->second;
  return 0;
}

struct libhoth_device* htool_libhoth_device(void) { return g_mock_dev; }

void htool_report_error(const char* cmd_name, libhoth_error err) {
  (void)cmd_name;
  (void)err;
}

}  // extern "C"
