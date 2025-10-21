// Copyright 2025 Google LLC
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

#include "protocol/host_cmd.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "test/libhoth_device_mock.h"

#include "protocol/host_cmd.h"
#include "transports/libhoth_device.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

constexpr int kCmd = 0xff42;

uint8_t const ERROR_RESPONSE_EXTENDED[] = {
	0x03, 0xa2, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0xc7, 0x89,
};

uint8_t const ERROR_RESPONSE_LEGACY[] = {
	0x03, 0xfb, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
};

TEST_F(LibHothTest, response_failure_legacy) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyRespRaw(&ERROR_RESPONSE_LEGACY, sizeof(ERROR_RESPONSE_LEGACY)),
                      Return(LIBHOTH_OK)));

  uint8_t resp_buf[1024];
  size_t out_resp_size;
  EXPECT_EQ(
    libhoth_hostcmd_exec(&hoth_dev_, kCmd, 0, nullptr, 0,  resp_buf, sizeof(resp_buf), &out_resp_size),
    HTOOL_ERROR_HOST_COMMAND_START + 2);
}

TEST_F(LibHothTest, response_failure_extended) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyRespRaw(&ERROR_RESPONSE_EXTENDED, sizeof(ERROR_RESPONSE_EXTENDED)),
                      Return(LIBHOTH_OK)));

  uint8_t resp_buf[1024];
  size_t out_resp_size;
  EXPECT_EQ(
    libhoth_hostcmd_exec(&hoth_dev_, kCmd, 0, nullptr, 0,  resp_buf, sizeof(resp_buf), &out_resp_size),
    HTOOL_ERROR_HOST_COMMAND_START + 2);
}
