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

#include "console.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <unistd.h>

#include <cstdint>

#include "test/libhoth_device_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

constexpr uint32_t kCmdChannelRead =
    HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_CHANNEL_READ;

bool CheckReadSize(const void* data) {
  const auto* req = static_cast<const struct hoth_channel_read_request*>(data);
  return req->size == 1012;
}

TEST_F(LibHothTest, read_console_test) {
  EXPECT_CALL(mock_,
              send(_, UsesCommandWithData(kCmdChannelRead, CheckReadSize), _))
      .WillOnce(Return(LIBHOTH_OK));

  struct {
    struct hoth_channel_read_response hdr;
    uint8_t data[1012];
  } fake_response = {};
  fake_response.hdr.offset = 100;

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&fake_response, sizeof(fake_response)),
                      Return(LIBHOTH_OK)));

  uint32_t offset = 100;
  EXPECT_EQ(libhoth_read_console(&hoth_dev_, STDOUT_FILENO, false, 0, &offset),
            HOTH_SUCCESS);
  EXPECT_EQ(offset, 100 + 1012);
}
