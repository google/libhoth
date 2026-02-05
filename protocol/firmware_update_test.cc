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

#include "firmware_update.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>

#include "protocol/host_cmd.h"
#include "test/libhoth_device_mock.h"
#include "transports/libhoth_device.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

TEST_F(LibHothTest, firmware_update_test_skipped) {
  EXPECT_CALL(mock_, send(_, UsesCommand(HOTH_CMD_FIRMWARE_UPDATE), _))
      .WillOnce(Return(LIBHOTH_OK));
  uint32_t dummy;
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&dummy, 0), Return(LIBHOTH_OK)));
  EXPECT_CALL(mock_, reconnect).Times(0);
  EXPECT_EQ(
      libhoth_firmware_update_from_flash_and_reset(&hoth_dev_, /*offset=*/0),
      0);
}

TEST_F(LibHothTest, firmware_update_test_rebooting) {
  EXPECT_CALL(mock_, send(_, UsesCommand(HOTH_CMD_FIRMWARE_UPDATE), _))
      .WillOnce(Return(LIBHOTH_OK));
  uint32_t dummy;
  EXPECT_CALL(mock_, receive).WillOnce(DoAll(CopyResp(&dummy, 0), Return(-1)));
  EXPECT_CALL(mock_, reconnect).WillOnce(Return(LIBHOTH_OK));
  EXPECT_EQ(
      libhoth_firmware_update_from_flash_and_reset(&hoth_dev_, /*offset=*/0),
      0);
}

TEST_F(LibHothTest, firmware_update_test_failed_without_rebooting) {
  EXPECT_CALL(mock_, send(_, UsesCommand(HOTH_CMD_FIRMWARE_UPDATE), _))
      .WillOnce(Return(LIBHOTH_OK));
  uint8_t const ERROR_RESPONSE_UNAVAILABLE[] = {
      0x03, 0xf4, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
  };

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyRespRaw(ERROR_RESPONSE_UNAVAILABLE,
                                  sizeof(ERROR_RESPONSE_UNAVAILABLE)),
                      Return(LIBHOTH_OK)));
  EXPECT_CALL(mock_, reconnect).Times(0);
  EXPECT_EQ(
      libhoth_firmware_update_from_flash_and_reset(&hoth_dev_, /*offset=*/0),
      HTOOL_ERROR_HOST_COMMAND_START + HOTH_RES_UNAVAILABLE);
}
