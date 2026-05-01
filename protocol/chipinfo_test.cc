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

#include "chipinfo.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "test/libhoth_device_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

TEST_F(LibHothTest, haven_chipinfo_test) {
  struct libhoth_haven_device_id haven_data = {};
  haven_data.hardware_identity = 0xABCD1234;
  haven_data.hardware_category = 1234;
  haven_data.info_variant = 2;

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_CHIP_INFO),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(&haven_data, sizeof(haven_data)), Return(LIBHOTH_OK)));

  struct hoth_response_chip_info chipinfo;
  EXPECT_EQ(libhoth_chipinfo(&hoth_dev_, &chipinfo), LIBHOTH_OK);

  EXPECT_EQ(chipinfo.version, 0);
  EXPECT_EQ(chipinfo.data.haven_device_id.hardware_identity,
            haven_data.hardware_identity);
  EXPECT_EQ(chipinfo.data.haven_device_id.hardware_category,
            haven_data.hardware_category);
  EXPECT_EQ(chipinfo.data.haven_device_id.info_variant,
            haven_data.info_variant);
}

TEST_F(LibHothTest, opentitan_chipinfo_test) {
  uint8_t opentitan_data[32];
  memcpy(opentitan_data,
         "\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00"
         "\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\x00",
         32);

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_CHIP_INFO),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(opentitan_data, sizeof(opentitan_data)),
                      Return(LIBHOTH_OK)));

  struct hoth_response_chip_info chipinfo;
  EXPECT_EQ(libhoth_chipinfo(&hoth_dev_, &chipinfo), LIBHOTH_OK);

  EXPECT_EQ(chipinfo.version, 1);
  EXPECT_EQ(memcmp(chipinfo.data.open_titan_device_id, opentitan_data, 32), 0);
}
