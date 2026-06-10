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

TEST_F(LibHothTest, hoth_chipinfo_test) {
  struct hoth_device_id hoth_data = {};
  hoth_data.hardware_identity = 0xABCD1234;
  hoth_data.hardware_category = 1234;
  hoth_data.info_variant = 2;

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_CHIP_INFO),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(&hoth_data, sizeof(hoth_data)), Return(LIBHOTH_OK)));

  struct hoth_response_chip_info chipinfo;
  EXPECT_EQ(libhoth_chipinfo(&hoth_dev_, &chipinfo), LIBHOTH_OK);

  EXPECT_EQ(chipinfo.version, 0);
  EXPECT_EQ(chipinfo.data.hoth_device_id.hardware_identity,
            hoth_data.hardware_identity);
  EXPECT_EQ(chipinfo.data.hoth_device_id.hardware_category,
            hoth_data.hardware_category);
  EXPECT_EQ(chipinfo.data.hoth_device_id.info_variant, hoth_data.info_variant);
}

TEST_F(LibHothTest, opentitan_chipinfo_test) {
  uint8_t opentitan_data[OPENTITAN_DEVICE_ID_LEN];
  memcpy(opentitan_data,
         "\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00"
         "\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\x00",
         OPENTITAN_DEVICE_ID_LEN);

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
  EXPECT_EQ(memcmp(chipinfo.data.open_titan_device_id, opentitan_data,
                   OPENTITAN_DEVICE_ID_LEN),
            0);
}

TEST(ChipInfoTest, ParseOpenTitanDeviceId) {
  uint8_t data[OPENTITAN_DEVICE_ID_LEN] = {0};
  data[31] = 0x34;  // creator_id low
  data[30] = 0x12;  // creator_id high -> 0x1234
  data[29] = 0x78;  // product_id low
  data[28] = 0x56;  // product_id high -> 0x5678
  data[27] = 0x55;  // year low nibble = 5 -> 2025, week low nibble = 5
  data[26] = 0x34;  // lot high = 3, week high nibble = 4 -> week 45, lot = 123
  data[25] = 0x12;  // lot low = 1, 2 -> lot = 123
  data[24] = 0x67;  // wafer = 67
  data[23] = 0x89;  // wafer_x = 89 (if high nibble of 22 is 0)
  data[22] = 0x01;  // wafer_x high = 1, wafer_y low = 0
  data[21] = 0x23;  // wafer_y high = 2, lot low = 3 -> wafer_y = 230
  data[20] = 0xAA;  // reserved_din
  data[16] = 0x11;
  data[17] = 0x22;
  data[18] = 0x33;
  data[19] = 0x44;
  data[15] = 0xBB;  // package_id
  data[14] = 0xCC;  // ast_config_version
  data[13] = 'B';   // otp_id[1]
  data[12] = 'A';   // otp_id[0]
  data[11] = 0xDD;  // otp_version
  data[7] = '4';    // sku_id[3]
  data[6] = '3';    // sku_id[2]
  data[5] = '2';    // sku_id[1]
  data[4] = '1';    // sku_id[0]
  data[0] = 0xEE;   // sku_specific_version

  struct opentitan_device_id parsed;
  ASSERT_EQ(parse_opentitan_device_id(data, &parsed), 0);

  EXPECT_EQ(parsed.creator_id, 0x1234);
  EXPECT_EQ(parsed.product_id, 0x5678);
  EXPECT_EQ(parsed.device_year, 2025);
  EXPECT_EQ(parsed.device_week, 45);
  EXPECT_EQ(parsed.lot_number, 123);
  EXPECT_EQ(parsed.wafer_number, 67);
  EXPECT_EQ(parsed.wafer_x, 189);
  EXPECT_EQ(parsed.wafer_y, 230);
  EXPECT_EQ(parsed.reserved_din, 0xAA);
  EXPECT_EQ(parsed.reserved, 0x11223344);
  EXPECT_EQ(parsed.package_id, 0xBB);
  EXPECT_EQ(parsed.ast_config_version, 0xCC);
  EXPECT_STREQ(parsed.otp_id, "AB");
  EXPECT_EQ(parsed.otp_version, 0xDD);
  EXPECT_STREQ(parsed.sku_id_string, "1234");
  EXPECT_EQ(parsed.sku_specific_version, 0xEE);
}
