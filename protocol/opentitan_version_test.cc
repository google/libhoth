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

#include "opentitan_version.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>

#include "test/libhoth_device_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::ElementsAreArray;
using ::testing::Return;

TEST_F(LibHothTest, opentitan_version_test) {
  struct opentitan_get_version_resp mock_response = {};
  struct opentitan_get_version_resp response = {};

  mock_response.rom_ext.slots[0].major = 0;
  mock_response.rom_ext.slots[0].minor = 123;
  mock_response.rom_ext.slots[1].major = 0;
  mock_response.rom_ext.slots[1].minor = 124;

  mock_response.app.slots[0].major = 0;
  mock_response.app.slots[0].minor = 123;
  mock_response.app.slots[1].major = 0;
  mock_response.app.slots[1].minor = 124;

  EXPECT_CALL(mock_, send(_, UsesCommand(HOTH_OPENTITAN_GET_VERSION), _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&mock_response, sizeof(mock_response)),
                      Return(LIBHOTH_OK)));

  EXPECT_EQ(libhoth_opentitan_version(&hoth_dev_, &response), LIBHOTH_OK);

  EXPECT_EQ(response.rom_ext.slots[0].major,
            mock_response.rom_ext.slots[0].major);
  EXPECT_EQ(response.rom_ext.slots[0].minor,
            mock_response.rom_ext.slots[0].minor);
  EXPECT_EQ(response.rom_ext.slots[1].major,
            mock_response.rom_ext.slots[1].major);
  EXPECT_EQ(response.rom_ext.slots[1].minor,
            mock_response.rom_ext.slots[1].minor);
  EXPECT_EQ(response.app.slots[0].major, mock_response.app.slots[0].major);
  EXPECT_EQ(response.app.slots[0].minor, mock_response.app.slots[0].minor);
  EXPECT_EQ(response.app.slots[1].major, mock_response.app.slots[1].major);
  EXPECT_EQ(response.app.slots[1].minor, mock_response.app.slots[1].minor);
}

TEST_F(LibHothTest, opentitan_image_version_eq_test) {
  struct opentitan_image_version v1 = {
      .major = 6,
      .minor = 5,
      .security_version = 1,
      .timestamp = 1234,
      .measurement = {},
  };

  struct opentitan_image_version v2 = {
      .major = 6,
      .minor = 5,
      .security_version = 1,
      .timestamp = 1234,
      .measurement = {},
  };

  EXPECT_TRUE(libhoth_ot_version_eq(&v1, &v2));
  v1.minor = 4;
  EXPECT_FALSE(libhoth_ot_version_eq(&v1, &v2));
}

TEST_F(LibHothTest, opentitan_image_version_helper_test) {
  struct opentitan_get_version_resp resp = {};

  resp.rom_ext.slots[0].major = 6;
  resp.rom_ext.slots[0].minor = 111;
  resp.rom_ext.slots[1].major = 7;
  resp.rom_ext.slots[1].minor = 222;

  resp.app.slots[0].major = 8;
  resp.app.slots[0].minor = 333;
  resp.app.slots[1].major = 9;
  resp.app.slots[1].minor = 444;

  resp.rom_ext.booted_slot = kOpentitanBootSlotA;
  resp.app.booted_slot = kOpentitanBootSlotB;

  EXPECT_EQ(libhoth_ot_boot_app(&resp)->major, 9);
  EXPECT_EQ(libhoth_ot_boot_app(&resp)->minor, 444);
  EXPECT_EQ(libhoth_ot_boot_romext(&resp)->major, 6);
  EXPECT_EQ(libhoth_ot_boot_romext(&resp)->minor, 111);

  EXPECT_EQ(libhoth_ot_staged_app(&resp)->major, 8);
  EXPECT_EQ(libhoth_ot_staged_app(&resp)->minor, 333);
  EXPECT_EQ(libhoth_ot_staged_romext(&resp)->major, 7);
  EXPECT_EQ(libhoth_ot_staged_romext(&resp)->minor, 222);

  resp.rom_ext.booted_slot = kOpentitanBootSlotB;
  resp.app.booted_slot = kOpentitanBootSlotA;

  EXPECT_EQ(libhoth_ot_boot_app(&resp)->major, 8);
  EXPECT_EQ(libhoth_ot_boot_app(&resp)->minor, 333);
  EXPECT_EQ(libhoth_ot_boot_romext(&resp)->major, 7);
  EXPECT_EQ(libhoth_ot_boot_romext(&resp)->minor, 222);

  EXPECT_EQ(libhoth_ot_staged_app(&resp)->major, 9);
  EXPECT_EQ(libhoth_ot_staged_app(&resp)->minor, 444);
  EXPECT_EQ(libhoth_ot_staged_romext(&resp)->major, 6);
  EXPECT_EQ(libhoth_ot_staged_romext(&resp)->minor, 111);
}

TEST_F(LibHothTest, opentitan_image_compare_test) {
  struct opentitan_get_version_resp resp = {};

  resp.rom_ext.slots[0].major = 6;
  resp.rom_ext.slots[0].minor = 111;
  resp.rom_ext.slots[1].major = 7;
  resp.rom_ext.slots[1].minor = 222;

  resp.app.slots[0].major = 8;
  resp.app.slots[0].minor = 333;
  resp.app.slots[1].major = 9;
  resp.app.slots[1].minor = 444;

  resp.rom_ext.booted_slot = kOpentitanBootSlotA;
  resp.app.booted_slot = kOpentitanBootSlotB;

  EXPECT_TRUE(libhoth_ot_boot_slot_eq(&resp, libhoth_ot_boot_romext(&resp),
                                      libhoth_ot_boot_app(&resp)));
  EXPECT_FALSE(libhoth_ot_boot_slot_eq(&resp, libhoth_ot_staged_romext(&resp),
                                       libhoth_ot_boot_app(&resp)));
  EXPECT_FALSE(libhoth_ot_boot_slot_eq(&resp, libhoth_ot_boot_romext(&resp),
                                       libhoth_ot_staged_app(&resp)));

  EXPECT_TRUE(libhoth_ot_staged_slot_eq(&resp, libhoth_ot_staged_romext(&resp),
                                        libhoth_ot_staged_app(&resp)));
  EXPECT_FALSE(libhoth_ot_staged_slot_eq(&resp, libhoth_ot_boot_romext(&resp),
                                         libhoth_ot_staged_app(&resp)));
  EXPECT_FALSE(libhoth_ot_staged_slot_eq(&resp, libhoth_ot_staged_romext(&resp),
                                         libhoth_ot_boot_app(&resp)));

  struct opentitan_image_version romext = {
      .major = 6,
      .minor = 111,
      .security_version = 7,
      .timestamp = 1234,
      .measurement = {},
  };

  struct opentitan_image_version app = {
      .major = 1,
      .minor = 116,
      .security_version = 2,
      .timestamp = 6789,
      .measurement = {},
  };

  resp.rom_ext.slots[0] = romext;
  resp.rom_ext.slots[1] = romext;
  resp.app.slots[0] = app;
  resp.app.slots[1] = app;

  EXPECT_TRUE(libhoth_update_complete(&resp, &romext, &app));
  EXPECT_FALSE(libhoth_update_complete(&resp, &romext, &romext));
  EXPECT_FALSE(libhoth_update_complete(&resp, &app, &app));
}
