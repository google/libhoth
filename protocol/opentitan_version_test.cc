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

TEST_F(LibHothTest, ExtractOtBundleBoundsCheckLargeOffset) {
  size_t image_size = 70000;
  std::vector<uint8_t> image(image_size, 0);
  struct opentitan_image_version rom_ext;
  struct opentitan_image_version app;

  // Magic
  const char* magic = "_OTFWUPDATE_";
  memcpy(image.data(), magic, strlen(magic));

  // Offset = 65536, causes
  // 65536 + OPENTITAN_OFFSET_APP_FW + OPENTITAN_OFFSET_VERSION_MINOR + 4
  // = 65536 + 65536 + 840 + 4 = 131916
  // to be > image_size, triggering bounds check.
  uint32_t offset = 65536;
  image[OPENTITAN_OFFSET_HEADER_DATA] = offset & 0xff;
  image[OPENTITAN_OFFSET_HEADER_DATA + 1] = (offset >> 8) & 0xff;
  image[OPENTITAN_OFFSET_HEADER_DATA + 2] = (offset >> 16) & 0xff;
  image[OPENTITAN_OFFSET_HEADER_DATA + 3] = (offset >> 24) & 0xff;

  // Expect call to fail with -1
  EXPECT_EQ(libhoth_extract_ot_bundle(image.data(), image_size, &rom_ext, &app),
            -1);
}

TEST_F(LibHothTest, ExtractOtBundleBoundsCheckSmallImage) {
  size_t image_size = 66379;
  std::vector<uint8_t> image(image_size, 0);
  struct opentitan_image_version rom_ext;
  struct opentitan_image_version app;

  // Magic
  const char* magic = "_OTFWUPDATE_";
  memcpy(image.data(), magic, strlen(magic));

  // Offset = 0, but image_size is too small for reads because
  // 0 + OPENTITAN_OFFSET_APP_FW + OPENTITAN_OFFSET_VERSION_MINOR + 4
  // = 0 + 65536 + 840 + 4 = 66380
  // is > image_size, triggering bounds check.
  uint32_t offset = 0;
  image[OPENTITAN_OFFSET_HEADER_DATA] = offset & 0xff;
  image[OPENTITAN_OFFSET_HEADER_DATA + 1] = (offset >> 8) & 0xff;
  image[OPENTITAN_OFFSET_HEADER_DATA + 2] = (offset >> 16) & 0xff;
  image[OPENTITAN_OFFSET_HEADER_DATA + 3] = (offset >> 24) & 0xff;

  // Expect call to fail with -1
  EXPECT_EQ(libhoth_extract_ot_bundle(image.data(), image_size, &rom_ext, &app),
            -1);
}

TEST_F(LibHothTest, ExtractOtBundleImageTooSmall) {
  size_t image_size = 100;
  std::vector<uint8_t> image(image_size, 0);
  struct opentitan_image_version rom_ext;
  struct opentitan_image_version app;

  // Magic
  const char* magic = "_OTFWUPDATE_";
  memcpy(image.data(), magic, strlen(magic));

  // image_size is 100, which is smaller than
  // OPENTITAN_OFFSET_APP_FW + sizeof(struct opentitan_image_version)
  // = 65536 + 64 = 65600
  uint32_t offset = 0;
  image[OPENTITAN_OFFSET_HEADER_DATA] = offset & 0xff;
  image[OPENTITAN_OFFSET_HEADER_DATA + 1] = (offset >> 8) & 0xff;
  image[OPENTITAN_OFFSET_HEADER_DATA + 2] = (offset >> 16) & 0xff;
  image[OPENTITAN_OFFSET_HEADER_DATA + 3] = (offset >> 24) & 0xff;

  // Expect call to fail with -1
  EXPECT_EQ(libhoth_extract_ot_bundle(image.data(), image_size, &rom_ext, &app),
            -1);
}

TEST_F(LibHothTest, ExtractOtBundleIntegerOverflow) {
  size_t image_size = 0xFFFFFFFF;
  std::vector<uint8_t> image(66380, 0);  // small image buffer is fine
  struct opentitan_image_version rom_ext;
  struct opentitan_image_version app;

  // Magic
  const char* magic = "_OTFWUPDATE_";
  memcpy(image.data(), magic, strlen(magic));

  // Offset = 0xFFFFFFFF, causes
  // offset + OPENTITAN_OFFSET_APP_FW + OPENTITAN_OFFSET_VERSION_MINOR + 4
  // to wrap around.
  // 0xFFFFFFFF + 65536 + 840 + 4 = 66379 (mod 2^32)
  // 66379 < 0xFFFFFFFF should trigger overflow check
  uint32_t offset = 0xFFFFFFFF;
  image[OPENTITAN_OFFSET_HEADER_DATA] = offset & 0xff;
  image[OPENTITAN_OFFSET_HEADER_DATA + 1] = (offset >> 8) & 0xff;
  image[OPENTITAN_OFFSET_HEADER_DATA + 2] = (offset >> 16) & 0xff;
  image[OPENTITAN_OFFSET_HEADER_DATA + 3] = (offset >> 24) & 0xff;

  // Expect call to fail with -1
  EXPECT_EQ(libhoth_extract_ot_bundle(image.data(), image_size, &rom_ext, &app),
            -1);
}
