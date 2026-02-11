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

#include "dfu_check.h"

#include <fcntl.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/mman.h>

#include <cstdint>
#include <cstring>
#include <iomanip>

#include "opentitan_version.h"
#include "test/libhoth_device_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::ElementsAreArray;
using ::testing::Return;

constexpr char kTestData[] = "protocol/test/test_fwupdate.bin";

TEST_F(LibHothTest, dfu_check_test) {
  int fd = open(kTestData, O_RDONLY, 0);
  ASSERT_NE(fd, -1);

  struct stat statbuf;
  ASSERT_EQ(fstat(fd, &statbuf), 0);

  uint8_t* image = reinterpret_cast<uint8_t*>(
      mmap(NULL, statbuf.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0));
  ASSERT_NE(image, nullptr);

  struct opentitan_image_version rom_ext;
  struct opentitan_image_version app;
  libhoth_extract_ot_bundle(image, statbuf.st_size, &rom_ext, &app);

  struct opentitan_get_version_resp mock_response = {};

  mock_response.rom_ext.slots[0].major = 1;
  mock_response.rom_ext.slots[0].minor = 0;
  mock_response.rom_ext.slots[1].major = 1;
  mock_response.rom_ext.slots[1].minor = 0;

  mock_response.app.slots[0].major = 2;
  mock_response.app.slots[0].minor = 5;
  mock_response.app.slots[1].major = 2;
  mock_response.app.slots[1].minor = 5;

  EXPECT_EQ(
      libhoth_dfu_check(&hoth_dev_, image, statbuf.st_size, &mock_response),
      LIBHOTH_OK);
}

TEST_F(LibHothTest, dfu_check_fail) {
  int fd = open(kTestData, O_RDONLY, 0);
  ASSERT_NE(fd, -1);

  struct stat statbuf;
  ASSERT_EQ(fstat(fd, &statbuf), 0);

  uint8_t* image = reinterpret_cast<uint8_t*>(
      mmap(NULL, statbuf.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0));
  ASSERT_NE(image, nullptr);

  struct opentitan_image_version rom_ext;
  struct opentitan_image_version app;
  libhoth_extract_ot_bundle(image, statbuf.st_size, &rom_ext, &app);

  struct opentitan_get_version_resp mock_response = {};

  mock_response.rom_ext.slots[0].major = 0;
  mock_response.rom_ext.slots[0].minor = 11;
  mock_response.rom_ext.slots[1].major = 0;
  mock_response.rom_ext.slots[1].minor = 11;

  mock_response.app.slots[0].major = 0;
  mock_response.app.slots[0].minor = 20;
  mock_response.app.slots[1].major = 0;
  mock_response.app.slots[1].minor = 20;

  EXPECT_EQ(
      libhoth_dfu_check(&hoth_dev_, image, statbuf.st_size, &mock_response),
      -1);
}
