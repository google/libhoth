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
#include <sys/stat.h>

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

// Helper to manage test image lifetime
struct MappedFile {
  int fd = -1;
  uint8_t* data = nullptr;
  size_t size = 0;
  ~MappedFile() {
    if (data) munmap(data, size);
    if (fd != -1) close(fd);
  }

  bool Load(const char* path) {
    fd = open(path, O_RDONLY, 0);
    if (fd == -1) return false;
    struct stat statbuf = {0};
    if (fstat(fd, &statbuf) != 0) return false;
    size = statbuf.st_size;
    data = reinterpret_cast<uint8_t*>(
        mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0));
    return data != MAP_FAILED;
  }
};

TEST_F(LibHothTest, dfu_check_test) {
  MappedFile image = {};
  ASSERT_TRUE(image.Load(kTestData));

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
      libhoth_dfu_check(&hoth_dev_, image.data, image.size, &mock_response),
      LIBHOTH_OK);
}

TEST_F(LibHothTest, dfu_check_fail) {
  MappedFile image = {};
  ASSERT_TRUE(image.Load(kTestData));

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
      libhoth_dfu_check(&hoth_dev_, image.data, image.size, &mock_response),
      -1);
}
