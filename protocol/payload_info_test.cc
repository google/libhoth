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

#include "protocol/payload_info.h"

#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/mman.h>

#include <cstdint>
#include <cstring>
#include <iomanip>

#include "payload_info.h"

constexpr char kTestData[] = "protocol/test/test_payload.bin";
constexpr char kTestHash[] =
    "50316da1d3b006ff87989aa8bcd48a33ecc4bfe2114ded138ee594f6097d58b3";

TEST(PayloadInfotest, payload_info) {
  int fd = open(kTestData, O_RDONLY, 0);
  ASSERT_NE(fd, -1);

  struct stat statbuf;
  ASSERT_EQ(fstat(fd, &statbuf), 0);

  uint8_t *image = reinterpret_cast<uint8_t *>(
      mmap(NULL, statbuf.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0));
  ASSERT_NE(image, nullptr);

  const struct image_descriptor *descr =
      libhoth_find_image_descriptor(image, statbuf.st_size);

  ASSERT_NE(descr, nullptr);

  struct payload_info info;
  EXPECT_TRUE(libhoth_payload_info(image, statbuf.st_size, &info));

  EXPECT_STREQ(info.image_name, "test layout");
  EXPECT_EQ(info.image_family, 2);

  EXPECT_EQ(info.image_version.major, 1);
  EXPECT_EQ(info.image_version.minor, 0);
  EXPECT_EQ(info.image_version.point, 0);
  EXPECT_EQ(info.image_version.subpoint, 0);

  EXPECT_EQ(info.image_type, 0);

  std::stringstream stream;
  stream << std::hex;
  for (const auto c : info.image_hash) {
    stream << std::setw(2) << std::setfill('0') << (int)c;
  }

  EXPECT_EQ(kTestHash, stream.str());

  // Clobber the magic
  const_cast<image_descriptor *>(descr)->descriptor_magic += 1;

  EXPECT_FALSE(libhoth_payload_info(image, statbuf.st_size, &info));

  (void)munmap(image, statbuf.st_size);
}

TEST(PayloadInfotest, descriptor_clipping) {
  int fd = open(kTestData, O_RDONLY, 0);
  ASSERT_NE(fd, -1);

  struct stat statbuf;
  ASSERT_EQ(fstat(fd, &statbuf), 0);

  uint8_t *image = reinterpret_cast<uint8_t *>(
      mmap(NULL, statbuf.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0));
  ASSERT_NE(image, nullptr);

  struct image_descriptor *descr = const_cast<image_descriptor *>(
      libhoth_find_image_descriptor(image, statbuf.st_size));
  ASSERT_NE(descr, nullptr);

  ASSERT_EQ(descr->descriptor_area_size, 2 * TITAN_IMAGE_DESCRIPTOR_ALIGNMENT);

  void *end_of_image = image + statbuf.st_size - descr->descriptor_area_size;

  // Move the descriptor to the very end, so that the regions just barely fits
  // into the last 2 64K slots at the end
  std::memcpy(end_of_image, descr, sizeof(image_descriptor));
  descr->descriptor_magic += 1;  // Clobber previous image descriptor

  descr = const_cast<image_descriptor*>(libhoth_find_image_descriptor(image, statbuf.st_size));
  ASSERT_NE(descr, nullptr);

  // Move the points to the last 64K
  // Putting the descriptor in here should fail because it extends
  // beyond the end of the payload
  end_of_image = (uint8_t *)end_of_image + (1 << 16);

  std::memcpy(end_of_image, descr, sizeof(image_descriptor));
  descr->descriptor_magic += 1;  // Clobber previous image descriptor

  EXPECT_EQ(libhoth_find_image_descriptor(image, statbuf.st_size), nullptr);

  (void)munmap(image, statbuf.st_size);
}

TEST(PayloadInfotest, payload_info_non_SHA256_hash_type) {
  int fd = open(kTestData, O_RDONLY, 0);
  ASSERT_NE(fd, -1);

  struct stat statbuf;
  ASSERT_EQ(fstat(fd, &statbuf), 0);

  uint8_t *image = reinterpret_cast<uint8_t *>(
      mmap(NULL, statbuf.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0));
  ASSERT_NE(image, nullptr);

  const struct image_descriptor *descr =
      libhoth_find_image_descriptor(image, statbuf.st_size);

  ASSERT_NE(descr, nullptr);

  // Clobber the hash type to something other than SHA256 to fail since
  // we only support SHA256
  const_cast<image_descriptor *>(descr)->hash_type = HASH_SHA2_224;

  struct payload_info info;
  EXPECT_FALSE(libhoth_payload_info(image, statbuf.st_size, &info));

  (void)munmap(image, statbuf.st_size);
}