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
#include <vector>

#include "payload_info.h"

constexpr char kTestData[] = "protocol/test/test_payload.bin";
constexpr char kTestHash[] =
    "50316da1d3b006ff87989aa8bcd48a33ecc4bfe2114ded138ee594f6097d58b3";

TEST(PayloadInfotest, payload_info) {
  int fd = open(kTestData, O_RDONLY, 0);
  ASSERT_NE(fd, -1);

  struct stat statbuf;
  ASSERT_EQ(fstat(fd, &statbuf), 0);

  uint8_t* image = reinterpret_cast<uint8_t*>(
      mmap(NULL, statbuf.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0));
  ASSERT_NE(image, nullptr);

  const struct image_descriptor* descr =
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
  const_cast<image_descriptor*>(descr)->descriptor_magic += 1;

  EXPECT_FALSE(libhoth_payload_info(image, statbuf.st_size, &info));

  (void)munmap(image, statbuf.st_size);
}

TEST(PayloadInfotest, descriptor_clipping) {
  int fd = open(kTestData, O_RDONLY, 0);
  ASSERT_NE(fd, -1);

  struct stat statbuf;
  ASSERT_EQ(fstat(fd, &statbuf), 0);

  uint8_t* image = reinterpret_cast<uint8_t*>(
      mmap(NULL, statbuf.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0));
  ASSERT_NE(image, nullptr);

  struct image_descriptor* descr = const_cast<image_descriptor*>(
      libhoth_find_image_descriptor(image, statbuf.st_size));
  ASSERT_NE(descr, nullptr);

  ASSERT_EQ(descr->descriptor_area_size, 2 * TITAN_IMAGE_DESCRIPTOR_ALIGNMENT);

  void* end_of_image = image + statbuf.st_size - descr->descriptor_area_size;

  // Move the descriptor to the very end, so that the regions just barely fits
  // into the last 2 64K slots at the end
  std::memcpy(end_of_image, descr, sizeof(image_descriptor));
  descr->descriptor_magic += 1;  // Clobber previous image descriptor

  descr = const_cast<image_descriptor*>(
      libhoth_find_image_descriptor(image, statbuf.st_size));
  ASSERT_NE(descr, nullptr);

  // Move the points to the last 64K
  // Putting the descriptor in here should fail because it extends
  // beyond the end of the payload
  end_of_image = (uint8_t*)end_of_image + (1 << 16);

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

  uint8_t* image = reinterpret_cast<uint8_t*>(
      mmap(NULL, statbuf.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0));
  ASSERT_NE(image, nullptr);

  const struct image_descriptor* descr =
      libhoth_find_image_descriptor(image, statbuf.st_size);

  ASSERT_NE(descr, nullptr);

  // Clobber the hash type to something other than SHA256 to fail since
  // we only support SHA256
  const_cast<image_descriptor*>(descr)->hash_type = HASH_SHA2_224;

  struct payload_info info;
  EXPECT_FALSE(libhoth_payload_info(image, statbuf.st_size, &info));

  (void)munmap(image, statbuf.st_size);
}

TEST(PayloadInfoTest, PayloadInfoFuzzRegression) {
  std::string data = std::string(
      "_IMGDSC_\035_\to\245\245IM\007\001\000\000GDS\360\360\360\360\360C_"
      "\to\245\245\267\267\342\342\342\342\342\342\342\267\267\267\267\267\267"
      "\267\267\245\245\245\245\245\245\245\251\345\034%"
      "\035\252\000\241\254\332\314\374\r\242\205\342\246\247\327Z\241\364\000"
      "\250\002\246\205\260I\002\023\255\201\277\247\247\006C\235\234\245\245"
      "\245\245\245\245\245\245\245\245\245\245\200\200\200\000\300^"
      "\000\246\270\356\027\265\035\000\245\245\245\245\245\003\003\003\245\035"
      "\035\035\035\035\035\035\035\035\035\035\035\035\035\035\035\035\035\035"
      "\035\035\035\035\035\035\035\035\035\035\035\035\035\035\035\035\035\035"
      "\035\035\035\035\035\035\035\035\035\035\035\035\035\035\035\035\035\035"
      "\035\035\035\035\035\035\035\035\035\035\035\035\035\035\000\035\035\034"
      "\035\035\035\035\035\035\035\035\035\035\035\035\035\035\035\035\035\035"
      "\035\035\035\035\035\035\035\035\035\035\035\035\035\035\035\035\035\035"
      "\035\035\035\035\035\035\035\035~~~~"
      "\035\035\035\035\035\035\035\035\035\035\035\035\035\035\035\035\035\035"
      "\035\035\035\035\035\035\035",
      279);
  struct payload_info info;
  EXPECT_FALSE(libhoth_payload_info(
      reinterpret_cast<const uint8_t*>(data.data()), data.size(), &info));
}

TEST(PayloadInfotest, payload_info_all) {
  int fd = open(kTestData, O_RDONLY, 0);
  ASSERT_NE(fd, -1);

  struct stat statbuf;
  ASSERT_EQ(fstat(fd, &statbuf), 0);

  uint8_t* image = reinterpret_cast<uint8_t*>(
      mmap(NULL, statbuf.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0));
  ASSERT_NE(image, nullptr);

  struct image_descriptor* descr = const_cast<image_descriptor*>(
      libhoth_find_image_descriptor(image, statbuf.st_size));
  ASSERT_NE(descr, nullptr);

  struct payload_info_all info_all;
  EXPECT_TRUE(libhoth_payload_info_all(image, statbuf.st_size, &info_all));

  // Verify basic info fields match the existing payload_info test
  EXPECT_STREQ(info_all.info.image_name, "test layout");
  EXPECT_EQ(info_all.info.image_family, 2);
  EXPECT_EQ(info_all.info.image_version.major, 1);
  EXPECT_EQ(info_all.info.image_version.minor, 0);
  EXPECT_EQ(info_all.info.image_version.point, 0);
  EXPECT_EQ(info_all.info.image_version.subpoint, 0);
  EXPECT_EQ(info_all.info.image_type, 0);

  // Verify hash matches
  std::stringstream stream;
  stream << std::hex;
  for (const auto c : info_all.info.image_hash) {
    stream << std::setw(2) << std::setfill('0') << (int)c;
  }
  EXPECT_EQ(kTestHash, stream.str());

  // Verify extended fields
  EXPECT_EQ(info_all.hash_type, HASH_SHA2_256);
  ASSERT_EQ(info_all.region_count, 8);
  EXPECT_EQ(info_all.image_size, 0x400000u);

  // Verify region offsets and sizes against the known test image layout.
  EXPECT_EQ(info_all.regions[0].region_offset, 0x0u);
  EXPECT_EQ(info_all.regions[0].region_size, 0x1000u);
  EXPECT_EQ(info_all.regions[1].region_offset, 0x1000u);
  EXPECT_EQ(info_all.regions[1].region_size, 0xf000u);
  EXPECT_EQ(info_all.regions[2].region_offset, 0x10000u);
  EXPECT_EQ(info_all.regions[2].region_size, 0x10000u);
  EXPECT_EQ(info_all.regions[3].region_offset, 0x20000u);
  EXPECT_EQ(info_all.regions[3].region_size, 0x20000u);
  EXPECT_EQ(info_all.regions[4].region_offset, 0x40000u);
  EXPECT_EQ(info_all.regions[4].region_size, 0x10000u);
  EXPECT_EQ(info_all.regions[5].region_offset, 0x50000u);
  EXPECT_EQ(info_all.regions[5].region_size, 0x10000u);
  EXPECT_EQ(info_all.regions[6].region_offset, 0x60000u);
  EXPECT_EQ(info_all.regions[6].region_size, 0x20000u);
  EXPECT_EQ(info_all.regions[7].region_offset, 0x80000u);
  EXPECT_EQ(info_all.regions[7].region_size, 0x380000u);

  // Set region_count beyond PAYLOAD_INFO_ALL_MAX_REGIONS (32) to verify
  // that libhoth_payload_info_all() rejects it.
  descr->region_count = 64;

  EXPECT_FALSE(libhoth_payload_info_all(image, statbuf.st_size, &info_all));

  (void)munmap(image, statbuf.st_size);
  close(fd);
}

namespace {

constexpr uint32_t kBlobListMagic = 0x424f4c42;           // "BLOB"
constexpr uint32_t kTargetWatchdogBlobType = 0x48435754;  // "TWCH"
constexpr uint32_t kOtherBlobType = 0x5248544f;           // "OTHR"
constexpr size_t kBlobHeaderSize = 8;
constexpr uint32_t kDescriptorOffset = TITAN_IMAGE_DESCRIPTOR_ALIGNMENT;
constexpr uint32_t kDescriptorAreaSize = 4096;
constexpr uint8_t kRegionCount = 1;

using Bytes = std::vector<uint8_t>;

void AppendLe32(Bytes& bytes, uint32_t value) {
  for (int shift = 0; shift < 32; shift += 8) {
    bytes.push_back(static_cast<uint8_t>(value >> shift));
  }
}

Bytes BlobEntry(uint32_t blob_type, const Bytes& payload) {
  Bytes entry;
  AppendLe32(entry, blob_type);
  AppendLe32(entry, payload.size());
  entry.insert(entry.end(), payload.begin(), payload.end());
  while (entry.size() % 4 != 0) {
    entry.push_back(0xff);
  }
  return entry;
}

Bytes TargetWatchdogEntry(const struct target_watchdog_config& config) {
  Bytes payload;
  AppendLe32(payload, config.initial_delay_seconds);
  AppendLe32(payload, config.watchdog_timeout_seconds);
  AppendLe32(payload, config.hold_in_reset_microseconds);
  return BlobEntry(kTargetWatchdogBlobType, payload);
}

Bytes Concat(std::initializer_list<Bytes> entries) {
  Bytes list;
  for (const auto& entry : entries) {
    list.insert(list.end(), entry.begin(), entry.end());
  }
  return list;
}

// Lays out a payload image as:
// the descriptor, its regions, the hash, the optional denylist, then the blob
// list.
struct TestImage {
  Bytes blob_list;
  uint8_t denylist_size = 0;
  uint32_t blob_list_magic = kBlobListMagic;
  uint8_t descriptor_major = 1;
  uint8_t hash_type = HASH_SHA2_256;

  size_t BlobListMagicOffset() const {
    size_t offset = sizeof(struct image_descriptor) +
                    kRegionCount * sizeof(struct image_region) +
                    sizeof(struct hash_sha256);
    if (denylist_size != 0) {
      offset += sizeof(uint32_t) + denylist_size * sizeof(payload_version);
    }
    return offset;
  }

  Bytes DescriptorArea() const {
    Bytes area(kDescriptorAreaSize, 0xff);

    struct image_descriptor descr = {};
    descr.descriptor_magic = TITAN_IMAGE_DESCRIPTOR_MAGIC;
    descr.descriptor_major = descriptor_major;
    descr.descriptor_area_size = kDescriptorAreaSize;
    descr.hash_type = hash_type;
    descr.denylist_size = denylist_size;
    descr.region_count = kRegionCount;
    descr.image_size = kDescriptorOffset + kDescriptorAreaSize;
    descr.blob_size = blob_list.size();
    std::memcpy(area.data(), &descr, sizeof(descr));

    struct image_region region = {};
    region.region_offset = kDescriptorOffset;
    region.region_size = kDescriptorAreaSize;
    region.region_attributes = IMAGE_REGION_STATIC;
    std::memcpy(area.data() + sizeof(descr), &region, sizeof(region));

    struct hash_sha256 hash = {};
    hash.hash_magic = TITAN_IMAGE_DESCRIPTOR_HASH_MAGIC;
    std::memcpy(area.data() + sizeof(descr) + sizeof(region), &hash,
                sizeof(hash));

    if (!blob_list.empty()) {
      Bytes blob_section;
      AppendLe32(blob_section, blob_list_magic);
      blob_section.insert(blob_section.end(), blob_list.begin(),
                          blob_list.end());
      std::copy(blob_section.begin(), blob_section.end(),
                area.begin() + BlobListMagicOffset());
    }
    return area;
  }

  Bytes Image() const {
    Bytes image(kDescriptorOffset, 0xff);
    Bytes area = DescriptorArea();
    image.insert(image.end(), area.begin(), area.end());
    return image;
  }
};

enum image_blob_status ReadTargetWatchdog(
    const Bytes& image, struct target_watchdog_config* config) {
  return libhoth_payload_target_watchdog_config(image.data(), image.size(),
                                                config);
}

constexpr struct target_watchdog_config kConfig = {600, 60, 100000};

}  // namespace

bool operator==(const struct target_watchdog_config& a,
                const struct target_watchdog_config& b) {
  return a.initial_delay_seconds == b.initial_delay_seconds &&
         a.watchdog_timeout_seconds == b.watchdog_timeout_seconds &&
         a.hold_in_reset_microseconds == b.hold_in_reset_microseconds;
}

TEST(PayloadTargetWatchdogTest, FullImageWithTargetWatchdog) {
  TestImage image{.blob_list = TargetWatchdogEntry(kConfig)};

  struct target_watchdog_config config;
  ASSERT_EQ(ReadTargetWatchdog(image.Image(), &config), IMAGE_BLOB_OK);
  EXPECT_EQ(config, kConfig);
}

TEST(PayloadTargetWatchdogTest, RawDescriptorWithTargetWatchdog) {
  TestImage image{.blob_list = TargetWatchdogEntry(kConfig)};

  struct target_watchdog_config config;
  ASSERT_EQ(ReadTargetWatchdog(image.DescriptorArea(), &config), IMAGE_BLOB_OK);
  EXPECT_EQ(config, kConfig);
}

TEST(PayloadTargetWatchdogTest, TruncatedRawDescriptorIsRejected) {
  TestImage image{.blob_list = TargetWatchdogEntry(kConfig)};
  Bytes raw_descriptor = image.DescriptorArea();
  raw_descriptor.pop_back();

  struct target_watchdog_config config;
  EXPECT_EQ(ReadTargetWatchdog(raw_descriptor, &config),
            IMAGE_BLOB_NO_DESCRIPTOR);
}

TEST(PayloadTargetWatchdogTest, NoBlobs) {
  TestImage image;

  struct target_watchdog_config config;
  EXPECT_EQ(ReadTargetWatchdog(image.Image(), &config), IMAGE_BLOB_NOT_FOUND);
}

TEST(PayloadTargetWatchdogTest, TestPayloadHasNoTargetWatchdog) {
  int fd = open(kTestData, O_RDONLY, 0);
  ASSERT_NE(fd, -1);
  struct stat statbuf;
  ASSERT_EQ(fstat(fd, &statbuf), 0);
  uint8_t* image = reinterpret_cast<uint8_t*>(
      mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0));
  ASSERT_NE(image, MAP_FAILED);

  struct target_watchdog_config config;
  EXPECT_EQ(
      libhoth_payload_target_watchdog_config(image, statbuf.st_size, &config),
      IMAGE_BLOB_NOT_FOUND);

  (void)munmap(image, statbuf.st_size);
  close(fd);
}

TEST(PayloadTargetWatchdogTest, UnknownBlobsAndTargetWatchdog) {
  TestImage image{.blob_list = Concat({
                      BlobEntry(kOtherBlobType, {0xaa, 0xaa, 0xaa}),
                      TargetWatchdogEntry(kConfig),
                      BlobEntry(kOtherBlobType, {}),
                  })};

  struct target_watchdog_config config;
  ASSERT_EQ(ReadTargetWatchdog(image.Image(), &config), IMAGE_BLOB_OK);
  EXPECT_EQ(config, kConfig);
}

TEST(PayloadTargetWatchdogTest, OnlyUnknownBlobs) {
  TestImage image{.blob_list = BlobEntry(kOtherBlobType, {1, 2, 3, 4})};

  struct target_watchdog_config config;
  EXPECT_EQ(ReadTargetWatchdog(image.Image(), &config), IMAGE_BLOB_NOT_FOUND);
}

TEST(PayloadTargetWatchdogTest, DenylistPrecedesBlobList) {
  TestImage image{.blob_list = TargetWatchdogEntry(kConfig),
                  .denylist_size = 2};

  struct target_watchdog_config config;
  ASSERT_EQ(ReadTargetWatchdog(image.Image(), &config), IMAGE_BLOB_OK);
  EXPECT_EQ(config, kConfig);
}

TEST(PayloadTargetWatchdogTest, ListMayEndInPadding) {
  Bytes unpadded_entry = BlobEntry(kOtherBlobType, {0xaa});
  unpadded_entry.resize(kBlobHeaderSize + 1);
  TestImage image{.blob_list =
                      Concat({TargetWatchdogEntry(kConfig), unpadded_entry})};

  struct target_watchdog_config config;
  ASSERT_EQ(ReadTargetWatchdog(image.Image(), &config), IMAGE_BLOB_OK);
  EXPECT_EQ(config, kConfig);
}

TEST(PayloadTargetWatchdogTest, InvalidBlobListMagic) {
  TestImage image{.blob_list = TargetWatchdogEntry(kConfig),
                  .blob_list_magic = 0x12345678};

  struct target_watchdog_config config;
  EXPECT_EQ(ReadTargetWatchdog(image.Image(), &config),
            IMAGE_BLOB_LIST_INVALID_MAGIC);
}

TEST(PayloadTargetWatchdogTest, MalformedEntries) {
  Bytes entry = TargetWatchdogEntry(kConfig);
  Bytes truncated_header(kBlobHeaderSize - 1, 0);
  Bytes truncated_payload(entry.begin(), entry.end() - 1);
  Bytes oversized_payload = BlobEntry(kOtherBlobType, Bytes(4));
  std::fill(oversized_payload.begin() + 4, oversized_payload.begin() + 8, 0xff);

  for (const Bytes& list : {
           truncated_header,
           truncated_payload,
           oversized_payload,
           // The firmware validates the whole list, not just up to the
           // target watchdog blob.
           Concat({entry, truncated_header}),
       }) {
    TestImage image{.blob_list = list};

    struct target_watchdog_config config;
    EXPECT_EQ(ReadTargetWatchdog(image.Image(), &config),
              IMAGE_BLOB_LIST_MALFORMED);
  }
}

TEST(PayloadTargetWatchdogTest, DuplicateTargetWatchdog) {
  TestImage image{.blob_list = Concat({TargetWatchdogEntry(kConfig),
                                       TargetWatchdogEntry(kConfig)})};

  struct target_watchdog_config config;
  EXPECT_EQ(ReadTargetWatchdog(image.Image(), &config), IMAGE_BLOB_DUPLICATE);
}

TEST(PayloadTargetWatchdogTest, WrongTargetWatchdogSize) {
  TestImage image{.blob_list = BlobEntry(kTargetWatchdogBlobType, Bytes(8))};

  struct target_watchdog_config config;
  EXPECT_EQ(ReadTargetWatchdog(image.Image(), &config),
            IMAGE_BLOB_INVALID_SIZE);
}

TEST(PayloadTargetWatchdogTest, ValuesTheRotWouldRejectAreReturnedAsStored) {
  constexpr struct target_watchdog_config kRejected = {UINT32_MAX, 0,
                                                       UINT32_MAX};
  TestImage image{.blob_list = TargetWatchdogEntry(kRejected)};

  struct target_watchdog_config config;
  ASSERT_EQ(ReadTargetWatchdog(image.Image(), &config), IMAGE_BLOB_OK);
  EXPECT_EQ(config, kRejected);
}

TEST(PayloadTargetWatchdogTest, BlobListFillingDescriptorArea) {
  TestImage image;
  size_t list_size = kDescriptorAreaSize - image.BlobListMagicOffset() - 4;
  Bytes entry = TargetWatchdogEntry(kConfig);
  image.blob_list = Concat(
      {entry,
       BlobEntry(kOtherBlobType,
                 Bytes(list_size - entry.size() - kBlobHeaderSize, 0xaa))});
  ASSERT_EQ(image.blob_list.size(), list_size);
  Bytes bytes = image.DescriptorArea();
  auto* descr = reinterpret_cast<struct image_descriptor*>(bytes.data());

  struct target_watchdog_config config;
  ASSERT_EQ(ReadTargetWatchdog(bytes, &config), IMAGE_BLOB_OK);
  EXPECT_EQ(config, kConfig);

  for (uint32_t blob_size :
       {static_cast<uint32_t>(list_size + 1), UINT32_MAX}) {
    descr->blob_size = blob_size;
    EXPECT_EQ(ReadTargetWatchdog(bytes, &config), IMAGE_BLOB_LIST_MALFORMED);
  }
}

TEST(PayloadTargetWatchdogTest, UnsupportedDescriptor) {
  TestImage newer_major{.blob_list = TargetWatchdogEntry(kConfig),
                        .descriptor_major = 2};
  TestImage sha512{.blob_list = TargetWatchdogEntry(kConfig),
                   .hash_type = HASH_SHA2_512};

  struct target_watchdog_config config;
  EXPECT_EQ(ReadTargetWatchdog(newer_major.Image(), &config),
            IMAGE_BLOB_UNSUPPORTED_DESCRIPTOR);
  EXPECT_EQ(ReadTargetWatchdog(sha512.Image(), &config),
            IMAGE_BLOB_UNSUPPORTED_DESCRIPTOR);
}

TEST(PayloadTargetWatchdogTest, NoDescriptor) {
  Bytes bytes(kDescriptorAreaSize, 0xff);

  struct target_watchdog_config config;
  EXPECT_EQ(ReadTargetWatchdog(bytes, &config), IMAGE_BLOB_NO_DESCRIPTOR);
}
