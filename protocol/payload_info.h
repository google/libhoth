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

#ifndef LIBHOTH_PROTOCOL_PAYLOAD_INFO_H_
#define LIBHOTH_PROTOCOL_PAYLOAD_INFO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TITAN_IMAGE_DESCRIPTOR_MAGIC 0x5f435344474d495f  // "_IMGDSC_"
#define TITAN_IMAGE_DESCRIPTOR_ALIGNMENT (1 << 16)
#define TITAN_IMAGE_DESCRIPTOR_HASH_MAGIC 0x48534148  // "HASH"

enum image_type {
  IMAGE_DEV = 0,
  IMAGE_PROD = 1,
  IMAGE_BREAKOUT = 2,
  IMAGE_TEST = 3,
  IMAGE_UNSIGNED_INTEGRITY = 4
};

enum hash_type {
  HASH_NONE = 0,
  HASH_SHA2_224 = 1,
  HASH_SHA2_256 = 2,
  HASH_SHA2_384 = 3,
  HASH_SHA2_512 = 4,
  HASH_SHA3_224 = 5,
  HASH_SHA3_256 = 6,
  HASH_SHA3_384 = 7,
  HASH_SHA3_512 = 8
};

#define IMAGE_REGION_STATIC (1 << 0)
#define IMAGE_REGION_COMPRESSED (1 << 1)
#define IMAGE_REGION_WRITE_PROTECTED (1 << 2)
#define IMAGE_REGION_PERSISTENT (1 << 4)
#define IMAGE_REGION_PERSISTENT_RELOCATABLE (1 << 5)
#define IMAGE_REGION_PERSISTENT_EXPANDABLE (1 << 6)
#define IMAGE_REGION_OVERRIDE (1 << 7)
#define IMAGE_REGION_OVERRIDE_ON_TRANSITION (1 << 8)
#define IMAGE_REGION_MAILBOX (1 << 9)
#define IMAGE_REGION_SKIP_BOOT_VALIDATION (1 << 10)
#define IMAGE_REGION_EMPTY (1 << 11)

#define HASH_SHA256_BYTES 32

struct image_region {
  uint8_t region_name[32];  // null-terminated ASCII string
  uint32_t region_offset;   // read- and write- protected regions must be
                            // aligned to IMAGE_REGION_PROTECTED_ALIGNMENT.
                            // Other regions are also aligned which
                            // simplifies their implementation.
  uint32_t region_size;     // read- and write- protected regions must be a
                            // multiple of IMAGE_REGION_PROTECTED_PAGE_LENGTH.
  /* Regions will not be persisted across different versions.
   * This field is intended to flag potential incompatibilities in the
   * context of data migration (e.g. the ELOG format changed between
   * two BIOS releases).
   */
  uint16_t region_version;
  /* See IMAGE_REGION_* defines above. */
  uint16_t region_attributes;
} __attribute__((__packed__));

/* Hash the static regions (IMAGE_REGION_STATIC) excluding this descriptor
 * structure i.e. skipping image_descriptor.descriptor_size bytes (optional).
 */
struct hash_sha256 {
  uint32_t hash_magic;  // #define TITAN_IMAGE_DESCRIPTOR_HASH_MAGIC
  uint8_t hash[HASH_SHA256_BYTES];
} __attribute__((__packed__));

struct hash_sha512 {
  uint32_t hash_magic;  // #define TITAN_IMAGE_DESCRIPTOR_HASH_MAGIC
  uint8_t hash[64];
} __attribute__((__packed__));

struct image_descriptor {
  uint64_t descriptor_magic;
  uint8_t descriptor_major;
  uint8_t descriptor_minor;
  uint16_t reserved_0;

  uint32_t descriptor_offset;
  uint32_t descriptor_area_size;

  uint8_t image_name[32];
  uint32_t image_family;

  /* Follow the Kibbles versioning scheme. */
  uint32_t image_major;
  uint32_t image_minor;
  uint32_t image_point;
  uint32_t image_subpoint;

  /* Seconds since epoch. */
  uint64_t build_timestamp;

  /* image_type enum { DEV, PROD, BREAKOUT, UNSIGNED_INTEGRITY} */
  uint8_t image_type;

  uint8_t reserved_3;

  /* hash_type enum { NONE, SHA2_224, SHA2_256, ...} */
  uint8_t hash_type;

  uint8_t reserved_4;

  /* struct image_region array size. */
  uint8_t region_count;
  uint8_t reserved_1;
  uint16_t reserved_2;
  /* The sum of the image_region.region_size fields must add up. */
  uint32_t image_size;
  /* Authenticated opaque data exposed to system software. Must be a multiple
   * of 4 to maintain alignment. Does not include the blob struct magic.
   */
  uint32_t blob_size;
  /* The list is strictly ordered by region_offset.
   * Must exhaustively describe the image.
   */
  struct image_region image_regions[];
} __attribute__((__packed__));

struct payload_version {
  uint32_t major;
  uint32_t minor;
  uint32_t point;
  uint32_t subpoint;
};

struct payload_info {
  char image_name[32];
  uint32_t image_family;
  struct payload_version image_version;
  uint8_t image_type;
  uint8_t image_hash[HASH_SHA256_BYTES];
};

// Returns a pointer to a valid image_descriptor if found inside the image,
// otherwise returns NULL
const struct image_descriptor* libhoth_find_image_descriptor(
    const uint8_t* image, size_t len);
bool libhoth_payload_info(const uint8_t* image, size_t len,
                          struct payload_info* payload_info);

#ifdef __cplusplus
}
#endif

#endif
