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

#include "payload_info.h"

#include <string.h>

const struct image_descriptor* libhoth_find_image_descriptor(
    const uint8_t* image, size_t len) {
  for (size_t off = 0; off + sizeof(struct image_descriptor) - 1 < len;
       off += TITAN_IMAGE_DESCRIPTOR_ALIGNMENT) {
    int64_t magic_candidate;
    memcpy(&magic_candidate, image + off, sizeof(magic_candidate));
    if (magic_candidate == TITAN_IMAGE_DESCRIPTOR_MAGIC) {
      struct image_descriptor* img_dsc =
          (struct image_descriptor*)(image + off);

      if (img_dsc->descriptor_area_size + off > len) {
        // Image descriptor is clipped
        return NULL;
      }

      return img_dsc;
    }
  }
  return NULL;
}

bool libhoth_payload_info(const uint8_t* image, size_t len,
                          struct payload_info* payload_info) {
  const struct image_descriptor* descr =
      libhoth_find_image_descriptor(image, len);
  if (descr == NULL) {
    return false;
  }

  memcpy(payload_info->image_name, descr->image_name,
         sizeof(payload_info->image_name));
  payload_info->image_name[sizeof(payload_info->image_name) - 1] = 0;

  payload_info->image_family = descr->image_family;
  payload_info->image_version.major = descr->image_major;
  payload_info->image_version.minor = descr->image_minor;
  payload_info->image_version.point = descr->image_point;
  payload_info->image_version.subpoint = descr->image_subpoint;
  payload_info->image_type = descr->image_type;

  // Any hash type other than SHA256 is treated as no hash and fail the
  // retrieval. HW doesnt have support for other hash types.
  if (descr->hash_type != HASH_SHA2_256) {
    memset(payload_info->image_hash, 0, sizeof(payload_info->image_hash));
    return false;
  } else {
    // Check for integer overflow
    if (descr->descriptor_area_size <=
        sizeof(struct image_descriptor) + sizeof(struct hash_sha256)) {
      return false;
    }

    uint32_t region_size = descr->region_count * sizeof(struct image_region);
    // Check for overread
    if (region_size >
        (descr->descriptor_area_size - sizeof(struct image_descriptor) -
         sizeof(struct hash_sha256))) {
      return false;
    }

    struct hash_sha256* hash =
        (struct hash_sha256*)((uint8_t*)&descr->image_regions + region_size);
    memcpy(payload_info->image_hash, hash->hash, sizeof(hash->hash));
  }

  return true;
}

bool libhoth_payload_info_all(const uint8_t* image, size_t len,
                              struct payload_info_all* info_all) {
  if (!libhoth_payload_info(image, len, &info_all->info)) {
    return false;
  }

  const struct image_descriptor* descr =
      libhoth_find_image_descriptor(image, len);
  if (descr == NULL) {
    return false;
  }

  // Reject images with more regions than PAYLOAD_INFO_ALL_MAX_REGIONS
  uint8_t count = descr->region_count;
  if (count > PAYLOAD_INFO_ALL_MAX_REGIONS) {
    return false;
  }

  // Validate that the claimed region_count fits within descriptor_area_size.
  uint32_t regions_end =
      sizeof(struct image_descriptor) + count * sizeof(struct image_region);
  if (regions_end > descr->descriptor_area_size) {
    return false;
  }

  info_all->descriptor_major = descr->descriptor_major;
  info_all->descriptor_minor = descr->descriptor_minor;
  info_all->build_timestamp = descr->build_timestamp;
  info_all->hash_type = descr->hash_type;
  info_all->region_count = descr->region_count;
  info_all->image_size = descr->image_size;
  info_all->blob_size = descr->blob_size;

  for (uint8_t i = 0; i < count; i++) {
    const struct image_region* src = &descr->image_regions[i];
    struct payload_region_info* dst = &info_all->regions[i];
    memcpy(dst->region_name, src->region_name, sizeof(dst->region_name));
    dst->region_name[sizeof(dst->region_name) - 1] = 0;
    dst->region_offset = src->region_offset;
    dst->region_size = src->region_size;
    dst->region_version = src->region_version;
    dst->region_attributes = src->region_attributes;
  }

  return true;
}
