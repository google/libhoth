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

      if (img_dsc->descriptor_area_size > len - off) {
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

#define TITAN_IMAGE_DESCRIPTOR_MAX_MAJOR_VERSION 1
#define TITAN_IMAGE_DESCRIPTOR_BLOB_MAGIC 0x424f4c42  // "BLOB"
#define IMAGE_BLOB_ALIGNMENT 4
#define IMAGE_BLOB_TYPE_TARGET_WATCHDOG 0x48435754  // "TWCH"

struct image_blob_header {
  uint32_t blob_type;
  // Size of the blob in bytes. Does NOT include `sizeof(image_blob_header)`.
  uint32_t payload_size;
} __attribute__((__packed__));

static uint32_t blob_list_magic_offset(const struct image_descriptor* descr) {
  uint32_t offset = sizeof(struct image_descriptor) +
                    descr->region_count * sizeof(struct image_region) +
                    sizeof(struct hash_sha256);
  if (descr->denylist_size != 0) {
    offset += sizeof(uint32_t) +
              descr->denylist_size * sizeof(struct payload_version);
  }
  return offset;
}

const char* libhoth_image_blob_status_string(enum image_blob_status status) {
  switch (status) {
    case IMAGE_BLOB_OK:
      return "ok";
    case IMAGE_BLOB_NOT_FOUND:
      return "blob not found";
    case IMAGE_BLOB_NO_DESCRIPTOR:
      return "no image descriptor found";
    case IMAGE_BLOB_UNSUPPORTED_DESCRIPTOR:
      return "unsupported image descriptor version or hash type";
    case IMAGE_BLOB_LIST_INVALID_MAGIC:
      return "invalid blob list magic";
    case IMAGE_BLOB_LIST_MALFORMED:
      return "malformed blob list";
    case IMAGE_BLOB_DUPLICATE:
      return "duplicate blob";
    case IMAGE_BLOB_INVALID_SIZE:
      return "invalid blob payload size";
  }
  return "unknown error";
}

enum image_blob_status libhoth_payload_target_watchdog_config(
    const uint8_t* image, size_t len, struct target_watchdog_config* config) {
  const struct image_descriptor* descr =
      libhoth_find_image_descriptor(image, len);
  if (descr == NULL) {
    return IMAGE_BLOB_NO_DESCRIPTOR;
  }
  // The blob list's location depends on the descriptor's layout.
  if (descr->descriptor_major > TITAN_IMAGE_DESCRIPTOR_MAX_MAJOR_VERSION ||
      descr->hash_type != HASH_SHA2_256) {
    return IMAGE_BLOB_UNSUPPORTED_DESCRIPTOR;
  }
  if (descr->blob_size == 0) {
    return IMAGE_BLOB_NOT_FOUND;
  }

  // libhoth_find_image_descriptor() guarantees that the whole descriptor area
  // is inside `image`, so bounding the list by it keeps every read in bounds.
  const uint8_t* descr_bytes = (const uint8_t*)descr;
  uint64_t magic_offset = blob_list_magic_offset(descr);
  uint64_t list_end = magic_offset + sizeof(uint32_t) + descr->blob_size;
  if (list_end > descr->descriptor_area_size) {
    return IMAGE_BLOB_LIST_MALFORMED;
  }
  uint32_t magic;
  memcpy(&magic, descr_bytes + magic_offset, sizeof(magic));
  if (magic != TITAN_IMAGE_DESCRIPTOR_BLOB_MAGIC) {
    return IMAGE_BLOB_LIST_INVALID_MAGIC;
  }

  bool found = false;
  uint64_t offset = magic_offset + sizeof(magic);
  while (offset < list_end) {
    struct image_blob_header header;
    if (list_end - offset < sizeof(header)) {
      return IMAGE_BLOB_LIST_MALFORMED;
    }
    memcpy(&header, descr_bytes + offset, sizeof(header));
    offset += sizeof(header);
    if (header.payload_size > list_end - offset) {
      return IMAGE_BLOB_LIST_MALFORMED;
    }

    if (header.blob_type == IMAGE_BLOB_TYPE_TARGET_WATCHDOG) {
      if (found) {
        return IMAGE_BLOB_DUPLICATE;
      }
      if (header.payload_size != sizeof(*config)) {
        return IMAGE_BLOB_INVALID_SIZE;
      }
      memcpy(config, descr_bytes + offset, sizeof(*config));
      found = true;
    }

    offset += header.payload_size;
    offset = (offset + IMAGE_BLOB_ALIGNMENT - 1) / IMAGE_BLOB_ALIGNMENT *
             IMAGE_BLOB_ALIGNMENT;
  }
  return found ? IMAGE_BLOB_OK : IMAGE_BLOB_NOT_FOUND;
}
