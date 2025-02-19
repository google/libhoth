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

const int64_t TITAN_IMAGE_DESCRIPTOR_MAGIC = 0x5F435344474D495F;
const int64_t TITAN_IMAGE_DESCRIPTOR_ALIGNMENT = 1 << 16;

const int64_t IMAGE_NAME_OFFSET = 20;
const int64_t IMAGE_FAMILY_OFFSET = 52;
const int64_t IMAGE_VERSION_OFFSET = 56;
const int64_t IMAGE_TYPE_OFFSET = 80;
const int64_t HASH_TYPE_OFFSET = 82;
const int64_t REGION_COUNT_OFFSET = 84;

bool libhoth_find_image_descriptor(uint8_t* image, size_t len, size_t* offset) {
  for (size_t off = 0; off + sizeof(int64_t) - 1 < len;
       off += TITAN_IMAGE_DESCRIPTOR_ALIGNMENT) {
    int64_t magic_candidate;
    memcpy(&magic_candidate, image + off, sizeof(int64_t));
    if (magic_candidate == TITAN_IMAGE_DESCRIPTOR_MAGIC) {
      if (offset) {
        *offset = off;
      }
      return true;
    }
  }
  return false;
}

bool libhoth_payload_info(uint8_t* image, size_t len,
                          struct payload_info* payload_info) {
  size_t offset;

  if (!libhoth_find_image_descriptor(image, len, &offset)) {
    return false;
  }

  uint8_t* descr_start = &image[offset];
  memcpy(payload_info->image_name, descr_start + IMAGE_NAME_OFFSET,
         sizeof(payload_info->image_name));
  payload_info->image_family = *(uint32_t*)(descr_start + IMAGE_FAMILY_OFFSET);

  uint32_t* version_start = (uint32_t*)(descr_start + IMAGE_VERSION_OFFSET);
  payload_info->image_version.major = version_start[0];
  payload_info->image_version.minor = version_start[1];
  payload_info->image_version.point = version_start[2];
  payload_info->image_version.subpoint = version_start[3];

  payload_info->image_type = descr_start[IMAGE_TYPE_OFFSET];

  if (descr_start[HASH_TYPE_OFFSET] == 0) {
    memset(payload_info->image_hash, 0, sizeof(payload_info->image_hash));
  } else {
    uint8_t* hash_start =
        descr_start + 96                          /* region offset */
        + (descr_start[REGION_COUNT_OFFSET] * 44) /* region size */
        + 4;                                      /* Hash magic */

    memcpy(payload_info->image_hash, hash_start,
           sizeof(payload_info->image_hash));
  }

  return true;
}
