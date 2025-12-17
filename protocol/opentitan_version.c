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

#include <stddef.h>
#include <stdbool.h>

#include "opentitan_version.h"

int libhoth_opentitan_version(struct libhoth_device * dev,
                              struct opentitan_get_version_resp * output) {

  uint32_t request = 0;
  struct opentitan_get_version_resp response;
  const int rv =
    libhoth_hostcmd_exec(dev, HOTH_OPENTITAN_GET_VERSION, /*version=*/0, &request,
                          sizeof(request), &response, sizeof(response), NULL);

  if (rv == 0) {
    *output = response;
  }

  return rv;
}

int libhoth_extract_ot_bundle(const uint8_t* image,
                              struct opentitan_image_version * rom_ext,
                              struct opentitan_image_version * app) {

  // Check if the image is valid
  if(image == NULL) {
    fprintf(stderr, "Image is NULL\n");
    return -1;
  }

  // Check if the image has the correct magic number
  char magic[] = "_OTFWUPDATE_";
  for(int i = 0; i < (sizeof(magic) - 1); i++) {
    if(image[i] != magic[i]) {
      fprintf(stderr, "Image does not have the correct magic number\n");
      return -1;
    }
  }

  // Extract the offset that contains the ROM_EXT version information
  // We will have the desired ROM_EXT version be stored on slot index 0 and keep slot index 1 with 0xDEADBEEF
  uint32_t offset = (image[OPENTITAN_OFFSET_HEADER_DATA] | image[OPENTITAN_OFFSET_HEADER_DATA + 1] << 8 | image[OPENTITAN_OFFSET_HEADER_DATA + 2] << 16 | image[OPENTITAN_OFFSET_HEADER_DATA + 3] << 24);
  rom_ext->major = image[offset + OPENTITAN_OFFSET_VERSION_MAJOR] | image[offset + OPENTITAN_OFFSET_VERSION_MAJOR + 1] << 8 | image[offset + OPENTITAN_OFFSET_VERSION_MAJOR + 2] << 16 | image[offset + OPENTITAN_OFFSET_VERSION_MAJOR + 3] << 24;
  rom_ext->minor = image[offset + OPENTITAN_OFFSET_VERSION_MINOR] | image[offset + OPENTITAN_OFFSET_VERSION_MINOR + 1] << 8 | image[offset + OPENTITAN_OFFSET_VERSION_MINOR + 2] << 16 | image[offset + OPENTITAN_OFFSET_VERSION_MINOR + 3] << 24;

  // Extract the offset that contains the APP version information
  // We will have the desired APP version be stored on slot index 0 and keep slot index 1 empty
  uint32_t offset_app = offset + OPENTITAN_OFFSET_APP_FW;
  app->major = image[offset_app + OPENTITAN_OFFSET_VERSION_MAJOR] | image[offset_app + OPENTITAN_OFFSET_VERSION_MAJOR + 1] << 8 | image[offset_app + OPENTITAN_OFFSET_VERSION_MAJOR + 2] << 16 | image[offset_app + OPENTITAN_OFFSET_VERSION_MAJOR + 3] << 24;
  app->minor = image[offset_app + OPENTITAN_OFFSET_VERSION_MINOR] | image[offset_app + OPENTITAN_OFFSET_VERSION_MINOR + 1] << 8 | image[offset_app + OPENTITAN_OFFSET_VERSION_MINOR + 2] << 16 | image[offset_app + OPENTITAN_OFFSET_VERSION_MINOR + 3] << 24;

  return 0;
}

bool libhoth_ot_version_eq(const struct opentitan_image_version * a,
                          const struct opentitan_image_version * b) {

  if(a->major == b->major && a->minor == b->minor) {
    return true;
  } else {
    return false;
  }

}

char * bootslot_str(enum opentitan_boot_slot input) {

  // Primary BL0 slot values are hardcoded in pie_rot
  // Boot slotA: 0x5f5f4141
  // Boot slotB: 0x42425f5f)
  if (input == kOpentitanBootSlotA) {
    return "Boot slot A";
  } else if (input == kOpentitanBootSlotB) {
    return "Boot slot B";
  } else {
    return "Unknown boot slot";
  }
}

int bootslot_int(enum opentitan_boot_slot input) {

  // Primary BL0 slot values are hardcoded in pie_rot
  // Boot slotA: 0x5f5f4141
  // Boot slotB: 0x42425f5f)
  if (input == kOpentitanBootSlotA) {
    return 0x0;
  } else if (input == kOpentitanBootSlotB) {
    return 0x1;
  } else {
    return 0x0;
  }

}