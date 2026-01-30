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

#ifndef _LIBHOTH_OPENTITAN_VERSION_H_
#define _LIBHOTH_OPENTITAN_VERSION_H_

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include "host_cmd.h"
#include "protocol/console.h"
#include "transports/libhoth_device.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HOTH_OPENTITAN_GET_VERSION 0x3300

#define OPENTITAN_VERSION_HASH_SIZE 8
#define OPENTITAN_NUM_SLOTS 2

#define OPENTITAN_OFFSET_HEADER_DATA 36
#define OPENTITAN_OFFSET_APP_FW 65536
#define OPENTITAN_OFFSET_VERSION_MAJOR 836
#define OPENTITAN_OFFSET_VERSION_MINOR 840
#define OPENTITAN_OFFSET_VERSION_SECURITY 844
#define OPENTITAN_OFFSET_TIMESTAMP 848

typedef uint32_t opentitan_boot_slot_t;

enum opentitan_boot_slot {
  kOpentitanBootSlotA = 0x5f5f4141,
  kOpentitanBootSlotB = 0x42425f5f,
};

struct opentitan_image_version {
  uint32_t major;
  uint32_t minor;
  uint32_t security_version;
  uint32_t reserved[3];
  uint64_t timestamp;
  uint32_t measurement[OPENTITAN_VERSION_HASH_SIZE];
};
static_assert(offsetof(struct opentitan_image_version, major) == 0, "");
static_assert(offsetof(struct opentitan_image_version, minor) == 4, "");
static_assert(offsetof(struct opentitan_image_version, security_version) == 8,
              "");
static_assert(offsetof(struct opentitan_image_version, reserved) == 12, "");
static_assert(offsetof(struct opentitan_image_version, timestamp) == 24, "");
static_assert(offsetof(struct opentitan_image_version, measurement) == 32, "");
static_assert(sizeof(struct opentitan_image_version) == 64, "");

struct opentitan_image_boot_info {
  struct opentitan_image_version slots[OPENTITAN_NUM_SLOTS];
  opentitan_boot_slot_t booted_slot;
  uint32_t reserved[3];
};
static_assert(offsetof(struct opentitan_image_boot_info, slots) == 0, "");
static_assert(offsetof(struct opentitan_image_boot_info, booted_slot) == 128,
              "");
static_assert(offsetof(struct opentitan_image_boot_info, reserved) == 132, "");
static_assert(sizeof(struct opentitan_image_boot_info) == 144, "");

struct opentitan_owner_config_version {
  uint32_t config_version;
  uint32_t reserved[3];
  uint32_t sha256[OPENTITAN_VERSION_HASH_SIZE];
};
static_assert(offsetof(struct opentitan_owner_config_version, config_version) ==
                  0,
              "");
static_assert(offsetof(struct opentitan_owner_config_version, reserved) == 4,
              "");
static_assert(offsetof(struct opentitan_owner_config_version, sha256) == 16,
              "");
static_assert(sizeof(struct opentitan_owner_config_version) == 48, "");

struct opentitan_get_version_resp {
  struct opentitan_image_boot_info rom_ext;
  struct opentitan_image_boot_info app;
  opentitan_boot_slot_t primary_bl0_slot;
  uint32_t bl0_min_sec_ver;
  struct opentitan_owner_config_version owner_config;
};
static_assert(offsetof(struct opentitan_get_version_resp, rom_ext) == 0, "");
static_assert(offsetof(struct opentitan_get_version_resp, app) == 144, "");
static_assert(offsetof(struct opentitan_get_version_resp, primary_bl0_slot) ==
                  288,
              "");
static_assert(offsetof(struct opentitan_get_version_resp, bl0_min_sec_ver) ==
                  292,
              "");
static_assert(offsetof(struct opentitan_get_version_resp, owner_config) == 296,
              "");
static_assert(sizeof(struct opentitan_get_version_resp) == 344, "");

int libhoth_opentitan_version(struct libhoth_device* device,
                              struct opentitan_get_version_resp* response);

int libhoth_extract_ot_bundle(const uint8_t* image, size_t image_size,
                              struct opentitan_image_version* rom_ext,
                              struct opentitan_image_version* app);

bool libhoth_ot_version_eq(const struct opentitan_image_version* a,
                           const struct opentitan_image_version* b);

void libhoth_print_ot_version(const char* prefix,
                              const struct opentitan_image_version* ver);
void libhoth_print_ot_version_resp(
    const struct opentitan_get_version_resp* ver);
const char* bootslot_str(enum opentitan_boot_slot input);
int bootslot_int(enum opentitan_boot_slot input);

#ifdef __cplusplus
}
#endif

#endif  // _LIBHOTH_OPENTITAN_VERSION_H_
