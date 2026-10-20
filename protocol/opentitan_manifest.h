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

#ifndef _LIBHOTH_OPENTITAN_MANIFEST_H_
#define _LIBHOTH_OPENTITAN_MANIFEST_H_

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Offsets of the app (BL0) image within a flash image, for the legacy 64k and
// the 88k ROM_EXT layouts.
#define OPENTITAN_MANIFEST_APP_OFFSET_64K (64 * 1024)
#define OPENTITAN_MANIFEST_APP_OFFSET_88K (88 * 1024)

// Manifest identifiers ("OTRE" and "OTB0" as little-endian u32s).
#define OPENTITAN_MANIFEST_IDENTIFIER_ROM_EXT 0x4552544f
#define OPENTITAN_MANIFEST_IDENTIFIER_OWNER_FIRST_STAGE 0x3042544f

// Value of unused manifest words, e.g. an unset manifest_base_address.
#define OPENTITAN_MANIFEST_UNUSED_WORD 0xa5a5a5a5

// The bits of a manifest_base_address that select the memory-mapped flash
// base and the slot; the remaining bits are the offset within the slot.
#define OPENTITAN_MANIFEST_FLASH_BASE_AND_SLOT_BITS \
  (0xa0000000u | (512u * 1024u))

// The leading fields of an OpenTitan manifest, up to and including the
// security version. Copy it in and out of images with memcpy, since image
// buffers may not be aligned. Manifest fields are little-endian, so this is
// only valid on little-endian hosts.
static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
              "opentitan_manifest_prefix requires a little-endian host");
struct opentitan_manifest_prefix {
  uint32_t signature[96];
  uint32_t usage_constraints[12];
  uint32_t public_key[56];
  uint32_t reserved[38];
  uint32_t on_demand_dice;
  uint32_t manifest_base_address;
  uint32_t address_translation;
  uint32_t identifier;
  uint32_t manifest_version;
  uint32_t signed_region_end;
  uint32_t length;
  uint32_t version_major;
  uint32_t version_minor;
  uint32_t security_version;
};
static_assert(offsetof(struct opentitan_manifest_prefix, signature) == 0, "");
static_assert(offsetof(struct opentitan_manifest_prefix, usage_constraints) ==
                  384,
              "");
static_assert(offsetof(struct opentitan_manifest_prefix, public_key) == 432,
              "");
static_assert(offsetof(struct opentitan_manifest_prefix, reserved) == 656, "");
static_assert(offsetof(struct opentitan_manifest_prefix, on_demand_dice) == 808,
              "");
static_assert(offsetof(struct opentitan_manifest_prefix,
                       manifest_base_address) == 812,
              "");
static_assert(offsetof(struct opentitan_manifest_prefix, address_translation) ==
                  816,
              "");
static_assert(offsetof(struct opentitan_manifest_prefix, identifier) == 820,
              "");
static_assert(offsetof(struct opentitan_manifest_prefix, manifest_version) ==
                  824,
              "");
static_assert(offsetof(struct opentitan_manifest_prefix, signed_region_end) ==
                  828,
              "");
static_assert(offsetof(struct opentitan_manifest_prefix, length) == 832, "");
static_assert(offsetof(struct opentitan_manifest_prefix, version_major) == 836,
              "");
static_assert(offsetof(struct opentitan_manifest_prefix, version_minor) == 840,
              "");
static_assert(offsetof(struct opentitan_manifest_prefix, security_version) ==
                  844,
              "");
static_assert(sizeof(struct opentitan_manifest_prefix) == 848, "");

#ifdef __cplusplus
}
#endif

#endif  // _LIBHOTH_OPENTITAN_MANIFEST_H_
