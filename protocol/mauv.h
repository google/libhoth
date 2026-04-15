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

#ifndef _LIBHOTH_PROTOCOL_MAUV_H_
#define _LIBHOTH_PROTOCOL_MAUV_H_

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "protocol/host_cmd.h"
#include "transports/libhoth_device.h"

/* Fetches the MAUV, if the Haven has one.
 * If no input arguments are provided, outputs one little-endian uint32_t:
 *   - MAUV-version: Version associated with the contents of the struct; will be
 * incremented each time the contents change.
 * If the input argument is for haven MAUV, outputs a haven_mauv struct.
 * If the input argument is for image MAUV, outputs a image_mauv struct.
 */

#define EC_PRV_CMD_HAVEN_MAUV 0x000B

// Current version of the `haven_mauv` struct.
#define HAVEN_MAUV_STRUCT_VERSION 1

// The maximum number of denylisted versions in `haven_mauv`.
#define HAVEN_MAUV_MAX_DENYLIST_SIZE 8

#ifdef __cplusplus
extern "C" {
#endif

enum mauv_category {
  HAVEN_MAUV = 1,
  IMAGE_MAUV = 2,
};

enum mauv_state {
  MAUV_STATE_EFFECTIVE = 1,  // The MAUV is currently in effect.
  MAUV_STATE_COMPILED =
      2,  // The MAUV that is compiled into the current firmware.
  MAUV_STATE_PROPOSED = 3,  // The MAUV that is proposed. Reserved for future
                            // use. Returns EC_ERROR_UNIMPLEMENTED if used.
};

typedef struct haven_image_version {
  uint32_t epoch;
  uint32_t major;
  uint64_t minor;
} __attribute__((packed)) haven_image_version;
static_assert(sizeof(struct haven_image_version) == 16,
              "struct haven_image_version size should be 16 bytes");
static_assert(offsetof(struct haven_image_version, epoch) == 0,
              "epoch should be at offset 0");
static_assert(offsetof(struct haven_image_version, major) == 4,
              "major should be at offset 4");
static_assert(offsetof(struct haven_image_version, minor) == 8,
              "minor should be at offset 8");

typedef struct haven_mauv {
  // Must be HAVEN_MAUV_STRUCT_VERSION.
  uint32_t struct_version;

  // Monotonically increases; a Haven will update its on-flash copy of the MAUV
  // if it's compiled with an MAUV with a greater `mauv_version`.
  uint32_t mauv_version;

  // The minimum version firmware will allow rollback to.
  struct haven_image_version minimum_acceptable_update_version;

  // The number of populated entries in `denylist`.
  uint32_t denylist_num_entries;

  // Versions that are explicitly disallowed.
  struct haven_image_version denylist[HAVEN_MAUV_MAX_DENYLIST_SIZE];
} __attribute__((packed)) haven_mauv;
static_assert(sizeof(struct haven_mauv) == 156,
              "struct haven_mauv size should be 156 bytes");
static_assert(offsetof(struct haven_mauv, struct_version) == 0,
              "struct_version should be at offset 0");
static_assert(offsetof(struct haven_mauv, mauv_version) == 4,
              "mauv_version should be at offset 4");
static_assert(offsetof(struct haven_mauv, minimum_acceptable_update_version) ==
                  8,
              "minimum_acceptable_update_version should be at offset 8");
static_assert(offsetof(struct haven_mauv, denylist_num_entries) == 24,
              "denylist_num_entries should be at offset 24");
static_assert(offsetof(struct haven_mauv, denylist) == 28,
              "denylist should be at offset 28");

struct image_mauv {
  /* Version of the MAUV structure. */
  uint32_t mauv_struct_version;

  /* padding for 64-bit alignment of payload_security_version
   * must be set to 0xffffffff */
  uint32_t reserved_0;

  /* The version of the payload in which this `struct image_mauv` was embedded.
   * This would be better inside of `struct image_descriptor`, but that
   * structure doesn't have any spare fields or a reasonable way to grow the
   * structure. When processing firmware updates, the update will be aborted if
   * `payload_security_version` of the update payload is less than the
   * `minimum_acceptable_update_version` in gNVRAM.
   */
  uint64_t payload_security_version;

  /* A monotonic counter that should be increased whenever the
   * `minimum_acceptable_update_version or version_denylist fields are changed.
   * In order for the image_mauv structure in gNVRAM to be updated after an
   * payload update, the `mauv_update_timestamp` field in the new payload must
   * be greater than the `mauv_update_timestamp` field in gNVRAM.
   *
   * Although the firmware doesn't assign any semantic meaning to this value,
   * by convention should be the number of seconds since the unix epoch at the
   * time the payload was signed.
   */
  uint64_t mauv_update_timestamp;

  /* Minimum acceptable update version.  An update to a payload with its
   * `payload_security_version` field less than this field in gNVRAM is
   * forbidden. This value is not monotonic.
   */
  uint64_t minimum_acceptable_update_version;

  /* padding for 64-bit alignment of version_denylist
   * must be set to 0xffffffff */
  uint32_t reserved_1;

  /* Number of entries in the denylist. */
  uint32_t version_denylist_num_entries;

  /* A version denylist.  Updates to any version in this list will be rejected
   * by the firmware.
   */
  uint64_t version_denylist[];
} __attribute__((packed));
static_assert(offsetof(struct image_mauv, version_denylist) == 40,
              "version_denylist should be at offset 40");
static_assert(sizeof(struct image_mauv) == 40,
              "struct image_mauv size should be 40 bytes");
static_assert(offsetof(struct image_mauv, mauv_struct_version) == 0,
              "mauv_struct_version should be at offset 0");
static_assert(offsetof(struct image_mauv, reserved_0) == 4,
              "reserved_0 should be at offset 4");
static_assert(offsetof(struct image_mauv, mauv_update_timestamp) == 16,
              "mauv_update_timestamp should be at offset 16");
static_assert(offsetof(struct image_mauv, minimum_acceptable_update_version) ==
                  24,
              "minimum_acceptable_update_version should be at offset 24");
static_assert(offsetof(struct image_mauv, reserved_1) == 32,
              "reserved_1 should be at offset 32");
static_assert(offsetof(struct image_mauv, version_denylist_num_entries) == 36,
              "version_denylist_num_entries should be at offset 36");

struct mauv_request {
  uint8_t category; /* enum mauv_category */
  uint8_t state;    /* enum mauv_state */
  uint16_t reserved_0;
} __attribute__((packed, aligned(4)));
static_assert(sizeof(struct mauv_request) == 4,
              "struct mauv_request size should be 4 bytes");
static_assert(offsetof(struct mauv_request, category) == 0,
              "category should be at offset 0");
static_assert(offsetof(struct mauv_request, state) == 1,
              "state should be at offset 1");
static_assert(offsetof(struct mauv_request, reserved_0) == 2,
              "reserved_0 should be at offset 2");

struct hoth_response_mauv {
  union {
    uint32_t version;
    struct haven_mauv haven;
    struct image_mauv image;
  };
} __attribute__((packed));

int libhoth_fetch_mauv(struct libhoth_device* dev, uint8_t state,
                       uint8_t category, struct hoth_response_mauv* mauv);

#ifdef __cplusplus
}
#endif

#endif  // _LIBHOTH_PROTOCOL_MAUV_H_
