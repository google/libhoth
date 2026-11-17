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

#ifndef LIBHOTH_PROTOCOL_FLASH_UID_H_
#define LIBHOTH_PROTOCOL_FLASH_UID_H_

#include <assert.h>
#include <stdint.h>

#include "protocol/host_cmd.h"
#include "protocol/status.h"
#include "transports/libhoth_device.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Read cached SPI NOR flash JEDEC ID and Unique ID. */
#define HOTH_PRV_CMD_HOTH_GET_FLASH_UID 0x0063

#define HOTH_FLASH_MAX_DEVICES 2
#define HOTH_FLASH_JEDEC_ID_LEN 3
#define HOTH_FLASH_UID_MAX_LEN 20

struct hoth_flash_device_uid {
  uint8_t uid_len;  // Number of valid bytes in `uid` (0 if unavailable).
  uint8_t jedec_id[HOTH_FLASH_JEDEC_ID_LEN];  // Cached 3-byte JEDEC ID.
  uint8_t uid[HOTH_FLASH_UID_MAX_LEN];        // Cached Unique ID bytes.
} __hoth_align4;
static_assert(sizeof(struct hoth_flash_device_uid) == 24,
              "struct hoth_flash_device_uid size must be 24 bytes");

struct hoth_response_get_flash_uid {
  uint8_t device_count;  // Total SPI NOR flash device slots configured.
  uint8_t reserved[3];
  struct hoth_flash_device_uid devices[HOTH_FLASH_MAX_DEVICES];
} __hoth_align4;
static_assert(sizeof(struct hoth_response_get_flash_uid) == 52,
              "struct hoth_response_get_flash_uid size must be 52 bytes");

libhoth_error libhoth_get_flash_uid(
    struct libhoth_device* dev, struct hoth_response_get_flash_uid* response);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_PROTOCOL_FLASH_UID_H_
