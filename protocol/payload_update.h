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

#ifndef LIBHOTH_PROTOCOL_PAYLOAD_UPDATE_H_
#define LIBHOTH_PROTOCOL_PAYLOAD_UPDATE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#include "transports/libhoth_device.h"

#define HOTH_PRV_CMD_HOTH_PAYLOAD_UPDATE 0x0005

#define PAYLOAD_UPDATE_INITIATE 0
#define PAYLOAD_UPDATE_CONTINUE 1
#define PAYLOAD_UPDATE_FINALIZE 2
#define PAYLOAD_UPDATE_AUX_DATA 3
#define PAYLOAD_UPDATE_VERIFY 4
#define PAYLOAD_UPDATE_ACTIVATE 5
#define PAYLOAD_UPDATE_READ 6
#define PAYLOAD_UPDATE_GET_STATUS 7
#define PAYLOAD_UPDATE_ERASE 8
#define PAYLOAD_UPDATE_VERIFY_CHUNK 9
#define PAYLOAD_UPDATE_CONFIRM 10
#define PAYLOAD_UPDATE_VERIFY_DESCRIPTOR 11

struct payload_update_status {
  uint8_t a_valid;         /* 0 = invalid, 1 = unverified, 2 = valid, */
                           /* 3 = descriptor valid */
  uint8_t b_valid;         /* 0 = invalid, 1 = unverified, 2 = valid, */
                           /* 3 = descriptor valid */
  uint8_t active_half;     /* 0, 1 */
  uint8_t next_half;       /* 0, 1 */
  uint8_t persistent_half; /* 0, 1 */
} __attribute__((packed));

enum payload_update_err {
  PAYLOAD_UPDATE_OK = 0,
  PAYLOAD_UPDATE_BAD_IMG,
  PAYLOAD_UPDATE_INITIATE_FAIL,
  PAYLOAD_UPDATE_FLASH_FAIL,
  PAYLOAD_UPDATE_FINALIZE_FAIL,
  PAYLOAD_UPDATE_READ_FAIL,
  PAYLOAD_UPDATE_IMAGE_NOT_SECTOR_ALIGNED,
  PAYLOAD_UPDATE_ERASE_FAIL,
};

struct payload_update_packet {
  uint32_t offset; /* image offset */
  uint32_t len;    /* packet length excluding this header */
  uint8_t type;    /* One of PAYLOAD_UPDATE_* */
  /* payload data immediately follows */
} __attribute__((packed));

struct payload_update_finalize_response_v1 {
  // Non-zero if configuration currently running on PLD needs to be
  // re-initialized (reloaded from internal configuration flash)
  // Zero otherwise
  uint8_t pld_needs_reinitialization;
} __attribute__((packed));

enum payload_update_err libhoth_payload_update(struct libhoth_device* dev,
                                               uint8_t* image, size_t len, bool skip_erase);
int libhoth_payload_update_getstatus(
    struct libhoth_device* dev, struct payload_update_status* update_status);
enum payload_update_err libhoth_payload_update_read_chunk(struct libhoth_device* dev, int fd, size_t len, size_t offset);

#ifdef __cplusplus
}
#endif

#endif
