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

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

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

typedef uint32_t payload_update_confirm_seconds;
typedef uint8_t payload_update_confirm_op;

static const payload_update_confirm_seconds
    PAYLOAD_UPDATE_CONFIRM_SECONDS_ZERO = 0;
static const payload_update_confirm_seconds PAYLOAD_UPDATE_CONFIRM_SECONDS_MIN =
    30;
static const payload_update_confirm_seconds PAYLOAD_UPDATE_CONFIRM_SECONDS_MAX =
    60 * 60;
static const payload_update_confirm_seconds
    PAYLOAD_UPDATE_CONFIRM_SECONDS_DEFAULT = 15 * 60;

typedef struct {
  payload_update_confirm_seconds min;
  payload_update_confirm_seconds max;
  payload_update_confirm_seconds default_val;
  payload_update_confirm_seconds current;
} payload_update_confirm_timeouts_t;
static_assert(sizeof(payload_update_confirm_timeouts_t) == 16,
              "Unexpected struct size for payload_update_confirm_timeouts_t");
static_assert(offsetof(payload_update_confirm_timeouts_t, min) == 0,
              "Unexpected offset for min");
static_assert(offsetof(payload_update_confirm_timeouts_t, max) == 4,
              "Unexpected offset for max");
static_assert(offsetof(payload_update_confirm_timeouts_t, default_val) == 8,
              "Unexpected offset for default_val");
static_assert(offsetof(payload_update_confirm_timeouts_t, current) == 12,
              "Unexpected offset for current");

typedef struct {
  payload_update_confirm_op op;
  uint8_t padding[3];
  payload_update_confirm_seconds timeout;
  uint64_t cookie;
} payload_update_confirm_request_t;
static_assert(offsetof(payload_update_confirm_request_t, op) == 0,
              "Unexpected offset for op");
static_assert(offsetof(payload_update_confirm_request_t, padding) == 1,
              "Unexpected offset for padding");
static_assert(offsetof(payload_update_confirm_request_t, timeout) == 4,
              "Unexpected offset for timeout");
static_assert(offsetof(payload_update_confirm_request_t, cookie) == 8,
              "Unexpected offset for cookie");
static_assert(sizeof(payload_update_confirm_request_t) == 16,
              "Unexpected struct size for payload_update_confirm_request_t");

typedef struct {
  payload_update_confirm_timeouts_t timeouts;
} payload_update_confirm_response_t;
static_assert(offsetof(payload_update_confirm_response_t, timeouts) == 0, "");
static_assert(sizeof(payload_update_confirm_response_t) ==
                  sizeof(payload_update_confirm_timeouts_t),
              "");

struct payload_update_status {
  uint8_t a_valid;         /* 0 = invalid, 1 = unverified, 2 = valid, */
                           /* 3 = descriptor valid */
  uint8_t b_valid;         /* 0 = invalid, 1 = unverified, 2 = valid, */
                           /* 3 = descriptor valid */
  uint8_t active_half;     /* 0, 1 */
  uint8_t next_half;       /* 0, 1 */
  uint8_t persistent_half; /* 0, 1 */
} __attribute__((packed));
static_assert(sizeof(struct payload_update_status) == 5,
              "Unexpected struct size");
static_assert(offsetof(struct payload_update_status, a_valid) == 0,
              "Unexpected offset for a_valid");
static_assert(offsetof(struct payload_update_status, b_valid) == 1,
              "Unexpected offset for b_valid");
static_assert(offsetof(struct payload_update_status, active_half) == 2,
              "Unexpected offset for active_half");
static_assert(offsetof(struct payload_update_status, next_half) == 3,
              "Unexpected offset for next_half");
static_assert(offsetof(struct payload_update_status, persistent_half) == 4,
              "Unexpected offset for persistent_half");

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
static_assert(sizeof(struct payload_update_packet) == 9,
              "Unexpected struct size");
static_assert(offsetof(struct payload_update_packet, offset) == 0,
              "Unexpected offset for offset");
static_assert(offsetof(struct payload_update_packet, len) == 4,
              "Unexpected offset for len");
static_assert(offsetof(struct payload_update_packet, type) == 8,
              "Unexpected offset for type");

struct payload_update_finalize_response_v1 {
  // Non-zero if configuration currently running on PLD needs to be
  // re-initialized (reloaded from internal configuration flash)
  // Zero otherwise
  uint8_t pld_needs_reinitialization;
} __attribute__((packed));

enum payload_update_err libhoth_payload_update(struct libhoth_device* dev,
                                               uint8_t* image, size_t len,
                                               bool skip_erase,
                                               bool binary_file);
int libhoth_payload_update_getstatus(
    struct libhoth_device* dev, struct payload_update_status* update_status);
enum payload_update_err libhoth_payload_update_read_chunk(
    struct libhoth_device* dev, int fd, size_t len, size_t offset);
int libhoth_payload_update_confirm(struct libhoth_device* dev);
int libhoth_payload_update_confirm_enable(struct libhoth_device* dev,
                                          bool enable,
                                          uint32_t timeout_seconds);
int libhoth_payload_update_confirm_get_timeout(
    struct libhoth_device* dev,
    payload_update_confirm_response_t* timeout_seconds);

#ifdef __cplusplus
}
#endif

#endif
