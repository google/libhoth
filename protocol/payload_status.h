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

#ifndef LIBHOTH_PROTOCOL_PAYLOAD_STATUS_H_
#define LIBHOTH_PROTOCOL_PAYLOAD_STATUS_H_

#include <stdint.h>

#include "transports/libhoth_device.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HOTH_PRV_CMD_HOTH_PAYLOAD_STATUS 0x0006

struct payload_status_response_header {
  uint8_t version;
  uint8_t lockdown_state;
  uint8_t active_half;
  uint8_t region_count;
} __attribute__((packed));

enum payload_validation_state {
  PAYLOAD_IMAGE_INVALID = 0,
  PAYLOAD_IMAGE_UNVERIFIED = 1,
  PAYLOAD_IMAGE_VALID = 2,
  PAYLOAD_DESCRIPTOR_VALID = 3,
};

struct payload_region_state {
  uint8_t validation_state; /* enum payload_validation_state */
  uint8_t failure_reason;   /* enum payload_validation_failure_reason */
  uint8_t reserved_0;
  uint8_t image_type; /* enum image_type (dev, prod, breakout) */
  uint16_t key_index;
  uint16_t reserved_1;
  uint32_t image_family; /* handy to disambiguate during enumeration */
  uint32_t version_major;
  uint32_t version_minor;
  uint32_t version_point;
  uint32_t version_subpoint;
  uint32_t descriptor_offset; /* can be used to pull the image hash/signature */
} __attribute__((packed));

struct payload_status {
  struct payload_status_response_header resp_hdr;
  struct payload_region_state region_state[2];
} __attribute__((packed));

const char* libhoth_sps_eeprom_lockdown_status_string(uint8_t st);
const char* libhoth_payload_validation_state_string(uint8_t s);
const char* libhoth_payload_validation_failure_reason_string(uint8_t r);
const char* libhoth_image_type_string(uint8_t type);

int libhoth_payload_status(struct libhoth_device* dev,
                           struct payload_status* payload_state);

#ifdef __cplusplus
}
#endif

#endif
