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

#ifndef _LIBHOTH_PROTOCOL_HOST_CMD_H_
#define _LIBHOTH_PROTOCOL_HOST_CMD_H_

#include <stdint.h>
#include <stdio.h>

#include "transports/libhoth_device.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __packed
#define __packed __attribute__((packed))
#endif
#ifndef __aligned
#define __aligned(x) __attribute__((aligned(x)))
#endif

#define __ec_align1 __packed
#define __ec_align2 __packed __aligned(2)
#define __ec_align4 __packed __aligned(4)

#define HTOOL_ERROR_HOST_COMMAND_START 537200

// NOTE: All PRV commands in this file are offset by
// EC_CMD_BOARD_SPECIFIC_BASE.
#define EC_CMD_BOARD_SPECIFIC_BASE 0x3E00
#define EC_CMD_BOARD_SPECIFIC_LAST 0x3FFF

enum ec_status {
  EC_RES_SUCCESS = 0,
  EC_RES_INVALID_COMMAND = 1,
  EC_RES_ERROR = 2,
  EC_RES_INVALID_PARAM = 3,
  EC_RES_ACCESS_DENIED = 4,
  EC_RES_INVALID_RESPONSE = 5,
  EC_RES_INVALID_VERSION = 6,
  EC_RES_INVALID_CHECKSUM = 7,
  EC_RES_IN_PROGRESS = 8,
  EC_RES_UNAVAILABLE = 9,
  EC_RES_TIMEOUT = 10,
  EC_RES_OVERFLOW = 11,
  EC_RES_INVALID_HEADER = 12,
  EC_RES_REQUEST_TRUNCATED = 13,
  EC_RES_RESPONSE_TOO_BIG = 14,
  EC_RES_BUS_ERROR = 15,
  EC_RES_BUSY = 16,
  EC_RES_INVALID_HEADER_VERSION = 17,
  EC_RES_INVALID_HEADER_CRC = 18,
  EC_RES_INVALID_DATA_CRC = 19,
  EC_RES_DUP_UNAVAILABLE = 20,
  EC_RES_MAX = UINT16_MAX
} __packed;

#define EC_HOST_REQUEST_VERSION 3

struct ec_host_request {
  // Should be EC_HOST_REQUEST_VERSION
  uint8_t struct_version;
  // Checksum of request and data; sum of all bytes including checksum should
  // total to 0.
  uint8_t checksum;
  // Command to send (EC_CMD_...)
  uint16_t command;
  // Command version
  uint8_t command_version;
  uint8_t reserved;
  // Length of data that follows this header
  uint16_t data_len;
} __ec_align4;

#define EC_HOST_RESPONSE_VERSION 3

struct ec_host_response {
  // Should be EC_HOST_RESPONSE_VERSION
  uint8_t struct_version;
  // Checksum of request and data; sum of all bytes including checksum should
  // total to 0.
  uint8_t checksum;
  // One of the EC_RES_* status codes
  uint16_t result;
  // Length of data which follows this header.
  uint16_t data_len;
  uint16_t reserved;
} __ec_align4;

int hostcmd_exec(struct libhoth_device* dev, uint16_t command, uint8_t version,
                 const void* req_payload, size_t req_payload_size,
                 void* resp_buf, size_t resp_buf_size, size_t* out_resp_size);

uint8_t calculate_ec_command_checksum(const void* header, size_t header_size,
                                      const void* data, size_t data_size);

void hex_dump(FILE* out, const void* buffer, size_t size);

#ifdef __cplusplus
}
#endif

#endif  // _LIBHOTH_TRANSPORTS_HOST_CMD_H_
