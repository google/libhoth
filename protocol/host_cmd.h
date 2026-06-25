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

#include "status.h"
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

#define __hoth_align1 __packed
#define __hoth_align2 __packed __aligned(2)
#define __hoth_align4 __packed __aligned(4)

#define HTOOL_ERROR_HOST_COMMAND_START 537200

// NOTE: All PRV commands in this file are offset by
// HOTH_CMD_BOARD_SPECIFIC_BASE.
#define HOTH_CMD_BOARD_SPECIFIC_BASE 0x3E00
#define HOTH_CMD_BOARD_SPECIFIC_LAST 0x3FFF

#define HOTH_HOST_REQUEST_VERSION 3

#define HOTH_CMD_TIMEOUT_MS_DEFAULT 180000  // 180 seconds

struct hoth_host_request {
  // Should be HOTH_HOST_REQUEST_VERSION
  uint8_t struct_version;
  // Checksum of request and data; sum of all bytes including checksum should
  // total to 0.
  uint8_t checksum;
  // Command to send (HOTH_CMD_...)
  uint16_t command;
  // Command version
  uint8_t command_version;
  uint8_t reserved;
  // Length of data that follows this header
  uint16_t data_len;
} __hoth_align4;

#define HOTH_HOST_RESPONSE_VERSION 3

struct hoth_host_response {
  // Should be HOTH_HOST_RESPONSE_VERSION
  uint8_t struct_version;
  // Checksum of request and data; sum of all bytes including checksum should
  // total to 0.
  uint8_t checksum;
  // One of the HOTH_RES_* status codes
  uint16_t result;
  // Length of data which follows this header.
  uint16_t data_len;
  uint16_t reserved;
} __hoth_align4;

int libhoth_hostcmd_exec(struct libhoth_device* dev, uint16_t command,
                         uint8_t version, const void* req_payload,
                         size_t req_payload_size, void* resp_buf,
                         size_t resp_buf_size, size_t* out_resp_size);

libhoth_error libhoth_hostcmd_exec_v2(struct libhoth_device* dev,
                                      uint16_t command, uint8_t version,
                                      const void* req_payload,
                                      size_t req_payload_size, void* resp_buf,
                                      size_t resp_buf_size,
                                      size_t* out_resp_size);

uint8_t libhoth_calculate_checksum(const void* header, size_t header_size,
                                   const void* data, size_t data_size);

void hex_dump(FILE* out, const void* buffer, size_t size);

#ifdef __cplusplus
}
#endif

#endif  // _LIBHOTH_TRANSPORTS_HOST_CMD_H_
