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

#ifndef LIBHOTH_PROTOCOL_STATUS_H_
#define LIBHOTH_PROTOCOL_STATUS_H_

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HOTH_SUCCESS 0x0ULL

typedef uint64_t libhoth_error;

const char* libhoth_error_ctx_str(uint32_t ctx);
const char* libhoth_error_space_str(uint16_t space);
const char* libhoth_error_ec_str(uint16_t code);
void libhoth_log_err(FILE* stream, libhoth_error err);

/** Constructs a libhoth error code from its components.
 *  Cxt (16 bits) uniquely identifies the libhoth operation or subsystem.
 *  Space (16 bits) indicates the domain of errors.
 *  Code (32 bits) indicates specific error condition.
 */
#define LIBHOTH_ERR_CONSTRUCT(ctx, space, code) \
  ((((uint64_t)(ctx) & 0xFFFFULL) << 48) |      \
   (((uint64_t)(space) & 0xFFFFULL) << 32) |    \
   ((uint64_t)(code) & 0xFFFFFFFFULL))

#define LIBHOTH_ERR_GET_CTX(err) \
  ((uint16_t)(((uint64_t)(err) >> 48) & 0xFFFFULL))
#define LIBHOTH_ERR_GET_SPACE(err) \
  ((uint16_t)(((uint64_t)(err) >> 32) & 0xFFFFULL))
#define LIBHOTH_ERR_GET_CODE(err) ((uint32_t)((uint64_t)(err) & 0xFFFFFFFFULL))

typedef enum {
  LIBHOTH_OK = 0,
  LIBHOTH_ERR_UNKNOWN_VENDOR = 1,
  LIBHOTH_ERR_INTERFACE_NOT_FOUND = 2,
  LIBHOTH_ERR_MALLOC_FAILED = 3,
  LIBHOTH_ERR_TIMEOUT = 4,
  LIBHOTH_ERR_OUT_UNDERFLOW = 5,
  LIBHOTH_ERR_IN_OVERFLOW = 6,
  LIBHOTH_ERR_UNSUPPORTED_VERSION = 7,
  LIBHOTH_ERR_INVALID_PARAMETER = 8,
  LIBHOTH_ERR_FAIL = 9,
  LIBHOTH_ERR_RESPONSE_BUFFER_OVERFLOW = 10,
  LIBHOTH_ERR_INTERFACE_BUSY = 11,
  LIBHOTH_ERR_DFU_APP_MISMATCH = 12,
  LIBHOTH_ERR_DFU_ROMEXT_MISMATCH = 13,
} libhoth_status;

// hoth_context_id: High 16 bits of the error code.
// Uniquely identifies the libhoth operation or subsystem.
enum hoth_context_id {
  HOTH_CTX_NONE = 0,
  HOTH_CTX_INIT = 1,       // Initialization / General
  HOTH_CTX_USB = 10,       // USB transport
  HOTH_CTX_SPI = 20,       // SPI transport
  HOTH_CTX_CMD_EXEC = 30,  // Host command execution
};

// hoth_host_space: Middle 16 bits of the 64-bit error code.
// Indicates the domain of errors.
enum hoth_host_space {
  HOTH_HOST_SPACE_EC = 0x0001,          // old-school EC_RES errors
  HOTH_HOST_SPACE_MTD = 0x0002,         // errno values from MTD
  HOTH_HOST_SPACE_LIBUSB = 0x0003,      // libusb_error values
  HOTH_HOST_SPACE_SPIDEV = 0x0004,      // SPIDEV failures
  HOTH_HOST_SPACE_LIBHOTH = 0x0005,     // libhoth internal errors
  HOTH_HOST_SPACE_PIEROT_ERR = 0x0006,  // Pie-RoT 32-bit firmware errors
};

#ifndef __packed
#define __packed __attribute__((packed))
#endif

enum hoth_status {
  HOTH_RES_SUCCESS = 0,
  HOTH_RES_INVALID_COMMAND = 1,
  HOTH_RES_ERROR = 2,
  HOTH_RES_INVALID_PARAM = 3,
  HOTH_RES_ACCESS_DENIED = 4,
  HOTH_RES_INVALID_RESPONSE = 5,
  HOTH_RES_INVALID_VERSION = 6,
  HOTH_RES_INVALID_CHECKSUM = 7,
  HOTH_RES_IN_PROGRESS = 8,
  HOTH_RES_UNAVAILABLE = 9,
  HOTH_RES_TIMEOUT = 10,
  HOTH_RES_OVERFLOW = 11,
  HOTH_RES_INVALID_HEADER = 12,
  HOTH_RES_REQUEST_TRUNCATED = 13,
  HOTH_RES_RESPONSE_TOO_BIG = 14,
  HOTH_RES_BUS_ERROR = 15,
  HOTH_RES_BUSY = 16,
  HOTH_RES_INVALID_HEADER_VERSION = 17,
  HOTH_RES_INVALID_HEADER_CRC = 18,
  HOTH_RES_INVALID_DATA_CRC = 19,
  HOTH_RES_DUP_UNAVAILABLE = 20,
  HOTH_RES_MAX = UINT16_MAX
} __packed;

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_PROTOCOL_STATUS_H_
