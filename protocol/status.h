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

#define HOTH_SUCCESS 0x0ULL

typedef uint64_t libhoth_error;

const char* libhoth_error_ctx_str(uint32_t ctx);
const char* libhoth_error_space_str(uint16_t space);
const char* libhoth_error_code_fw_str(uint16_t code);

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
  HOTH_HOST_SPACE_FW = 0x0001,           // Firmware errors directly
  HOTH_HOST_SPACE_POSIX = 0x0002,        // errno values
  HOTH_HOST_SPACE_LIBUSB = 0x0003,       // libusb_error values
  HOTH_HOST_SPACE_LIBHOTH = 0x0005,      // libhoth internal errors
  HOTH_HOST_SPACE_FW_EARLGREY = 0x0006,  // Earlgrey 32-bit firmware errors
};

#ifndef __packed
#define __packed __attribute__((packed))
#endif

// Hoth error code: Low 16 bits of the 32-bit Base Error Code
// Firmware Error
enum hoth_fw_error_status {
  HOTH_FW_SUCCESS = 0,
  HOTH_FW_INVALID_COMMAND = 1,
  HOTH_FW_ERROR = 2,
  HOTH_FW_INVALID_PARAM = 3,
  HOTH_FW_ACCESS_DENIED = 4,
  HOTH_FW_INVALID_RESPONSE = 5,
  HOTH_FW_INVALID_VERSION = 6,
  HOTH_FW_INVALID_CHECKSUM = 7,
  HOTH_FW_IN_PROGRESS = 8,
  HOTH_FW_UNAVAILABLE = 9,
  HOTH_FW_TIMEOUT = 10,
  HOTH_FW_OVERFLOW = 11,
  HOTH_FW_INVALID_HEADER = 12,
  HOTH_FW_REQUEST_TRUNCATED = 13,
  HOTH_FW_RESPONSE_TOO_BIG = 14,
  HOTH_FW_BUS_ERROR = 15,
  HOTH_FW_BUSY = 16,
  HOTH_FW_INVALID_HEADER_VERSION = 17,
  HOTH_FW_INVALID_HEADER_CRC = 18,
  HOTH_FW_INVALID_DATA_CRC = 19,
  HOTH_FW_DUP_UNAVAILABLE = 20,
  HOTH_FW_MAX = UINT16_MAX
} __packed;

#endif  // LIBHOTH_PROTOCOL_STATUS_H_
