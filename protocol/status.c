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

#include "status.h"

const char* libhoth_error_ctx_str(uint32_t ctx) {
  switch (ctx) {
    case HOTH_CTX_NONE:
      return "NONE";
    case HOTH_CTX_INIT:
      return "INIT";
    case HOTH_CTX_USB:
      return "USB";
    case HOTH_CTX_SPI:
      return "SPI";
    case HOTH_CTX_CMD_EXEC:
      return "CMD_EXEC";
    default:
      return "UNKNOWN";
  }
}

const char* libhoth_error_space_str(uint16_t space) {
  switch (space) {
    case HOTH_HOST_SPACE_FW:
      return "FW";
    case HOTH_HOST_SPACE_POSIX:
      return "POSIX";
    case HOTH_HOST_SPACE_LIBUSB:
      return "LIBUSB";
    case HOTH_HOST_SPACE_LIBHOTH:
      return "LIBHOTH";
    default:
      return "UNKNOWN";
  }
}

const char* libhoth_error_code_fw_str(uint16_t code) {
  switch (code) {
    case HOTH_FW_SUCCESS:
      return "SUCCESS";
    case HOTH_FW_INVALID_COMMAND:
      return "INVALID_COMMAND";
    case HOTH_FW_ERROR:
      return "ERROR";
    case HOTH_FW_INVALID_PARAM:
      return "INVALID_PARAM";
    case HOTH_FW_ACCESS_DENIED:
      return "ACCESS_DENIED";
    case HOTH_FW_INVALID_RESPONSE:
      return "INVALID_RESPONSE";
    case HOTH_FW_INVALID_VERSION:
      return "INVALID_VERSION";
    case HOTH_FW_INVALID_CHECKSUM:
      return "INVALID_CHECKSUM";
    case HOTH_FW_IN_PROGRESS:
      return "IN_PROGRESS";
    case HOTH_FW_UNAVAILABLE:
      return "UNAVAILABLE";
    case HOTH_FW_TIMEOUT:
      return "TIMEOUT";
    case HOTH_FW_OVERFLOW:
      return "OVERFLOW";
    case HOTH_FW_INVALID_HEADER:
      return "INVALID_HEADER";
    case HOTH_FW_REQUEST_TRUNCATED:
      return "REQUEST_TRUNCATED";
    case HOTH_FW_RESPONSE_TOO_BIG:
      return "RESPONSE_TOO_BIG";
    case HOTH_FW_BUS_ERROR:
      return "BUS_ERROR";
    case HOTH_FW_BUSY:
      return "BUSY";
    case HOTH_FW_INVALID_HEADER_VERSION:
      return "INVALID_HEADER_VERSION";
    case HOTH_FW_INVALID_HEADER_CRC:
      return "INVALID_HEADER_CRC";
    case HOTH_FW_INVALID_DATA_CRC:
      return "INVALID_DATA_CRC";
    case HOTH_FW_DUP_UNAVAILABLE:
      return "DUP_UNAVAILABLE";
    default:
      return "UNKNOWN";
  }
}
