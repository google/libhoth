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

#ifdef LIBHOTH_SUPPORT_LIBUSB
#include <libusb.h>
#endif
#include <string.h>

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
    case HOTH_HOST_SPACE_EC:
      return "EC_RES";
    case HOTH_HOST_SPACE_MTD:
      return "MTD";
    case HOTH_HOST_SPACE_LIBUSB:
      return "LIBUSB";
    case HOTH_HOST_SPACE_SPIDEV:
      return "SPIDEV";
    case HOTH_HOST_SPACE_LIBHOTH:
      return "LIBHOTH";
    case HOTH_HOST_SPACE_PIEROT_ERR:
      return "PIE_ROT";
    default:
      return "UNKNOWN";
  }
}

const char* libhoth_error_ec_str(uint16_t code) {
  switch (code) {
    case HOTH_RES_SUCCESS:
      return "SUCCESS";
    case HOTH_RES_INVALID_COMMAND:
      return "INVALID_COMMAND";
    case HOTH_RES_ERROR:
      return "ERROR";
    case HOTH_RES_INVALID_PARAM:
      return "INVALID_PARAM";
    case HOTH_RES_ACCESS_DENIED:
      return "ACCESS_DENIED";
    case HOTH_RES_INVALID_RESPONSE:
      return "INVALID_RESPONSE";
    case HOTH_RES_INVALID_VERSION:
      return "INVALID_VERSION";
    case HOTH_RES_INVALID_CHECKSUM:
      return "INVALID_CHECKSUM";
    case HOTH_RES_IN_PROGRESS:
      return "IN_PROGRESS";
    case HOTH_RES_UNAVAILABLE:
      return "UNAVAILABLE";
    case HOTH_RES_TIMEOUT:
      return "TIMEOUT";
    case HOTH_RES_OVERFLOW:
      return "OVERFLOW";
    case HOTH_RES_INVALID_HEADER:
      return "INVALID_HEADER";
    case HOTH_RES_REQUEST_TRUNCATED:
      return "REQUEST_TRUNCATED";
    case HOTH_RES_RESPONSE_TOO_BIG:
      return "RESPONSE_TOO_BIG";
    case HOTH_RES_BUS_ERROR:
      return "BUS_ERROR";
    case HOTH_RES_BUSY:
      return "BUSY";
    case HOTH_RES_INVALID_HEADER_VERSION:
      return "INVALID_HEADER_VERSION";
    case HOTH_RES_INVALID_HEADER_CRC:
      return "INVALID_HEADER_CRC";
    case HOTH_RES_INVALID_DATA_CRC:
      return "INVALID_DATA_CRC";
    case HOTH_RES_DUP_UNAVAILABLE:
      return "DUP_UNAVAILABLE";
    default:
      return "UNKNOWN";
  }
}

void libhoth_log_err(FILE* stream, libhoth_error err) {
  if (err == HOTH_SUCCESS) {
    return;
  }

  uint32_t ctx = LIBHOTH_ERR_GET_CTX(err);
  uint16_t space = LIBHOTH_ERR_GET_SPACE(err);
  uint32_t code = LIBHOTH_ERR_GET_CODE(err);

  const char* ctx_str = libhoth_error_ctx_str(ctx);
  const char* space_str = libhoth_error_space_str(space);
  const char* code_str = NULL;

  switch (space) {
#ifdef LIBHOTH_SUPPORT_LIBUSB
    case HOTH_HOST_SPACE_LIBUSB:
      code_str = libusb_strerror(code);
      break;
#endif
    case HOTH_HOST_SPACE_MTD:
    case HOTH_HOST_SPACE_SPIDEV:
      code_str = strerror(code);
      break;
    case HOTH_HOST_SPACE_EC:
      code_str = libhoth_error_ec_str(code);
      break;
  }

  if (code_str == NULL) {
    fprintf(stream, "[%s][%s][0x%08X]\n", ctx_str, space_str, code);
  } else {
    fprintf(stream, "[%s][%s][%s]\n", ctx_str, space_str, code_str);
  }
}
