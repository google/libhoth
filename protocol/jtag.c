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

#include "jtag.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "host_cmd.h"
#include "transports/libhoth_device.h"

int libhoth_jtag_read_idcode(struct libhoth_device* dev, uint16_t clk_idiv,
                             uint32_t* idcode) {
  const struct hoth_request_jtag_operation request = {
      .clk_idiv = clk_idiv,
      .operation = HOTH_JTAG_OP_READ_IDCODE,
  };
  struct hoth_response_jtag_read_idcode_operation response;

  size_t response_length = 0;
  int ret = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_JTAG_OPERATION,
      /*version=*/0, &request, sizeof(request), &response, sizeof(response),
      &response_length);

  if (ret != 0) {
    fprintf(stderr, "HOTH_JTAG_OPERATION error code: %d\n", ret);
    return -1;
  }

  if (response_length != sizeof(response)) {
    fprintf(stderr,
            "HOTH_JTAG_OPERATION expected exactly %zu reseponse bytes, got %zu",
            sizeof(response), response_length);
    return -1;
  }

  *idcode = response.idcode;
  return 0;
}

int libhoth_jtag_test_bypass(
    struct libhoth_device* dev, uint16_t clk_idiv,
    const uint8_t tdi_bytes[HOTH_JTAG_TEST_BYPASS_PATTERN_LEN],
    uint8_t tdo_bytes[HOTH_JTAG_TEST_BYPASS_PATTERN_LEN]) {
  struct {
    struct hoth_request_jtag_operation operation;
    struct hoth_request_jtag_test_bypass_operation params;
  } __attribute__((packed, aligned(4))) request = {
      .operation =
          {
              .clk_idiv = clk_idiv,
              .operation = HOTH_JTAG_OP_TEST_BYPASS,
          },
  };

  memcpy(request.params.tdi_pattern, tdi_bytes,
         HOTH_JTAG_TEST_BYPASS_PATTERN_LEN);

  struct hoth_response_jtag_test_bypass_operation response;
  size_t response_len = 0;
  int ret = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_JTAG_OPERATION,
      /*version=*/0, &request, sizeof(request), &response, sizeof(response),
      &response_len);

  if (ret != 0) {
    fprintf(stderr, "HOTH_JTAG_OPERATION error code: %d\n", ret);
    return -1;
  }

  if (response_len != sizeof(response)) {
    fprintf(stderr,
            "HOTH_JTAG_OPERATION expected exactly %zu response bytes, got %zu",
            sizeof(response), response_len);
    return -1;
  }

  memcpy(tdo_bytes, response.tdo_pattern, HOTH_JTAG_TEST_BYPASS_PATTERN_LEN);
  return 0;
}

int libhoth_jtag_program_and_verify_pld(struct libhoth_device* dev,
                                        uint32_t offset) {
  struct {
    struct hoth_request_jtag_operation operation;
    struct hoth_request_jtag_program_and_verify_pld_operation params;
  } __attribute__((packed, aligned(4))) request = {
      .operation =
          {
              .clk_idiv = 0,  // Not used
              .operation = HOTH_JTAG_OP_PROGRAM_AND_VERIFY_PLD,
          },
      .params =
          {
              .data_offset = offset,
          },
  };

  size_t response_length = 0;
  int ret = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_JTAG_OPERATION,
      /*version=*/0, &request, sizeof(request), /*resp_buf=*/NULL,
      /*resp_buf_size=*/0, &response_length);

  if (ret != 0) {
    fprintf(stderr, "HOTH_JTAG_OPERATION error code: %d\n", ret);
    return -1;
  }

  if (response_length != 0) {
    fprintf(stderr,
            "HOTH_JTAG_OPERATION expected exactly %u response bytes, got %zu\n",
            0, response_length);
    return -1;
  }

  return 0;
}

int libhoth_jtag_verify_pld(struct libhoth_device* dev, uint32_t offset) {
  struct {
    struct hoth_request_jtag_operation operation;
    struct hoth_request_jtag_program_and_verify_pld_operation params;
  } __attribute__((packed, aligned(4))) request = {
      .operation =
          {
              .clk_idiv = (uint16_t)0,  // Not used
              .operation = HOTH_JTAG_OP_VERIFY_PLD,
          },
      .params =
          {
              .data_offset = offset,
          },
  };

  size_t response_length = 0;
  int ret = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_JTAG_OPERATION,
      /*version=*/0, &request, sizeof(request), /*resp_buf=*/NULL,
      /*resp_buf_size=*/0, &response_length);

  if (ret != 0) {
    fprintf(stderr, "HOTH_JTAG_OPERATION error code: %d\n", ret);
    return -1;
  }

  if (response_length != 0) {
    fprintf(stderr,
            "HOTH_JTAG_OPERATION expected exactly %u response bytes, got %zu\n",
            0, response_length);
    return -1;
  }

  return 0;
}
