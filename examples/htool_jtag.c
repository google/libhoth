// Copyright 2024 Google LLC
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

#include "htool_jtag.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host_commands.h"
#include "htool.h"
#include "htool_cmd.h"

char JTAG_TEST_BYPASS_PATTERN_DEFAULT_VALUE[] =
    // PRBS9 with '0' bit added at the beginning to make it exactly 64 bytes
    "0x42 0x30 0x9c 0xab 0xd 0xe9 0xb9 0x14 0x2b 0x4f 0xd9 0x25 0xbf 0x26 0xa6 "
    "0x60 0x31 0x94 0x69 0x7f 0x45 0x8e 0xb2 0xcf 0x1f 0x74 0x1a 0xdb 0xb0 "
    "0x5a 0xfa 0xa8 0x14 0xaf 0x2e 0xe0 0x73 0xa4 0xf5 0xd4 0x48 0x67 0xb 0xdb "
    "0x34 0x3b 0xc3 0xfe 0xf 0x7c 0x5c 0xc8 0x25 0x3b 0x47 0x9f 0x36 0x2a 0x47 "
    "0x1b 0x57 0x13 0x11 0x0";

static int jtag_read_idcode(struct libhoth_device *dev,
                            const struct htool_invocation *inv) {
  uint32_t clk_idiv;

  if (htool_get_param_u32(inv, "clk_idiv", &clk_idiv)) {
    return -1;
  }

  if (clk_idiv > UINT16_MAX) {
    fprintf(stderr, "Clock divisor value too large. Expected <= %u\n",
            UINT16_MAX);
    return -1;
  }

  const struct ec_request_jtag_operation request = {
      .clk_idiv = (uint16_t)clk_idiv,
      .operation = EC_JTAG_OP_READ_IDCODE,
  };

  struct ec_response_jtag_read_idcode_operation response;
  size_t response_length = 0;
  int ret = htool_exec_hostcmd(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_JTAG_OPERATION,
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

  printf("IDCODE: 0x%08x\n", response.idcode);
  return 0;
}

// Parse exactly `expected_bytes_count` byte tokens from `param_value` string
// into `byte_sequence`.
// If fewer than `expected_bytes_count` byte tokens are present in
// `param_value`, return code indicates error.
// If more than `expected_bytes_count` byte tokens are present in `param_value`,
// return code indicates error.
static int parse_string_param_into_byte_sequence(
    char *param_value, uint8_t *const byte_sequence,
    const size_t expected_bytes_count) {
  char *saveptr = NULL;
  char *token = strtok_r(param_value, " ", &saveptr);
  for (size_t i = 0; i < expected_bytes_count; i++) {
    if (token == NULL) {
      fprintf(stderr, "Expected %zu bytes, found %zu\n", expected_bytes_count,
              i);
      return -1;
    }
    char *endptr = NULL;
    unsigned long int parsed_value = strtoul(token, &endptr, 0);
    if ((token == endptr) || (parsed_value > UINT8_MAX) || (*endptr != '\0')) {
      fprintf(stderr, "Invalid byte token '%s'\n", token);
      return -1;
    }
    byte_sequence[i] = (uint8_t)parsed_value;
    token = strtok_r(NULL, " ", &saveptr);
  }

  // Check the last token after parsing `expected_bytes_count` tokens
  if (token != NULL) {
    fprintf(stderr,
            "Expected %zu bytes, but found more starting at token '%s'\n",
            expected_bytes_count, token);
    return -1;
  }

  return 0;
}

static int jtag_test_bypass(struct libhoth_device *dev,
                            const struct htool_invocation *inv) {
  char *tdi_bytes = NULL;
  uint32_t clk_idiv;

  if (htool_get_param_u32(inv, "clk_idiv", &clk_idiv) ||
      htool_get_param_string(inv, "tdi_bytes", (const char **)&tdi_bytes)) {
    return -1;
  }

  if (tdi_bytes[0] == '\0') {
    // Empty string indicates use default value since no value was provided on
    // command line
    tdi_bytes = JTAG_TEST_BYPASS_PATTERN_DEFAULT_VALUE;
  }

  if (clk_idiv > UINT16_MAX) {
    fprintf(stderr, "Clock divisor value too large. Expected <= %u\n",
            UINT16_MAX);
    return -1;
  }

  struct {
    struct ec_request_jtag_operation operation;
    struct ec_request_jtag_test_bypass_operation params;
  } __attribute__((packed, aligned(4))) request = {
      .operation =
          {
              .clk_idiv = (uint16_t)clk_idiv,
              .operation = EC_JTAG_OP_TEST_BYPASS,
          },
  };

  int ret = parse_string_param_into_byte_sequence(
      tdi_bytes, request.params.tdi_pattern, EC_JTAG_TEST_BYPASS_PATTERN_LEN);
  if (ret != 0) {
    return ret;
  }

  printf("TDI: ");
  for (uint8_t i = 0; i < EC_JTAG_TEST_BYPASS_PATTERN_LEN; i++) {
    printf("0x%02x ", request.params.tdi_pattern[i]);
  }
  printf("\n");

  struct ec_response_jtag_test_bypass_operation response;
  size_t response_len = 0;
  ret = htool_exec_hostcmd(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_JTAG_OPERATION,
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

  bool tdo_matches_tdi = true;
  printf("TDO: ");
  for (uint8_t i = 0; i < EC_JTAG_TEST_BYPASS_PATTERN_LEN; i++) {
    if (response.tdo_pattern[i] != request.params.tdi_pattern[i]) {
      tdo_matches_tdi = false;
    }
    printf("0x%02x ", response.tdo_pattern[i]);
  }
  printf("\n");

  printf("Captured TDO bytes match sent TDI bytes? %s\n",
         tdo_matches_tdi ? "YES" : "NO");
  return 0;
}

int command_jtag_operation_run(const struct htool_invocation *inv) {
  struct libhoth_device *dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  if (strncmp(inv->cmd->verbs[1], JTAG_READ_IDCODE_CMD_STR,
              sizeof(JTAG_READ_IDCODE_CMD_STR)) == 0) {
    return jtag_read_idcode(dev, inv);
  } else if (strncmp(inv->cmd->verbs[1], JTAG_TEST_BYPASS_CMD_STR,
                     sizeof(JTAG_TEST_BYPASS_CMD_STR)) == 0) {
    return jtag_test_bypass(dev, inv);
  }
  return -1;
}
