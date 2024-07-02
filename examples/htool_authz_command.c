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

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "host_commands.h"

struct ec_authorized_command_request authz_command_build_request(
    uint64_t hardware_identity, uint32_t opcode, uint32_t key_info,
    const uint32_t* nonce) {
  struct ec_authorized_command_request request = {
      .version = AUTHORIZED_COMMAND_VERSION,
      .size = sizeof(request),
      .key_info = key_info,
      .dev_id_0 = hardware_identity & UINT32_C(0xffffffff),
      .dev_id_1 = hardware_identity >> 32,
      .opcode = opcode,
  };
  memcpy(request.nonce, nonce, sizeof(request.nonce));
  return request;
}

void authz_command_print_request(
    struct ec_authorized_command_request* request) {
  const uint8_t* out = (const uint8_t*)request;
  for (int i = 0; i < sizeof(*request); i++) {
    printf("%02x", out[i]);
  }
  printf("\n");
}

static uint8_t parse_nibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 0xa;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 0xa;
  }
  return UINT8_MAX;
}

int authz_command_hex_to_struct(const char* hexstring,
                                struct ec_authorized_command_request* request) {
  size_t actual_len = strlen(hexstring);
  size_t expected_len = 2 * sizeof(*request);
  if (actual_len != expected_len) {
    fprintf(stderr, "Bad hexstring length. Got %ld but expected %ld\n",
            actual_len, expected_len);
    return -1;
  }

  uint8_t* out = (uint8_t*)request;

  for (int i = 0; i < sizeof(*request); i++) {
    uint8_t nibble_0 = parse_nibble(hexstring[2 * i]);
    uint8_t nibble_1 = parse_nibble(hexstring[2 * i + 1]);
    if (nibble_0 == UINT8_MAX || nibble_1 == UINT8_MAX) {
      fprintf(stderr, "Invalid hex character at byte %d\n", i);
      return -1;
    }
    out[i] = (nibble_0 << 4) | nibble_1;
  }

  return 0;
}
