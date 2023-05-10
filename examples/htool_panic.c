// Copyright 2023 Google LLC
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

#include "htool_panic.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host_commands.h"
#include "htool.h"
#include "htool_cmd.h"

static int check_expected_response_length(uint16_t length, uint16_t expected) {
  if (length != expected) {
    fprintf(stderr, "Bad response length %d (expected %d)\n", length, expected);
    return -1;
  }
  return 0;
}

static int clear_persistent_panic_info(struct libhoth_device* dev) {
  printf("TODO: clear_persistent_panic_info\n");
  return 0;
}

static int get_persistent_panic_info(struct libhoth_device* dev,
                                     struct panic_data* panic, char** log) {
  const uint16_t cmd =
      EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_PERSISTENT_PANIC_INFO;
  struct ec_response_persistent_panic_info pdata;
  memset(&pdata, 0, sizeof(pdata));
  uint8_t* dest = (uint8_t*)&pdata;

  // The persistent panic info record is 6KiB long, so we have to retrieve it
  // in chunks.
  const size_t chunk_size = HOTH_PERSISTENT_PANIC_INFO_CHUNK_SIZE;
  for (size_t i = 0; i < sizeof(pdata) / chunk_size; ++i, dest += chunk_size) {
    size_t rlen;

    struct ec_request_persistent_panic_info req = {
        .operation = PERSISTENT_PANIC_INFO_GET,
        .index = i,
    };

    if (htool_exec_hostcmd(dev, cmd, 0, &req, sizeof(req), dest, chunk_size,
                           &rlen)) {
      return -1;
    }

    if (check_expected_response_length(rlen, chunk_size)) {
      return -1;
    }
  }

  // TODO(rkr35): Populate panic console log.

  memcpy(panic, pdata.panic_record, sizeof(*panic));
  return 0;
}

static void print_hex_dump_buffer(size_t size, const void* buffer,
                                  uint32_t address) {
  if (!buffer) {
    fprintf(stderr, "print_hex_dump_buffer with null buffer.\n");
    return;
  }

  enum { BYTES_PER_LINE = 16 };
  const uint8_t* bytes = (const uint8_t*)buffer;
  char line_ascii[BYTES_PER_LINE + 1] = {0};

  for (size_t offset = 0; offset < size; offset += BYTES_PER_LINE) {
    printf("0x%04lx: ", address + offset);
    const size_t remaining = size - offset;
    const size_t chunk_size =
        remaining < BYTES_PER_LINE ? remaining : BYTES_PER_LINE;

    for (size_t i = 0; i < BYTES_PER_LINE; ++i) {
      if (i > 0 && (i % 8) == 0) {
        // Insert a gap between sets of 8 bytes.
        printf(" ");
      }

      if (i < chunk_size) {
        uint8_t byte = bytes[offset + i];
        printf("%02X ", byte);
        line_ascii[i] = isgraph(byte) ? byte : '.';
      } else {
        printf("   ");  // filler instead of hex digits
        line_ascii[i] = ' ';
      }
    }

    printf("|%s|\n", line_ascii);
  }
}

static void print_panic_info(const struct panic_data* data) {
  printf("TODO: print_panic_info\n");
}

int htool_panic_get_panic(const struct htool_invocation* inv) {
  bool clear;
  bool hexdump;

  if (htool_get_param_bool(inv, "clear", &clear) ||
      htool_get_param_bool(inv, "hexdump", &hexdump)) {
    return -1;
  }

  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  if (clear) {
    printf("Clearing panic log from flash.\n");
    return clear_persistent_panic_info(dev);
  }

  struct panic_data panic;
  memset(&panic, 0, sizeof(panic));

  char* console_log = NULL;

  if (get_persistent_panic_info(dev, &panic, &console_log)) {
    return -1;
  }

  if (hexdump) {
    print_hex_dump_buffer(sizeof(panic), &panic, 0);
  } else {
    print_panic_info(&panic);
  }

  if (console_log) {
    printf("Saved console log:\n");
    printf("%s\n", console_log);
    free(console_log);
  }

  return 0;
}
