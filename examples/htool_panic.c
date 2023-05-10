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
  size_t rlen;
  struct ec_request_persistent_panic_info req = {
      .operation = PERSISTENT_PANIC_INFO_ERASE};
  const uint16_t cmd =
      EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_PERSISTENT_PANIC_INFO;

  if (htool_exec_hostcmd(dev, cmd, 0, &req, sizeof(req), NULL, 0, &rlen)) {
    return -1;
  }

  if (check_expected_response_length(rlen, 0)) {
    return -1;
  }

  return 0;
}

static char* get_panic_console_log(
    const struct ec_response_persistent_panic_info* pdata) {
  char* console = calloc(sizeof(pdata->uart_buf) + 1, sizeof(char));

  if (!console) {
    fprintf(stderr, "Failed to allocate memory for panic console log\n");
    return NULL;
  }

  char* cursor = console;

  // To reconstruct the log, we consider the case where the uart buffer
  // has wrapped: consider the head to be the oldest character written and
  // advance through the buffer until we return to the head.
  // The uart buffer is in the firmware's .bss section, so any unwritten
  // bytes will be nul characters and we can simply skip them.
  //
  // If uart_head has all bits set, then this record is empty and is
  // erased flash.
  if (pdata->uart_head != 0xFFFFFFFF) {
    size_t head = pdata->uart_head % sizeof(pdata->uart_buf);
    size_t i = head;
    do {
      char ch = pdata->uart_buf[i];
      if (ch != '\0') {
        *cursor = ch;
        cursor++;
      }
      i = (i + 1) % sizeof(pdata->uart_buf);
    } while (i != head);
  }

  return console;
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

  if (log) {
    *log = get_panic_console_log(&pdata);
  }

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

static const char* panic_arch_string(enum panic_arch arch) {
  switch (arch) {
    case PANIC_ARCH_CORTEX_M:
      return "ARCH_CORTEX_M";
    case PANIC_ARCH_RISCV_RV32I:
      return "ARCH_RISCV_RV32I";
    default:
      return "arch-unknown";
  }
}

static void print_panic_flags_string(uint8_t flags) {
  if (flags & PANIC_DATA_FLAG_FRAME_VALID) {
    printf("FRAME_VALID,");
  }
  if (flags & PANIC_DATA_FLAG_OLD_CONSOLE) {
    printf("OLD_CONSOLE,");
  }
  if (flags & PANIC_DATA_FLAG_OLD_HOSTCMD) {
    printf("OLD_HOSTCMD,");
  }
  if (flags & PANIC_DATA_FLAG_OLD_HOSTEVENT) {
    printf("OLD_HOSTEVENT,");
  }
}

static void print_panic_info_cortex_m(const struct cortex_panic_data* data) {
  // TODO(rkr35): Pretty-print ARM Cortex-M registers.
}

static void print_panic_info_riscv(const struct rv32i_panic_data* data) {
  // TODO(rkr35): Pretty-print RISC-V registers.
}

static void print_panic_info(const struct panic_data* data) {
  if (data->magic != PANIC_DATA_MAGIC) {
    printf("Invalid panic record (magic is %08x, expected %08x).\n",
           data->magic, PANIC_DATA_MAGIC);
    return;
  }

  printf("arch: %s (%d)\n", panic_arch_string(data->arch), data->arch);
  printf("version: %d\n", data->struct_version);

  printf("flags: ");
  print_panic_flags_string(data->flags);
  printf(" (0x%02x)\n", data->flags);

  switch (data->arch) {
    case PANIC_ARCH_CORTEX_M:
      print_panic_info_cortex_m(&data->cm);
      break;
    case PANIC_ARCH_RISCV_RV32I:
      print_panic_info_riscv(&data->riscv);
      break;
    default:
      printf("Unknown Architecture.  Hexdump Follows:\n");
      print_hex_dump_buffer(sizeof(*data), data, 0);
  }

  printf("struct_size: %d\n", data->struct_size);
  printf("magic: %.*s (0x%08x)\n", (int)sizeof(data->magic),
         (const char*)&data->magic, data->magic);
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
