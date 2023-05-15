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

static int get_persistent_panic_info(
    struct libhoth_device* dev,
    struct ec_response_persistent_panic_info* panic) {
  const uint16_t cmd =
      EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_PERSISTENT_PANIC_INFO;
  uint8_t* dest = (uint8_t*)panic;

  // The persistent panic info record is 6KiB long, so we have to retrieve it
  // in chunks.
  const size_t chunk_size = HOTH_PERSISTENT_PANIC_INFO_CHUNK_SIZE;
  const size_t num_chunks = sizeof(*panic) / chunk_size;
  for (size_t i = 0; i < num_chunks; ++i, dest += chunk_size) {
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

static void print_arm_register(int r, const uint32_t* reg, int offset) {
  static const char* const NAMES[] = {
      "r0", "r1", "r2",  "r3",  "r4",  "r5", "r6", "r7",
      "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc",
  };

  if (r >= (sizeof(NAMES) / sizeof(NAMES[0]))) {
    fprintf(stderr, "r (%d) is out-of-bounds of NAMES.\n", r);
    return;
  }

  printf("%3s: %08x%s", NAMES[r], reg[offset], (r % 4 == 3) ? "\n" : " ");
}

static void print_mmfs_name(uint32_t mmfs) {
  // These descriptions are documented in the ARM user guide, section 4.3.10:
  // Configurable Fault Status Register.  The EC firmware misnames this
  // register as MMFS (memory management fault status), which is the name of
  // the first 8 bits of the CFSR.
  // The following definitions were copied directly from the EC firmware.
  static char const* const NAMES[32] = {
      "Instruction access violation",
      "Data access violation",
      NULL,
      "Unstack from exception violation",
      "Stack from exception violation",
      NULL,
      NULL,
      NULL,

      "Instruction bus error",
      "Precise data bus error",
      "Imprecise data bus error",
      "Unstack from exception bus fault",
      "Stack from exception bus fault",
      NULL,
      NULL,
      NULL,

      "Undefined instructions",
      "Invalid state",
      "Invalid PC",
      "No coprocessor",
      NULL,
      NULL,
      NULL,
      NULL,

      "Unaligned",
      "Divide by 0",
      NULL,
      NULL,

      NULL,
      NULL,
      NULL,
      NULL,
  };

  unsigned count = 0;
  for (unsigned i = 0; i < 32; ++i) {
    uint32_t bit = 1UL << i;
    if ((mmfs & bit) != 0 && NAMES[i]) {
      printf("%s%s", count ? ", " : "", NAMES[i]);
      ++count;
    }
  }

  printf("\n");
}

static void print_panic_info_cortex_m(const struct cortex_panic_data* data) {
  const uint32_t* lregs = data->regs;
  const uint32_t* sregs = data->frame;

  uint32_t exc_return = data->regs[11] & 0xf;
  bool in_handler = exc_return == 1 || exc_return == 9;

  printf("=== %s EXCEPTION: %02x ====== xPSR: %08x ===\n",
         in_handler ? "HANDLER" : "PROCESS", lregs[1] & 0xFF, sregs[7]);

  for (int i = 0; i < 4; ++i) {
    print_arm_register(i, sregs, i);
  }

  for (int i = 4; i < 10; ++i) {
    print_arm_register(i, lregs, i - 1);
  }

  print_arm_register(10, lregs, 9);
  print_arm_register(11, lregs, 10);
  print_arm_register(12, sregs, 4);
  print_arm_register(13, lregs, in_handler ? 2 : 0);
  print_arm_register(14, sregs, 5);
  print_arm_register(15, sregs, 6);

  printf("Reason: ");
  print_mmfs_name(data->mmfs);
  printf("Extra:\n");
  printf("mmfs = %08x\n", data->mmfs);
  printf("bfar = %08x\n", data->bfar);
  printf("mfar = %08x\n", data->mfar);
  printf("shcsr = %08x\n", data->shcsr);
  printf("hfsr = %08x\n", data->hfsr);
  printf("dfsr = %08x\n", data->dfsr);
}

static void print_panic_info_riscv(const struct rv32i_panic_data* data) {
  const uint32_t* regs = data->regs;
  printf("=== EXCEPTION: MCAUSE=%x ===\n", data->mcause);
  printf("s11: %08x s10: %08x  s9: %08x  s8:   %08x\n", regs[0], regs[1],
         regs[2], regs[3]);
  printf("s7:  %08x s6:  %08x  s5: %08x  s4:   %08x\n", regs[4], regs[5],
         regs[6], regs[7]);
  printf("s3:  %08x s2:  %08x  s1: %08x  s0:   %08x\n", regs[8], regs[9],
         regs[10], regs[11]);
  printf("t6:  %08x t5:  %08x  t4: %08x  t3:   %08x\n", regs[12], regs[13],
         regs[14], regs[15]);
  printf("t2:  %08x t1:  %08x  t0: %08x  a7:   %08x\n", regs[16], regs[17],
         regs[18], regs[19]);
  printf("a6:  %08x a5:  %08x  a4: %08x  a3:   %08x\n", regs[20], regs[21],
         regs[22], regs[23]);
  printf("a2:  %08x a1:  %08x  a0: %08x  tp:   %08x\n", regs[24], regs[25],
         regs[26], regs[27]);
  printf("gp:  %08x ra:  %08x  sp: %08x  mepc: %08x\n", regs[28], regs[29],
         regs[30], data->mepc);
}

static void print_panic_info(
    const struct ec_response_persistent_panic_info* panic) {
  const struct panic_data* data = (struct panic_data*)panic->panic_record;

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

int dump_panic_record_to_file(
    const char* filename,
    const struct ec_response_persistent_panic_info* panic) {
  FILE* file = fopen(filename, "wb");
  if (!file) {
    perror("Failed to open file");
    return -1;
  }

  int rv = 0;

  if (fwrite(panic, sizeof(*panic), 1, file) != 1 || ferror(file)) {
    perror("Failed to write panic data to file");
    rv = -1;
  }

  fclose(file);
  return rv;
}

int htool_panic_get_panic(const struct htool_invocation* inv) {
  bool clear;
  bool hexdump;
  const char* output_file = NULL;

  if (htool_get_param_bool(inv, "clear", &clear) ||
      htool_get_param_bool(inv, "hexdump", &hexdump) ||
      htool_get_param_string(inv, "file", &output_file)) {
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

  struct ec_response_persistent_panic_info panic;
  memset(&panic, 0, sizeof(panic));

  if (get_persistent_panic_info(dev, &panic)) {
    return -1;
  }

  if (output_file && output_file[0]) {
    return dump_panic_record_to_file(output_file, &panic);
  } else if (hexdump) {
    print_hex_dump_buffer(sizeof(panic.panic_record), &panic.panic_record, 0);
  } else {
    print_panic_info(&panic);
  }

  char* console_log = get_panic_console_log(&panic);

  if (console_log) {
    printf("Saved console log:\n");
    printf("%s\n", console_log);
    free(console_log);
  }

  return 0;
}
