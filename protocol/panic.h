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

#ifndef LIBHOTH_PROTOCOL_PANIC_H_
#define LIBHOTH_PROTOCOL_PANIC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

#include "transports/libhoth_device.h"

#define HOTH_PRV_CMD_HOTH_PERSISTENT_PANIC_INFO 0x0014
#define HOTH_PERSISTENT_PANIC_INFO_CHUNK_SIZE 512
enum persistent_panic_op {
  PERSISTENT_PANIC_INFO_GET = 0,
  PERSISTENT_PANIC_INFO_ERASE = 1,
};

struct hoth_request_persistent_panic_info {
  /* The operation is one of persistent_panic_op. */
  uint32_t operation;
  /* When the operation is PERSISTENT_PANIC_INFO_GET, the index
   * is which 512-byte chunk of the response to retrieve.
   */
  uint32_t index;
} __attribute__((packed));

struct persistent_panic_rw_version {
  uint32_t epoch;
  uint32_t major;
  uint32_t minor;
} __attribute__((packed));

struct hoth_response_persistent_panic_info {
  uint8_t panic_record[144];

  /* The uart_head is the next location in the buffer that console output
   * would write to.
   */
  uint32_t uart_head;
  /* The uart_tail is the next location the uart dma transmitter
   * would had read from (had the firmware not crashed).
   */
  uint32_t uart_tail;
  /* The uart_buf contains the last 4096 characters written to the uart
   * output. The oldest character written is pointed to by head and the
   * newest character written is pointed to by head-1.
   */
  char uart_buf[4096];
  /* The reserved field pads this structure out to 6KiB. 6KiB is chosen
   * because the erase granularity of the internal flash storage is 2KiB
   */
  uint8_t reserved0[1880];
  /* The rw_version of the firmware which created this record */
  struct persistent_panic_rw_version rw_version;
  /* The version number of the persistent panic record struct.
   * -1: Doesn't include rw_version field.
   * 0: Includes rw_version field.
   */
  int32_t persistent_panic_record_version;
} __attribute__((packed));

/* ARM Cortex-Mx registers saved on panic */
struct cortex_panic_data {
  uint32_t regs[12]; /* psp, ipsr, msp, r4-r11, lr */
  uint32_t frame[8]; /* r0-r3, r12, lr, pc, xPSR */

  uint32_t mmfs;
  uint32_t bfar;
  uint32_t mfar;
  uint32_t shcsr;
  uint32_t hfsr;
  uint32_t dfsr;
};

/* RISC-V RV32I registers saved on panic */
struct rv32i_panic_data {
  uint32_t regs[31]; /* s11-s0, t6-t0, a7-a0, tp, gp, ra, sp */
  uint32_t mepc;     /* mepc */
  uint32_t mcause;   /* mcause */
};

/* Data saved across reboots */
struct panic_data {
  uint8_t arch;           /* Architecture (PANIC_ARCH_*) */
  uint8_t struct_version; /* Structure version (currently 2) */
  uint8_t flags;          /* Flags (PANIC_DATA_FLAG_*) */
  uint8_t reserved;       /* Reserved; set 0 */

  /* core specific panic data */
  union {
    struct cortex_panic_data cm;   /* Cortex-Mx registers */
    struct rv32i_panic_data riscv; /* RISC-V RV32I */
  };

  /*
   * These fields go at the END of the struct so we can find it at the
   * end of memory.
   */
  uint32_t struct_size; /* Size of this struct */
  uint32_t magic;       /* PANIC_SAVE_MAGIC if valid */
};

#define PANIC_DATA_MAGIC 0x21636e50 /* "Pnc!" */
enum panic_arch {
  PANIC_ARCH_CORTEX_M = 1,    /* Cortex-M architecture */
  PANIC_ARCH_RISCV_RV32I = 4, /* RISC-V RV32I */
};

/* Flags for panic_data.flags */
/* panic_data.frame is valid */
#define PANIC_DATA_FLAG_FRAME_VALID (1 << 0)
/* Already printed at console */
#define PANIC_DATA_FLAG_OLD_CONSOLE (1 << 1)
/* Already returned via host command */
#define PANIC_DATA_FLAG_OLD_HOSTCMD (1 << 2)
/* Already reported via host event */
#define PANIC_DATA_FLAG_OLD_HOSTEVENT (1 << 3)

int libhoth_get_panic(struct libhoth_device* dev,
                      struct hoth_response_persistent_panic_info* panic_data);
int libhoth_clear_persistent_panic_info(struct libhoth_device* dev);
void libhoth_print_panic_info(
    const struct hoth_response_persistent_panic_info* panic);

/* Internally mallocs, caller must free */
char* libhoth_get_panic_console_log(
    const struct hoth_response_persistent_panic_info* pdata);

#ifdef __cplusplus
}
#endif

#endif
