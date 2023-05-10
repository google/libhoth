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

#ifndef LIBHOTH_EXAMPLES_HTOOL_PANIC_H_
#define LIBHOTH_EXAMPLES_HTOOL_PANIC_H_

#include <stdint.h>

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

struct htool_invocation;
int htool_panic_get_panic(const struct htool_invocation* inv);

#endif
