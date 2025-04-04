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

#ifndef LIBHOTH_PROTOCOL_JTAG_H_
#define LIBHOTH_PROTOCOL_JTAG_H_

#include <stdint.h>

#include "transports/libhoth_device.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Request RoT to perform operations as a JTAG controller. Assumes only a single
 * device in JTAG chain.
 */
#define HOTH_PRV_CMD_HOTH_JTAG_OPERATION (0x0048)

enum hoth_jtag_operation {
  HOTH_JTAG_OP_UNDEFINED = 0,
  // Read IDCODE from a JTAG device connected to RoT
  HOTH_JTAG_OP_READ_IDCODE = 1,
  // Send and receive data after putting JTAG device connected to RoT in BYPASS
  // mode
  HOTH_JTAG_OP_TEST_BYPASS = 2,
  // Program a PLD connected to RoT using JTAG and verify that the programming
  // worked
  HOTH_JTAG_OP_PROGRAM_AND_VERIFY_PLD = 3,
  // Verify PLD connected to RoT using JTAG
  HOTH_JTAG_OP_VERIFY_PLD = 4,
};

struct hoth_request_jtag_operation {
  // Integer divisor for JTAG clock. Clock frequency used is ~
  // `(48/(clk_idiv+1))` MHz.
  // This can be used to limit the max JTAG peripheral clock frequency - higher
  // `clk_idiv` => lower the clock frequency.
  uint16_t clk_idiv;
  uint8_t operation;  // `enum hoth_jtag_operation`
  uint8_t reserved0;  // pad to 4-byte boundary
  // Request data (if present) follows. See `struct
  // hoth_request_jtag_<op>_operation`
} __attribute__((packed, aligned(4)));

#define HOTH_JTAG_TEST_BYPASS_PATTERN_LEN (64)
struct hoth_request_jtag_test_bypass_operation {
  // Test pattern to send over TDI with `HOTH_JTAG_OP_TEST_BYPASS`
  uint8_t tdi_pattern[HOTH_JTAG_TEST_BYPASS_PATTERN_LEN];
};

struct hoth_request_jtag_program_and_verify_pld_operation {
  // Offset in external flash where data to program and verify PLD is stored
  uint32_t data_offset;
} __attribute__((packed, aligned(4)));

struct hoth_request_jtag_verify_pld_operation {
  // Offset in external flash where data to verify PLD is stored
  uint32_t data_offset;
} __attribute__((packed, aligned(4)));

// Separate response structures for each operation. Naming convention: `struct
// hoth_response_jtag_<op>_operation`

struct hoth_response_jtag_read_idcode_operation {
  uint32_t idcode;
} __attribute__((packed, aligned(4)));

struct hoth_response_jtag_test_bypass_operation {
  // Pattern captured over TDO with `HOTH_JTAG_OP_TEST_BYPASS`
  uint8_t tdo_pattern[HOTH_JTAG_TEST_BYPASS_PATTERN_LEN];
} __attribute__((packed, aligned(4)));

int libhoth_jtag_read_idcode(struct libhoth_device* dev, uint16_t clk_idiv,
                             uint32_t* idcode);


int libhoth_jtag_test_bypass(
    struct libhoth_device* dev,
    uint16_t clk_idiv,
    const uint8_t tdi_bytes[HOTH_JTAG_TEST_BYPASS_PATTERN_LEN],
    uint8_t tdo_bytes[HOTH_JTAG_TEST_BYPASS_PATTERN_LEN]);

int libhoth_jtag_program_and_verify_pld(struct libhoth_device* dev, uint32_t offset);

int libhoth_jtag_verify_pld(struct libhoth_device* dev, uint32_t offset);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_PROTOCOL_JTAG_H_
