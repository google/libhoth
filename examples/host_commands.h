// Copyright 2022 Google LLC
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

#ifndef LIBHOTH_EXAMPLES_HOST_COMMANDS_H_
#define LIBHOTH_EXAMPLES_HOST_COMMANDS_H_

#include <stdint.h>

#include "protocol/host_cmd.h"

#ifdef __cplusplus
extern "C" {
#endif

enum ec_image {
  EC_IMAGE_UNKNOWN = 0,
  EC_IMAGE_RO,
  EC_IMAGE_RW,
  EC_IMAGE_RW_A = EC_IMAGE_RW,
  EC_IMAGE_RO_B,
  EC_IMAGE_RW_B
};

#define EC_CMD_HELLO 0x0001

struct ec_params_hello {
  // Pass anything here
  uint32_t in_data;
} __ec_align4;

struct ec_response_hello {
  // Output will be in_data + 0x01020304.
  uint32_t out_data;
} __ec_align4;

#define EC_CMD_FLASH_SPI_INFO 0x0018

struct ec_response_flash_spi_info {
  /* JEDEC info from command 0x9F (manufacturer, memory type, size) */
  uint8_t jedec[3];

  /* Pad byte; currently always contains 0 */
  uint8_t reserved0;

  /* Manufacturer / device ID from command 0x90 */
  uint8_t mfr_dev_id[2];

  /* Status registers from command 0x05 and 0x35 */
  uint8_t sr1, sr2;
} __ec_align1;

/* Options and request struct for EC_PRV_CMD_HOTH_RESET_TARGET */
enum ec_target_reset_option {
  EC_TARGET_RESET_OPTION_RELEASE = 0,  // Release target from reset
  EC_TARGET_RESET_OPTION_SET = 1,      // Put target in reset
  EC_TARGET_RESET_OPTION_PULSE = 2,    // Put target in reset then release
};

#define RESET_TARGET_ID_RSTCTRL0 0
struct ec_request_reset_target {
  uint32_t target_id;
  uint8_t reset_option;  // "reset_option" must be one of ec_target_reset_option
                         // Side-by-Side (Hammurabi and Chopper) only support
                         // RESET_PULSE. For backward compatibility, if
                         // EC_PRV_CMD_HOTH_RESET_TARGET is sent without a
                         // request param, it defaults to RESET_PULSE. Viperlite
                         // and Diorite only support RESET_SET and RESET_RELEASE
  uint8_t reserved[12];
} __attribute__((packed));

/* Reset the target device. */
#define EC_PRV_CMD_HOTH_RESET_TARGET 0x0012

// Arm the coordinated reset trigger, which will cause the hoth to perform a
// hard reset when it receives the hardware trigger event.
#define EC_PRV_CMD_HOTH_ARM_COORDINATED_RESET 0x001A

#define EC_PRV_CMD_HOTH_CHANNEL_READ 0x0036
struct ec_channel_read_request {
  uint32_t channel_id;

  // The 32-bit offset from the start of the stream to retrieve data from. If no
  // data is available at this offset, it will be incremented to the first
  // available data. The caller can detect discontinuities by observing the
  // returned offset.
  //
  // This value will wrap around once the channel has delivered 4GiB of data.
  uint32_t offset;
  // the amount of data to return
  uint32_t size;
  // Maximum time to wait for new data to show up. If timeout is hit, command
  // will succeed but will return 0 bytes.
  uint32_t timeout_us;
} __attribute__((packed, aligned(4)));

struct ec_channel_read_response {
  // The actual offset where the returned data was found.
  // This won't match the offset in the read request if the requested data
  // wasn't available. Instead, it will be the offset of the first available
  // data.
  uint32_t offset;

  // followed by the requested bytes.
} __attribute__((packed, aligned(4)));

#define EC_PRV_CMD_HOTH_CHANNEL_STATUS 0x0037
struct ec_channel_status_request {
  uint32_t channel_id;
} __attribute__((packed, aligned(4)));

struct ec_channel_status_response {
  // The offset where the next data received in the channel will be written
  uint32_t write_offset;
} __attribute__((packed, aligned(4)));

#define EC_PRV_CMD_HOTH_CHANNEL_WRITE 0x0038

struct ec_channel_write_request_v0 {
  uint32_t channel_id;

  // followed by the bytes to write
} __attribute__((packed, aligned(4)));

#define EC_CHANNEL_WRITE_REQUEST_FLAG_FORCE_DRIVE_TX (1 << 0)
#define EC_CHANNEL_WRITE_REQUEST_FLAG_SEND_BREAK (1 << 1)

struct ec_channel_write_request_v1 {
  uint32_t channel_id;

  // One of EC_CHANNEL_WRITE_REQUEST_FLAG_*
  uint32_t flags;

  // followed by the bytes to write
} __attribute__((packed, aligned(4)));

// Takes struct ec_channel_uart_config_get_req as
// input and returns ec_channel_uart_config as output.
#define EC_PRV_CMD_HOTH_CHANNEL_UART_CONFIG_GET 0x0039

struct ec_channel_uart_config_get_req {
  uint32_t channel_id;
} __attribute__((packed, aligned(4)));

struct ec_channel_uart_config {
  uint32_t baud_rate;
  // must be 0
  uint32_t reserved;
} __attribute__((packed, aligned(4)));

// Takes struct ec_channel_uart_config_set_req as input.
#define EC_PRV_CMD_HOTH_CHANNEL_UART_CONFIG_SET 0x003a

struct ec_channel_uart_config_set_req {
  uint32_t channel_id;
  struct ec_channel_uart_config config;
} __attribute__((packed, aligned(4)));

#define EC_CMD_CONSOLE_REQUEST 0x0097
#define EC_CMD_CONSOLE_READ 0x0098

enum ec_console_read_subcmd {
  CONSOLE_READ_NEXT = 0,
  CONSOLE_READ_RECENT = 1,
};

struct ec_params_console_read_v1 {
  uint8_t subcmd;
} __ec_align1;

// After sending this command, any future synchronous SPI reads from the RoT's
// SPI-slave interface will return all zeroes, but out-of-band methods (such as
// EC_SPI_OPERATION via USB) will be able to interact with the SPI flash.
#define EC_PRV_CMD_HOTH_SPS_PASSTHROUGH_DISABLE 0x003b

// Re-enables SPS passthrough. Future out-of-band access to the SPI flash will
// fail.
#define EC_PRV_CMD_HOTH_SPS_PASSTHROUGH_ENABLE 0x003c

#define EC_PRV_CMD_HOTH_AUTHZ_COMMAND 0x0034

#define AUTHORIZED_COMMAND_SIGNATURE_SIZE 64
#define AUTHORIZED_COMMAND_NONCE_SIZE 32
#define AUTHORIZED_COMMAND_VERSION 1

#define EC_PRV_CMD_HOTH_GET_AUTHZ_COMMAND_NONCE 0x0035

struct ec_authorized_command_get_nonce_response {
  uint32_t nonce[AUTHORIZED_COMMAND_NONCE_SIZE / sizeof(uint32_t)];
  uint32_t supported_key_info;
} __attribute__((packed, aligned(4)));

struct ec_authorized_command_request {
  uint8_t signature[AUTHORIZED_COMMAND_SIGNATURE_SIZE];
  uint32_t version;
  uint32_t size;
  uint32_t key_info;
  uint32_t dev_id_0;
  uint32_t dev_id_1;
  uint32_t nonce[AUTHORIZED_COMMAND_NONCE_SIZE / sizeof(uint32_t)];
  uint32_t opcode;
  uint32_t arg_bytes[];
} __attribute__((packed, aligned(4)));

#define MAILBOX_SIZE 1024

// This command allows callers to push initial measurements into PCR0. This
// command will fail if the TPM has already been started up, or if the
// data to measure exceeds SRTM_DATA_MAX_SIZE_BYTES.
#define EC_PRV_CMD_HOTH_SRTM 0x0044
#define SRTM_DATA_MAX_SIZE_BYTES 64

struct ec_srtm_request {
  uint16_t data_size;
  uint8_t data[SRTM_DATA_MAX_SIZE_BYTES];
} __attribute__((packed, aligned(4)));

/* Control miscellaneous boolean functions on target */
#define EC_PRV_CMD_HOTH_TARGET_CONTROL 0x0047

/* Options and request struct for EC_PRV_CMD_HOTH_TARGET_CONTROL */
enum ec_target_control_action {
  // Returns the current enabled/disabled status of the given function.
  EC_TARGET_CONTROL_ACTION_GET_STATUS = 0,

  // Changes the status of the given function to "Disabled". Returns the
  // previous enabled/disabled status of the given function.
  EC_TARGET_CONTROL_ACTION_DISABLE = 1,

  // Changes the status of the given function to "Enabled". Returns the previous
  // enabled/disabled status of the given function.
  EC_TARGET_CONTROL_ACTION_ENABLE = 2,
};

enum ec_target_control_function {
  EC_TARGET_CONTROL_RESERVED0 = 0,
  EC_TARGET_CONTROL_RESERVED1 = 1,
  // Allow control over GPIO for I2C Mux select (if present)
  EC_TARGET_CONTROL_I2C_MUX = 2,
  // Allow control over GPIO for Generic Mux select (if present)
  EC_TARGET_CONTROL_GENERIC_MUX = 3,
  // Allow checking whether external USB host is connected to system in which
  // RoT is present
  EC_TARGET_DETECT_EXTERNAL_USB_HOST_PRESENCE = 4,
  EC_TARGET_CONTROL_FUNCTION_MAX,
};

enum ec_target_control_status {
  EC_TARGET_CONTROL_STATUS_UNKNOWN = 0,
  EC_TARGET_CONTROL_STATUS_DISABLED = 1,
  EC_TARGET_CONTROL_STATUS_ENABLED = 2,

  // Recommended to be used for `EC_TARGET_DETECT_EXTERNAL_USB_HOST_PRESENCE`
  EC_TARGET_EXTERNAL_USB_HOST_NOT_PRESENT = EC_TARGET_CONTROL_STATUS_DISABLED,
  EC_TARGET_EXTERNAL_USB_HOST_PRESENT = EC_TARGET_CONTROL_STATUS_ENABLED,
};

struct ec_request_target_control {
  uint16_t function;  // must be ec_target_control_function
  uint16_t action;    // must be ec_target_control_action
  uint8_t args[];     // function+action specific args. Unused right now
} __attribute__((packed, aligned(4)));

struct ec_response_target_control {
  // If the action changes the target control status, returns the status prior
  // to the change requested by the host command.
  //
  // Must be ec_target_control_status
  uint16_t status;
} __attribute__((packed, aligned(4)));

#define EC_PRV_CMD_HOTH_JTAG_OPERATION (0x0048)
// Amount of bytes to send and receive for testing JTAG device in BYPASS mode
#define EC_JTAG_TEST_BYPASS_PATTERN_LEN (64)

enum ec_jtag_operation {
  EC_JTAG_OP_UNDEFINED = 0,
  EC_JTAG_OP_READ_IDCODE = 1,
  EC_JTAG_OP_TEST_BYPASS = 2,
  EC_JTAG_OP_PROGRAM_AND_VERIFY_PLD = 3,
  EC_JTAG_OP_VERIFY_PLD = 4,
};

struct ec_request_jtag_operation {
  // Integer divisor for JTAG clock. Clock frequency used is ~
  // `(48/(clk_idiv+1))` MHz.
  // This can be used to limit the max JTAG peripheral clock frequency - higher
  // `clk_idiv` => lower the clock frequency.
  uint16_t clk_idiv;
  uint8_t operation;  // `enum ec_jtag_operation`
  uint8_t reserved0;  // pad to 4-byte boundary
  // Request data (if present) follows. See `struct
  // ec_request_jtag_<op>_operation`
} __attribute__((packed, aligned(4)));

struct ec_request_jtag_test_bypass_operation {
  // Test pattern to send over TDI with `EC_JTAG_OP_TEST_BYPASS`
  uint8_t tdi_pattern[EC_JTAG_TEST_BYPASS_PATTERN_LEN];
};

struct ec_request_jtag_program_and_verify_pld_operation {
  // Offset in external flash where data to program and verify PLD is stored
  uint32_t data_offset;
} __attribute__((packed, aligned(4)));

struct ec_request_jtag_verify_pld_operation {
  // Offset in external flash where data to verify PLD is stored
  uint32_t data_offset;
} __attribute__((packed, aligned(4)));

// Separate response structures for each operation. Naming convention: `struct
// ec_response_jtag_<op>_operation`

struct ec_response_jtag_read_idcode_operation {
  uint32_t idcode;
} __attribute__((packed, aligned(4)));

struct ec_response_jtag_test_bypass_operation {
  // Pattern captured over TDO with `EC_JTAG_OP_TEST_BYPASS`
  uint8_t tdo_pattern[EC_JTAG_TEST_BYPASS_PATTERN_LEN];
} __attribute__((packed, aligned(4)));

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_HOST_COMMANDS_H_
