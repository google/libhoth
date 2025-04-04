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

enum hoth_image {
  HOTH_IMAGE_UNKNOWN = 0,
  HOTH_IMAGE_RO,
  HOTH_IMAGE_RW,
  HOTH_IMAGE_RW_A = HOTH_IMAGE_RW,
  HOTH_IMAGE_RO_B,
  HOTH_IMAGE_RW_B
};

#define HOTH_CMD_HELLO 0x0001

struct hoth_params_hello {
  // Pass anything here
  uint32_t in_data;
} __hoth_align4;

struct hoth_response_hello {
  // Output will be in_data + 0x01020304.
  uint32_t out_data;
} __hoth_align4;

#define HOTH_CMD_FLASH_SPI_INFO 0x0018

struct hoth_response_flash_spi_info {
  /* JEDEC info from command 0x9F (manufacturer, memory type, size) */
  uint8_t jedec[3];

  /* Pad byte; currently always contains 0 */
  uint8_t reserved0;

  /* Manufacturer / device ID from command 0x90 */
  uint8_t mfr_dev_id[2];

  /* Status registers from command 0x05 and 0x35 */
  uint8_t sr1, sr2;
} __hoth_align1;

/* Options and request struct for HOTH_PRV_CMD_HOTH_RESET_TARGET */
enum hoth_target_reset_option {
  HOTH_TARGET_RESET_OPTION_RELEASE = 0,  // Release target from reset
  HOTH_TARGET_RESET_OPTION_SET = 1,      // Put target in reset
  HOTH_TARGET_RESET_OPTION_PULSE = 2,    // Put target in reset then release
};

#define RESET_TARGET_ID_RSTCTRL0 0
struct hoth_request_reset_target {
  uint32_t target_id;
  uint8_t reset_option;  // "reset_option" must be one of hoth_target_reset_option
                         // Side-by-Side (Hammurabi and Chopper) only support
                         // RESET_PULSE. For backward compatibility, if
                         // HOTH_PRV_CMD_HOTH_RESET_TARGET is sent without a
                         // request param, it defaults to RESET_PULSE. Viperlite
                         // and Diorite only support RESET_SET and RESET_RELEASE
  uint8_t reserved[12];
} __attribute__((packed));

/* Reset the target device. */
#define HOTH_PRV_CMD_HOTH_RESET_TARGET 0x0012

// Arm the coordinated reset trigger, which will cause the hoth to perform a
// hard reset when it receives the hardware trigger event.
#define HOTH_PRV_CMD_HOTH_ARM_COORDINATED_RESET 0x001A

#define HOTH_PRV_CMD_HOTH_CHANNEL_READ 0x0036
struct hoth_channel_read_request {
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

struct hoth_channel_read_response {
  // The actual offset where the returned data was found.
  // This won't match the offset in the read request if the requested data
  // wasn't available. Instead, it will be the offset of the first available
  // data.
  uint32_t offset;

  // followed by the requested bytes.
} __attribute__((packed, aligned(4)));

#define HOTH_PRV_CMD_HOTH_CHANNEL_STATUS 0x0037
struct hoth_channel_status_request {
  uint32_t channel_id;
} __attribute__((packed, aligned(4)));

struct hoth_channel_status_response {
  // The offset where the next data received in the channel will be written
  uint32_t write_offset;
} __attribute__((packed, aligned(4)));

#define HOTH_PRV_CMD_HOTH_CHANNEL_WRITE 0x0038

struct hoth_channel_write_request_v0 {
  uint32_t channel_id;

  // followed by the bytes to write
} __attribute__((packed, aligned(4)));

#define HOTH_CHANNEL_WRITE_REQUEST_FLAG_FORCE_DRIVE_TX (1 << 0)
#define HOTH_CHANNEL_WRITE_REQUEST_FLAG_SEND_BREAK (1 << 1)

struct hoth_channel_write_request_v1 {
  uint32_t channel_id;

  // One of HOTH_CHANNEL_WRITE_REQUEST_FLAG_*
  uint32_t flags;

  // followed by the bytes to write
} __attribute__((packed, aligned(4)));

// Takes struct hoth_channel_uart_config_get_req as
// input and returns hoth_channel_uart_config as output.
#define HOTH_PRV_CMD_HOTH_CHANNEL_UART_CONFIG_GET 0x0039

struct hoth_channel_uart_config_get_req {
  uint32_t channel_id;
} __attribute__((packed, aligned(4)));

struct hoth_channel_uart_config {
  uint32_t baud_rate;
  // must be 0
  uint32_t reserved;
} __attribute__((packed, aligned(4)));

// Takes struct hoth_channel_uart_config_set_req as input.
#define HOTH_PRV_CMD_HOTH_CHANNEL_UART_CONFIG_SET 0x003a

struct hoth_channel_uart_config_set_req {
  uint32_t channel_id;
  struct hoth_channel_uart_config config;
} __attribute__((packed, aligned(4)));

#define HOTH_CMD_CONSOLE_REQUEST 0x0097
#define HOTH_CMD_CONSOLE_READ 0x0098

enum hoth_console_read_subcmd {
  CONSOLE_READ_NEXT = 0,
  CONSOLE_READ_RECENT = 1,
};

struct hoth_params_console_read_v1 {
  uint8_t subcmd;
} __hoth_align1;

// After sending this command, any future synchronous SPI reads from the RoT's
// SPI-slave interface will return all zeroes, but out-of-band methods (such as
// HOTH_SPI_OPERATION via USB) will be able to interact with the SPI flash.
#define HOTH_PRV_CMD_HOTH_SPS_PASSTHROUGH_DISABLE 0x003b

// Re-enables SPS passthrough. Future out-of-band access to the SPI flash will
// fail.
#define HOTH_PRV_CMD_HOTH_SPS_PASSTHROUGH_ENABLE 0x003c

#define HOTH_PRV_CMD_HOTH_AUTHZ_COMMAND 0x0034

#define AUTHORIZED_COMMAND_SIGNATURE_SIZE 64
#define AUTHORIZED_COMMAND_NONCE_SIZE 32
#define AUTHORIZED_COMMAND_VERSION 1

#define HOTH_PRV_CMD_HOTH_GET_AUTHZ_COMMAND_NONCE 0x0035

struct hoth_authorized_command_get_nonce_response {
  uint32_t nonce[AUTHORIZED_COMMAND_NONCE_SIZE / sizeof(uint32_t)];
  uint32_t supported_key_info;
} __attribute__((packed, aligned(4)));

struct hoth_authorized_command_request {
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
#define HOTH_PRV_CMD_HOTH_SRTM 0x0044
#define SRTM_DATA_MAX_SIZE_BYTES 64

struct hoth_srtm_request {
  uint16_t data_size;
  uint8_t data[SRTM_DATA_MAX_SIZE_BYTES];
} __attribute__((packed, aligned(4)));

/* Control miscellaneous boolean functions on target */
#define HOTH_PRV_CMD_HOTH_TARGET_CONTROL 0x0047

/* Options and request struct for HOTH_PRV_CMD_HOTH_TARGET_CONTROL */
enum hoth_target_control_action {
  // Returns the current enabled/disabled status of the given function.
  HOTH_TARGET_CONTROL_ACTION_GET_STATUS = 0,

  // Changes the status of the given function to "Disabled". Returns the
  // previous enabled/disabled status of the given function.
  HOTH_TARGET_CONTROL_ACTION_DISABLE = 1,

  // Changes the status of the given function to "Enabled". Returns the previous
  // enabled/disabled status of the given function.
  HOTH_TARGET_CONTROL_ACTION_ENABLE = 2,
};

enum hoth_target_control_function {
  HOTH_TARGET_CONTROL_RESERVED0 = 0,
  HOTH_TARGET_CONTROL_RESERVED1 = 1,
  // Allow control over GPIO for I2C Mux select (if present)
  HOTH_TARGET_CONTROL_I2C_MUX = 2,
  // Allow control over GPIO for Generic Mux select (if present)
  HOTH_TARGET_CONTROL_GENERIC_MUX = 3,
  // Allow checking whether external USB host is connected to system in which
  // RoT is present
  HOTH_TARGET_DETECT_EXTERNAL_USB_HOST_PRESENCE = 4,
  HOTH_TARGET_CONTROL_FUNCTION_MAX,
};

enum hoth_target_control_status {
  HOTH_TARGET_CONTROL_STATUS_UNKNOWN = 0,
  HOTH_TARGET_CONTROL_STATUS_DISABLED = 1,
  HOTH_TARGET_CONTROL_STATUS_ENABLED = 2,

  // Recommended to be used for `HOTH_TARGET_DETECT_EXTERNAL_USB_HOST_PRESENCE`
  HOTH_TARGET_EXTERNAL_USB_HOST_NOT_PRESENT =
      HOTH_TARGET_CONTROL_STATUS_DISABLED,
  HOTH_TARGET_EXTERNAL_USB_HOST_PRESENT = HOTH_TARGET_CONTROL_STATUS_ENABLED,
};

struct hoth_request_target_control {
  uint16_t function;  // must be hoth_target_control_function
  uint16_t action;    // must be hoth_target_control_action
  uint8_t args[];     // function+action specific args. Unused right now
} __attribute__((packed, aligned(4)));

struct hoth_response_target_control {
  // If the action changes the target control status, returns the status prior
  // to the change requested by the host command.
  //
  // Must be hoth_target_control_status
  uint16_t status;
} __attribute__((packed, aligned(4)));

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_HOST_COMMANDS_H_
