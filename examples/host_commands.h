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

#ifndef __packed
#define __packed __attribute__((packed))
#endif
#ifndef __aligned
#define __aligned(x) __attribute__((aligned(x)))
#endif

#define __ec_align1 __packed
#define __ec_align2 __packed __aligned(2)
#define __ec_align4 __packed __aligned(4)

enum ec_status {
  EC_RES_SUCCESS = 0,
  EC_RES_INVALID_COMMAND = 1,
  EC_RES_ERROR = 2,
  EC_RES_INVALID_PARAM = 3,
  EC_RES_ACCESS_DENIED = 4,
  EC_RES_INVALID_RESPONSE = 5,
  EC_RES_INVALID_VERSION = 6,
  EC_RES_INVALID_CHECKSUM = 7,
  EC_RES_IN_PROGRESS = 8,
  EC_RES_UNAVAILABLE = 9,
  EC_RES_TIMEOUT = 10,
  EC_RES_OVERFLOW = 11,
  EC_RES_INVALID_HEADER = 12,
  EC_RES_REQUEST_TRUNCATED = 13,
  EC_RES_RESPONSE_TOO_BIG = 14,
  EC_RES_BUS_ERROR = 15,
  EC_RES_BUSY = 16,
  EC_RES_INVALID_HEADER_VERSION = 17,
  EC_RES_INVALID_HEADER_CRC = 18,
  EC_RES_INVALID_DATA_CRC = 19,
  EC_RES_DUP_UNAVAILABLE = 20,
  EC_RES_MAX = UINT16_MAX
} __packed;

#define EC_HOST_REQUEST_VERSION 3

struct ec_host_request {
  // Should be EC_HOST_REQUEST_VERSION
  uint8_t struct_version;
  // Checksum of request and data; sum of all bytes including checksum should
  // total to 0.
  uint8_t checksum;
  // Command to send (EC_CMD_...)
  uint16_t command;
  // Command version
  uint8_t command_version;
  uint8_t reserved;
  // Length of data that follows this header
  uint16_t data_len;
} __ec_align4;

#define EC_HOST_RESPONSE_VERSION 3

struct ec_host_response {
  // Should be EC_HOST_RESPONSE_VERSION
  uint8_t struct_version;
  // Checksum of request and data; sum of all bytes including checksum should
  // total to 0.
  uint8_t checksum;
  // One of the EC_RES_* status codes
  uint16_t result;
  // Length of data which follows this header.
  uint16_t data_len;
  uint16_t reserved;
} __ec_align4;

#define EC_CMD_GET_VERSION 0x0002

enum ec_image {
  EC_IMAGE_UNKNOWN = 0,
  EC_IMAGE_RO,
  EC_IMAGE_RW,
  EC_IMAGE_RW_A = EC_IMAGE_RW,
  EC_IMAGE_RO_B,
  EC_IMAGE_RW_B
};

struct ec_response_get_version {
  // Null-terminated RO version string
  char version_string_ro[32];

  // Null-terminated RW version string
  char version_string_rw[32];

  char reserved[32];

  // One of ec_image
  uint32_t current_image;
} __ec_align4;

#define EC_CMD_HELLO 0x0001

struct ec_params_hello {
  // Pass anything here
  uint32_t in_data;
} __ec_align4;

struct ec_response_hello {
  // Output will be in_data + 0x01020304.
  uint32_t out_data;
} __ec_align4;

#define EC_CMD_REBOOT_EC 0x00D2

enum ec_reboot_cmd {
  EC_REBOOT_COLD = 4,
};

struct ec_params_reboot_ec {
  // enum ec_reboot_cmd
  uint8_t cmd;
  // Should be 0
  uint8_t flags;
} __ec_align1;

#define EC_CMD_BOARD_SPECIFIC_BASE 0x3E00
#define EC_CMD_BOARD_SPECIFIC_LAST 0x3FFF

// NOTE: All further commands in this file are offset by
// EC_CMD_BOARD_SPECIFIC_BASE.

#define EC_PRV_CMD_HOTH_CHIP_INFO 0x0010
struct ec_response_chip_info {
  uint64_t hardware_identity;
  uint16_t hardware_category;
  uint16_t reserved0;
  uint32_t info_variant;
} __attribute__((packed, aligned(4)));

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

struct ec_spi_operation_request {
  // The number of MOSI bytes we're sending
  uint16_t mosi_len;
  // The number of MISO bytes we want to receive
  uint16_t miso_len;

  // Note: The total size of the SPI transaction on the wire is
  // MAX(mosi_len, miso_len).
} __attribute__((packed));

// A EC_PRV_CMD_HOTH_SPI_OPERATION request consists of one or more SPI
// transactions. Each SPI transaction consists of a ec_spi_operation_request
// header followed by the MOSI bytes (starting with the opcode), and each
// transaction is laid-out back-to-back with no padding or alignment.
//
// The response consists of the first ec_spi_operation_request::miso_len
// MISO bytes of each SPI transaction, including the dummy MISO bytes sent while
// the opcode/addr/dummy MOSI bytes are being transmitted. All the MISO bytes
// are laid-out back-to-back with no header, padding, or alignment.
#define EC_PRV_CMD_HOTH_SPI_OPERATION 0x0020

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

#define MAILBOX_SIZE 1024

#endif  // LIBHOTH_EXAMPLES_HOST_COMMANDS_H_
