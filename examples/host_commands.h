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

#include "authorization_record.h"

#ifdef __cplusplus
extern "C" {
#endif

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

#define EC_CMD_BOARD_SPECIFIC_BASE 0x3E00
#define EC_CMD_BOARD_SPECIFIC_LAST 0x3FFF

// NOTE: All further commands in this file are offset by
// EC_CMD_BOARD_SPECIFIC_BASE.

struct boot_timing_data {
  uint32_t start_us;
  uint32_t end_us;
};

/* Get various statistics */
#define EC_PRV_CMD_HOTH_GET_STATISTICS 0x000F
struct ec_response_statistics {
  /*
   * Number of 32 bit words returned from this command.
   * That's not including the reserved fields.
   *  Offset: 0
   */
  uint32_t valid_words;

  /*
   * The set of flags which describe the most recent reset.  See
   * include/system.h RESET_FLAG_* for details.
   *  Offset: 1 (32 bit words)
   */
  uint32_t hoth_reset_flags;

  /*
   * Number of microseconds since the last hoth boot.
   *  Offset: 2
   */
  uint64_t time_since_hoth_boot_us;

  /*
   * The current temperature of the hoth chip. This is just the value
   * in the SUM8 register, no conversion to celsius or fahrenheit is applied.
   * The value returned is a 9.3 bit fixed point binary number. Anything
   * greater than the max value of a 9.3 bit fixed point binary number is
   * considered invalid. Default invalid return value is 0xFFFFFFFF.
   *  Offset: 4
   */
  uint32_t hoth_temperature;

  /*
   * The current INFO strike count in the RO region.
   * Offset: 5
   */
  uint32_t ro_info_strikes;

  /*
   * The current INFO strike count in the RW region.
   * Offset: 6
   */
  uint32_t rw_info_strikes;

  /*
   * For testing, a scratch value to say something
   * Debug only, should be zero in release builds
   * Offset: 7
   */
  uint32_t scratch_value;

  /*
   * Reason code for last payload update failure.
   */
  uint16_t payload_update_failure_reason;

  /*
   * Reason for last firmware update failure.
   */
  uint16_t firmware_update_failure_reason;

  /*
   * Minor version of the last firmware update that failed.
   */
  uint32_t failed_firmware_minor_version;

  /*
   * Time in microseconds of various things we want to measure during
   * bootup.  All times are in microseconds.
   * total - Time from reset to boot up
   * update - Time spent in the self update routine.  Since a proper self update
   *          involves a reset, this time is always expected to be low.
   * mirroring - Time spent mirroing the self-update.  This time is a reasonable
   *             proxy for the total self update time.
   * payload_validation - Time spent validating the payload, copying mutable
   *                      regions and/or dealing with failsafe fallback.
   */
  struct boot_timing_data boot_timing_total;
  struct boot_timing_data boot_timing_firmware_update;
  struct boot_timing_data boot_timing_firmware_mirroring;
  struct boot_timing_data boot_timing_payload_validation;

  /*
   * Confirmation cookie for Payload Update
   */
  uint32_t payload_update_confirmation_cookie_failure_reason;
  uint64_t payload_update_confirmation_cookie;

  /*
   * Error code returned by a bootloader update failure.
   */
  uint32_t bootloader_update_error;

  /*
   * Future expansion.
   */
  uint32_t reserved[42];
} __attribute__((packed));

#define STATISTIC_OFFSET(field) \
  (offsetof(struct ec_response_statistics, field) / sizeof(uint32_t))

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

// Arm the coordinated reset trigger, which will cause the hoth to perform a
// hard reset when it receives the hardware trigger event.
#define EC_PRV_CMD_HOTH_ARM_COORDINATED_RESET 0x001A

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

// After sending this command, any future synchronous SPI reads from the RoT's
// SPI-slave interface will return all zeroes, but out-of-band methods (such as
// EC_SPI_OPERATION via USB) will be able to interact with the SPI flash.
#define EC_PRV_CMD_HOTH_SPS_PASSTHROUGH_DISABLE 0x003b

// Re-enables SPS passthrough. Future out-of-band access to the SPI flash will
// fail.
#define EC_PRV_CMD_HOTH_SPS_PASSTHROUGH_ENABLE 0x003c

/* Program authorization records */
#define EC_PRV_CMD_HOTH_SET_AUTHZ_RECORD 0x0017

struct ec_authz_record_set_request {
  // Authorization record index to program or erase. Currently only index=0 is
  // supported.
  uint8_t index;

  // When `erase` is a non-zero value, the authorization record at `index` is
  // erased and the value of `record` is ignored by firmware.
  uint8_t erase;

  uint8_t reserved[2];

  // Authorization record to program.
  struct authorization_record record;
} __attribute__((packed, aligned(4)));

#define EC_PRV_CMD_HOTH_GET_AUTHZ_RECORD 0x0018

struct ec_authz_record_get_request {
  // Authorization record index to get. Currently only index=0 is
  // supported.
  uint8_t index;
  uint8_t reserved[3];
} __attribute__((packed));

struct ec_authz_record_get_response {
  // Index of authorization record in the response. This value matches the
  // `index` in the corresponding host command request.
  uint8_t index;

  // When `valid` is non-zero value, the `record` at `index` in this
  // response is valid.
  uint8_t valid;
  uint8_t reserved[2];
  struct authorization_record record;
} __attribute__((packed, aligned(4)));

#define EC_PRV_CMD_HOTH_GET_AUTHZ_RECORD_NONCE 0x0019

struct ec_authz_record_get_nonce_response {
  uint32_t authorization_nonce[8];

  // key_id supported by RO and RW. These key_id's are expected to match one
  // another to successfully program an authorization record. key_id == 0 should
  // be interpreted as an unknown key_id.
  uint32_t ro_supported_key_id;
  uint32_t rw_supported_key_id;
} __attribute__((packed));

#define MAILBOX_SIZE 1024

#define EC_PRV_CMD_HOTH_PAYLOAD_UPDATE 0x0005
#define EC_PRV_CMD_HOTH_PAYLOAD_STATUS 0x0006

#define PAYLOAD_UPDATE_INITIATE 0
#define PAYLOAD_UPDATE_CONTINUE 1
#define PAYLOAD_UPDATE_FINALIZE 2
#define PAYLOAD_UPDATE_AUX_DATA 3
#define PAYLOAD_UPDATE_VERIFY 4
#define PAYLOAD_UPDATE_ACTIVATE 5
#define PAYLOAD_UPDATE_READ 6
#define PAYLOAD_UPDATE_GET_STATUS 7
#define PAYLOAD_UPDATE_ERASE 8
#define PAYLOAD_UPDATE_VERIFY_CHUNK 9
#define PAYLOAD_UPDATE_CONFIRM 10
#define PAYLOAD_UPDATE_VERIFY_DESCRIPTOR 11

struct payload_status_response_header {
  uint8_t version;
  uint8_t lockdown_state;
  uint8_t active_half;
  uint8_t region_count;
} __attribute__((packed));

enum payload_validation_state {
  PAYLOAD_IMAGE_INVALID = 0,
  PAYLOAD_IMAGE_UNVERIFIED = 1,
  PAYLOAD_IMAGE_VALID = 2,
  PAYLOAD_DESCRIPTOR_VALID = 3,
};

struct payload_region_state {
  uint8_t validation_state; /* enum payload_validation_state */
  uint8_t failure_reason;   /* enum payload_validation_failure_reason */
  uint8_t reserved_0;
  uint8_t image_type; /* enum image_type (dev, prod, breakout) */
  uint16_t key_index;
  uint16_t reserved_1;
  uint32_t image_family; /* handy to disambiguate during enumeration */
  uint32_t version_major;
  uint32_t version_minor;
  uint32_t version_point;
  uint32_t version_subpoint;
  uint32_t descriptor_offset; /* can be used to pull the image hash/signature */
} __attribute__((packed));

struct payload_update_packet {
  uint32_t offset; /* image offset */
  uint32_t len;    /* packet length excluding this header */
  uint8_t type;    /* One of PAYLOAD_UPDATE_* */
  /* payload data immediately follows */
} __attribute__((packed));

struct payload_update_status {
  uint8_t a_valid;         /* 0 = invalid, 1 = unverified, 2 = valid, */
                           /* 3 = descriptor valid */
  uint8_t b_valid;         /* 0 = invalid, 1 = unverified, 2 = valid, */
                           /* 3 = descriptor valid */
  uint8_t active_half;     /* 0, 1 */
  uint8_t next_half;       /* 0, 1 */
  uint8_t persistent_half; /* 0, 1 */
} __attribute__((packed));

#define EC_PRV_CMD_HOTH_PERSISTENT_PANIC_INFO 0x0014
#define HOTH_PERSISTENT_PANIC_INFO_CHUNK_SIZE 512
enum persistent_panic_op {
  PERSISTENT_PANIC_INFO_GET = 0,
  PERSISTENT_PANIC_INFO_ERASE = 1,
};

struct ec_request_persistent_panic_info {
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

struct ec_response_persistent_panic_info {
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

// This command allows callers to push initial measurements into PCR0. This
// command will fail if the TPM has already been started up, or if the
// data to measure exceeds SRTM_DATA_MAX_SIZE_BYTES.
#define EC_PRV_CMD_HOTH_SRTM 0x0044
#define SRTM_DATA_MAX_SIZE_BYTES 64

struct ec_srtm_request {
  uint16_t data_size;
  uint8_t data[SRTM_DATA_MAX_SIZE_BYTES];
} __attribute__((packed, aligned(4)));

/*
 * I2C Detect. This scans for I2C devices on the Hoth's I2C Bus
 */
#define EC_PRV_CMD_HOTH_I2C_DETECT 0x0045
#define I2C_DETECT_DATA_MAX_SIZE_BYTES (16)  // 128 bits (addresses)

struct ec_request_i2c_detect {
  // Which I2C bus to run the scan on
  uint8_t bus_number;

  // What 7-bit addresses to start and end scan on?
  uint8_t start_address;
  uint8_t end_address;
} __attribute__((packed, aligned(4)));

struct ec_response_i2c_detect {
  // Non-zero code for error on the i2c bus
  uint8_t bus_response;

  // How many devices were found
  uint8_t devices_count;

  // Bit mask for detected 7-bit addresses
  uint8_t devices_mask[I2C_DETECT_DATA_MAX_SIZE_BYTES];
} __attribute__((packed, aligned(4)));

/*
 * I2C Transfer. This runs an I2C transaction on the Hoth's I2C bus
 */
#define EC_PRV_CMD_HOTH_I2C_TRANSFER 0x0046
#define I2C_TRANSFER_DATA_MAX_SIZE_BYTES (256)

#define I2C_BITS_WRITE (1 << 0)
#define I2C_BITS_NO_STOP (1 << 1)
#define I2C_BITS_NO_START (1 << 2)
#define I2C_BITS_REPEATED_START (1 << 3)

struct ec_request_i2c_transfer {
  // Which I2C bus to run the transfer on
  uint8_t bus_number;

  // Override default bus speed. (100, 400, 1000)
  uint16_t speed_khz;

  // What 7-bit device address to transact to
  uint8_t dev_address;

  // Any I2C flags needed. Use `I2C_BITS_*`
  uint32_t flags;

  // Number of bytes to write
  uint16_t size_write;

  // Number of bytes to read
  uint16_t size_read;

  // Byte array to send if write
  uint8_t arg_bytes[I2C_TRANSFER_DATA_MAX_SIZE_BYTES];
} __attribute__((packed, aligned(4)));

struct ec_response_i2c_transfer {
  // // Non-zero code for error on the i2c bus
  uint8_t bus_response;

  // How many bytes were read
  uint16_t read_bytes;

  // Byte array to send if write
  uint8_t resp_bytes[I2C_TRANSFER_DATA_MAX_SIZE_BYTES];
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
};

enum ec_target_control_status {
  EC_TARGET_CONTROL_STATUS_UNKNOWN = 0,
  EC_TARGET_CONTROL_STATUS_DISABLED = 1,
  EC_TARGET_CONTROL_STATUS_ENABLED = 2,
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

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_HOST_COMMANDS_H_
