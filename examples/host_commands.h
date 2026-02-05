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

#include "protocol/console.h"
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

#define HOTH_CMD_BOARD_SPECIFIC_BASE 0x3E00

// NOTE: All further commands in this file are offset by
// HOTH_CMD_BOARD_SPECIFIC_BASE.

/**
 * The identifier for the SecurityV2 host command. All SecurityV2 commands are
 * handled by a single host command handler. Specific SecurityV2 commands are
 * identified by the "major_command" and "minor_command" fields of a command's
 * request header.
 */
#define HOTH_PRV_CMD_HOTH_SECURITY_V2 0x0003

/* Reports on whether a command is allowed to run given the current host command
 * filtering that the firmware is using.
 */
#define HOTH_PRV_CMD_HOTH_IS_HOST_COMMAND_SUPPORTED 0x0011

/**
 * The identifier for the SecurityV3 host command. All SecurityV3 commands are
 * handled by a single host command handler.
 */
#define HOTH_PRV_CMD_HOTH_SECURITY_V3 0x0033

/**
 * Macro to retrieve the final address of a command, which is the sum of the
 * base address and the added command.
 */
#define HOTH_BASE_CMD(cmd) (HOTH_CMD_BOARD_SPECIFIC_BASE + (cmd))

/* The major command identifier for the Provisioning Log read host command. */
#define HOTH_PRV_CMD_HOTH_PROVISIONING_LOG 0x0040

/**
 * The request header structure for security v2 commands
 */
struct hoth_security_v2_request_header {
  /* The major and minor command codes that identify a specific SecurityV2
   * command. */
  uint8_t major_command;
  uint8_t minor_command;

  /* The number of parameters that follow the header in the request. */
  uint16_t param_count;
} __attribute__((packed));

/**
 * The response header structure for a security v2 command
 */
struct hoth_security_v2_response_header {
  /* The number of parameters that follow the header in the response. */
  uint16_t param_count;

  /* Reserved value, set to 0; used for 32-bit alignment. */
  uint16_t reserved;
} __attribute__((packed));

/**
 * The parameter structure for security v2 commands
 *
 * Parameters follow request/response headers and are 32-bit aligned.
 */
struct hoth_security_v2_parameter {
  /* The number of bytes in the parameter's value. */
  uint16_t size;

  /* Reserved value, set to 0; used for 32-bit alignment. */
  uint16_t reserved;

  /* The bytes representing the value of the parameter should immediately follow
   * this struct. */
} __attribute__((packed));

/**
 * The size of the parameter being passed in a security v2 command
 */
#define HOTH_SECURITY_V2_PARAM_OVERHEAD \
  (sizeof(struct hoth_security_v2_parameter))

/**
 * The size of the request for a security v2 command
 */
#define HOTH_SECURITY_V2_REQUEST_SIZE(param_count)  \
  (sizeof(struct hoth_security_v2_request_header) + \
   (param_count) * HOTH_SECURITY_V2_PARAM_OVERHEAD)

/**
 * The size of the response for a security v2 command
 */
#define HOTH_SECURITY_V2_RESPONSE_SIZE(param_count)  \
  (sizeof(struct hoth_security_v2_response_header) + \
   (param_count) * HOTH_SECURITY_V2_PARAM_OVERHEAD)

/**
 * The command needed to get any certificates from the device.
 */
#define HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND 1

/**
 * The command to get the alias key certificate from the device.
 */
#define HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_ALIAS_KEY_MINOR_COMMAND 20

/**
 * The command to get the device id certificates from the device.
 */
#define HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_DEVICE_ID_MINOR_COMMAND 19

/**
 * The command to get the attestation public certificate from the device.
 */
#define HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_ATTESTATION_PUB_CERT_MINOR_COMMAND 4

/**
 * The command to get the signed attestation public certificates ferom the
 * device.
 */
#define HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_SIGNED_ATTESTATION_PUB_CERT_MINOR_COMMAND \
  25

/**
 * The command to get token information from the device.
 */
#define HOTH_PRV_CMD_HOTH_SECURITY_V2_TOKENS_MAJOR_COMMAND 5

/**
 * The command to get the amount of loaded token sets.
 */
#define HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_TOKEN_SET_COUNT_MINOR_COMMAND 6

/**
 * The command to get the loaded token at a given set index.
 */
#define HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_TOKENS_IN_SET_MINOR_COMMAND 8

/**
 * The command to get the token info at a given set index.
 */
#define HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_TOKEN_SET_INFO_MINOR_COMMAND 7

/**
 * The identifier for the getting the major version of the SecurityV2 Info
 * command.
 */
#define HOTH_PRV_CMD_HOTH_SECURITY_V2_INFO_MAJOR_COMMAND 0x0003

/* Options and request struct for HOTH_PRV_CMD_HOTH_RESET_TARGET */
enum hoth_target_reset_option {
  HOTH_TARGET_RESET_OPTION_RELEASE = 0,  // Release target from reset
  HOTH_TARGET_RESET_OPTION_SET = 1,      // Put target in reset
  HOTH_TARGET_RESET_OPTION_PULSE = 2,    // Put target in reset then release
};

#define RESET_TARGET_ID_RSTCTRL0 0
struct hoth_request_reset_target {
  uint32_t target_id;
  // "reset_option" must be one of hoth_target_reset_option
  // Side-by-Side (Hammurabi and Chopper) only support
  // RESET_PULSE. For backward compatibility, if
  // HOTH_PRV_CMD_HOTH_RESET_TARGET is sent without a
  // request param, it defaults to RESET_PULSE. Viperlite
  // and Diorite only support RESET_SET and RESET_RELEASE
  uint8_t reset_option;
  uint8_t reserved[12];
} __attribute__((packed));

/* Reset the target device. */
#define HOTH_PRV_CMD_HOTH_RESET_TARGET 0x0012

// Arm the coordinated reset trigger, which will cause the hoth to perform a
// hard reset when it receives the hardware trigger event.
#define HOTH_PRV_CMD_HOTH_ARM_COORDINATED_RESET 0x001A

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

  // Recommended to be used for `HOTH_TARGET_CONTROL_SBS_MUX_SINGLE` function
  HOTH_TARGET_CONTROL_ACTION_SBS_MUX_SINGLE_CONNECT_FLASH_TO_ROT =
      HOTH_TARGET_CONTROL_ACTION_DISABLE,
  HOTH_TARGET_CONTROL_ACTION_SBS_MUX_SINGLE_CONNECT_FLASH_TO_TARGET =
      HOTH_TARGET_CONTROL_ACTION_ENABLE,

  // Recommended to be used for `HOTH_TARGET_CONTROL_SBS_MUX_DUAL` function
  HOTH_TARGET_CONTROL_ACTION_SBS_MUX_DUAL_CONNECT_TARGET_TO_SPI_FLASH_0 =
      HOTH_TARGET_CONTROL_ACTION_DISABLE,
  HOTH_TARGET_CONTROL_ACTION_SBS_MUX_DUAL_CONNECT_TARGET_TO_SPI_FLASH_1 =
      HOTH_TARGET_CONTROL_ACTION_ENABLE,
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
  HOTH_TARGET_CONTROL_SBS_MUX_SINGLE = 5,
  HOTH_TARGET_CONTROL_SBS_MUX_DUAL = 6,
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

  // Recommended to be used for `HOTH_TARGET_CONTROL_SBS_MUX_SINGLE` function
  HOTH_TARGET_CONTROL_SBS_SINGLE_MUX_CONNECTED_FLASH_TO_ROT =
      HOTH_TARGET_CONTROL_STATUS_DISABLED,
  HOTH_TARGET_CONTROL_SBS_SINGLE_MUX_CONNECTED_FLASH_TO_TARGET =
      HOTH_TARGET_CONTROL_STATUS_ENABLED,

  // Recommended to be used for `HOTH_TARGET_CONTROL_SBS_MUX_DUAL` function
  HOTH_TARGET_CONTROL_SBS_MUX_DUAL_TARGET_CONNECTED_TO_SPI_FLASH_0 =
      HOTH_TARGET_CONTROL_STATUS_DISABLED,
  HOTH_TARGET_CONTROL_SBS_MUX_DUAL_TARGET_CONNECTED_TO_SPI_FLASH_1 =
      HOTH_TARGET_CONTROL_STATUS_ENABLED,
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

// Host Command for Provisioning Commands
#define HOTH_PRV_CMD_HOTH_PROVISIONING_LOG 0x0040

#endif  // LIBHOTH_EXAMPLES_HOST_COMMANDS_H_
