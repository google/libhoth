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

#ifndef LIBHOTH_PROTOCOL_STATISTICS_H_
#define LIBHOTH_PROTOCOL_STATISTICS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "transports/libhoth_device.h"

/* Get various statistics */
#define EC_PRV_CMD_HOTH_GET_STATISTICS 0x000F

struct boot_timing_data {
  uint32_t start_us;
  uint32_t end_us;
};

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

int libhoth_get_statistics(struct libhoth_device* dev,
                           struct ec_response_statistics* stats);

#ifdef __cplusplus
}
#endif

#endif
