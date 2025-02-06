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

#include "htool_statistics.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "host_commands.h"
#include "htool.h"
#include "htool_constants.h"
#include "htool_update_failure_reasons.h"
#include "protocol/statistics.h"

#define STATISTIC_OFFSET(field) \
  (offsetof(struct ec_response_statistics, field) / sizeof(uint32_t))

const char* FirmwareUpdateErrorToString(uint16_t reason) {
  switch (reason) {
    case FIRMWARE_UPDATE_SUCCESS:
      return "SUCCESS";
    case FIRMWARE_UPDATE_NO_HEADER_FOUND:
      return "FIRMWARE_UPDATE_NO_HEADER_FOUND";
    case FIRMWARE_UPDATE_INVALID_HEADER_SIZE:
      return "FIRMWARE_UPDATE_INVALID_HEADER_SIZE";
    case FIRMWARE_UPDATE_INVALID_DESCRIPTOR:
      return "FIRMWARE_UPDATE_INVALID_DESCRIPTOR";
    case FIRMWARE_UPDATE_DELIVERY_MECHANISM_MISMATCH:
      return "FIRMWARE_UPDATE_DELIVERY_MECHANISM_MISMATCH";
    case FIRMWARE_UPDATE_INVALID_REGION:
      return "FIRMWARE_UPDATE_INVALID_REGION";
    case FIRMWARE_UPDATE_VERIFY_BAD_HEADER:
      return "FIRMWARE_UPDATE_VERIFY_BAD_HEADER";
    case FIRMWARE_UPDATE_VERIFY_HASH_IMAGE_FAILED:
      return "FIRMWARE_UPDATE_VERIFY_HASH_IMAGE_FAILED";
    case FIRMWARE_UPDATE_VERIFY_HASH_FUSE_MAP_FAILED:
      return "FIRMWARE_UPDATE_VERIFY_HASH_FUSE_MAP_FAILED";
    case FIRMWARE_UPDATE_VERIFY_HASH_INFO_MAP_FAILED:
      return "FIRMWARE_UPDATE_VERIFY_HASH_INFO_MAP_FAILED";
    case FIRMWARE_UPDATE_VERIFY_SIGNATURE_FAILED:
      return "FIRMWARE_UPDATE_VERIFY_SIGNATURE_FAILED";
    case FIRMWARE_UPDATE_HASH_IMAGE_FIPS_FAILED:
      return "FIRMWARE_UPDATE_HASH_IMAGE_FIPS_FAILED";
    case FIRMWARE_UPDATE_VERIFY_FIPS_FAILED:
      return "FIRMWARE_UPDATE_VERIFY_FIPS_FAILED";
    case FIRMWARE_UPDATE_EXTERNAL_AB_HEADER_MISMATCH:
      return "FIRMWARE_UPDATE_EXTERNAL_AB_HEADER_MISMATCH";
    case FIRMWARE_UPDATE_VERSIONS_EQUAL:
      return "FIRMWARE_UPDATE_VERSIONS_EQUAL";
    case FIRMWARE_UPDATE_FIRST_VERSION_NEWER:
      return "FIRMWARE_UPDATE_FIRST_VERSION_NEWER";
    case FIRMWARE_UPDATE_MAUV_UPDATE_NOT_ALLOWED:
      return "FIRMWARE_UPDATE_MAUV_UPDATE_NOT_ALLOWED";
    case FIRMWARE_UPDATE_EVEN_ODD_ROLLBACK_NOT_ALLOWED:
      return "FIRMWARE_UPDATE_EVEN_ODD_ROLLBACK_NOT_ALLOWED";
    case FIRMWARE_UPDATE_EVEN_ODD_ROLLBACK_PAYLOAD_TOO_OLD:
      return "FIRMWARE_UPDATE_EVEN_ODD_ROLLBACK_PAYLOAD_TOO_OLD";
    case FIRMWARE_UPDATE_MIRROR_VERIFY_FAILED:
      return "FIRMWARE_UPDATE_MIRROR_VERIFY_FAILED";
    case FIRMWARE_UPDATE_MIRROR_RW_FAILED:
      return "FIRMWARE_UPDATE_MIRROR_RW_FAILED";
    case FIRMWARE_UPDATE_MIRROR_RO_FAILED:
      return "FIRMWARE_UPDATE_MIRROR_RO_FAILED";
    case FIRMWARE_UPDATE_VERSION_MATCHES_DENYLIST:
      return "FIRMWARE_UPDATE_VERSION_MATCHES_DENYLIST";
    case FIRMWARE_UPDATE_ERROR_MAX:
      return "FIRMWARE_UPDATE_ERROR_MAX";
    case FIRMWARE_UPDATE_INVALID_RW_KEY_TRANSITION:
      return "FIRMWARE_UPDATE_INVALID_RW_KEY_TRANSITION";
    default:
      return "Invalid Status Code";
  }
}

const char* PayloadUpdateErrorToString(uint16_t reason) {
  switch (reason) {
    case PAYLOAD_UPDATE_SUCCESS:
      return "SUCCESS";
    case PAYLOAD_UPDATE_VALIDATE_RUNTIME_FAILURE:
      return "PAYLOAD_UPDATE_VALIDATE_RUNTIME_FAILURE";
    case PAYLOAD_UPDATE_VALIDATE_UNSUPPORTED_DESCRIPTOR:
      return "PAYLOAD_UPDATE_VALIDATE_UNSUPPORTED_DESCRIPTOR";
    case PAYLOAD_UPDATE_VALIDATE_INVALID_DESCRIPTOR:
      return "PAYLOAD_UPDATE_VALIDATE_INVALID_DESCRIPTOR";
    case PAYLOAD_UPDATE_VALIDATE_INVALID_IMAGE_FAMILY:
      return "PAYLOAD_UPDATE_VALIDATE_INVALID_IMAGE_FAMILY";
    case PAYLOAD_UPDATE_VALIDATE_IMAGE_TYPE_DISALLOWED:
      return "PAYLOAD_UPDATE_VALIDATE_IMAGE_TYPE_DISALLOWED";
    case PAYLOAD_UPDATE_VALIDATE_DENYLISTED_VERSION:
      return "PAYLOAD_UPDATE_VALIDATE_DENYLISTED_VERSION";
    case PAYLOAD_UPDATE_VALIDATE_UNTRUSTED_KEY:
      return "PAYLOAD_UPDATE_VALIDATE_UNTRUSTED_KEY";
    case PAYLOAD_UPDATE_VALIDATE_INVALID_SIGNATURE:
      return "PAYLOAD_UPDATE_VALIDATE_INVALID_SIGNATURE";
    case PAYLOAD_UPDATE_VALIDATE_INVALID_HASH:
      return "PAYLOAD_UPDATE_VALIDATE_INVALID_HASH";
    case PAYLOAD_UPDATE_VALIDATE_PENDING:
      return "PAYLOAD_UPDATE_VALIDATE_PENDING";
    case PAYLOAD_UPDATE_VALIDATE_INVALID_SESSION_ID:
      return "PAYLOAD_UPDATE_VALIDATE_INVALID_SESSION_ID";
    case PAYLOAD_UPDATE_VALIDATE_FINGERPRINT_NOT_FOUND:
      return "PAYLOAD_UPDATE_VALIDATE_FINGERPRINT_NOT_FOUND";
    case PAYLOAD_UPDATE_VALIDATE_UNSUPPORTED_FINGERPRINT_HASH_TYPE:
      return "PAYLOAD_UPDATE_VALIDATE_UNSUPPORTED_FINGERPRINT_HASH_TYPE";
    case PAYLOAD_UPDATE_VALIDATE_MISSING_BOOT_HASH:
      return "PAYLOAD_UPDATE_VALIDATE_MISSING_BOOT_HASH";
    case PAYLOAD_UPDATE_VALIDATE_UNEXPECTED_SKIP_BOOT_VALIDATION_REGION:
      return "PAYLOAD_UPDATE_VALIDATE_UNEXPECTED_SKIP_BOOT_VALIDATION_REGION";
    case PAYLOAD_UPDATE_VALIDATE_MULTIPLE_DESCRIPTORS_FOUND:
      return "PAYLOAD_UPDATE_VALIDATE_MULTIPLE_DESCRIPTORS_FOUND";
    case PAYLOAD_UPDATE_VALIDATE_RESERVED_8:
    case PAYLOAD_UPDATE_VALIDATE_RESERVED_9:
    case PAYLOAD_UPDATE_VALIDATE_RESERVED_10:
    case PAYLOAD_UPDATE_VALIDATE_RESERVED_11:
      return "PAYLOAD_UPDATE_VALIDATE_RESERVED";
    case PAYLOAD_UPDATE_ERASE_FAILED:
      return "PAYLOAD_UPDATE_ERASE_FAILED";
    case PAYLOAD_UPDATE_WRITE_FAILED:
      return "PAYLOAD_UPDATE_WRITE_FAILED";
    case PAYLOAD_UPDATE_READ_FAILED:
      return "PAYLOAD_UPDATE_READ_FAILED";
    case PAYLOAD_UPDATE_INVALID_PARAMS:
      return "PAYLOAD_UPDATE_INVALID_PARAMS";
    case PAYLOAD_UPDATE_INVALID_STAGING_OFFSET:
      return "PAYLOAD_UPDATE_INVALID_STAGING_OFFSET";
    case PAYLOAD_UPDATE_INVALID_STAGING_SIZE:
      return "PAYLOAD_UPDATE_INVALID_STAGING_SIZE";
    case PAYLOAD_UPDATE_FILTER_CALLBACK_FAILED:
      return "PAYLOAD_UPDATE_FILTER_CALLBACK_FAILED";
    case PAYLOAD_UPDATE_ABORT_PENDING_UPDATE_FAILED:
      return "PAYLOAD_UPDATE_ABORT_PENDING_UPDATE_FAILED";
    case PAYLOAD_UPDATE_BAD_PACKET_HEADER:
      return "PAYLOAD_UPDATE_BAD_PACKET_HEADER";
    case PAYLOAD_UPDATE_FPGA_UPDATE_HEADER_FAILED:
      return "PAYLOAD_UPDATE_FPGA_UPDATE_HEADER_FAILED";
    case PAYLOAD_UPDATE_REGIONS_NOT_COMPATIBLE_FOR_MIGRATION:
      return "PAYLOAD_UPDATE_REGIONS_NOT_COMPATIBLE_FOR_MIGRATION";
    case PAYLOAD_UPDATE_MAUV_DOES_NOT_ALLOW_UPDATE:
      return "PAYLOAD_UPDATE_MAUV_DOES_NOT_ALLOW_UPDATE";
    case PAYLOAD_UPDATE_STAGING_AREA_INVALID:
      return "PAYLOAD_UPDATE_STAGING_AREA_INVALID";
    case PAYLOAD_UPDATE_SET_ACTIVE_HALF_FAILED:
      return "PAYLOAD_UPDATE_SET_ACTIVE_HALF_FAILED";
    case PAYLOAD_UPDATE_CALLBACK_FAILED:
      return "PAYLOAD_UPDATE_CALLBACK_FAILED";
    case PAYLOAD_UPDATE_SET_PENDING_MIGRATION_FAILED:
      return "PAYLOAD_UPDATE_SET_PENDING_MIGRATION_FAILED";
    case PAYLOAD_UPDATE_CONFIRM_INVALID_TIMEOUT:
      return "PAYLOAD_UPDATE_CONFIRM_INVALID_TIMEOUT";
    case PAYLOAD_UPDATE_CONFIRM_NOT_ENABLED:
      return "PAYLOAD_UPDATE_CONFIRM_NOT_ENABLED";
    case PAYLOAD_UPDATE_CONFIRM_NO_UPDATE_PAYLOAD:
      return "PAYLOAD_UPDATE_CONFIRM_NO_UPDATE_PAYLOAD";
    case PAYLOAD_UPDATE_CONFIRM_NO_PENDING_PAYLOAD:
      return "PAYLOAD_UPDATE_CONFIRM_NO_PENDING_PAYLOAD";
    case PAYLOAD_UPDATE_CONFIRM_GNVRAM_ERROR:
      return "PAYLOAD_UPDATE_CONFIRM_GNVRAM_ERROR";
    case PAYLOAD_UPDATE_CONFIRM_REVERT_PAYLOAD:
      return "PAYLOAD_UPDATE_CONFIRM_REVERT_PAYLOAD";
    case PAYLOAD_UPDATE_CONFIRM_NOT_SUPPORTED:
      return "PAYLOAD_UPDATE_CONFIRM_NOT_SUPPORTED";
    case PAYLOAD_UPDATE_ERROR_MAX:
      return "PAYLOAD_UPDATE_ERROR_MAX";
    default:
      return "Invalid Status Code";
  }
}

int htool_statistics() {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  struct ec_response_statistics stat;
  int ret = libhoth_get_statistics(dev, &stat);
  if (ret != 0) {
    fprintf(stderr, "HOTH_STATISTICS error code: %d\n", ret);
    return -1;
  }

  printf("Valid statistics words: %u\n", stat.valid_words);
  uint32_t flags = stat.hoth_reset_flags;
  printf("Reset flags: 0x%08x\n", flags);
  const char kIndent[] = "             %s\n";
  // clang-format off
  if (flags & kResetFlagOther)      printf(kIndent, "ResetFlagOther");
  if (flags & kResetFlagResetPin)   printf(kIndent, "ResetFlagResetPin");
  if (flags & kResetFlagBrownout)   printf(kIndent, "ResetFlagBrownout");
  if (flags & kResetFlagPowerOn)    printf(kIndent, "ResetFlagPowerOn");
  if (flags & kResetFlagWatchdog)   printf(kIndent, "ResetFlagWatchdog");
  if (flags & kResetFlagSoft)       printf(kIndent, "ResetFlagSoft");
  if (flags & kResetFlagHibernate)  printf(kIndent, "ResetFlagHibernate");
  if (flags & kResetFlagRtcAlarm)   printf(kIndent, "ResetFlagRtcAlarm");
  if (flags & kResetFlagWakePin)    printf(kIndent, "ResetFlagWakePin");
  if (flags & kResetFlagLowBattery) printf(kIndent, "ResetFlagLowBattery");
  if (flags & kResetFlagSysjump)    printf(kIndent, "ResetFlagSysjump");
  if (flags & kResetFlagHard)       printf(kIndent, "ResetFlagHard");
  if (flags & kResetFlagApOff)      printf(kIndent, "ResetFlagApOff");
  if (flags & kResetFlagPreserved)  printf(kIndent, "ResetFlagPreserved");
  if (flags & kResetFlagUsbResume)  printf(kIndent, "ResetFlagUsbResume");
  if (flags & kResetFlagRdd)        printf(kIndent, "ResetFlagRdd");
  if (flags & kResetFlagRbox)       printf(kIndent, "ResetFlagRbox");
  if (flags & kResetFlagSecurity)   printf(kIndent, "ResetFlagSecurity");
  if (flags & kResetFlagApWatchdog) printf(kIndent, "ResetFlagApWatchdog");
  // clang-format on

  printf("Time since boot: %" PRIu64 " us\n", stat.time_since_hoth_boot_us);
  if (stat.hoth_temperature == 0xFFFFFFFF) {
    printf("Temperature: (invalid)\n");
  } else {
    // The temperature is expressed as a 9.3b fixed point number.
    // Divide the fixed-point value by 8 to get a floating point value.
    // Unfortunately, the temperature sensor is an uncalibrated ADC and the
    // raw value needs to be converted into proper units.  Sadly, no-one
    // seems to be be doing that, so we just report the raw value.
    double temperature = stat.hoth_temperature / 8.0;
    printf("Temperature: %.3f (raw value)\n", temperature);
  }

  if (stat.valid_words > STATISTIC_OFFSET(ro_info_strikes)) {
    printf("ro info strikes: %u\n", stat.ro_info_strikes);
  }

  if (stat.valid_words > STATISTIC_OFFSET(rw_info_strikes)) {
    printf("rw info strikes: %u\n", stat.rw_info_strikes);
  }

  if (stat.valid_words > STATISTIC_OFFSET(scratch_value)) {
    printf("Debug scratch: %u\n", stat.scratch_value);
  }

  if (stat.valid_words > STATISTIC_OFFSET(payload_update_failure_reason)) {
    printf("Payload update failure reason: %s\n",
           PayloadUpdateErrorToString(stat.payload_update_failure_reason));
  }

  if (stat.valid_words > STATISTIC_OFFSET(firmware_update_failure_reason)) {
    printf("Firmware update failure reason: %s\n",
           FirmwareUpdateErrorToString(stat.firmware_update_failure_reason));
  }

  if (stat.valid_words > STATISTIC_OFFSET(failed_firmware_minor_version)) {
    printf("Failed firmware minor version: %u\n",
           stat.failed_firmware_minor_version);
  }

  if (stat.valid_words > STATISTIC_OFFSET(boot_timing_payload_validation)) {
    printf("Total boot time:         [%u, %u]us\n",
           stat.boot_timing_total.start_us, stat.boot_timing_total.end_us);
    printf("Payload validation time: [%u, %u]us\n",
           stat.boot_timing_payload_validation.start_us,
           stat.boot_timing_payload_validation.end_us);
    printf("Firmware update time:    [%u, %u]us\n",
           stat.boot_timing_firmware_update.start_us,
           stat.boot_timing_firmware_update.end_us);
    printf("Firmware mirroring time: [%u, %u]us\n",
           stat.boot_timing_firmware_mirroring.start_us,
           stat.boot_timing_firmware_mirroring.end_us);
  }

  if (stat.valid_words > STATISTIC_OFFSET(payload_update_confirmation_cookie)) {
    if (stat.payload_update_confirmation_cookie_failure_reason !=
        PAYLOAD_UPDATE_SUCCESS) {
      printf("Payload Update Confirmation Cookie: failed with %s\n",
             PayloadUpdateErrorToString(
                 stat.payload_update_confirmation_cookie_failure_reason));
    } else {
      printf("Payload Update Confirmation Cookie: %" PRIu64 "\n",
             stat.payload_update_confirmation_cookie);
    }
  }

  if (stat.valid_words > STATISTIC_OFFSET(bootloader_update_error)) {
    if (stat.bootloader_update_error) {
      printf("Bootloader update error: 0x%08x\n", stat.bootloader_update_error);
    } else {
      printf("Bootloader update error: 0x0 (no error)\n");
    }
  }
  return 0;
}
