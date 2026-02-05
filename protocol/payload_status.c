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

#include "payload_status.h"

#include <stddef.h>

#include "host_cmd.h"

int libhoth_payload_status(struct libhoth_device* dev,
                           struct payload_status* payload_status) {
  size_t rlen = 0;
  int ret = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_PAYLOAD_STATUS, 0,
      NULL, 0, payload_status, sizeof(*payload_status), &rlen);

  if (ret != 0) {
    return ret;
  }

  size_t expected_rlen = sizeof(struct payload_status_response_header) +
                         payload_status->resp_hdr.region_count *
                             sizeof(struct payload_region_state);

  if (rlen != expected_rlen) {
    return -1;
  }

  return ret;
}

const char* libhoth_sps_eeprom_lockdown_status_string(uint8_t st) {
  switch (st) {
    case 0:
      return "Failsafe";
    case 1:
      return "Ready";
    case 2:
      return "Immutable";
    case 3:
      return "Enabled";
    default:
      return "(unknown sps_eeprom_lockdown_status)";
  }
}

const char* libhoth_payload_validation_state_string(uint8_t s) {
  switch (s) {
    case PAYLOAD_IMAGE_INVALID:
      return "Invalid";
    case PAYLOAD_IMAGE_UNVERIFIED:
      return "Unverified";
    case PAYLOAD_IMAGE_VALID:
      return "Valid";
    case PAYLOAD_DESCRIPTOR_VALID:
      return "Descriptor Valid";
    default:
      return "(unknown payload_validation_state)";
  }
}

const char* libhoth_payload_validation_failure_reason_string(uint8_t r) {
  switch (r) {
    case 0:
      return "Success";
    case 1:
      return "Runtime Failure";
    case 2:
      return "Unsupported Descriptor";
    case 3:
      return "Invalid Descriptor";
    case 4:
      return "Invalid Image Family";
    case 5:
      return "Image Type Disallowed";
    case 6:
      return "Denylisted Version";
    case 7:
      return "Untrusted Key";
    case 8:
      return "Invalid Signature";
    case 9:
      return "Invalid Hash";
    default:
      return "(unknown payload_validation_failure_reason)";
  }
}

const char* libhoth_image_type_string(uint8_t type) {
  switch (type) {
    case 0:
      return "Dev";
    case 1:
      return "Prod";
    case 2:
      return "Breakout";
    case 3:
      return "Test";
    case 4:
      return "UnsignedIntegrity";
    case 255:
      return "Unspecified";
    default:
      return "(unknown image_type)";
  }
}
