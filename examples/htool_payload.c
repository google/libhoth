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

#include "htool_payload.h"

#include <stdio.h>
#include <stdlib.h>

#include "host_commands.h"
#include "htool.h"

int htool_payload_status() {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  uint8_t buffer[sizeof(struct payload_status_response_header) +
                 2 * sizeof(struct payload_region_state)];
  size_t rlen = 0;
  int ret = htool_exec_hostcmd(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_PAYLOAD_STATUS, 0, NULL,
      0, &buffer, sizeof(buffer), &rlen);
  if (ret != 0) {
    fprintf(stderr, "HOTH_PAYLOAD_STATUS error code: %d\n", ret);
    return -1;
  }

  struct payload_status_response_header* ppsr =
      (struct payload_status_response_header*)(buffer);
  printf("lockdown_state: %s (%u)\n",
         sps_eeprom_lockdown_status_string(ppsr->lockdown_state),
         ppsr->lockdown_state);
  printf("active_half   : %c\n", ppsr->active_half ? 'B' : 'A');

  size_t expected_rlen =
      sizeof(struct payload_status_response_header) +
      ppsr->region_count * sizeof(struct payload_region_state);
  if (rlen != expected_rlen) {
    printf("rlen is %zu while expected rlen is %zu, region_count is %u.\n",
           rlen, expected_rlen, ppsr->region_count);
    return -1;
  }

  for (int region_index = 0; region_index < ppsr->region_count;
       region_index++) {
    int offset = sizeof(struct payload_status_response_header) +
                 region_index * sizeof(struct payload_region_state);
    const struct payload_region_state* rs =
        (struct payload_region_state*)(&buffer[offset]);
    printf("Region %c:\n", region_index == 0 ? 'A' : 'B');
    printf("  validation_state: %s (%u)\n",
           payload_validation_state_string(rs->validation_state),
           rs->validation_state);
    if (rs->validation_state == PAYLOAD_IMAGE_UNVERIFIED) {
      // The rest of the fields won't have meaningful values.
      continue;
    }
    printf("  failure_reason: %s (%u)\n",
           payload_validation_failure_reason_string(rs->failure_reason),
           rs->failure_reason);
    printf("  image_type: %s (%u)\n", image_type_string(rs->image_type),
           rs->image_type);
    printf("  image_family: (0x%08x)\n", rs->image_family);
    printf("  version: %u.%u.%u.%u\n", rs->version_major, rs->version_minor,
           rs->version_point, rs->version_subpoint);
    printf("  descriptor_offset: 0x%08x\n", rs->descriptor_offset);
  }
  return 0;
}

const char* sps_eeprom_lockdown_status_string(uint8_t st) {
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

const char* payload_validation_state_string(uint8_t s) {
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

const char* payload_validation_failure_reason_string(uint8_t r) {
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

const char* image_type_string(uint8_t type) {
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
