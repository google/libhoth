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
#include "protocol/payload_status.h"

int htool_payload_status() {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  struct payload_status ps;
  int ret = libhoth_payload_status(dev, &ps);
  if (ret != 0) {
    fprintf(stderr, "HOTH_PAYLOAD_STATUS error code: %d\n", ret);
    return -1;
  }

  struct payload_status_response_header* ppsr = &ps.resp_hdr;

  printf("lockdown_state: %s (%u)\n",
         libhoth_sps_eeprom_lockdown_status_string(ppsr->lockdown_state),
         ppsr->lockdown_state);
  printf("active_half   : %c\n", ppsr->active_half ? 'B' : 'A');

  for (int region_index = 0; region_index < ppsr->region_count;
       region_index++) {
    const struct payload_region_state* rs = &ps.region_state[region_index];

    printf("Region %c:\n", region_index == 0 ? 'A' : 'B');
    printf("  validation_state: %s (%u)\n",
           libhoth_payload_validation_state_string(rs->validation_state),
           rs->validation_state);
    if (rs->validation_state == PAYLOAD_IMAGE_UNVERIFIED) {
      // The rest of the fields won't have meaningful values.
      continue;
    }
    if (rs->failure_reason) {
      printf(
          "  failure_reason: %s (%u)\n",
          libhoth_payload_validation_failure_reason_string(rs->failure_reason),
          rs->failure_reason);
    }
    printf("  image_type: %s (%u)\n", libhoth_image_type_string(rs->image_type),
           rs->image_type);
    printf("  image_family: (0x%08x)\n", rs->image_family);
    printf("  version: %u.%u.%u.%u\n", rs->version_major, rs->version_minor,
           rs->version_point, rs->version_subpoint);
    printf("  descriptor_offset: 0x%08x\n", rs->descriptor_offset);
  }
  return 0;
}
