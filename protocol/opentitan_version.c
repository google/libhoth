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

#include <stddef.h>

#include "opentitan_version.h"

int libhoth_opentitan_version(struct libhoth_device * dev,
                              struct opentitan_get_version_resp * output) {

  uint32_t request = 0;
  struct opentitan_get_version_resp response;
  const int rv =
    libhoth_hostcmd_exec(dev, HOTH_OPENTITAN_GET_VERSION, /*version=*/0, &request,
                          sizeof(request), &response, sizeof(response), NULL);

  if (rv == 0) {
    *output = response;
  }

  return rv;
}

char * bootslot_str(enum opentitan_boot_slot input) {

  // Primary BL0 slot values are hardcoded in pie_rot
  // Boot slotA: 0x5f5f4141
  // Boot slotB: 0x42425f5f)
  if (input == kOpentitanBootSlotA) {
    return "Boot slot A";
  } else if (input == kOpentitanBootSlotB) {
    return "Boot slot B";
  } else {
    return "Unknown boot slot";
  }

}