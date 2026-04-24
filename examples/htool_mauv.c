// Copyright 2026 Google LLC
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

#include "htool_mauv.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "htool.h"
#include "protocol/mauv.h"

static void print_firmware_mauv(const struct hoth_response_mauv* mauv) {
  printf("Firmware MAUV:\n");
  printf("  Struct Version: %u\n", mauv->haven.struct_version);
  printf("  MAUV Version:   %u\n", mauv->haven.mauv_version);
  printf("  Minimum Version: %u.%u.%lu\n",
         mauv->haven.minimum_acceptable_update_version.epoch,
         mauv->haven.minimum_acceptable_update_version.major,
         mauv->haven.minimum_acceptable_update_version.minor);
  printf("  Denylist (%u entries):\n", mauv->haven.denylist_num_entries);
  for (uint32_t i = 0;
       i < mauv->haven.denylist_num_entries && i < HAVEN_MAUV_MAX_DENYLIST_SIZE;
       i++) {
    printf("    [%u]: %u.%u.%lu\n", i, mauv->haven.denylist[i].epoch,
           mauv->haven.denylist[i].major, mauv->haven.denylist[i].minor);
  }
}

int htool_mauv_compiled(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  struct hoth_response_mauv mauv;
  int ret = libhoth_fetch_mauv(dev, MAUV_STATE_COMPILED, HAVEN_MAUV, &mauv);
  if (ret != 0) {
    fprintf(stderr, "Failed to get compiled firmware MAUV: %d\n", ret);
    return -1;
  }

  print_firmware_mauv(&mauv);
  return 0;
}

int htool_mauv_effective(const struct htool_invocation* inv) {
  // TODO: support FW MAUV effective once it's implemented in firmware.
  return 0;
}
