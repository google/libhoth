// Copyright 2024 Google LLC
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

#include "protocol/secure_boot.h"

#include <stddef.h>
#include <stdint.h>

#include "protocol/host_cmd.h"
#include "transports/libhoth_device.h"

int libhoth_secure_boot_get_enforcement(
    struct libhoth_device* dev,
    enum secure_boot_enforcement_status* enforcement) {
  struct secure_boot_enforcement_state response;
  size_t rlen = 0;
  int ret =
      libhoth_hostcmd_exec(dev,
                           HOTH_CMD_BOARD_SPECIFIC_BASE +
                               HOTH_PRV_CMD_HOTH_GET_SECURE_BOOT_ENFORCEMENT,
                           0, NULL, 0, &response, sizeof(response), &rlen);
  if (ret != 0) {
    return ret;
  }
  if (rlen != sizeof(response)) {
    return -1;
  }
  *enforcement = response.enabled;
  return 0;
}

int libhoth_secure_boot_enable_enforcement(struct libhoth_device* dev) {
  struct secure_boot_enforcement_state request = {
      .enabled = SECURE_BOOT_ENFORCEMENT_ENABLED};
  size_t rlen = 0;
  int ret =
      libhoth_hostcmd_exec(dev,
                           HOTH_CMD_BOARD_SPECIFIC_BASE +
                               HOTH_PRV_CMD_HOTH_SET_SECURE_BOOT_ENFORCEMENT,
                           0, &request, sizeof(request), NULL, 0, &rlen);
  if (ret != 0) {
    return ret;
  }
  return 0;
}
