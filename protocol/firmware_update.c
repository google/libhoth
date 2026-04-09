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

#include "firmware_update.h"

#include <stdint.h>
#include <stdio.h>

#include "protocol/host_cmd.h"
#include "transports/libhoth_device.h"

libhoth_error libhoth_firmware_update_from_flash_and_reset(
    struct libhoth_device* dev, uint32_t offset) {
  const struct hoth_request_firmware_update request = {
      .operation = HOTH_FIRMWARE_UPDATE_OP_UPDATE_AND_RESET,
      .flags = 0,
      .offset = offset,
  };
  const libhoth_error rv =
      libhoth_hostcmd_exec(dev, HOTH_CMD_FIRMWARE_UPDATE, /*version=*/0,
                           &request, sizeof(request), NULL, 0, NULL);
  if (rv == 0) {
    fprintf(stderr,
            "Skipped update package at flash offset 0x%x containing same "
            "version as running. Chip is not reset.\n",
            offset);
    return 0;
  }
  if (rv != 0 && (rv >> 32) == HOTH_CTX_CMD_EXEC &&
      ((rv >> 16) & 0xFFFF) == HOTH_HOST_SPACE_FW) {
    fprintf(stderr,
            "Firmware update from flash offset 0x%x failed with error code: "
            "%ld. Aborting.\n",
            offset, rv);
    return rv;
  }

  if (rv != 0) {
    fprintf(
        stderr,
        "Lost connection after firmware update command (error code %ld). "
        "This is expected if the device reset. Attempting to reconnect...\n",
        rv);
  }
  return (libhoth_error)libhoth_device_reconnect(dev);
}
