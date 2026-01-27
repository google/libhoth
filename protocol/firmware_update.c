#include "firmware_update.h"

#include <stdint.h>
#include <stdio.h>

#include "protocol/host_cmd.h"
#include "transports/libhoth_device.h"

int libhoth_firmware_update_from_flash_and_reset(struct libhoth_device* dev,
                                                 uint32_t offset) {
  const struct hoth_request_firmware_update request = {
      .operation = HOTH_FIRMWARE_UPDATE_OP_UPDATE_AND_RESET,
      .flags = 0,
      .offset = offset,
  };
  const int rv =
      libhoth_hostcmd_exec(dev, HOTH_CMD_FIRMWARE_UPDATE, /*version=*/0,
                           &request, sizeof(request), NULL, 0, NULL);
  if (rv == 0) {
    fprintf(stderr,
            "Skipped update package at flash offset 0x%x containing same "
            "version as running. Chip is not reset.\n",
            offset);
    return 0;
  }
  if (rv > HTOOL_ERROR_HOST_COMMAND_START) {
    fprintf(stderr,
            "Firmware update from flash offset 0x%x failed with error code: "
            "%d. Aborting.\n",
            offset, rv);
    return rv;
  }

  fprintf(stderr,
          "Lost connection after firmware update command (error code %d). "
          "This is expected if the device reset. Attempting to reconnect...\n",
          rv);
  return libhoth_device_reconnect(dev);
}
