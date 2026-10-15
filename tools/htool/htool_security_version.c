
#include "htool_security_version.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "host_commands.h"
#include "htool.h"
#include "protocol/host_cmd.h"
#include "protocol/status.h"

libhoth_security_version htool_get_security_version(
    struct libhoth_device* dev) {
  uint16_t command;
  libhoth_error status;
  uint8_t is_supported;

  // Check if SecurityV2 is supported.
  command = HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2);
  status = libhoth_hostcmd_exec_v2(
      dev, HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_IS_HOST_COMMAND_SUPPORTED), 0,
      &command, sizeof(command), &is_supported, sizeof(is_supported), NULL);
  if (status != HOTH_SUCCESS) {
    fprintf(stderr,
            "Failed to check SecurityV2 support (0x%016" PRIx64 "): ", status);
    libhoth_log_err(stderr, status);
    return LIBHOTH_SECURITY_UNKNOWN;
  }
  if (is_supported) {
    return LIBHOTH_SECURITY_V2;
  }

  // Check if SecurityV3 is supported.
  command = HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V3);
  status = libhoth_hostcmd_exec_v2(
      dev, HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_IS_HOST_COMMAND_SUPPORTED), 0,
      &command, sizeof(command), &is_supported, sizeof(is_supported), NULL);
  if (status != HOTH_SUCCESS) {
    fprintf(stderr,
            "Failed to check SecurityV3 support (0x%016" PRIx64 "): ", status);
    libhoth_log_err(stderr, status);
    return LIBHOTH_SECURITY_UNKNOWN;
  }
  if (is_supported) {
    return LIBHOTH_SECURITY_V3;
  }

  return LIBHOTH_SECURITY_NONE;
}
