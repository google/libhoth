
#include "htool_security_version.h"

#include <stddef.h>
#include <stdint.h>

#include "host_commands.h"
#include "htool.h"
#include "protocol/host_cmd.h"

libhoth_security_version htool_get_security_version(
    struct libhoth_device* dev) {
  uint16_t command;
  int status;
  uint8_t is_supported;

  // Check if SecurityV2 is supported.
  command = HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2);
  status = libhoth_hostcmd_exec(
      dev, HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_IS_HOST_COMMAND_SUPPORTED), 0,
      &command, sizeof(command), &is_supported, sizeof(is_supported), NULL);
  if (status != 0) {
    return LIBHOTH_SECURITY_UNKNOWN;
  }
  if (is_supported) {
    return LIBHOTH_SECURITY_V2;
  }

  // Check if SecurityV3 is supported.
  command = HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V3);
  status = libhoth_hostcmd_exec(
      dev, HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_IS_HOST_COMMAND_SUPPORTED), 0,
      &command, sizeof(command), &is_supported, sizeof(is_supported), NULL);
  if (status != 0) {
    return LIBHOTH_SECURITY_UNKNOWN;
  }
  if (is_supported) {
    return LIBHOTH_SECURITY_V3;
  }

  return LIBHOTH_SECURITY_NONE;
}
