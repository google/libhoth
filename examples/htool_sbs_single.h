#ifndef HTOOL_SBS_SINGLE_H_
#define HTOOL_SBS_SINGLE_H_

#include "htool_cmd.h"

#define SBS_SINGLE_GET_CMD_STR "get"
#define SBS_SINGLE_CONNECT_FLASH_TO_ROT_CMD_STR "connect_flash_to_rot"
#define SBS_SINGLE_CONNECT_FLASH_TO_TARGET_CMD_STR "connect_flash_to_target"

int htool_sbs_single_run(const struct htool_invocation* inv);

#endif  // HTOOL_SBS_SINGLE_H_
