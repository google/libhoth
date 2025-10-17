#ifndef HTOOL_SBS_DUAL_H_
#define HTOOL_SBS_DUAL_H_

#include "htool_cmd.h"

#define SBS_DUAL_GET_CMD_STR "get"
#define SBS_DUAL_CONNECT_TARGET_TO_SPI_FLASH_0_CMD_STR \
  "connect_target_to_spi_flash_0"
#define SBS_DUAL_CONNECT_TARGET_TO_SPI_FLASH_1_CMD_STR \
  "connect_target_to_spi_flash_1"

int htool_sbs_dual_run(const struct htool_invocation* inv);

#endif  // HTOOL_SBS_DUAL_H_
