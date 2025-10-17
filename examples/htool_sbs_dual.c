#include "htool_sbs_dual.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "host_commands.h"
#include "htool_cmd.h"
#include "htool_target_control.h"

const char* sbs_dual_status_str(uint16_t status);

static int sbs_dual_perform_action(enum hoth_target_control_action action) {
  struct hoth_response_target_control response;
  int ret = target_control_perform_action(HOTH_TARGET_CONTROL_SBS_MUX_DUAL,
                                          action, &response);
  if (ret) {
    return ret;
  }
  printf("Previous SBS Mux State: %s\n", sbs_dual_status_str(response.status));
  return 0;
}

static int sbs_dual_get_status(void) {
  struct hoth_response_target_control response;
  int ret = target_control_perform_action(HOTH_TARGET_CONTROL_SBS_MUX_DUAL,
                                          HOTH_TARGET_CONTROL_ACTION_GET_STATUS,
                                          &response);
  if (ret) {
    return ret;
  }

  printf("%s\n", sbs_dual_status_str(response.status));
  return 0;
}

const char* sbs_dual_status_str(uint16_t status) {
  switch (status) {
    case HOTH_TARGET_CONTROL_SBS_MUX_DUAL_TARGET_CONNECTED_TO_SPI_FLASH_0:
      return "Target connected to spi flash 0";
    case HOTH_TARGET_CONTROL_SBS_MUX_DUAL_TARGET_CONNECTED_TO_SPI_FLASH_1:
      return "Target connected to spi flash 1";
    default:
      return "Unknown\n";
  }
}

int htool_sbs_dual_run(const struct htool_invocation* inv) {
  const char* subcommand = inv->cmd->verbs[1];
  if (strcmp(subcommand, SBS_DUAL_GET_CMD_STR) == 0) {
    return sbs_dual_get_status();
  } else if (strcmp(subcommand,
                    SBS_DUAL_CONNECT_TARGET_TO_SPI_FLASH_0_CMD_STR) == 0) {
    return sbs_dual_perform_action(
        HOTH_TARGET_CONTROL_ACTION_SBS_MUX_DUAL_CONNECT_TARGET_TO_SPI_FLASH_0);
  } else if (strcmp(subcommand,
                    SBS_DUAL_CONNECT_TARGET_TO_SPI_FLASH_1_CMD_STR) == 0) {
    return sbs_dual_perform_action(
        HOTH_TARGET_CONTROL_ACTION_SBS_MUX_DUAL_CONNECT_TARGET_TO_SPI_FLASH_1);
  } else {
    fprintf(stderr, "Invalid subcommand: %s\n", subcommand);
    return -1;
  }
  return 0;
}
