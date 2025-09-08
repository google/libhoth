#include "htool_sbs.h"

#include <stdio.h>
#include <string.h>

#include "host_commands.h"
#include "htool_cmd.h"
#include "htool_target_control.h"

static int sbs_perform_action(enum hoth_target_control_action action) {
  struct hoth_response_target_control response;
  int ret = target_control_perform_action(HOTH_TARGET_CONTROL_SBS_MUX, action,
                                          &response);
  if (ret) {
    return ret;
  }
  printf("Previous SBS Mux State: %s\n",
         response.status == HOTH_TARGET_CONTROL_STATUS_ENABLED ? "enabled"
                                                              : "disabled");
  return 0;
}

static int sbs_get_status(void) {
  struct hoth_response_target_control response;
  int ret = target_control_perform_action(
      HOTH_TARGET_CONTROL_SBS_MUX, HOTH_TARGET_CONTROL_ACTION_GET_STATUS,
      &response);
  if (ret) {
    return ret;
  }

  switch (response.status) {
    case HOTH_TARGET_CONTROL_SBS_MUX_TARGET_CONNECTED_TO_SPI_FLASH_0:
      printf("Target connected to spi flash 0 / Flash connected to RoT\n");
      break;
    case HOTH_TARGET_CONTROL_SBS_MUX_TARGET_CONNECTED_TO_SPI_FLASH_1:
      printf("Target connected to spi flash 1 / Flash connected to target\n");
      break;
    default:
      printf("Unknown\n");
      break;
  }
  return 0;
}

int htool_sbs_run(const struct htool_invocation* inv) {
  const char* subcommand = inv->cmd->verbs[1];
  if (strcmp(subcommand, SBS_GET_CMD_STR) == 0) {
    return sbs_get_status();
  } else if (strcmp(subcommand, SBS_CONNECT_FLASH_TO_ROT_CMD_STR) == 0) {
    return sbs_perform_action(HOTH_TARGET_CONTROL_ACTION_SBS_MUX_CONNECT_FLASH_TO_ROT);
  } else if (strcmp(subcommand, SBS_CONNECT_FLASH_TO_TARGET_CMD_STR) == 0) {
    return sbs_perform_action(HOTH_TARGET_CONTROL_ACTION_SBS_MUX_CONNECT_FLASH_TO_TARGET);
  } else if (strcmp(subcommand,
                    SBS_CONNECT_TARGET_TO_SPI_FLASH_0_CMD_STR) == 0) {
    return sbs_perform_action(
        HOTH_TARGET_CONTROL_ACTION_SBS_MUX_CONNECT_TARGET_TO_SPI_FLASH_0);
  } else if (strcmp(subcommand,
                    SBS_CONNECT_TARGET_TO_SPI_FLASH_1_CMD_STR) == 0) {
    return sbs_perform_action(
        HOTH_TARGET_CONTROL_ACTION_SBS_MUX_CONNECT_TARGET_TO_SPI_FLASH_1);
  } else {
    fprintf(stderr, "Invalid subcommand: %s\n", subcommand);
    return -1;
  }
  return 0;
}
