#include "htool_sbs_single.h"

#include <stdio.h>
#include <string.h>

#include "host_commands.h"
#include "htool_cmd.h"
#include "htool_target_control.h"

const char* sbs_single_status_str(uint16_t status);

static int sbs_single_perform_action(enum hoth_target_control_action action) {
  struct hoth_response_target_control response;
  int ret = target_control_perform_action(HOTH_TARGET_CONTROL_SBS_MUX_SINGLE,
                                          action, &response);
  if (ret) {
    return ret;
  }
  printf("Previous SBS Mux State: %s\n",
         sbs_single_status_str(response.status));
  return 0;
}

static int sbs_single_get_status(void) {
  struct hoth_response_target_control response;
  int ret = target_control_perform_action(HOTH_TARGET_CONTROL_SBS_MUX_SINGLE,
                                          HOTH_TARGET_CONTROL_ACTION_GET_STATUS,
                                          &response);
  if (ret) {
    return ret;
  }

  printf("%s\n", sbs_single_status_str(response.status));
  return 0;
}

const char* sbs_single_status_str(uint16_t status) {
  switch (status) {
    case HOTH_TARGET_CONTROL_SBS_SINGLE_MUX_CONNECTED_FLASH_TO_ROT:
      return "Flash connected to RoT";
    case HOTH_TARGET_CONTROL_SBS_SINGLE_MUX_CONNECTED_FLASH_TO_TARGET:
      return "Flash connected to target";
    default:
      return "Unknown\n";
  }
}

int htool_sbs_single_run(const struct htool_invocation* inv) {
  const char* subcommand = inv->cmd->verbs[1];
  if (strcmp(subcommand, SBS_SINGLE_GET_CMD_STR) == 0) {
    return sbs_single_get_status();
  } else if (strcmp(subcommand, SBS_SINGLE_CONNECT_FLASH_TO_ROT_CMD_STR) == 0) {
    return sbs_single_perform_action(
        HOTH_TARGET_CONTROL_ACTION_SBS_MUX_SINGLE_CONNECT_FLASH_TO_ROT);
  } else if (strcmp(subcommand, SBS_SINGLE_CONNECT_FLASH_TO_TARGET_CMD_STR) ==
             0) {
    return sbs_single_perform_action(
        HOTH_TARGET_CONTROL_ACTION_SBS_MUX_SINGLE_CONNECT_FLASH_TO_TARGET);
  } else {
    fprintf(stderr, "Invalid subcommand: %s\n", subcommand);
    return -1;
  }
  return 0;
}
