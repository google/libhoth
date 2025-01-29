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

#include "htool_target_control.h"

#include <stdint.h>
#include <stdio.h>

#include "host_commands.h"
#include "htool.h"

int target_control_perform_action(
    const enum ec_target_control_function function,
    const enum ec_target_control_action action,
    struct ec_response_target_control* const response) {
  if (response == NULL) {
    return -1;
  }

  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  const struct ec_request_target_control request = {
      .function = function,
      .action = action,
  };

  size_t response_length = 0;
  int ret = hostcmd_exec(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_TARGET_CONTROL,
      /*version=*/0, &request, sizeof(request), response, sizeof(*response),
      &response_length);

  if (ret != 0) {
    fprintf(stderr, "HOTH_TARGET_CONTROL error code: %d\n", ret);
    switch (ret) {
      case (HTOOL_ERROR_HOST_COMMAND_START + EC_RES_INVALID_COMMAND):
        fprintf(stderr,
                "Command not supported, or requested action is forbidden on "
                "function. Please confirm if the RoT FW version supports this "
                "command, and requested action is allowed on the function\n");
        break;
      case (HTOOL_ERROR_HOST_COMMAND_START + EC_RES_INVALID_PARAM):
        fprintf(stderr,
                "Invalid function or action. Please confirm if the RoT "
                "firmware version supports the given function, and action on "
                "that function is correct\n");
        break;
      case (HTOOL_ERROR_HOST_COMMAND_START + EC_RES_ACCESS_DENIED):
        fprintf(stderr,
                "Not authorized to perform requested action on function. "
                "Please use `authz_host_command` commands to authorize RoT to "
                "perform requested action on function\n");
        break;
    }
    return -1;
  }
  if (response_length != sizeof(*response)) {
    fprintf(
        stderr,
        "HOTH_TARGET_CONTROL expected exactly %zu response bytes, got %zu\n",
        sizeof(*response), response_length);
    return -1;
  }

  return 0;
}
