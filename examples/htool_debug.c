
// Copyright 2025 Google LLC
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
#include "htool_debug.h"

#include <stdio.h>

#include "host_commands.h"
#include "htool_target_control.h"
int htool_target_debug_enable(const struct htool_invocation* inv) {
  (void)inv;
  struct hoth_response_target_control response;
  int ret = target_control_perform_action(
      HOTH_TARGET_CONTROL_DEBUG, HOTH_TARGET_CONTROL_ACTION_ENABLE, &response);
  if (ret != 0) {
    return ret;
  }
  printf("Target debug enabled.\n");
  return 0;
}
int htool_target_debug_disable(const struct htool_invocation* inv) {
  (void)inv;
  struct hoth_response_target_control response;
  int ret = target_control_perform_action(
      HOTH_TARGET_CONTROL_DEBUG, HOTH_TARGET_CONTROL_ACTION_DISABLE, &response);
  if (ret != 0) {
    return ret;
  }
  printf("Target debug disabled.\n");
  return 0;
}
int htool_target_debug_get(const struct htool_invocation* inv) {
  (void)inv;
  struct hoth_response_target_control response;
  int ret = target_control_perform_action(HOTH_TARGET_CONTROL_DEBUG,
                                          HOTH_TARGET_CONTROL_ACTION_GET_STATUS,
                                          &response);
  if (ret != 0) {
    return ret;
  }
  switch (response.status) {
    case HOTH_TARGET_CONTROL_STATUS_ENABLED:
      printf("Target debug status: Enabled\n");
      break;
    case HOTH_TARGET_CONTROL_STATUS_DISABLED:
      printf("Target debug status: Disabled\n");
      break;
    default:
      printf("Target debug status: Unknown\n");
      break;
  }
  return 0;
}
