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

#include "htool_rot_usb.h"

#include <stdint.h>
#include <stdio.h>

#include "host_commands.h"
#include "htool_cmd.h"
#include "htool_target_control.h"

// USB mux control actions to Target control actions mapping
enum {
  ROT_USB_ACTION_GET = HOTH_TARGET_CONTROL_ACTION_GET_STATUS,
  ROT_USB_ACTION_CONNECT_ROT_TO_HOST = HOTH_TARGET_CONTROL_ACTION_ENABLE,
  ROT_USB_ACTION_CONNECT_ROT_TO_FRONT_PANEL =
      HOTH_TARGET_CONTROL_ACTION_DISABLE,
};

static const char* rot_usb_muxctrl_status_str_map(
    const enum hoth_target_control_status status) {
  switch (status) {
    case HOTH_TARGET_CONTROL_STATUS_ENABLED:
      return "RoT connected to host";
    case HOTH_TARGET_CONTROL_STATUS_DISABLED:
      return "RoT connected to front panel";
    default:
      return "Unknown";
  }
}

int htool_rot_usb_muxctrl_get(const struct htool_invocation* inv) {
  struct hoth_response_target_control response;
  int ret = target_control_perform_action(HOTH_TARGET_CONTROL_GENERIC_MUX,
                                          ROT_USB_ACTION_GET, &response);
  if (ret != 0) {
    return ret;
  }

  printf("USB Mux control status: %s\n",
         rot_usb_muxctrl_status_str_map(response.status));
  return 0;
}

int rot_usb_mux_control_change_select(
    const enum hoth_target_control_action action) {
  struct hoth_response_target_control response;

  int ret = target_control_perform_action(HOTH_TARGET_CONTROL_GENERIC_MUX,
                                          action, &response);
  if (ret != 0) {
    return ret;
  }
  const enum hoth_target_control_status old_status = response.status;

  ret = target_control_perform_action(HOTH_TARGET_CONTROL_GENERIC_MUX,
                                      ROT_USB_ACTION_GET, &response);
  if (ret != 0) {
    return ret;
  }
  const enum hoth_target_control_status new_status = response.status;

  printf("USB Mux control status changed: %s -> %s\n",
         rot_usb_muxctrl_status_str_map(old_status),
         rot_usb_muxctrl_status_str_map(new_status));
  return 0;
}

int htool_rot_usb_muxctrl_connect_rot_to_host(
    const struct htool_invocation* inv) {
  return rot_usb_mux_control_change_select(ROT_USB_ACTION_CONNECT_ROT_TO_HOST);
}

int htool_rot_usb_muxctrl_connect_rot_to_front_panel(
    const struct htool_invocation* inv) {
  return rot_usb_mux_control_change_select(
      ROT_USB_ACTION_CONNECT_ROT_TO_FRONT_PANEL);
}
