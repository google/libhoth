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

#include "htool_target_usb.h"

#include <stdint.h>
#include <stdio.h>

#include "host_commands.h"
#include "htool_cmd.h"
#include "htool_target_control.h"

// USB mux control actions to Target control actions mapping
enum {
  TARGET_USB_ACTION_GET = EC_TARGET_CONTROL_ACTION_GET_STATUS,
  TARGET_USB_ACTION_CONNECT_TARGET_TO_HOST = EC_TARGET_CONTROL_ACTION_ENABLE,
  TARGET_USB_ACTION_CONNECT_TARGET_TO_FRONT_PANEL =
      EC_TARGET_CONTROL_ACTION_DISABLE,
};

static const char* target_usb_muxctrl_status_str_map(
    const enum ec_target_control_status status) {
  switch (status) {
    case EC_TARGET_CONTROL_STATUS_ENABLED:
      return "Target connected to host";
    case EC_TARGET_CONTROL_STATUS_DISABLED:
      return "Target connected to front panel";
    default:
      return "Unknown";
  }
}

int htool_target_usb_muxctrl_get(const struct htool_invocation* inv) {
  struct ec_response_target_control response;
  int ret = target_control_perform_action(EC_TARGET_CONTROL_GENERIC_MUX,
                                          TARGET_USB_ACTION_GET, &response);
  if (ret != 0) {
    return ret;
  }

  printf("USB Mux control status: %s\n",
         target_usb_muxctrl_status_str_map(response.status));
  return 0;
}

int target_usb_mux_control_change_select(
    const enum ec_target_control_action action) {
  struct ec_response_target_control response;

  int ret = target_control_perform_action(EC_TARGET_CONTROL_GENERIC_MUX, action,
                                          &response);
  if (ret != 0) {
    return ret;
  }
  const enum ec_target_control_status old_status = response.status;

  ret = target_control_perform_action(EC_TARGET_CONTROL_GENERIC_MUX,
                                      TARGET_USB_ACTION_GET, &response);
  if (ret != 0) {
    return ret;
  }
  const enum ec_target_control_status new_status = response.status;

  printf("USB Mux control status changed: %s -> %s\n",
         target_usb_muxctrl_status_str_map(old_status),
         target_usb_muxctrl_status_str_map(new_status));
  return 0;
}

int htool_target_usb_muxctrl_connect_target_to_host(
    const struct htool_invocation* inv) {
  return target_usb_mux_control_change_select(
      TARGET_USB_ACTION_CONNECT_TARGET_TO_HOST);
}

int htool_target_usb_muxctrl_connect_target_to_front_panel(
    const struct htool_invocation* inv) {
  return target_usb_mux_control_change_select(
      TARGET_USB_ACTION_CONNECT_TARGET_TO_FRONT_PANEL);
}
