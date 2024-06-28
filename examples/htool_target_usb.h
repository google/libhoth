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

#ifndef LIBHOTH_EXAMPLES_HTOOL_TARGET_USB_H_
#define LIBHOTH_EXAMPLES_HTOOL_TARGET_USB_H_

#ifdef __cplusplus
extern "C" {
#endif

#define TARGET_USB_MUXCTRL_CMD_STR "mux_ctrl"
#define TARGET_USB_MUXCTRL_GET_SUBCMD_STR "get"
#define TARGET_USB_MUXCTRL_CONNECT_TARGET_TO_HOST_SUBCMD_STR \
  "connect_target_to_host"
#define TARGET_USB_MUXCTRL_CONNECT_TARGET_TO_FRONT_PANEL \
  "connect_target_to_front_panel"

// Forward declaration
struct htool_invocation;

int htool_target_usb_muxctrl_get(const struct htool_invocation* inv);

int htool_target_usb_muxctrl_connect_target_to_host(
    const struct htool_invocation* inv);

int htool_target_usb_muxctrl_connect_target_to_front_panel(
    const struct htool_invocation* inv);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_HTOOL_TARGET_USB_H_
