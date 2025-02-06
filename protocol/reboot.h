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

#ifndef LIBHOTH_PROTOCOL_REBOOT_H_
#define LIBHOTH_PROTOCOL_REBOOT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "transports/libhoth_device.h"

#define EC_CMD_REBOOT_EC 0x00D2

enum ec_reboot_cmd {
  EC_REBOOT_COLD = 4,
};

struct ec_params_reboot_ec {
  // enum ec_reboot_cmd
  uint8_t cmd;
  // Should be 0
  uint8_t flags;
} __ec_align1;

int libhoth_reboot(struct libhoth_device* dev);

#ifdef __cplusplus
}
#endif

#endif
