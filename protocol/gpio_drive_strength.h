// Copyright 2026 Google LLC
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

#ifndef _LIBHOTH_PROTOCOL_GPIO_DRIVE_STRENGTH_H_
#define _LIBHOTH_PROTOCOL_GPIO_DRIVE_STRENGTH_H_

#include <stdint.h>

#include "protocol/host_cmd.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HOTH_CMD_SET_GPIO_DRIVE_STRENGTH 0x3E56
#define MAX_GPIO_DRIVE_STRENGTH 0xF

struct hoth_request_set_gpio_drive_strength {
  uint8_t pad;
  uint8_t strength;
} __hoth_align1;

int libhoth_set_gpio_drive_strength(struct libhoth_device* dev, uint8_t pad,
                                    uint8_t strength);

#ifdef __cplusplus
}
#endif

#endif  // _LIBHOTH_PROTOCOL_GPIO_DRIVE_STRENGTH_H_
