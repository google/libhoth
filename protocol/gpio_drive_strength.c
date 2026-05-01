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

#include "protocol/gpio_drive_strength.h"

#include <stddef.h>
#include <stdint.h>

#include "protocol/host_cmd.h"

int libhoth_set_gpio_drive_strength(struct libhoth_device* const dev,
                                    const uint8_t pad, const uint8_t strength) {
  const struct hoth_request_set_gpio_drive_strength request = {
      .pad = pad,
      .strength = strength,
  };
  return libhoth_hostcmd_exec(dev, HOTH_CMD_SET_GPIO_DRIVE_STRENGTH,
                              /*version=*/0, &request, sizeof(request),
                              /*response=*/NULL, /*response_size=*/0, NULL);
}
