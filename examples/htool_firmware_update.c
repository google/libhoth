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

#include "htool_firmware_update.h"

#include <stdint.h>

#include "htool.h"
#include "htool_cmd.h"
#include "protocol/firmware_update.h"

int htool_firmware_update(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }
  uint32_t offset = 0;
  if (htool_get_param_u32(inv, "offset", &offset)) {
    return -1;
  }
  return libhoth_firmware_update_from_flash_and_reset(dev, offset);
}
