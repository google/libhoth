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

#include "command_version.h"

#include <stdint.h>

#include "host_cmd.h"
#include "transports/libhoth_device.h"

int libhoth_get_command_versions(struct libhoth_device* dev, uint16_t command,
                                 uint32_t* version_mask) {
  if (version_mask == NULL) {
    return -1;
  }
  return libhoth_hostcmd_exec(dev, HOTH_CMD_GET_CMD_VERSIONS,
                              /*version=*/1, &command, sizeof(command),
                              version_mask, sizeof(*version_mask), NULL);
}
