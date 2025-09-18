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

#ifndef LIBHOTH_PROTOCOL_COMMAND_VERSION_H_
#define LIBHOTH_PROTOCOL_COMMAND_VERSION_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "transports/libhoth_device.h"

#define HOTH_CMD_GET_CMD_VERSIONS 0x0008

int libhoth_get_command_versions(struct libhoth_device* dev, uint16_t command,
                                 uint32_t* version_mask);

#ifdef __cplusplus
}
#endif

#endif
