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

#ifndef _LIBHOTH_PROTOCOL_FIRMWARE_UPDATE_H_
#define _LIBHOTH_PROTOCOL_FIRMWARE_UPDATE_H_

#include <stdint.h>

#include "protocol/host_cmd.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HOTH_CMD_FIRMWARE_UPDATE 0x3e4b

enum hoth_firmware_update_operation {  // NOLINT
  HOTH_FIRMWARE_UPDATE_OP_GET_STATUS = 0,
  // Update to the bundle at the provided |offset| and soft-reset the firmware.
  HOTH_FIRMWARE_UPDATE_OP_UPDATE_AND_RESET = 1,
};

struct hoth_request_firmware_update {
  uint32_t operation;  // Must be hoth_firmware_update_operation
  uint32_t flags;      // Not used right now. Reserved for future.
  uint32_t offset;     // Bundle offset in the active side of flash.
} __attribute__((packed, aligned(4)));

int libhoth_firmware_update_from_flash_and_reset(struct libhoth_device* dev,
                                                 uint32_t offset);

#ifdef __cplusplus
}
#endif

#endif  // _LIBHOTH_PROTOCOL_FIRMWARE_UPDATE_H_
