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

#ifndef LIBHOTH_PROTOCOL_SECURE_BOOT_H_
#define LIBHOTH_PROTOCOL_SECURE_BOOT_H_

#include <stdint.h>

#include "transports/libhoth_device.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HOTH_PRV_CMD_HOTH_SET_SECURE_BOOT_ENFORCEMENT 0x001C
#define HOTH_PRV_CMD_HOTH_GET_SECURE_BOOT_ENFORCEMENT 0x001D

enum secure_boot_enforcement_status {
  SECURE_BOOT_ENFORCEMENT_DISABLED = 0,
  SECURE_BOOT_ENFORCEMENT_ENABLED = 1,
};

struct secure_boot_enforcement_state {
  uint8_t enabled;       // enum secure_boot_enforcement_status
  uint8_t reserved0[3];  // Reserved. Write zeroes.
} __attribute__((packed));

// Get the current state of target secure boot enforcement.
int libhoth_secure_boot_get_enforcement(
    struct libhoth_device* dev,
    enum secure_boot_enforcement_status* enforcement);

// Enable secure boot enforcement. Disabling is done via a different,
// authorized, command.
int libhoth_secure_boot_enable_enforcement(struct libhoth_device* dev);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_PROTOCOL_SECURE_BOOT_H_
