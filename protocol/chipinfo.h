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

#ifndef LIBHOTH_PROTOCOL_CHIPINFO_H_
#define LIBHOTH_PROTOCOL_CHIPINFO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "transports/libhoth_device.h"

#define HOTH_PRV_CMD_HOTH_CHIP_INFO 0x0010
// Chipinfo response structure supporting both old structured format
// (Haven/Dauntless) and new 256-bit format (OpenTitan).
struct hoth_response_chip_info {
  uint8_t version;  // 0: Haven/Dauntless, 1: OpenTitan
  union {
    struct {
      uint64_t hardware_identity;
      uint16_t hardware_category;
      uint16_t reserved0;
      uint32_t info_variant;
    } haven_device_id;                 // Old format (16 bytes)
    uint8_t open_titan_device_id[32];  // New format (32 bytes) - OpenTitan
                                       // Device ID
  } data;
} __attribute__((packed, aligned(4)));

int libhoth_chipinfo(struct libhoth_device* dev,
                     struct hoth_response_chip_info* chipinfo);

#ifdef __cplusplus
}
#endif

#endif
