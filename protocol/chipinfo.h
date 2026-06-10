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
#define OPENTITAN_DEVICE_ID_LEN 32

struct hoth_device_id {
  uint64_t hardware_identity;
  uint16_t hardware_category;
  uint16_t reserved0;
  uint32_t info_variant;
};

struct opentitan_device_id {
  uint16_t creator_id;
  uint16_t product_id;
  uint16_t device_year;
  uint8_t device_week;
  uint16_t lot_number;
  uint8_t wafer_number;
  uint16_t wafer_x;
  uint16_t wafer_y;
  uint8_t reserved_din;
  uint32_t reserved;
  uint8_t package_id;
  uint8_t ast_config_version;
  char otp_id[3];
  uint8_t otp_version;
  char sku_id_string[5];
  uint8_t sku_specific_version;
};

int parse_opentitan_device_id(const uint8_t* src,
                              struct opentitan_device_id* dst);

struct hoth_response_chip_info {
  uint32_t version;  // 0: old format, 1: OpenTitan
  uint32_t reserved;
  union {
    struct hoth_device_id hoth_device_id;  // Old format (16 bytes)
    uint8_t
        open_titan_device_id[OPENTITAN_DEVICE_ID_LEN];  // New format (32 bytes)
                                                        // - OpenTitan Device ID
  } data;
};

int libhoth_chipinfo(struct libhoth_device* dev,
                     struct hoth_response_chip_info* chipinfo);

#ifdef __cplusplus
}
#endif

#endif
