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

#include "chipinfo.h"

#include <string.h>

#include "host_cmd.h"

int libhoth_chipinfo(struct libhoth_device* dev,
                     struct hoth_response_chip_info* chipinfo) {
  uint8_t resp_buf[OPENTITAN_DEVICE_ID_LEN];  // Max size for new format
  size_t resp_size;

  int ret = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_CHIP_INFO,
      /*version=*/0, NULL, 0, resp_buf, sizeof(resp_buf), &resp_size);

  if (ret != 0) {
    return ret;
  }

  if (resp_size == sizeof(struct hoth_device_id)) {
    // Old format: structured data
    chipinfo->version = 0;
    memcpy(&chipinfo->data.hoth_device_id, resp_buf,
           sizeof(struct hoth_device_id));
  } else if (resp_size == OPENTITAN_DEVICE_ID_LEN) {
    // New format: OpenTitan Device ID
    chipinfo->version = 1;
    memcpy(chipinfo->data.open_titan_device_id, resp_buf,
           OPENTITAN_DEVICE_ID_LEN);
  } else {
    // Unexpected size
    return HTOOL_ERROR_HOST_COMMAND_START + HOTH_RES_INVALID_PARAM;
  }

  return 0;
}

int parse_opentitan_device_id(const uint8_t* src,
                              struct opentitan_device_id* dst) {
  if (src == NULL || dst == NULL) {
    return -1;
  }

  dst->creator_id = (uint16_t)(src[31]) | (src[30] << 8);
  dst->product_id = (uint16_t)(src[29]) | (src[28] << 8);
  dst->device_year = 2020 + (src[27] & 0x0F);
  dst->device_week = (src[26] & 0x0F) * 10 + (src[27] >> 4);
  dst->lot_number =
      (src[25] >> 4) * 100 + (src[25] & 0x0F) * 10 + (src[26] >> 4);
  dst->wafer_number = (src[24] >> 4) * 10 + (src[24] & 0x0F);
  dst->wafer_x =
      (src[22] & 0x0F) * 100 + (src[23] >> 4) * 10 + (src[23] & 0x0F);
  dst->wafer_y = (src[21] >> 4) * 100 + (src[21] & 0x0F) * 10 + (src[22] >> 4);
  dst->reserved_din = src[20];
  dst->reserved = (src[16] << 24) | (src[17] << 16) | (src[18] << 8) | src[19];
  dst->package_id = src[15];
  dst->ast_config_version = src[14];
  dst->otp_id[0] = src[12];
  dst->otp_id[1] = src[13];
  dst->otp_id[2] = '\0';
  dst->otp_version = src[11];
  dst->sku_id_string[0] = src[4];
  dst->sku_id_string[1] = src[5];
  dst->sku_id_string[2] = src[6];
  dst->sku_id_string[3] = src[7];
  dst->sku_id_string[4] = '\0';
  dst->sku_specific_version = src[0];

  return 0;
}
