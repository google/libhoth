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
  uint8_t resp_buf[32];  // Max size for new format
  size_t resp_size;

  int ret = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_CHIP_INFO,
      /*version=*/0, NULL, 0, resp_buf, sizeof(resp_buf), &resp_size);

  if (ret != 0) {
    return ret;
  }

  if (resp_size == 16) {
    // Old format: structured data
    chipinfo->version = 0;
    memcpy(&chipinfo->data.haven_device_id, resp_buf, 16);
  } else if (resp_size == 32) {
    // New format: OpenTitan Device ID
    chipinfo->version = 1;
    memcpy(chipinfo->data.open_titan_device_id, resp_buf, 32);
  } else {
    // Unexpected size
    return HTOOL_ERROR_HOST_COMMAND_START + HOTH_RES_INVALID_PARAM;
  }

  return 0;
}
