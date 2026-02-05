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

#include "i2c.h"

#include <stdio.h>

#include "host_cmd.h"

int libhoth_i2c_detect(struct libhoth_device* dev,
                       struct hoth_request_i2c_detect* req,
                       struct hoth_response_i2c_detect* resp) {
  size_t rLen = 0;
  int ret = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_I2C_DETECT, 0, req,
      sizeof(*req), resp, sizeof(*resp), &rLen);
  if (ret != 0) {
    fprintf(stderr, "HOTH_I2C_DETECT error code: %d\n", ret);
    return -1;
  }
  if (rLen != sizeof(*resp)) {
    fprintf(stderr,
            "HOTH_I2C_DETECT expected exactly %ld response "
            "bytes, got %ld\n",
            sizeof(*resp), rLen);
    return -1;
  }

  return ret;
}

void libhoth_i2c_device_list(uint8_t* devices_mask, uint32_t devices_count,
                             uint8_t* device_list) {
  if (!devices_count) {
    return;
  }

  uint32_t found_devs = 0;

  for (uint8_t i = 0; i < I2C_DETECT_DATA_MAX_SIZE_BYTES; i++) {
    for (uint8_t b = 0; b < 8; b++) {
      if (devices_mask[i] & (1 << b)) {
        device_list[found_devs] = (i * 8 + b);
        found_devs++;
        if (devices_count == found_devs) {
          return;
        }
      }
    }
  }

  return;
}

int libhoth_i2c_transfer(struct libhoth_device* dev,
                         struct hoth_request_i2c_transfer* req,
                         struct hoth_response_i2c_transfer* resp) {
  size_t rLen = 0;
  int ret = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_I2C_TRANSFER, 0,
      req, sizeof(*req), resp, sizeof(*resp), &rLen);
  if (ret != 0) {
    fprintf(stderr, "HOTH_I2C_TRANSFER error code: %d\n", ret);
    return -1;
  }
  if (rLen != sizeof(*resp)) {
    fprintf(stderr,
            "HOTH_I2C_TRANSFER expected exactly %ld response "
            "bytes, got %ld\n",
            sizeof(*resp), rLen);
    return -1;
  }

  return ret;
}
