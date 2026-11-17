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

#include "protocol/flash_uid.h"

#include <stddef.h>
#include <stdint.h>

#include "protocol/host_cmd.h"

libhoth_error libhoth_get_flash_uid(
    struct libhoth_device* dev, struct hoth_response_get_flash_uid* response) {
  if (dev == NULL || response == NULL) {
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_INVALID_PARAMETER);
  }
  libhoth_error err = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_GET_FLASH_UID,
      /*version=*/0, NULL, 0, response, sizeof(*response),
      /*out_resp_size=*/NULL);
  if (err != HOTH_SUCCESS) {
    return err;
  }
  if (response->device_count > HOTH_FLASH_MAX_DEVICES) {
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_FAIL);
  }
  for (uint8_t i = 0; i < response->device_count; ++i) {
    if (response->devices[i].uid_len > HOTH_FLASH_UID_MAX_LEN) {
      return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                   LIBHOTH_ERR_FAIL);
    }
  }
  return HOTH_SUCCESS;
}
