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

#include "mauv.h"

#include <stddef.h>
#include <stdint.h>

#include "protocol/host_cmd.h"

libhoth_error libhoth_fetch_mauv(struct libhoth_device* dev, uint8_t state,
                                 uint8_t category,
                                 struct hoth_response_mauv* mauv) {
  struct mauv_request request = {
      .category = category,
      .state = state,
      .reserved_0 = 0,
  };

  size_t rlen = 0;
  libhoth_error err = libhoth_hostcmd_exec_v2(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HAVEN_MAUV, 0, &request,
      sizeof(request), mauv, sizeof(*mauv), &rlen);
  if (err != HOTH_SUCCESS) {
    return err;
  }

  if (rlen == sizeof(uint32_t)) {
    // Old version response: only returns the version number.
    return HOTH_SUCCESS;
  }

  if (rlen != sizeof(struct hoth_response_mauv)) {
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_FAIL);
  }

  return HOTH_SUCCESS;
}

libhoth_error libhoth_update_mauv(struct libhoth_device* dev,
                                  const void* record, size_t record_size) {
  if (record_size > MAUV_MAX_RECORD_SIZE) {
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_INVALID_PARAMETER);
  }

  size_t rlen = 0;
  return libhoth_hostcmd_exec_v2(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_UPDATE_MAUV, 0, record,
      record_size, NULL, 0, &rlen);
}
