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

#include "protocol/target_watchdog.h"

#include <stddef.h>

#include "protocol/host_cmd.h"
#include "protocol/status.h"

libhoth_error libhoth_pet_target_watchdog(struct libhoth_device* dev,
                                          uint64_t notify_cookie) {
  if (dev == NULL) {
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_INVALID_PARAMETER);
  }

  struct ec_request_pet_target_watchdog req = {
      .notify_cookie = notify_cookie,
  };

  return libhoth_hostcmd_exec_v2(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_PET_TARGET_WATCHDOG,
      /*version=*/0, &req, sizeof(req), /*resp_buf=*/NULL,
      /*resp_buf_size=*/0, /*out_resp_size=*/NULL);
}
