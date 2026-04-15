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

int libhoth_fetch_mauv(struct libhoth_device* dev, uint8_t state,
                       uint8_t category, struct hoth_response_mauv* mauv) {
  struct mauv_request request = {
      .category = category,
      .state = state,
      .reserved_0 = 0,
  };

  size_t rlen = 0;
  int ret = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HAVEN_MAUV, 0, &request,
      sizeof(request), mauv, sizeof(*mauv), &rlen);
  if (ret != 0) {
    return ret;
  }

  if (rlen == sizeof(uint32_t)) {
    // Old version response: only returns the version number.
    return 0;
  }

  if (rlen != sizeof(struct hoth_response_mauv)) {
    return -1;
  }

  return 0;
}
