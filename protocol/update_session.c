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

#include "protocol/update_session.h"

#include <stddef.h>
#include <stdint.h>

#include "protocol/host_cmd.h"
#include "protocol/status.h"
#include "transports/libhoth_device.h"

libhoth_error libhoth_update_session_start(struct libhoth_device* dev,
                                           uint32_t timeout_seconds) {
  if (dev == NULL || timeout_seconds == 0) {
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_INVALID_PARAMETER);
  }

  struct update_session_start_request req = {
      .timeout_seconds = timeout_seconds,
  };
  size_t rlen = 0;
  return libhoth_hostcmd_exec_v2(
      dev,
      HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_UPDATE_SESSION_START, 0,
      &req, sizeof(req), NULL, 0, &rlen);
}

libhoth_error libhoth_update_session_finalize(struct libhoth_device* dev) {
  if (dev == NULL) {
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_INVALID_PARAMETER);
  }

  size_t rlen = 0;
  return libhoth_hostcmd_exec_v2(
      dev,
      HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_UPDATE_SESSION_FINALIZE,
      0, NULL, 0, NULL, 0, &rlen);
}

libhoth_error libhoth_update_session_get_status(
    struct libhoth_device* dev, struct update_session_status_response* status) {
  if (dev == NULL || status == NULL) {
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_INVALID_PARAMETER);
  }

  size_t rlen = 0;
  libhoth_error err =
      libhoth_hostcmd_exec_v2(dev,
                              HOTH_CMD_BOARD_SPECIFIC_BASE +
                                  HOTH_PRV_CMD_HOTH_UPDATE_SESSION_GET_STATUS,
                              0, NULL, 0, status, sizeof(*status), &rlen);
  if (err != HOTH_SUCCESS) {
    return err;
  }
  if (rlen != sizeof(*status)) {
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_FAIL);
  }
  return HOTH_SUCCESS;
}

const char* libhoth_update_session_state_string(
    enum update_session_state state) {
  switch (state) {
    case UPDATE_SESSION_NONE:
      return "NONE";
    case UPDATE_SESSION_PENDING_START:
      return "PENDING_START";
    case UPDATE_SESSION_UPDATING:
      return "UPDATING";
    case UPDATE_SESSION_FINALIZED:
      return "FINALIZED";
    case UPDATE_SESSION_START_TIMEOUT:
      return "START_TIMEOUT";
    case UPDATE_SESSION_UPDATE_TIMEOUT:
      return "UPDATE_TIMEOUT";
    default:
      return "UNKNOWN";
  }
}
