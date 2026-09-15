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

#ifndef LIBHOTH_PROTOCOL_UPDATE_SESSION_H_
#define LIBHOTH_PROTOCOL_UPDATE_SESSION_H_

#include <stdint.h>

#include "protocol/status.h"
#include "transports/libhoth_device.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HOTH_PRV_CMD_HOTH_UPDATE_SESSION_START 0x005a
#define HOTH_PRV_CMD_HOTH_UPDATE_SESSION_FINALIZE 0x005b
#define HOTH_PRV_CMD_HOTH_UPDATE_SESSION_GET_STATUS 0x005c

#define EC_PRV_CMD_UPDATE_SESSION_START 0x005a
#define EC_PRV_CMD_UPDATE_SESSION_FINALIZE 0x005b
#define EC_PRV_CMD_UPDATE_SESSION_GET_STATUS 0x005c

enum update_session_state {
  UPDATE_SESSION_NONE = 0,
  UPDATE_SESSION_PENDING_START = 1,
  UPDATE_SESSION_UPDATING = 2,
  UPDATE_SESSION_FINALIZED = 3,
  UPDATE_SESSION_START_TIMEOUT = 4,
  UPDATE_SESSION_UPDATE_TIMEOUT = 5,
};

struct update_session_start_request {
  uint32_t timeout_seconds;
} __attribute__((packed, aligned(4)));

struct update_session_status_response {
  uint32_t current_state;
  uint32_t timeout_seconds_left;
} __attribute__((packed, aligned(4)));

// Start an update session with the requested timeout in seconds.
libhoth_error libhoth_update_session_start(struct libhoth_device* dev,
                                           uint32_t timeout_seconds);

// Finalize the active update session.
libhoth_error libhoth_update_session_finalize(struct libhoth_device* dev);

// Get the current update session status.
libhoth_error libhoth_update_session_get_status(
    struct libhoth_device* dev, struct update_session_status_response* status);

// Returns a human-readable string representation of the update session state.
const char* libhoth_update_session_state_string(
    enum update_session_state state);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_PROTOCOL_UPDATE_SESSION_H_
