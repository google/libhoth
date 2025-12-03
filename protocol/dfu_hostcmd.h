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

// Code for performing a device-firmware update using host commands.

#ifndef _LIBHOTH_PROTOCOL_DFU_HOSTCMD_H_
#define _LIBHOTH_PROTOCOL_DFU_HOSTCMD_H_

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "protocol/host_cmd.h"
#include "transports/libhoth_device.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HOTH_CMD_DFU_WRITE 0x3e4f
#define HOTH_CMD_DFU_COMPLETE 0x3e50

enum {
  HOTH_DFU_TARGET_EARLGREY_FW_UPDATE = 0x77664745,
};

struct hoth_dfu_nonce {
  uint32_t low;
  uint32_t high;
};

struct hoth_dfu_session_id {
  /// The nonce should be randomly generated at the start of the session; it
  /// is used to detect simultaneous use of the DFU functionality.
  struct hoth_dfu_nonce nonce;

  // One of HOTH_DFU_TARGET_* constants
  uint32_t target;
};
static_assert(offsetof(struct hoth_dfu_session_id, nonce) == 0);
static_assert(offsetof(struct hoth_dfu_session_id, target) == 8);
static_assert(sizeof(struct hoth_dfu_session_id) == 12);

enum {
  // Set if this is the first chunk of a new DFU session.
  HOTH_DFU_WRITE_FLAGS_NEW_SESSION = (1 << 0)
};

struct hoth_dfu_write_request_header {
  struct hoth_dfu_session_id session_id;

  // combination of HOTH_DFU_WRITE_FLAGS_*
  uint32_t flags;
};
static_assert(offsetof(struct hoth_dfu_write_request_header, session_id) == 0);
static_assert(offsetof(struct hoth_dfu_write_request_header, flags) == 12);
static_assert(sizeof(struct hoth_dfu_write_request_header) == 16);

enum {
  // Set ifwe should restart the chip into the new firmware.
  HOTH_DFU_COMPLETE_FLAGS_COLD_RESTART = (1 << 0),

  // Set if we should do a warm restart the chip into the new firmware.
  HOTH_DFU_COMPLETE_FLAGS_WARM_RESTART = (1 << 1),
};

struct hoth_dfu_complete_request {
  struct hoth_dfu_session_id session_id;

  // combination of HOTH_DFU_COMPLETE_FLAGS_*
  uint32_t flags;
};
static_assert(offsetof(struct hoth_dfu_complete_request, session_id) == 0);
static_assert(offsetof(struct hoth_dfu_complete_request, flags) == 12);
static_assert(sizeof(struct hoth_dfu_complete_request) == 16);

/**
 * @brief Update the firmware on the device using DFU host commands.
 *
 * This function sends the provided firmware image to the device in chunks
 * and then sends a DFU complete command to finalize the update.
 *
 * @param dev The libhoth device handle.
 * @param image A pointer to the firmware image data.
 * @param image_size The size of the firmware image in bytes.
 * @param complete_flags Flags to be passed to the DFU complete command,
 *                       e.g., HOTH_DFU_COMPLETE_FLAGS_COLD_RESTART.
 * @return 0 on success, -1 on failure.
 */
int libhoth_dfu_update(struct libhoth_device* dev, const uint8_t* image,
                       size_t image_size, uint32_t complete_flags);

#ifdef __cplusplus
}
#endif

#endif  // _LIBHOTH_PROTOCOL_DFU_HOSTCMD_H_