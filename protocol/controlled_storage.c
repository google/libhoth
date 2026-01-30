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

#include "protocol/controlled_storage.h"

#include <string.h>

#include "controlled_storage.h"

int libhoth_controlled_storage_read(
    struct libhoth_device* dev, uint32_t slot,
    struct hoth_payload_controlled_storage* payload, size_t* payload_len) {
  struct hoth_request_controlled_storage req = {};

  req.operation = CONTROLLED_STORAGE_READ;
  req.slot = slot;
  return libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_CONTROLLED_STORAGE,
      /*version=*/0, &req, sizeof(req), payload, sizeof(*payload), payload_len);
}

int libhoth_controlled_storage_write(struct libhoth_device* dev, uint32_t slot,
                                     const uint8_t* data, size_t len) {
  struct hoth_request_controlled_storage req = {};
  if (len > sizeof(req.payload.data)) {
    return -1;
  }

  req.operation = CONTROLLED_STORAGE_WRITE;
  req.slot = slot;
  memcpy(req.payload.data, data, len);
  return libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_CONTROLLED_STORAGE,
      /*version=*/0, &req,
      sizeof(req) - sizeof(struct hoth_payload_controlled_storage) + len, NULL,
      0, NULL);
}

int libhoth_controlled_storage_delete(struct libhoth_device* dev,
                                      uint32_t slot) {
  struct hoth_request_controlled_storage req = {};

  req.operation = CONTROLLED_STORAGE_DELETE;
  req.slot = slot;
  return libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_CONTROLLED_STORAGE,
      /*version=*/0, &req,
      sizeof(req) - sizeof(struct hoth_payload_controlled_storage), NULL, 0,
      NULL);
}
