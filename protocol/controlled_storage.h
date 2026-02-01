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

#ifndef _LIBHOTH_PROTOCOL_CONTROLLED_STORAGE_H_
#define _LIBHOTH_PROTOCOL_CONTROLLED_STORAGE_H_

#include "host_cmd.h"
#include "transports/libhoth_device.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define HOTH_PRV_CMD_HOTH_CONTROLLED_STORAGE 0x0015
#define CONTROLLED_STORAGE_SIZE_MAX 128
#define CONTROLLED_STORAGE_SIZE 64

enum controlled_storage_op {
  CONTROLLED_STORAGE_READ = 0,
  CONTROLLED_STORAGE_WRITE = 1,
  CONTROLLED_STORAGE_DELETE = 2,
};

// Serves as the response to CONTROLLED_STORAGE_READ as well as payload to
// CONTROLLED_STORAGE_WRITE.
struct hoth_payload_controlled_storage {
  uint8_t data[CONTROLLED_STORAGE_SIZE];
} __attribute__((packed));

struct hoth_request_controlled_storage {
  /* The operation is one of controlled_storage_op. */
  uint32_t operation;
  /* Choose which (0-5) slot to operate on. */
  uint32_t slot;
  struct hoth_payload_controlled_storage payload;
} __attribute__((packed));

int libhoth_controlled_storage_read(
    struct libhoth_device* dev, uint32_t slot,
    struct hoth_payload_controlled_storage* payload, size_t* payload_len);
int libhoth_controlled_storage_write(struct libhoth_device* dev, uint32_t slot,
                                     const uint8_t* data, size_t len);
int libhoth_controlled_storage_delete(struct libhoth_device* dev,
                                      uint32_t slot);

#ifdef __cplusplus
}
#endif

#endif  // _LIBHOTH_PROTOCOL_CONTROLLED_STORAGE_H_
