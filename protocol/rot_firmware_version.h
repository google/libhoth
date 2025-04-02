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

#ifndef _LIBHOTH_PROTOCOL_ROT_FIRMWARE_VERSION_H_
#define _LIBHOTH_PROTOCOL_ROT_FIRMWARE_VERSION_H_

#include "host_cmd.h"
#include "transports/libhoth_device.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HOTH_CMD_GET_VERSION 0x0002

struct hoth_response_get_version {
  // Null-terminated RO version string
  char version_string_ro[32];

  // Null-terminated RW version string
  char version_string_rw[32];

  char reserved[32];

  // One of ec_image
  uint32_t current_image;
} __hoth_align4;

int libhoth_get_rot_fw_version(struct libhoth_device* dev,
                               struct hoth_response_get_version* ver);

#ifdef __cplusplus
}
#endif

#endif  // _LIBHOTH_PROTOCOL_ROT_FIRWARE_VERSION_H_
