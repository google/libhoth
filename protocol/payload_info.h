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

#ifndef LIBHOTH_PROTOCOL_PAYLOAD_INFO_H_
#define LIBHOTH_PROTOCOL_PAYLOAD_INFO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct payload_version {
  uint32_t major;
  uint32_t minor;
  uint32_t point;
  uint32_t subpoint;
};

struct payload_info {
  char image_name[32];
  uint32_t image_family;
  struct payload_version image_version;
  uint8_t image_type;
  uint8_t image_hash[32];
};

bool libhoth_find_image_descriptor(uint8_t* image, size_t len, size_t* offset);
bool libhoth_payload_info(uint8_t* image, size_t len,
                          struct payload_info* payload_info);

#ifdef __cplusplus
}
#endif

#endif
