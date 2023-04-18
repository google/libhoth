// Copyright 2023 Google LLC
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

#ifndef _LIBHOTH_LIBHOTH_EC_H_
#define _LIBHOTH_LIBHOTH_EC_H_

#include <stdint.h>

struct ec_host_response {
  uint8_t struct_version;
  uint8_t checksum;
  uint16_t result;
  uint16_t data_len;
  uint16_t reserved;
} __attribute__((packed));

#endif  // _LIBHOTH_LIBHOTH_EC_H_
