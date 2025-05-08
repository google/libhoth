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

#ifndef _LIBHOTH_PROTOCOL_HELLO_H_
#define _LIBHOTH_PROTOCOL_HELLO_H_

#include <stdint.h>

#include "protocol/host_cmd.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HOTH_CMD_HELLO 0x0001

struct hoth_request_hello {
  // Pass anything here
  uint32_t input;
} __hoth_align4;

struct hoth_response_hello {
  // Output will be input + 0x01020304.
  uint32_t output;
} __hoth_align4;

int libhoth_hello(struct libhoth_device* dev, uint32_t input, uint32_t* output);

#ifdef __cplusplus
}
#endif

#endif  // _LIBHOTH_PROTOCOL_HELLO_H_
