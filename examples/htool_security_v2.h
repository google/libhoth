// Copyright 2024 Google LLC
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

#ifndef LIBHOTH_EXAMPLES_HTOOL_SECURITY_V2_H_
#define LIBHOTH_EXAMPLES_HTOOL_SECURITY_V2_H_

#include <stdint.h>

#include "transports/libhoth_device.h"

#ifdef __cplusplus
extern "C" {
#endif

// Structures used for lightweight passing of allocated buffers/params.
struct security_v2_buffer {
  uint8_t* data;
  uint16_t size;
  uint16_t bytes_consumed;
};
struct security_v2_param {
  void* data;
  uint16_t size;
};

// Convenience macro for initializing a buffer from allocated storage. Intended
// for passing as a parameter to htool_exec_security_v2_cmd.
#define SECURITY_V2_BUFFER_PARAM(storage) \
  (&(struct security_v2_buffer){.data = (storage), .size = sizeof((storage))})

// Executes a SECURITY_V2 host command with `major.minor` command code. The
// request/response buffers serve as backing storage for the command, and the
// request/response params represent data that will be copied to/from the
// buffers.
int htool_exec_security_v2_cmd(struct libhoth_device* dev, uint8_t major,
                               uint8_t minor, uint16_t base_command,
                               struct security_v2_buffer* request_buffer,
                               const struct security_v2_param* request_params,
                               uint16_t request_param_count,
                               struct security_v2_buffer* response_buffer,
                               struct security_v2_param* response_params,
                               uint16_t response_param_count);

#ifdef __cplusplus
}
#endif

#endif
