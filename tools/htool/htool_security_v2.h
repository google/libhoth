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

struct security_v2_serialized_param {
  // The number of bytes in this parameter's value.
  uint16_t size;

  // Reserved Bytes
  uint16_t reserved;

  // This parameter's value.
  uint8_t value[];
};

struct security_v2_serialized_response_hdr {
  // The number of parameters that follow the header in this response.
  uint16_t param_count;

  // This field ensures that the size of this structure is a multiple of
  // 32-bits, encouraging proper alignment of structures written after
  // it in a byte stream.
  // Its value should never be looked at, but should be set to zero to
  // ensure consistent behavior if the structure is ever signed.
  uint16_t reserved;
};

// Convenience macro for initializing a buffer from allocated storage. Intended
// for passing as a parameter to htool_exec_security_v2_cmd.
#define SECURITY_V2_BUFFER_PARAM(storage) \
  (&(struct security_v2_buffer){.data = (storage), .size = sizeof((storage))})

// Convenience macro for initializing a buffer from allocated storage. Intended
// for passing as a parameter to htool_exec_security_v2_cmd.
#define SECURITY_V2_BUFFER_PARAM_WITH_VARIABLE_SIZE(storage, storage_size) \
  (&(struct security_v2_buffer){.data = (storage), .size = (storage_size)})

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
// Executes a SECURITY_V2 host command with `major.minor` code, using serialized
// response params
int htool_exec_security_v2_serialized_cmd(
    struct libhoth_device* dev, uint8_t major, uint8_t minor,
    uint16_t base_command, struct security_v2_buffer* request_buffer,
    const struct security_v2_param* request_params,
    uint16_t request_param_count, struct security_v2_buffer* response_buffer,
    const struct security_v2_serialized_param** response_params[],
    uint16_t response_param_count);

// Copies the serialized param value into an output buffer
int copy_param(const struct security_v2_serialized_param* param, void* output,
               size_t output_size);

// Returns the necessary padding given the size
static inline size_t padding_size(uint16_t size) {
  size_t align = size % sizeof(uint32_t);
  return align == 0 ? 0 : sizeof(uint32_t) - align;
}

#ifdef __cplusplus
}
#endif

#endif
