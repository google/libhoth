// Copyright 2022 Google LLC
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

#ifndef LIBHOTH_EXAMPLES_EC_UTIL_H_
#define LIBHOTH_EXAMPLES_EC_UTIL_H_

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "host_commands.h"

#ifdef __cplusplus
extern "C" {
#endif

uint8_t calculate_ec_command_checksum(const void* header, size_t header_size,
                                      const void* data, size_t data_size);

int populate_ec_request_header(uint16_t command, uint8_t command_version,
                               const void* request, size_t request_size,
                               struct ec_host_request* request_header);

int validate_ec_response_header(const struct ec_host_response* response_header,
                                const void* response, size_t response_size);

void hex_dump(FILE* out, const void* buffer, size_t size);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_EC_UTIL_H_
