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

#ifndef LIBHOTH_EXAMPLES_AUTHZ_COMMAND_H_
#define LIBHOTH_EXAMPLES_AUTHZ_COMMAND_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct hoth_authorized_command_request;

struct hoth_authorized_command_request authz_command_build_request(
    uint64_t hardware_identity, uint32_t opcode, uint32_t key_info,
    const uint32_t* nonce);

void authz_command_print_request(
    const struct hoth_authorized_command_request* request);

int authz_command_hex_to_struct(const char* hexstring,
                                struct hoth_authorized_command_request* out);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_AUTHZ_COMMAND_H_
