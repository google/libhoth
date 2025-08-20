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

#ifndef LIBHOTH_EXAMPLES_HTOOL_KEY_ROTATION_H_
#define LIBHOTH_EXAMPLES_HTOOL_KEY_ROTATION_H_

#include "htool.h"
#include "htool_cmd.h"

#ifdef __cplusplus
extern "C" {
#endif

struct htool_invocation;
int htool_key_rotation_get_status();
int htool_key_rotation_get_version();
int htool_key_rotation_payload_status();
int htool_key_rotation_read(const struct htool_invocation* inv);
int htool_key_rotation_read_chunk_type(const struct htool_invocation* inv);
int htool_key_rotation_update(const struct htool_invocation* inv);
int htool_key_rotation_chunk_type_count(const struct htool_invocation* inv);
int htool_key_rotation_erase_record(const struct htool_invocation* inv);
int htool_key_rotation_set_mauv(const struct htool_invocation* inv);
int htool_key_rotation_get_mauv(const struct htool_invocation* inv);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_HTOOL_KEY_ROTATION_H_
