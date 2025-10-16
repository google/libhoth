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

#ifndef LIBHOTH_EXAMPLES_HTOOL_SECURE_BOOT_H_
#define LIBHOTH_EXAMPLES_HTOOL_SECURE_BOOT_H_

#include "htool_cmd.h"

#ifdef __cplusplus
extern "C" {
#endif

int htool_secure_boot_get_enforcement(const struct htool_invocation* inv);
int htool_secure_boot_enable_enforcement(const struct htool_invocation* inv);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_HTOOL_SECURE_BOOT_H_
