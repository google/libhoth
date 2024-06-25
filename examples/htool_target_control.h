
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

#ifndef LIBHOTH_EXAMPLES_HTOOL_TARGET_CONTROL_H_
#define LIBHOTH_EXAMPLES_HTOOL_TARGET_CONTROL_H_

#include "host_commands.h"
#ifdef __cplusplus
extern "C" {
#endif

int target_control_perform_action(enum ec_target_control_function function,
                                  enum ec_target_control_action action,
                                  struct ec_response_target_control* response);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_HTOOL_I2C_H_
