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

#ifndef LIBHOTH_EXAMPLES_HTOOL_I2C_H_
#define LIBHOTH_EXAMPLES_HTOOL_I2C_H_

#include <stdint.h>

#define I2C_DETECT_CMD_STR "detect"
#define I2C_READ_CMD_STR "read"
#define I2C_WRITE_CMD_STR "write"

// Forward declaration
struct htool_invocation;

int htool_i2c_run(const struct htool_invocation* inv);

#endif // LIBHOTH_EXAMPLES_HTOOL_I2C_H_