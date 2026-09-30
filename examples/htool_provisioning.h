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
#ifndef LIBHOTH_EXAMPLES_HTOOL_PROVISIONING_H_
#define LIBHOTH_EXAMPLES_HTOOL_PROVISIONING_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "protocol/provisioning.h"

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration
struct htool_invocation;

// Retrieve the provisioning log from the device.
int htool_get_provisioning_log(const struct htool_invocation* inv);

// Validate and Sign the provisioning log.
int htool_validate_and_sign(const struct htool_invocation* inv);

// Loads secrets that were encrypted with the provisioning encryption key.
int htool_provisioning_store_secrets(const struct htool_invocation* inv);

// Writes and commits the provisioning log.
int htool_provisioning_write(const struct htool_invocation* inv);

// Loads the ML-DSA-44 public key to the RoT.
int htool_provisioning_load_mldsa_key(const struct htool_invocation* inv);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_HTOOL_PROVISIONING_H_
