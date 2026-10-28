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

#ifndef _LIBHOTH_PROTOCOL_UTIL_H_
#define _LIBHOTH_PROTOCOL_UTIL_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Helper function to get current monotonic time in milliseconds
uint64_t libhoth_get_monotonic_ms();

// Helper function for generating an adequate PRNG seed
uint32_t libhoth_prng_seed();

// Helper function for writing all of `buf` into `fd`
int libhoth_force_write(int fd, const void* buf, size_t count);

#ifdef __cplusplus
}
#endif

#endif  // _LIBHOTH_PROTOCOL_UTIL_H_
