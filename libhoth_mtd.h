// Copyright 2023 Google LLC
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

#ifndef _LIBHOTH_LIBHOTH_MTD_H_
#define _LIBHOTH_LIBHOTH_MTD_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct libhoth_device;

struct libhoth_mtd_device_init_options {
  // The device filepath to open
  const char* path;
  // The device name to open
  const char* name;
  // Address where mailbox is located
  unsigned int mailbox;
};

// Note that the options struct only needs to to live for the duration of
// this function call. It can be destroyed once libhoth_mtd_open returns.
int libhoth_mtd_open(const struct libhoth_mtd_device_init_options* options,
                     struct libhoth_device** out);

#ifdef __cplusplus
}
#endif

#endif  // _LIBHOTH_LIBHOTH_MTD_H_
