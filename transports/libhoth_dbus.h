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

#ifndef _LIBHOTH_LIBHOTH_DBUS_H_
#define _LIBHOTH_LIBHOTH_DBUS_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct libhoth_device;

struct libhoth_dbus_device_init_options {
  const char* hoth_id;
};

int libhoth_dbus_open(const struct libhoth_dbus_device_init_options* options,
                      struct libhoth_device** out);

#ifdef __cplusplus
}
#endif

#endif  // _LIBHOTH_LIBHOTH_DBUS_H_
