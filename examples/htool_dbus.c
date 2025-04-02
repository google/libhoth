
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
#include <stdio.h>

#ifdef DBUS_BACKEND

#include "htool_cmd.h"
#include "transports/libhoth_dbus.h"

struct libhoth_device* htool_libhoth_dbus_device(void) {
  static struct libhoth_device* result;
  if (result) {
    return result;
  }

  const char* hoth_id = NULL;
  int rv =
      htool_get_param_string(htool_global_flags(), "dbus_hoth_id", &hoth_id);
  if (rv) {
    return NULL;
  }

  struct libhoth_dbus_device_init_options opts = {
      .hoth_id = hoth_id,
  };

  rv = libhoth_dbus_open(&opts, &result);

  if (rv) {
    fprintf(stderr, "libhoth_dbus_open error: %d\n", rv);
    return NULL;
  }

  return result;
}

#else

struct libhoth_device* htool_libhoth_dbus_device(void) {
  fprintf(stderr, "This build doesn't have the D-Bus backend.\n");
  return NULL;
}

#endif  // DBUS_BACKEND
