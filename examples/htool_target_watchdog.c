// Copyright 2026 Google LLC
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

#include "htool_target_watchdog.h"

#include <stdint.h>

#include "htool.h"
#include "htool_cmd.h"
#include "protocol/target_watchdog.h"

int htool_target_watchdog_pet(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (dev == NULL) {
    return -1;
  }

  uint64_t notify_cookie = 0;
  if (htool_get_param_u64(inv, "cookie", &notify_cookie) != 0) {
    return -1;
  }

  libhoth_error err = libhoth_pet_target_watchdog(dev, notify_cookie);
  if (err != HOTH_SUCCESS) {
    htool_report_error("pet_target_watchdog", err);
    return -1;
  }
  return 0;
}
