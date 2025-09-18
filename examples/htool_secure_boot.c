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

#include "htool_secure_boot.h"

#include <stdint.h>
#include <stdio.h>

#include "third_party/libhoth/libhoth/examples/htool.h"
#include "htool_cmd.h"
#include "protocol/secure_boot.h"

int htool_secure_boot_get_enforcement(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (dev == NULL) {
    return -1;
  }
  enum secure_boot_enforcement_status enforcement =
      SECURE_BOOT_ENFORCEMENT_DISABLED;
  int ret = libhoth_secure_boot_get_enforcement(dev, &enforcement);
  if (ret != 0) {
    fprintf(stderr, "Failed to get secure boot enforcement: %d\n", ret);
    return ret;
  }
  printf(
      "Secure boot enforcement: %s\n",
      enforcement == SECURE_BOOT_ENFORCEMENT_ENABLED ? "enabled" : "disabled");
  return 0;
}

int htool_secure_boot_enable_enforcement(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (dev == NULL) {
    return -1;
  }
  int ret = libhoth_secure_boot_enable_enforcement(dev);
  if (ret) {
    fprintf(stderr, "Failed to enable secure boot enforcement: %d\n", ret);
    return ret;
  }
  printf("Secure boot enforcement enabled\n");
  return 0;
}
