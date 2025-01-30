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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../transports/libhoth_mtd.h"
#include "host_commands.h"
#include "htool.h"
#include "htool_cmd.h"

struct libhoth_device* htool_libhoth_mtd_device(void) {
  static struct libhoth_device* result;
  if (result) {
    return result;
  }

  int rv;
  const char* mtddev_path_str;
  const char* mtddev_name_str;
  uint32_t mailbox_location;
  rv = htool_get_param_string(htool_global_flags(), "mtddev_path",
                              &mtddev_path_str) ||
       htool_get_param_string(htool_global_flags(), "mtddev_name",
                              &mtddev_name_str) ||
       htool_get_param_u32(htool_global_flags(), "mailbox_location",
                           &mailbox_location);
  if (rv) {
    return NULL;
  }
  if (strlen(mtddev_path_str) <= 0 && strlen(mtddev_name_str) <= 0) {
    fprintf(stderr, "Must specify either mtddev_path or mtddev_name\n");
    return NULL;
  }

  struct libhoth_mtd_device_init_options opts = {
      .path = mtddev_path_str,
      .name = mtddev_name_str,
      .mailbox = mailbox_location,
  };
  rv = libhoth_mtd_open(&opts, &result);
  if (rv) {
    fprintf(stderr, "libhoth_mtd_open error: %d\n", rv);
    return NULL;
  }
  return result;
}
