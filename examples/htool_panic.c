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

#include "htool_panic.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "htool.h"
#include "htool_cmd.h"

static int clear_persistent_panic_info(struct libhoth_device* dev) {
  printf("TODO: clear_persistent_panic_info\n");
  return 0;
}

static int get_persistent_panic_info(struct libhoth_device* dev,
                                     struct panic_data* panic, char** log) {
  printf("TODO: get_persistent_panic_info\n");
  return 0;
}

static void print_hex_dump_buffer(size_t size, const void* buffer,
                                  uint32_t address) {
  printf("TODO: print_hex_dump_buffer\n");
}

static void print_panic_info(const struct panic_data* data) {
  printf("TODO: print_panic_info\n");
}

int htool_panic_get_panic(const struct htool_invocation* inv) {
  bool clear;
  bool hexdump;

  if (htool_get_param_bool(inv, "clear", &clear) ||
      htool_get_param_bool(inv, "hexdump", &hexdump)) {
    return -1;
  }

  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  if (clear) {
    printf("Clearing panic log from flash.\n");
    return clear_persistent_panic_info(dev);
  }

  struct panic_data panic;
  memset(&panic, 0, sizeof(panic));

  char* console_log = NULL;

  if (get_persistent_panic_info(dev, &panic, &console_log)) {
    return -1;
  }

  if (hexdump) {
    print_hex_dump_buffer(sizeof(panic), &panic, 0);
  } else {
    print_panic_info(&panic);
  }

  if (console_log) {
    printf("Saved console log:\n");
    printf("%s\n", console_log);
    free(console_log);
  }

  return 0;
}
