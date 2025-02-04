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

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host_commands.h"
#include "htool.h"
#include "htool_cmd.h"
#include "protocol/panic.h"

int dump_panic_record_to_file(
    const char* filename,
    const struct ec_response_persistent_panic_info* panic) {
  FILE* file = fopen(filename, "wb");
  if (!file) {
    perror("Failed to open file");
    return -1;
  }

  int rv = 0;

  if (fwrite(panic, sizeof(*panic), 1, file) != 1 || ferror(file)) {
    perror("Failed to write panic data to file");
    rv = -1;
  }

  fclose(file);
  return rv;
}

int htool_panic_get_panic(const struct htool_invocation* inv) {
  bool clear;
  bool hexdump;
  const char* output_file = NULL;

  if (htool_get_param_bool(inv, "clear", &clear) ||
      htool_get_param_bool(inv, "hexdump", &hexdump) ||
      htool_get_param_string(inv, "file", &output_file)) {
    return -1;
  }

  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  if (clear) {
    printf("Clearing panic log from flash.\n");
    return libhoth_clear_persistent_panic_info(dev);
  }

  struct ec_response_persistent_panic_info panic;
  memset(&panic, 0, sizeof(panic));

  if (libhoth_get_panic(dev, &panic)) {
    return -1;
  }

  if (output_file && output_file[0]) {
    return dump_panic_record_to_file(output_file, &panic);
  } else if (hexdump) {
    hex_dump(stdout, &panic.panic_record, sizeof(panic.panic_record));
  } else {
    libhoth_print_panic_info(&panic);
  }

  char* console_log = libhoth_get_panic_console_log(&panic);

  if (console_log) {
    printf("Saved console log:\n");
    printf("%s\n", console_log);
    free(console_log);
  }

  return 0;
}
