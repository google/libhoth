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

#include "authorization_record.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int authorization_record_print_hex_string(
    const struct authorization_record* record) {
  if (record == NULL) {
    return -1;
  }
  int i;
  const uint8_t* buf = (const uint8_t*)record;
  for (i = 0; i < sizeof(*record); ++i) {
    printf("%02x", buf[i]);
  }
  printf("\n");
  return 0;
}

int authorization_record_from_hex_string(struct authorization_record* record,
                                         const char* buf, size_t length) {
  if (record == NULL || buf == NULL ||
      length != 2 * AUTHORIZATION_RECORD_SIZE) {
    return -1;
  }
  char* out = (char*)record;
  char value_hex[3] = {};
  int i, j;
  for (i = 0, j = 0; i < length; i += 2, j += 1) {
    value_hex[0] = buf[i];
    value_hex[1] = buf[i + 1];
    out[j] = strtoul(value_hex, NULL, 16);
    // strtoul() returns 0 if input string cannot be parsed.
    if (out[j] == 0 && (value_hex[0] != '0' || value_hex[1] != '0')) {
      fprintf(stderr, "Invalid byte: %s\n", value_hex);
      return -1;
    }
  }
  return 0;
}
