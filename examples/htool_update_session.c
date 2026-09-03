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

#include "htool_update_session.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "htool.h"
#include "htool_cmd.h"
#include "protocol/update_session.h"

int htool_update_session_start(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (dev == NULL) {
    return -1;
  }

  const char* timeout_str = NULL;
  if (htool_has_param(inv, "timeout")) {
    htool_get_param_string(inv, "timeout", &timeout_str);
  }
  if ((!timeout_str || timeout_str[0] == '\0') &&
      htool_has_param(inv, "timeout_seconds")) {
    htool_get_param_string(inv, "timeout_seconds", &timeout_str);
  }
  if (!timeout_str || timeout_str[0] == '\0') {
    fprintf(
        stderr,
        "Missing required timeout (use --timeout=<seconds> or <seconds>)\n");
    return -1;
  }

  char* endptr = NULL;
  unsigned long val = strtoul(timeout_str, &endptr, 0);
  uint32_t timeout_seconds = 0;
  if (endptr != timeout_str && *endptr == '\0') {
    timeout_seconds = (uint32_t)val;
  } else {
    int64_t time_us = parse_time_string_us(timeout_str);
    if (time_us > 0 && time_us % 1000000 == 0) {
      timeout_seconds = (uint32_t)(time_us / 1000000);
    }
  }

  if (timeout_seconds == 0) {
    fprintf(stderr, "Invalid or zero timeout: %s\n", timeout_str);
    return -1;
  }

  libhoth_error err = libhoth_update_session_start(dev, timeout_seconds);
  if (err != HOTH_SUCCESS) {
    htool_report_error("update_session_start", err);
    return -1;
  }

  printf("Update session started (timeout: %u seconds)\n", timeout_seconds);
  return 0;
}

int htool_update_session_finalize(const struct htool_invocation* inv) {
  (void)inv;
  struct libhoth_device* dev = htool_libhoth_device();
  if (dev == NULL) {
    return -1;
  }

  libhoth_error err = libhoth_update_session_finalize(dev);
  if (err != HOTH_SUCCESS) {
    htool_report_error("update_session_finalize", err);
    return -1;
  }

  printf("Update session finalized\n");
  return 0;
}

int htool_update_session_status(const struct htool_invocation* inv) {
  (void)inv;
  struct libhoth_device* dev = htool_libhoth_device();
  if (dev == NULL) {
    return -1;
  }

  struct update_session_status_response status;
  memset(&status, 0, sizeof(status));

  libhoth_error err = libhoth_update_session_get_status(dev, &status);
  if (err != HOTH_SUCCESS) {
    htool_report_error("update_session_get_status", err);
    return -1;
  }

  printf("Update session status:\n");
  printf("  State:                %s (%u)\n",
         libhoth_update_session_state_string(
             (enum update_session_state)status.current_state),
         status.current_state);
  printf("  Timeout seconds left: %u\n", status.timeout_seconds_left);
  return 0;
}
