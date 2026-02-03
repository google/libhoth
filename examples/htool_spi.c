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

#include "../transports/libhoth_spi.h"
#include "host_commands.h"
#include "htool.h"
#include "htool_cmd.h"

struct libhoth_device* htool_libhoth_spi_device(void) {
  static struct libhoth_device* result;
  if (result) {
    return result;
  }

  int rv;
  const char* spidev_path_str;
  uint32_t mailbox_location;
  bool atomic;
  uint32_t spidev_speed_hz;
  uint32_t spidev_device_busy_wait_timeout;
  uint32_t spidev_device_busy_wait_check_interval;
  rv = htool_get_param_string(htool_global_flags(), "spidev_path",
                              &spidev_path_str) ||
       htool_get_param_u32(htool_global_flags(), "mailbox_location",
                           &mailbox_location) ||
       htool_get_param_bool(htool_global_flags(), "spidev_atomic", &atomic) ||
       htool_get_param_u32(htool_global_flags(), "spidev_speed_hz",
                           &spidev_speed_hz) ||
       htool_get_param_u32(htool_global_flags(),
                           "spidev_device_busy_wait_timeout",
                           &spidev_device_busy_wait_timeout) ||
       htool_get_param_u32(htool_global_flags(),
                           "spidev_device_busy_wait_check_interval",
                           &spidev_device_busy_wait_check_interval);
  if (rv) {
    return NULL;
  }

  if (strlen(spidev_path_str) <= 0) {
    fprintf(stderr, "Invalid spidev path: %s\n", spidev_path_str);
    return NULL;
  }

  // Get retry parameters from global flags
  const char* timeout_str;
  if (htool_get_param_string(htool_global_flags(), "connect_timeout",
                             &timeout_str)) {
    return NULL;
  }

  int64_t timeout_us = parse_time_string_us(timeout_str);

  if (timeout_us < 0) {
    fprintf(stderr, "Invalid format for --connect_timeout: %s\n", timeout_str);
    return NULL;
  }

  struct libhoth_spi_device_init_options opts = {
      .path = spidev_path_str,
      .mailbox = mailbox_location,
      .atomic = atomic,
      .speed = spidev_speed_hz,
      .device_busy_wait_timeout = spidev_device_busy_wait_timeout,
      .device_busy_wait_check_interval = spidev_device_busy_wait_check_interval,
      .timeout_us = timeout_us,
  };
  rv = libhoth_spi_open(&opts, &result);
  if (rv) {
    // TODO: Convert error-code to a string
    fprintf(stderr, "libhoth_spi_open error: %d\n", rv);
    return NULL;
  }
  return result;
}
