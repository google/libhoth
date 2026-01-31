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
#include <unistd.h>

#include "../transports/libhoth_device.h"
#include "../transports/libhoth_spi.h"
#include "host_commands.h"
#include "htool.h"
#include "htool_cmd.h"
#include "protocol/util.h"

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

  struct libhoth_spi_device_init_options opts = {
      .path = spidev_path_str,
      .mailbox = mailbox_location,
      .atomic = atomic,
      .speed = spidev_speed_hz,
      .device_busy_wait_timeout = spidev_device_busy_wait_timeout,
      .device_busy_wait_check_interval = spidev_device_busy_wait_check_interval,
  };

  // Get retry parameters from global flags
  const char* duration_str;
  const char* delay_str;
  if (htool_get_param_string(htool_global_flags(), "retry_duration",
                             &duration_str) ||
      htool_get_param_string(htool_global_flags(), "retry_delay",
                             &delay_str)) {
    return NULL;
  }

  int64_t retry_duration_us = parse_time_string_us(duration_str);
  int64_t retry_delay_us = parse_time_string_us(delay_str);

  if (retry_duration_us < 0) {
    fprintf(stderr, "Invalid format for --retry_duration: %s\n",
            duration_str);
    return NULL;
  }
  if (retry_delay_us < 0) {
    fprintf(stderr, "Invalid format for --retry_delay: %s\n", delay_str);
    return NULL;
  }
  // Convert duration to milliseconds for comparison with monotonic time helper
  uint64_t retry_duration_ms = (uint64_t)retry_duration_us / 1000;

  rv = LIBHOTH_ERR_INTERFACE_BUSY;  // Initialize rv to trigger the loop
  uint64_t start_time_ms = libhoth_get_monotonic_ms();
  uint64_t current_time_ms;

  while (rv == LIBHOTH_ERR_INTERFACE_BUSY) {
    rv = libhoth_spi_open(&opts, &result);
    if (rv == LIBHOTH_OK) {
          break; // Successfully opened
    }
    if (rv != LIBHOTH_ERR_INTERFACE_BUSY) {
        // A different error occurred, report it and exit
        fprintf(stderr, "libhoth_spi_open error: %d\n", rv);
        return NULL;
    }

    // Check elapsed time
    current_time_ms = libhoth_get_monotonic_ms();

    // Handle potential timer wrap-around or error from get_monotonic_ms
    if (current_time_ms < start_time_ms) {
        fprintf(stderr, "Monotonic clock error detected during retry loop.\n");
        return NULL;
    }

    if (current_time_ms - start_time_ms >= retry_duration_ms) {
        fprintf(stderr, "libhoth_spi_open timed out after %s (error: %d)\n",
                duration_str, rv);
        return NULL; // Timeout
    }

    // Wait before retrying
    // Ensure delay doesn't exceed reasonable limits for usleep (~10s)
    useconds_t sleep_us = (retry_delay_us > 10000000) ? 10000000 : (useconds_t)retry_delay_us;
    usleep(sleep_us);
  }

  return result;
}
