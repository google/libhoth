// Copyright 2022 Google LLC
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

#include "htool_usb.h"

#include <ctype.h>
#include <errno.h>
#include <libusb.h>
#include <fnmatch.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "host_commands.h"
#include "htool_cmd.h"
#include "transports/libhoth_usb.h"

static int enumerate_devices(
    libusb_context* libusb_ctx,
    void (*callback)(void* cb_param, libusb_device*,
                     const struct libusb_device_descriptor*),
    void* cb_param) {
  libusb_device** device;
  ssize_t num_devices = libusb_get_device_list(libusb_ctx, &device);
  if (num_devices < 0) {
    fprintf(stderr, "libusb_get_device_list() failed: %s\n",
            libusb_strerror(num_devices));
    return 1;
  }
  for (ssize_t i = 0; i < num_devices; i++) {
    struct libusb_device_descriptor device_descriptor;
    int rv = libusb_get_device_descriptor(device[i], &device_descriptor);
    if (rv != LIBUSB_SUCCESS) {
      continue;
    }

    if (!libhoth_device_is_hoth(&device_descriptor)) {
      continue;
    }

    callback(cb_param, device[i], &device_descriptor);
  }

  libusb_free_device_list(device, /*unref_devices=*/1);
  return 0;
}

static void print_device(void* cb_param, libusb_device* dev,
                         const struct libusb_device_descriptor* descriptor) {
  fprintf(stderr, "  ");
  struct libhoth_usb_loc loc;
  int rv = libhoth_get_usb_loc(dev, &loc);
  if (rv) {
    fprintf(stderr, " (unable to get usb_loc: %s)", libusb_strerror(rv));
  } else {
    fprintf(stderr, "--usb_loc %d-", loc.bus);
    for (int i = 0; i < loc.num_ports; i++) {
      fprintf(stderr, "%s%d", i == 0 ? "" : ".", loc.ports[i]);
    }
  }

  libusb_device_handle* dev_handle;
  char sys_path[256];
  rv = libusb_open(dev, &dev_handle);
  if (rv != LIBUSB_SUCCESS) {
    fprintf(stderr, " (unable to open device: %s)", libusb_strerror(rv));
    goto cleanup;
  }
  char product_name[512];
  int rv_or_len = libusb_get_string_descriptor_ascii(
      dev_handle, descriptor->iProduct, (unsigned char*)product_name,
      sizeof(product_name));
  if (rv_or_len < 0) {
    fprintf(stderr, " (unable to get product string: %s)",
            libusb_strerror(rv_or_len));
    goto cleanup2;
  }
  // valid product_name is returned
  fprintf(stderr, " - %.*s", rv_or_len, product_name);

cleanup2:
  libusb_close(dev_handle);
cleanup:
  rv = libhoth_get_usb_sys_path(dev, sys_path, sizeof(sys_path));
  if (rv != LIBUSB_SUCCESS) {
    fprintf(stderr, " (unable to get sys path: %s)", libusb_strerror(rv));
  } else {
    fprintf(stderr, " %s", sys_path);
  }
  fprintf(stderr, "\n");
}

struct select_device_cb_param {
  bool (*filter)(void* cb_param, libusb_device*,
                 const struct libusb_device_descriptor*);
  void* filter_cb_param;
  int count;
  libusb_device* first_match;
  bool print_matches;
};
static void select_device_cb(
    void* cb_param, libusb_device* dev,
    const struct libusb_device_descriptor* descriptor) {
  struct select_device_cb_param* param =
      (struct select_device_cb_param*)cb_param;
  if (param->filter(param->filter_cb_param, dev, descriptor)) {
    param->count++;
    if (!param->first_match) {
      param->first_match = dev;
      libusb_ref_device(param->first_match);
    }
    if (param->print_matches) {
      print_device(NULL, dev, descriptor);
    }
  }
}

// Caller must eventually call libusb_unref_device() on result
static libusb_device* select_device(
    libusb_context* libusb_ctx,
    bool filter(void* cb_param, libusb_device*,
                const struct libusb_device_descriptor*),
    void* cb_param) {
  struct select_device_cb_param param = {
      .filter = filter,
      .filter_cb_param = cb_param,
      .count = 0,
  };
  int rv = enumerate_devices(libusb_ctx, select_device_cb, &param);
  if (rv) {
    return NULL;
  }
  if (param.count == 0) {
    fprintf(stderr, "No matching devices found\n");
    return NULL;
  }
  if (param.count > 1) {
    fprintf(stderr, "%d matching devices found; please be more specific:\n",
            param.count);
    // To help the user, print out the matching devices:
    param.print_matches = true;
    enumerate_devices(libusb_ctx, select_device_cb, &param);
    libusb_unref_device(param.first_match);
    return NULL;
  }
  return param.first_match;
}

libusb_context* htool_libusb_context(void) {
  static libusb_context* result;
  if (result) {
    return result;
  }
  int rv = libusb_init(&result);
  if (rv != LIBUSB_SUCCESS) {
    fprintf(stderr, "libusb_init() failed: %s\n", libusb_strerror(rv));
  }
  return result;
}

static bool expect_u8(const char** s, uint8_t* result) {
  uint32_t sum = 0;
  if (**s < '0' || **s > '9') {
    return false;
  }
  while (**s >= '0' && **s <= '9') {
    sum = sum * 10 + (**s - '0');
    if (sum > 255) {
      return false;
    }
    (*s)++;
  }
  *result = (uint8_t)sum;
  return true;
}

static int parse_usb_loc(const char* s, struct libhoth_usb_loc* loc) {
  if (!expect_u8(&s, &loc->bus)) {
    fprintf(stderr, "unable to parse usb_loc: Expected 8-bit bus number\n");
    return -1;
  }
  if (!*s) {
    fprintf(stderr, "unable to parse usb_loc: Expected '-' was end-of-string");
    return -1;
  }
  if (*s != '-') {
    fprintf(stderr, "unable to parse usb_loc: Expected '-' was '%c'\n", *s);
    return -1;
  }
  s++;
  for (loc->num_ports = 0;;) {
    if (loc->num_ports >= sizeof(loc->ports)) {
      fprintf(stderr, "unable to parse usb_loc: too many ports\n");
      return -1;
    }
    if (!expect_u8(&s, &loc->ports[loc->num_ports])) {
      fprintf(stderr, "unable to parse usb_loc: Expected 8-bit port number\n");
      return -1;
    }
    loc->num_ports++;
    if (*s == '\0') {
      break;
    }
    if (*s != '.') {
      fprintf(stderr, "unable to parse usb_loc: Expected '.' was '%c'\n", *s);
      return -1;
    }
    s++;
  }
  return 0;
}

bool filter_by_usb_loc(void* cb_param, libusb_device* dev,
                       const struct libusb_device_descriptor* descriptor) {
  struct libhoth_usb_loc* desired_loc = (struct libhoth_usb_loc*)cb_param;
  struct libhoth_usb_loc device_loc;
  int rv = libhoth_get_usb_loc(dev, &device_loc);
  if (rv) {
    return false;
  }
  if (device_loc.bus != desired_loc->bus ||
      device_loc.num_ports != desired_loc->num_ports ||
      device_loc.num_ports > sizeof(device_loc.ports)) {
    return false;
  }
  return memcmp(device_loc.ports, desired_loc->ports, device_loc.num_ports) ==
         0;
}

bool filter_by_usb_product_substr(
    void* cb_param, libusb_device* dev,
    const struct libusb_device_descriptor* descriptor) {
  const char* usb_product_substr = (const char*)cb_param;

  libusb_device_handle* dev_handle;
  int rv = libusb_open(dev, &dev_handle);
  if (rv != LIBUSB_SUCCESS) {
    return false;
  }
  char product_name[512] = {};
  int len = libusb_get_string_descriptor_ascii(dev_handle, descriptor->iProduct,
                                               (unsigned char*)product_name,
                                               sizeof(product_name) - 1);
  if (len < 0) {
    libusb_close(dev_handle);
    return false;
  }
  return strstr(product_name, usb_product_substr) != NULL;
}

static bool filter_by_usb_path_glob(
    void* cb_param, libusb_device* dev,
    const struct libusb_device_descriptor* descriptor) {
  const char* glob_pattern = (const char*)cb_param;
  char sys_path[256];
  int rv = libhoth_get_usb_sys_path(dev, sys_path, sizeof(sys_path));
  if (rv != LIBUSB_SUCCESS) {
    fprintf(stderr, "libhoth_get_usb_sys_path failed: %s\n",
            libusb_strerror(rv));
    return false;
  }
  return fnmatch(glob_pattern, sys_path, 0) == 0;
}

bool filter_allow_all(void* cb_param, libusb_device* dev,
                      const struct libusb_device_descriptor* descriptor) {
  return true;
}

libusb_device* htool_libusb_device(void) {
  static libusb_device* result;
  if (result) {
    return result;
  }
  libusb_context* ctx = htool_libusb_context();
  if (!ctx) {
    return NULL;
  }
  const char* usb_loc_str;
  const char* usb_product_substr;
  const char* usb_path_glob_str;
  int rv =
      htool_get_param_string(htool_global_flags(), "usb_loc", &usb_loc_str) ||
      htool_get_param_string(htool_global_flags(), "usb_product",
                             &usb_product_substr) ||
      htool_get_param_string(htool_global_flags(), "usb_path",
                             &usb_path_glob_str);
  if (rv) {
    return NULL;
  }

  if (strlen(usb_loc_str) > 0) {
    struct libhoth_usb_loc usb_loc;
    rv = parse_usb_loc(usb_loc_str, &usb_loc);
    if (rv) {
      return NULL;
    }
    return select_device(ctx, filter_by_usb_loc, &usb_loc);
  }
  if (strlen(usb_product_substr) > 0) {
    return select_device(ctx, filter_by_usb_product_substr,
                         (void*)usb_product_substr);
  }
  if (strlen(usb_path_glob_str) > 0) {
    return select_device(ctx, filter_by_usb_path_glob,
                         (void*)usb_path_glob_str);
  }
  return select_device(ctx, filter_allow_all, NULL);
}

// Helper function to get current monotonic time in milliseconds
static uint64_t get_monotonic_ms() {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime failed");
        // Return 0 or a value indicating error, relying on caller checks
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

// Helper function to parse time string with units (s, ms, us) into microseconds
// Returns -1 on error.
static int64_t parse_time_string_us(const char* time_str) {
    if (!time_str || *time_str == '\0') {
        return -1; // Invalid input
    }

    char* endptr;
    long long val = strtoll(time_str, &endptr, 10);

    if (endptr == time_str || val < 0) {
        return -1; // No digits found or negative value
    }

    // Skip whitespace
    while (*endptr != '\0' && isspace((unsigned char)*endptr)) {
        endptr++;
    }

    uint64_t multiplier = 1000000; // Default to seconds if no unit

    if (*endptr != '\0') {
        // Check for units (case-insensitive)
        if (tolower((unsigned char)endptr[0]) == 's' && endptr[1] == '\0') {
            multiplier = 1000000; // seconds
        } else if (tolower((unsigned char)endptr[0]) == 'm' &&
                   tolower((unsigned char)endptr[1]) == 's' && endptr[2] == '\0') {
            multiplier = 1000; // milliseconds
        } else if (tolower((unsigned char)endptr[0]) == 'u' &&
                   tolower((unsigned char)endptr[1]) == 's' && endptr[2] == '\0') {
            multiplier = 1; // microseconds
        } else {
            return -1; // Invalid unit or extra characters
        }
    }

    // Check for potential overflow before multiplying
    if (val > INT64_MAX / multiplier) {
         return -1; // Overflow
    }

    return (int64_t)val * multiplier;
}


struct libhoth_device* htool_libhoth_usb_device(void) {
  static struct libhoth_device* result;
  if (result) {
    return result;
  }
  libusb_context* ctx = htool_libusb_context();
  libusb_device* usb_dev = htool_libusb_device();
  if (!ctx || !usb_dev) {
    return NULL;
  }

  // Get retry parameters from global flags
  const char* duration_str;
  const char* delay_str;
  if (htool_get_param_string(htool_global_flags(), "usb_retry_duration", &duration_str) ||
      htool_get_param_string(htool_global_flags(), "usb_retry_delay", &delay_str)) {
      return NULL;
  }

  int64_t retry_duration_us = parse_time_string_us(duration_str);
  int64_t retry_delay_us = parse_time_string_us(delay_str);

  if (retry_duration_us < 0) {
      fprintf(stderr, "Invalid format for --usb_retry_duration: %s\n", duration_str);
      return NULL;
  }
  if (retry_delay_us < 0) {
      fprintf(stderr, "Invalid format for --usb_retry_delay: %s\n", delay_str);
      return NULL;
  }
  // Convert duration to milliseconds for comparison with monotonic time helper
  uint64_t retry_duration_ms = (uint64_t)retry_duration_us / 1000;

  struct timespec monotonic_time;
  // `clock_gettime` function is guaranteed by POSIX standard on compliant
  // systems. But it may have implementation defined resolution. So xor with PID
  // as well
  if (clock_gettime(CLOCK_MONOTONIC, &monotonic_time) != 0) {
    fprintf(stderr, "Could not get clock time to generate PRNG seed\n");
    return NULL;
  }
  uint32_t prng_seed =
      monotonic_time.tv_sec ^ monotonic_time.tv_nsec ^ getpid();

  struct libhoth_usb_device_init_options opts = {
      .usb_device = usb_dev, .usb_ctx = ctx, .prng_seed = prng_seed};

  int rv = LIBUSB_ERROR_BUSY; // Initialize rv to trigger the loop
  uint64_t start_time_ms = get_monotonic_ms();
  if (start_time_ms == 0 && errno != 0) { // Check if get_monotonic_ms failed
      return NULL;
  }
  uint64_t current_time_ms;

  while (rv == LIBUSB_ERROR_BUSY) {
      rv = libhoth_usb_open(&opts, &result);
      if (rv == LIBUSB_SUCCESS) {
          break; // Successfully opened
      }
      if (rv != LIBUSB_ERROR_BUSY) {
          // A different error occurred, report it and exit
          fprintf(stderr, "libhoth_usb_open error: %d (%s)\n", rv, libusb_strerror(rv));
          return NULL;
      }

      // Check elapsed time
      current_time_ms = get_monotonic_ms();
       if (current_time_ms == 0 && errno != 0) {
           return NULL;
       }
      // Handle potential timer wrap-around or error from get_monotonic_ms
      if (current_time_ms < start_time_ms) {
          fprintf(stderr, "Monotonic clock error detected during retry loop.\n");
          return NULL;
      }

      if (current_time_ms - start_time_ms >= retry_duration_ms) {
          fprintf(stderr, "libhoth_usb_open timed out after %s (error: %d (%s))\n",
                  duration_str, rv, libusb_strerror(rv));
          return NULL; // Timeout
      }

      // Wait before retrying
      // Ensure delay doesn't exceed reasonable limits for usleep (~10s)
      useconds_t sleep_us = (retry_delay_us > 10000000) ? 10000000 : (useconds_t)retry_delay_us;
      usleep(sleep_us);
  }

  if (rv != LIBUSB_SUCCESS) {
      fprintf(stderr, "libhoth_usb_open error: %d (%s)\n", rv, libusb_strerror(rv));
      result = NULL;
      return NULL;
  }

  return result;
}

int htool_usb_print_devices(void) {
  libusb_context* libusb_ctx = htool_libusb_context();
  if (!libusb_ctx) {
    return 1;
  }
  return enumerate_devices(libusb_ctx, print_device, NULL);
}
