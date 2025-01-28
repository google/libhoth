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

#include <libusb.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../libhoth_usb.h"
#include "ec_util.h"
#include "host_commands.h"
#include "htool_cmd.h"

#define HOTH_VENDOR_ID 0x18d1
#define HOTH_B_PRODUCT_ID 0x5014
#define HOTH_D_PRODUCT_ID 0x022a

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
    if (device_descriptor.idVendor != HOTH_VENDOR_ID ||
        (device_descriptor.idProduct != HOTH_B_PRODUCT_ID &&
         device_descriptor.idProduct != HOTH_D_PRODUCT_ID)) {
      continue;
    }
    callback(cb_param, device[i], &device_descriptor);
  }

  libusb_free_device_list(device, /*unref_devices=*/1);
  return 0;
}

struct usb_loc {
  uint8_t bus;
  uint8_t ports[16];
  int num_ports;
};

static int get_usb_loc(libusb_device* dev, struct usb_loc* result) {
  result->bus = libusb_get_bus_number(dev);
  int num_ports =
      libusb_get_port_numbers(dev, result->ports, sizeof(result->ports));
  if (num_ports < 0) {
    return num_ports;
  }
  result->num_ports = num_ports;
  return 0;
}

static void print_device(void* cb_param, libusb_device* dev,
                         const struct libusb_device_descriptor* descriptor) {
  fprintf(stderr, "  ");
  struct usb_loc loc;
  int rv = get_usb_loc(dev, &loc);
  if (rv) {
    fprintf(stderr, " (unable to get usb_loc: %s)", libusb_strerror(rv));
  } else {
    fprintf(stderr, "--usb_loc %d-", loc.bus);
    for (int i = 0; i < loc.num_ports; i++) {
      fprintf(stderr, "%s%d", i == 0 ? "" : ".", loc.ports[i]);
    }
  }

  libusb_device_handle* dev_handle;
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

static int parse_usb_loc(const char* s, struct usb_loc* loc) {
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
  struct usb_loc* desired_loc = (struct usb_loc*)cb_param;
  struct usb_loc device_loc;
  int rv = get_usb_loc(dev, &device_loc);
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
  int rv =
      htool_get_param_string(htool_global_flags(), "usb_loc", &usb_loc_str) ||
      htool_get_param_string(htool_global_flags(), "usb_product",
                             &usb_product_substr);
  if (rv) {
    return NULL;
  }

  if (strlen(usb_loc_str) > 0) {
    struct usb_loc usb_loc;
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
  return select_device(ctx, filter_allow_all, NULL);
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

  struct timespec monotonic_time;
  // `clock_gettime` function is guaranteed by POSIX standard on compliant
  // systems. But it may have implementation defined resolution. So xor with PID
  // as well
  if (clock_gettime(CLOCK_MONOTONIC, &monotonic_time) != 0) {
    fprintf(stderr, "Could not get clock time to generate PRNG seed");
    return NULL;
  }
  uint32_t prng_seed =
      monotonic_time.tv_sec ^ monotonic_time.tv_nsec ^ getpid();

  struct libhoth_usb_device_init_options opts = {.usb_device = usb_dev,
                                                 .usb_ctx = ctx,
                                                 .prng_seed = prng_seed};

  int rv = libhoth_usb_open(&opts, &result);
  if (rv) {
    // TODO: Convert error-code to a string
    fprintf(stderr, "libhoth_usb_open error: %d\n", rv);
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
