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

#include <libusb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "libhoth_usb.h"

static libusb_context *ctx = NULL;

int hoth_usb_probe(struct libhoth_usb_device **dev, uint8_t bus,
                   uint8_t address, bool verbose) {
  int status = libusb_init(&ctx);
  if (status != LIBUSB_SUCCESS) {
    fprintf(stderr, "libusb_init() failed: %s\n", libusb_strerror(status));
    return -2;
  }

  libusb_device **device;
  ssize_t num_devices = libusb_get_device_list(ctx, &device);
  if (num_devices < 0) {
    fprintf(stderr, "libusb_get_device_list() failed: %s\n",
            libusb_strerror(num_devices));
    return -3;
  }

  libusb_device *target = NULL;
  for (ssize_t i = 0; i < num_devices; i++) {
    if (bus == libusb_get_bus_number(device[i]) &&
        address == libusb_get_device_address(device[i])) {
      if (verbose) {
        printf("Device found.\n");
      }
      target = device[i];
      break;
    }
  }
  if (target == NULL) {
    fprintf(stderr, "Failed to find the specified device\n");
    return -4;
  }

  struct libhoth_usb_device_init_options init_options = {
      .usb_device = target,
      .usb_ctx = ctx,
  };

  status = libhoth_usb_open(&init_options, dev);
  if (status != LIBHOTH_OK) {
    fprintf(stderr, "libhoth_usb_open() failed: %d\n", status);
    return -5;
  }
  libusb_free_device_list(device, /*unref_devices=*/1);
  if (verbose) {
    printf("Device bound to driver.\n");
  }
  return status;
}

int hoth_usb_remove(struct libhoth_usb_device *dev, bool verbose) {
  int status = libhoth_usb_close(dev);
  if (status != LIBHOTH_OK) {
    fprintf(stderr, "libhoth_usb_close() failed: %d\n", status);
    return -6;
  }
  if (verbose) {
    printf("Device closed.\n");
  }
  libusb_exit(ctx);
  return status;
}
