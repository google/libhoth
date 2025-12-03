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

#ifndef _LIBHOTH_LIBHOTH_USB_H_
#define _LIBHOTH_LIBHOTH_USB_H_

#include <libusb.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

struct libhoth_device;

struct libhoth_usb_device_init_options {
  // The device to open
  libusb_device* usb_device;
  // The libusb context to use for operations. Can be NULL for the default
  // context.
  libusb_context* usb_ctx;
  // Seed value to use for Pseudo-random number generator for communicating with
  // RoT over USB FIFO interface. Must be non-zero
  uint32_t prng_seed;
};

#define LIBHOTH_NUM_PORTS 16

struct libhoth_usb_loc {
  uint8_t bus;
  uint8_t ports[LIBHOTH_NUM_PORTS];
  int num_ports;
};

// Note that the options struct only needs to to live for the duration of
// this function call. It can be destroyed once libhoth_usb_open returns.
int libhoth_usb_open(const struct libhoth_usb_device_init_options* options,
                     struct libhoth_device** out);

int libhoth_usb_close(struct libhoth_device* dev);

int libhoth_usb_receive_response(struct libhoth_device* dev, void* response,
                                 size_t max_response_size, size_t* actual_size,
                                 int timeout_ms);

bool libhoth_device_is_hoth(const struct libusb_device_descriptor* dev);
int libhoth_usb_get_device(libusb_context* ctx,
                           const struct libhoth_usb_loc* usb_loc,
                           libusb_device** out);
int libhoth_get_usb_loc(libusb_device* dev, struct libhoth_usb_loc* result);

// Returns the sysfs path for the given libusb_device.
// Returns LIBUSB_SUCCESS on success, or a libusb error code on failure.
int libhoth_get_usb_sys_path(libusb_device* dev, char* path, size_t path_len);

#ifdef __cplusplus
}
#endif

#endif  // _LIBHOTH_LIBHOTH_USB_H_
