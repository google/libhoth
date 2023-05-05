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
#include <stddef.h>

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
};

// Note that the options struct only needs to to live for the duration of
// this function call. It can be destroyed once libhoth_usb_open returns.
int libhoth_usb_open(const struct libhoth_usb_device_init_options* options,
                     struct libhoth_device** out);

#ifdef __cplusplus
}
#endif

#endif  // _LIBHOTH_LIBHOTH_USB_H_
