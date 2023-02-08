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

#ifndef LIBHOTH_EXAMPLES_HTOOL_USB_H_
#define LIBHOTH_EXAMPLES_HTOOL_USB_H_

#include <stddef.h>
#include <stdint.h>

struct libusb_context;
struct libusb_device;
struct libhoth_device;

struct libusb_context* htool_libusb_context(void);
struct libusb_device* htool_libusb_device(void);

int htool_usb_print_devices(void);

#endif  // LIBHOTH_EXAMPLES_HTOOL_USB_H_
