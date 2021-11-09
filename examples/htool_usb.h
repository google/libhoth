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

#define HTOOL_ERROR_HOST_COMMAND_START 537200

struct libusb_context;
struct libusb_device;
struct libhoth_usb_device;

struct libusb_context* htool_libusb_context(void);
struct libusb_device* htool_libusb_device(void);
struct libhoth_usb_device* htool_libhoth_usb_device(void);

int htool_usb_print_devices(void);

int htool_exec_hostcmd(struct libhoth_usb_device* dev, uint16_t command,
                       uint8_t version, const void* req_payload,
                       size_t req_payload_size, void* resp_buf,
                       size_t resp_buf_size, size_t* out_resp_size);

#endif  // LIBHOTH_EXAMPLES_HTOOL_USB_H_
