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

typedef enum {
  LIBHOTH_OK = 0,
  LIBHOTH_ERR_UNKNOWN_VENDOR = 1,
  LIBHOTH_ERR_INTERFACE_NOT_FOUND = 2,
  LIBHOTH_ERR_MALLOC_FAILED = 3,
  LIBHOTH_ERR_TIMEOUT = 4,
  LIBHOTH_ERR_OUT_UNDERFLOW = 5,
  LIBHOTH_ERR_IN_OVERFLOW = 6,
} libhoth_status;

struct libhoth_usb_device;

struct libhoth_usb_device_init_options {
  // The device to open
  libusb_device* usb_device;
  // The libusb context to use for operations. Can be NULL for the default
  // context.
  libusb_context* usb_ctx;
};

int libhoth_usb_open(const struct libhoth_usb_device_init_options* options,
                     struct libhoth_usb_device** out);

// Claim the USB device. This function MUST be called before any send/receive
// request.
int libhoth_claim_interface(struct libhoth_usb_device* dev);

// Release the USB device. This function MUST be called after any send/receive
// request.
int libhoth_release_interface(struct libhoth_usb_device* dev);

// Request is a buffer containing the EC request header and trailing payload.
// This function is not thread-safe. In multi-threaded contexts, callers must
// ensure libhoth_usb_send_request() and libhoth_usb_receive_response() occur
// atomically (with respect to other calls to those functions).
int libhoth_usb_send_request(struct libhoth_usb_device* dev,
                             const void* request, size_t request_size);

// Response is a buffer where the EC response header and trailing payload will
// be written. Errors if libhoth_usb_send_request() wasn't called previously.
// Returns LIBHOTH_ERR_TIMEOUT if the response is not ready by the
// specified timeout, and the user can call again later. If timeout_ms is zero,
// returns immediately.
// This function is not thread-safe. In multi-threaded contexts, callers must
// ensure libhoth_usb_send_request() and libhoth_usb_receive_response() occur
// atomically (with respect to other calls to those functions).
int libhoth_usb_receive_response(struct libhoth_usb_device* dev, void* response,
                                 size_t response_size, size_t* actual_size,
                                 int timeout_ms);

int libhoth_usb_close(struct libhoth_usb_device* dev);

#endif  // _LIBHOTH_LIBHOTH_USB_H_
