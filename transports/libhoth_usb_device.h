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

#ifndef _LIBHOTH_LIBHOTH_USB_DEVICE_H_
#define _LIBHOTH_LIBHOTH_USB_DEVICE_H_

#include <libusb.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LIBHOTH_USB_VENDOR_ID 0x18d1
#define LIBHOTH_USB_INTERFACE_CLASS LIBUSB_CLASS_VENDOR_SPEC
#define LIBHOTH_USB_MAILBOX_INTERFACE_SUBCLASS 0x71
#define LIBHOTH_USB_MAILBOX_INTERFACE_PROTOCOL 0x01
#define LIBHOTH_USB_FIFO_INTERFACE_SUBCLASS 0x58
#define LIBHOTH_USB_FIFO_INTERFACE_PROTOCOL 0x01

// Note on multi-threading: This library is not generally thread-safe. Some
// drivers may use the asynchronous libusb transfer functions and call
// libusb_handle_events_completed().

enum libhoth_usb_interface_type {
  LIBHOTH_USB_INTERFACE_TYPE_UNKNOWN = 0,
  LIBHOTH_USB_INTERFACE_TYPE_MAILBOX,
  LIBHOTH_USB_INTERFACE_TYPE_FIFO,
};

struct libhoth_usb_mailbox {
  uint16_t max_packet_size_in;
  uint16_t max_packet_size_out;
  uint8_t ep_in;
  uint8_t ep_out;
};

struct libhoth_usb_fifo {
  struct libusb_transfer* in_transfer;
  struct libusb_transfer* out_transfer;
  uint8_t* in_buffer;
  uint8_t* out_buffer;
  uint16_t max_packet_size_in;
  uint16_t max_packet_size_out;
  uint8_t ep_in;
  uint8_t ep_out;
  int all_transfers_completed;
  bool in_transfer_completed;
  bool out_transfer_completed;
  uint32_t prng_state;
};

struct libhoth_usb_interface_info {
  enum libhoth_usb_interface_type type;
  uint8_t interface_id;
  uint8_t interface_altsetting;
};

struct libhoth_usb_device {
  libusb_context* ctx;
  libusb_device_handle* handle;
  struct libhoth_usb_interface_info info;
  union driver_data {
    struct libhoth_usb_mailbox mailbox;
    struct libhoth_usb_fifo fifo;
  } driver_data;
};

int libhoth_usb_fifo_open(struct libhoth_usb_device* dev,
                          const struct libusb_config_descriptor* descriptor,
                          uint32_t prng_seed);
int libhoth_usb_fifo_send_request(struct libhoth_usb_device* dev,
                                  const void* request, size_t request_size);
int libhoth_usb_fifo_receive_response(struct libhoth_usb_device* dev,
                                      void* response, size_t response_size,
                                      size_t* actual_size, int timeout_ms);
int libhoth_usb_fifo_close(struct libhoth_usb_device* dev);

int libhoth_usb_mailbox_open(struct libhoth_usb_device* dev,
                             const struct libusb_config_descriptor* descriptor);
int libhoth_usb_mailbox_send_request(struct libhoth_usb_device* dev,
                                     const void* request, size_t request_size);
int libhoth_usb_mailbox_receive_response(struct libhoth_usb_device* dev,
                                         void* response, size_t response_size,
                                         size_t* actual_size, int timeout_ms);
int libhoth_usb_mailbox_close(struct libhoth_usb_device* dev);

enum libusb_error transfer_status_to_error(
    enum libusb_transfer_status transfer_status);

#ifdef __cplusplus
}
#endif

#endif  // _LIBHOTH_USB_LIBHOTH_USB_DEVICE_H_
