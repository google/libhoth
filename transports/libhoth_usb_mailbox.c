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
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "transports/libhoth_device.h"
#include "transports/libhoth_ec.h"
#include "transports/libhoth_usb_device.h"

#define LIBHOTH_USB_MAILBOX_MTU 64

enum mailbox_request_type {
  MAILBOX_REQ_READ = 0x00,
  MAILBOX_REQ_WRITE = 0x02,
  MAILBOX_REQ_ERASE = 0x04,
};

enum mailbox_error {
  MAILBOX_SUCCESS = 0x00,
  MAILBOX_UNKNOWN_ERROR = 0x01,
  MAILBOX_INVAL = 0x02,
  MAILBOX_BUSY = 0x03,
};

struct mailbox_request {
  uint8_t type;
  uint32_t offset;
  uint8_t length;
} __attribute__((packed));

struct mailbox_response {
  uint8_t status;
  uint8_t rsvd;
} __attribute__((packed));

int libhoth_usb_mailbox_open(
    struct libhoth_usb_device* dev,
    const struct libusb_config_descriptor* descriptor) {
  if (dev == NULL || descriptor == NULL ||
      dev->info.type != LIBHOTH_USB_INTERFACE_TYPE_MAILBOX) {
    return LIBUSB_ERROR_INVALID_PARAM;
  }
  const struct libusb_interface* interface_settings =
      &descriptor->interface[dev->info.interface_id];
  const struct libusb_interface_descriptor* interface =
      &interface_settings->altsetting[dev->info.interface_altsetting];

  // Fill out driver data
  struct libhoth_usb_mailbox* drvdata = &dev->driver_data.mailbox;

  // There should only be one IN endpoint and one OUT endpoint.
  for (int i = 0; i < interface->bNumEndpoints; i++) {
    const struct libusb_endpoint_descriptor* endpoint = &interface->endpoint[i];
    enum libusb_endpoint_direction direction =
        endpoint->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK;
    enum libusb_transfer_type transfer_type =
        endpoint->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK;
    if (direction == LIBUSB_ENDPOINT_IN &&
        transfer_type == LIBUSB_TRANSFER_TYPE_BULK) {
      if (drvdata->ep_in != 0) {
        return LIBUSB_ERROR_INVALID_PARAM;
      }
      drvdata->ep_in = endpoint->bEndpointAddress;
      drvdata->max_packet_size_in = endpoint->wMaxPacketSize;
    } else if (direction == LIBUSB_ENDPOINT_OUT &&
               transfer_type == LIBUSB_TRANSFER_TYPE_BULK) {
      if (drvdata->ep_out != 0) {
        return LIBUSB_ERROR_INVALID_PARAM;
      }
      drvdata->ep_out = endpoint->bEndpointAddress;
      drvdata->max_packet_size_out = endpoint->wMaxPacketSize;
    }
  }
  if (drvdata->ep_in == 0 || drvdata->ep_out == 0 ||
      drvdata->max_packet_size_out < sizeof(struct mailbox_request) + 1 ||
      drvdata->max_packet_size_in < sizeof(struct mailbox_response) + 1 ||
      drvdata->max_packet_size_out > LIBHOTH_USB_MAILBOX_MTU ||
      drvdata->max_packet_size_in > LIBHOTH_USB_MAILBOX_MTU) {
    return LIBUSB_ERROR_INVALID_PARAM;
  }

  return LIBHOTH_OK;
}

int libhoth_usb_mailbox_send_request(struct libhoth_usb_device* dev,
                                     const void* request, size_t request_size) {
  uint8_t packet[LIBHOTH_USB_MAILBOX_MTU];
  if (dev == NULL || request == NULL) {
    return LIBUSB_ERROR_INVALID_PARAM;
  }

  struct libhoth_usb_mailbox* drvdata = &dev->driver_data.mailbox;
  const size_t max_payload_size =
      drvdata->max_packet_size_in - sizeof(struct mailbox_request);

  uint32_t offset = 0;
  while (offset < request_size) {
    int transferred;
    uint8_t length = (request_size - offset) < max_payload_size
                         ? request_size - offset
                         : max_payload_size;
    struct mailbox_request request_header = {
        .type = MAILBOX_REQ_WRITE,
        .offset = offset,
        .length = length,
    };
    struct mailbox_response response;
    memcpy(&packet[0], &request_header, sizeof(request_header));
    memcpy(&packet[sizeof(request_header)], (const uint8_t*)request + offset,
           length);

    int status = libusb_bulk_transfer(dev->handle, drvdata->ep_out, packet,
                                      sizeof(request_header) + length,
                                      &transferred, /*timeout=*/0);
    if (status != LIBUSB_SUCCESS) {
      return status;
    }
    if (transferred != sizeof(request_header) + length) {
      return LIBUSB_ERROR_IO;
    }

    status =
        libusb_bulk_transfer(dev->handle, drvdata->ep_in, (void*)&response,
                             sizeof(response), &transferred, /*timeout=*/0);
    if (status != LIBUSB_SUCCESS) {
      return status;
    }
    if (transferred != sizeof(response)) {
      return LIBUSB_ERROR_IO;
    }
    if (response.status != MAILBOX_SUCCESS) {
      return LIBUSB_ERROR_IO;
    }
    offset += length;
  }
  return LIBHOTH_OK;
}

int libhoth_usb_mailbox_receive_response(struct libhoth_usb_device* dev,
                                         void* response, size_t response_size,
                                         size_t* actual_size, int timeout_ms) {
  uint8_t packet[LIBHOTH_USB_MAILBOX_MTU];
  if (dev == NULL || response == NULL) {
    return LIBUSB_ERROR_INVALID_PARAM;
  }

  struct libhoth_usb_mailbox* drvdata = &dev->driver_data.mailbox;
  const size_t max_payload_size =
      drvdata->max_packet_size_in - sizeof(struct mailbox_response);

  if (response_size < sizeof(struct hoth_host_response)) {
    return LIBUSB_ERROR_INVALID_PARAM;
  }

  uint32_t expected_size = response_size;

  uint32_t offset = 0;
  while (offset < expected_size) {
    int transferred;
    uint8_t length = (response_size - offset) < max_payload_size
                         ? response_size - offset
                         : max_payload_size;
    struct mailbox_request request = {
        .type = MAILBOX_REQ_READ,
        .offset = offset,
        .length = length,
    };
    int status = libusb_bulk_transfer(dev->handle, drvdata->ep_out,
                                      (void*)&request, sizeof(request),
                                      &transferred, /*timeout=*/timeout_ms);
    if (status != LIBUSB_SUCCESS) {
      return status;
    }
    if (transferred != sizeof(request)) {
      return LIBUSB_ERROR_IO;
    }

    status = libusb_bulk_transfer(dev->handle, drvdata->ep_in, packet,
                                  sizeof(struct mailbox_response) + length,
                                  &transferred, /*timeout=*/timeout_ms);
    if (status != LIBUSB_SUCCESS) {
      return status;
    }
    if (transferred < sizeof(struct mailbox_response)) {
      return LIBUSB_ERROR_IO;
    }
    struct mailbox_response response_header;
    memcpy(&response_header, &packet[0], sizeof(response_header));
    if (response_header.status != MAILBOX_SUCCESS) {
      return LIBUSB_ERROR_IO;
    }
    memcpy((uint8_t*)response + offset, &packet[sizeof(response_header)],
           length);

    if (offset == 0 && length >= sizeof(struct hoth_host_response)) {
      struct hoth_host_response response_header;
      memcpy(&response_header, response, sizeof(response_header));
      if (response_header.struct_version != 3) {
        return LIBHOTH_ERR_UNSUPPORTED_VERSION;
      }
      if (expected_size > sizeof(response_header) + response_header.data_len) {
        expected_size = sizeof(response_header) + response_header.data_len;
      }
    }
    offset += length;
    if (transferred < max_payload_size) {
      break;
    }
  }
  *actual_size = expected_size;

  return LIBHOTH_OK;
}

int libhoth_usb_mailbox_close(struct libhoth_usb_device* dev) {
  if (dev == NULL) {
    return LIBUSB_ERROR_INVALID_PARAM;
  }
  return LIBHOTH_OK;
}
