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
#include "transports/libhoth_usb_device.h"

#define LIBHOTH_USB_FIFO_REQUEST_ID_SIZE 16
#define LIBHOTH_USB_FIFO_MAX_REQUEST_SIZE 1024
#define LIBHOTH_USB_FIFO_MTU \
  (LIBHOTH_USB_FIFO_REQUEST_ID_SIZE + LIBHOTH_USB_FIFO_MAX_REQUEST_SIZE)

static int libhoth_usb_fifo_run_transfers(struct libhoth_usb_device* dev,
                                          bool out, bool in) {
  struct libhoth_usb_fifo* drvdata = &dev->driver_data.fifo;
  drvdata->all_transfers_completed = 0;
  drvdata->out_transfer_completed = !out;
  drvdata->in_transfer_completed = !in;

  if (in) {
    int status = libusb_submit_transfer(drvdata->in_transfer);
    if (status != LIBUSB_SUCCESS) {
      return status;
    }
  }
  if (out) {
    int status = libusb_submit_transfer(drvdata->out_transfer);
    if (status != LIBUSB_SUCCESS) {
      return status;
    }
  }
  while (drvdata->all_transfers_completed == 0) {
    int status = libusb_handle_events_completed(
        dev->ctx, &drvdata->all_transfers_completed);
    if (status == LIBUSB_ERROR_INTERRUPTED) {
      return status;
    }
  }
  return LIBHOTH_OK;
}

static void fifo_transfer_callback(struct libusb_transfer* transfer) {
  struct libhoth_usb_device* dev =
      (struct libhoth_usb_device*)transfer->user_data;
  struct libhoth_usb_fifo* drvdata = &dev->driver_data.fifo;
  if (transfer == drvdata->in_transfer) {
    drvdata->in_transfer_completed = true;
    if (transfer->status != LIBUSB_TRANSFER_COMPLETED &&
        !drvdata->out_transfer_completed) {
      // Cancel pending OUT transfer so we don't get stuck waiting forever
      // inside libusb_handle_events_completed().
      libusb_cancel_transfer(drvdata->out_transfer);
    }
  }
  if (transfer == drvdata->out_transfer) {
    drvdata->out_transfer_completed = true;
    if (transfer->status != LIBUSB_TRANSFER_COMPLETED &&
        !drvdata->in_transfer_completed) {
      // Cancel pending IN transfer so we don't get stuck waiting forever
      // inside libusb_handle_events_completed().
      libusb_cancel_transfer(drvdata->in_transfer);
    }
  }
  if (drvdata->in_transfer_completed && drvdata->out_transfer_completed) {
    drvdata->all_transfers_completed = 1;
  }
}

// 32-bits XOR shift algorithm from "Xorshift RNGs" by George Marsaglia
static uint32_t libhoth_generate_pseudorandom_u32(uint32_t* seed) {
  *seed ^= (*seed << 13);
  // The paper seems to have a typo in the algorithm presented on Pg 4, missing
  // the ^ operation for second assignment. Pg 3 shows 8 shift operations that
  // can serve as basis for xorshift. All of them have ^= operation.
  *seed ^= (*seed >> 17);
  *seed ^= (*seed << 5);
  return *seed;
}

int libhoth_usb_fifo_open(struct libhoth_usb_device* dev,
                          const struct libusb_config_descriptor* descriptor,
                          uint32_t prng_seed) {
  int status = LIBHOTH_OK;
  if (dev == NULL || descriptor == NULL ||
      dev->info.type != LIBHOTH_USB_INTERFACE_TYPE_FIFO ||
      // XORShift PRNG must be seeded with non-zero value, otherwise it will
      // produce a stream of only zeroes
      (prng_seed == 0)) {
    return LIBUSB_ERROR_INVALID_PARAM;
  }
  const struct libusb_interface* interface_settings =
      &descriptor->interface[dev->info.interface_id];
  const struct libusb_interface_descriptor* interface =
      &interface_settings->altsetting[dev->info.interface_altsetting];

  // Fill out driver data.
  struct libhoth_usb_fifo* drvdata = &dev->driver_data.fifo;

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
  if (drvdata->ep_in == 0 || drvdata->ep_out == 0) {
    return LIBUSB_ERROR_INVALID_PARAM;
  }

  drvdata->in_transfer = libusb_alloc_transfer(0);
  drvdata->out_transfer = libusb_alloc_transfer(0);
  if (drvdata->in_transfer == NULL || drvdata->out_transfer == NULL) {
    return LIBHOTH_ERR_MALLOC_FAILED;
  }
  drvdata->in_transfer->length = 0;
  drvdata->out_transfer->length = 0;

  drvdata->in_buffer = (uint8_t*)malloc(LIBHOTH_USB_FIFO_MTU);
  drvdata->out_buffer = (uint8_t*)malloc(LIBHOTH_USB_FIFO_MTU);
  if (drvdata->in_buffer == NULL) {
    status = LIBHOTH_ERR_MALLOC_FAILED;
    goto err_out;
  }
  if (drvdata->out_buffer == NULL) {
    status = LIBHOTH_ERR_MALLOC_FAILED;
    goto err_out;
  }
  drvdata->prng_state = prng_seed;
  return LIBHOTH_OK;
err_out:
  if (drvdata->in_buffer != NULL) free(drvdata->in_buffer);
  if (drvdata->out_buffer != NULL) free(drvdata->out_buffer);
  libusb_free_transfer(drvdata->in_transfer);
  libusb_free_transfer(drvdata->out_transfer);
  return status;
}

int libhoth_usb_fifo_send_request(struct libhoth_usb_device* dev,
                                  const void* request, size_t request_size) {
  if (dev == NULL || request == NULL ||
      request_size > LIBHOTH_USB_FIFO_MAX_REQUEST_SIZE) {
    return LIBUSB_ERROR_INVALID_PARAM;
  }
  // TODO: Do something to warn users when doing two send_request() calls
  // without a receive_response() call in between?
  // if (drvdata->out_transfer->length != 0) {
  //   return LIBUSB_ERROR_BUSY;
  // }

  // Prepare the buffer with a request ID
  struct libhoth_usb_fifo* drvdata = &dev->driver_data.fifo;
  for (int i = 0; i < LIBHOTH_USB_FIFO_REQUEST_ID_SIZE; i++) {
    drvdata->out_buffer[i] =
        (uint8_t)libhoth_generate_pseudorandom_u32(&drvdata->prng_state);
  }

  memcpy(drvdata->out_buffer + LIBHOTH_USB_FIFO_REQUEST_ID_SIZE, request,
         request_size);
  // timeout is filled in later
  libusb_fill_bulk_transfer(drvdata->out_transfer, dev->handle, drvdata->ep_out,
                            drvdata->out_buffer,
                            LIBHOTH_USB_FIFO_REQUEST_ID_SIZE + request_size,
                            fifo_transfer_callback, dev, /*timeout=*/0);
  drvdata->out_transfer->flags |= LIBUSB_TRANSFER_ADD_ZERO_PACKET;
  return LIBHOTH_OK;
}

int libhoth_usb_fifo_receive_response(struct libhoth_usb_device* dev,
                                      void* response, size_t max_response_size,
                                      size_t* actual_size, int timeout_ms) {
  if (dev == NULL || response == NULL ||
      max_response_size > LIBHOTH_USB_FIFO_MAX_REQUEST_SIZE) {
    return LIBUSB_ERROR_INVALID_PARAM;
  }
  size_t max_in_transfer_size =
      LIBHOTH_USB_FIFO_REQUEST_ID_SIZE + max_response_size;
  struct libhoth_usb_fifo* drvdata = &dev->driver_data.fifo;
  if (drvdata->out_transfer->length == 0) {
    // OUT transfer not filled in. Forgot to call libhoth_usb_fifo_send_request?
    return LIBUSB_ERROR_IO;
  }
  libusb_fill_bulk_transfer(drvdata->in_transfer, dev->handle, drvdata->ep_in,
                            drvdata->in_buffer, LIBHOTH_USB_FIFO_MTU,
                            fifo_transfer_callback, dev, timeout_ms);
  drvdata->out_transfer->timeout = timeout_ms;
  int status = libhoth_usb_fifo_run_transfers(dev, /*out=*/true, /*in=*/true);
  if (status != LIBHOTH_OK) {
    goto transfer_done;
  }

  if (drvdata->in_transfer->status == LIBUSB_TRANSFER_STALL ||
      drvdata->out_transfer->status == LIBUSB_TRANSFER_STALL) {
    status = libusb_clear_halt(dev->handle, drvdata->ep_in);
    if (status != LIBUSB_SUCCESS) {
      goto transfer_done;
    }
    status = libusb_clear_halt(dev->handle, drvdata->ep_out);
    if (status != LIBUSB_SUCCESS) {
      goto transfer_done;
    }
    status = libhoth_usb_fifo_run_transfers(dev, /*out=*/true, /*in=*/true);
    if (status != LIBUSB_SUCCESS) {
      goto transfer_done;
    }
  }

  if (drvdata->out_transfer->status != LIBUSB_TRANSFER_COMPLETED) {
    status = transfer_status_to_error(drvdata->out_transfer->status);
    goto transfer_done;
  }

  if (drvdata->out_transfer->actual_length != drvdata->out_transfer->length) {
    return LIBHOTH_ERR_OUT_UNDERFLOW;
  }
  for (int i = 0;; i++) {
    if (drvdata->in_transfer->status != LIBUSB_TRANSFER_COMPLETED) {
      status = transfer_status_to_error(drvdata->in_transfer->status);
      goto transfer_done;
    }
    if (drvdata->in_transfer->actual_length > max_in_transfer_size) {
      status = LIBHOTH_ERR_IN_OVERFLOW;
      goto transfer_done;
    }
    if (drvdata->in_transfer->actual_length <
        LIBHOTH_USB_FIFO_REQUEST_ID_SIZE) {
      status = LIBUSB_ERROR_IO;
      goto transfer_done;
    }
    if (memcmp(drvdata->out_buffer, drvdata->in_buffer,
               LIBHOTH_USB_FIFO_REQUEST_ID_SIZE) == 0) {
      *actual_size = drvdata->in_transfer->actual_length -
                     LIBHOTH_USB_FIFO_REQUEST_ID_SIZE;
      memcpy(response, drvdata->in_buffer + LIBHOTH_USB_FIFO_REQUEST_ID_SIZE,
             *actual_size);
      break;
    }
    if (i >= 10) {
      // Tried 10 times. Giving up.
      status = LIBUSB_ERROR_IO;
      goto transfer_done;
    }

    // The most likely reason for this is that another process died in the
    // middle of a host command, leaving their response in the RoT's TxFIFO.
    // Let's make another transfer and hopefully find our response...
    status = libhoth_usb_fifo_run_transfers(dev, /*out=*/false, /*in=*/true);
    if (status != LIBHOTH_OK) {
      goto transfer_done;
    }
  }
  status = LIBHOTH_OK;

transfer_done:
  drvdata->out_transfer->length = 0;
  return status;
}

int libhoth_usb_fifo_close(struct libhoth_usb_device* dev) {
  if (dev == NULL) {
    return LIBUSB_ERROR_INVALID_PARAM;
  }
  struct libhoth_usb_fifo* drvdata = &dev->driver_data.fifo;
  if (drvdata->in_buffer != NULL) free(drvdata->in_buffer);
  if (drvdata->out_buffer != NULL) free(drvdata->out_buffer);
  libusb_free_transfer(drvdata->in_transfer);
  libusb_free_transfer(drvdata->out_transfer);
  return LIBHOTH_OK;
}
