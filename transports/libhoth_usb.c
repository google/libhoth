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

#include "transports/libhoth_usb.h"

#include <libusb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "libhoth_device.h"
#include "libhoth_usb.h"
#include "protocol/util.h"
#include "transports/libhoth_device.h"
#include "transports/libhoth_usb_device.h"

#define HOTH_VENDOR_ID 0x18d1
#define HOTH_B_PRODUCT_ID 0x5014
#define HOTH_D_PRODUCT_ID 0x022a
#define HOTH_E_PRODUCT_ID 0x023b

static int libhoth_usb_device_open(
    const struct libhoth_usb_device_init_options* options,
    struct libhoth_device* dev);

int libhoth_usb_send_request(struct libhoth_device* dev, const void* request,
                             size_t request_size);

int libhoth_usb_receive_response(struct libhoth_device* dev, void* response,
                                 size_t max_response_size, size_t* actual_size,
                                 int timeout_ms);

static struct libhoth_usb_interface_info libhoth_usb_find_interface(
    const struct libusb_config_descriptor* configuration) {
  struct libhoth_usb_interface_info info = {
      .type = LIBHOTH_USB_INTERFACE_TYPE_UNKNOWN,
  };
  for (int i = 0; i < configuration->bNumInterfaces; i++) {
    for (int j = 0; j < configuration->interface[i].num_altsetting; j++) {
      const struct libusb_interface_descriptor* interface =
          &configuration->interface[i].altsetting[j];
      if (interface->bInterfaceClass != LIBHOTH_USB_INTERFACE_CLASS) continue;
      if (interface->bInterfaceSubClass ==
              LIBHOTH_USB_MAILBOX_INTERFACE_SUBCLASS &&
          interface->bInterfaceProtocol ==
              LIBHOTH_USB_MAILBOX_INTERFACE_PROTOCOL) {
        info.type = LIBHOTH_USB_INTERFACE_TYPE_MAILBOX;
        info.interface_id = i;
        info.interface_altsetting = j;
        return info;
      }
      if (interface->bInterfaceSubClass ==
              LIBHOTH_USB_FIFO_INTERFACE_SUBCLASS &&
          interface->bInterfaceProtocol ==
              LIBHOTH_USB_FIFO_INTERFACE_PROTOCOL) {
        info.type = LIBHOTH_USB_INTERFACE_TYPE_FIFO;
        info.interface_id = i;
        info.interface_altsetting = j;
        return info;
      }
    }
  }
  return info;
}

static int libhoth_usb_claim(struct libhoth_device* dev) {
  struct libhoth_usb_device* usb_dev = dev->user_ctx;

  int status =
      libusb_claim_interface(usb_dev->handle, usb_dev->info.interface_id);

  if (status == LIBUSB_ERROR_BUSY) {
    return LIBHOTH_ERR_INTERFACE_BUSY;
  }

  return status;
}

static int libhoth_usb_release(struct libhoth_device* dev) {
  struct libhoth_usb_device* usb_dev = dev->user_ctx;
  return libusb_release_interface(usb_dev->handle, usb_dev->info.interface_id);
}

static int libhoth_usb_reconnect(struct libhoth_device* dev) {
  struct libhoth_usb_device* usb_dev = dev->user_ctx;
  libusb_context* usb_ctx = usb_dev->ctx;
  uint64_t timeout_us = usb_dev->claim_timeout_us;

  struct libusb_device* libusb_dev = libusb_get_device(usb_dev->handle);

  struct libhoth_usb_loc usb_loc;
  usb_loc.bus = libusb_get_bus_number(libusb_dev);
  usb_loc.num_ports = libusb_get_port_numbers(
      libusb_dev, (uint8_t*)&usb_loc.ports, LIBHOTH_NUM_PORTS);
  if (usb_loc.num_ports == LIBUSB_ERROR_OVERFLOW) {
    fprintf(stderr, "Failed to list port numbers when reconnecting. (%s)\n",
            libusb_strerror(LIBUSB_ERROR_OVERFLOW));
    return LIBUSB_ERROR_OVERFLOW;
  }

  libhoth_usb_close(dev);

  uint64_t start_time_ms = libhoth_get_monotonic_ms();

  while (1) {
    libusb_exit(usb_ctx);
    int ret = libusb_init(&usb_ctx);
    if (ret != 0) {
      fprintf(
          stderr,
          "libusb_init_context failed while reconnecting (error: %d (%s))\n",
          ret, libusb_strerror(ret));
    }

    ret = libhoth_usb_get_device(usb_ctx, &usb_loc, &libusb_dev);
    if (ret == 0) {
      // Found the device
      break;
    }

    uint64_t current_time_ms = libhoth_get_monotonic_ms();
    if (current_time_ms - start_time_ms >= (60 * 1000)) {
      // 60s timeout
      fprintf(
          stderr,
          "libhoth_usb_open timed out while reconnecting (error: %d (%s))\n",
          ret, libusb_strerror(ret));
      libusb_exit(usb_ctx);
      return ret;  // Timeout
    }

    // 100ms delay
    usleep(100 * 1000);
  }

  struct libhoth_usb_device_init_options opts;
  opts.usb_ctx = usb_ctx;
  opts.usb_device = libusb_dev;
  opts.timeout_us = timeout_us;
  opts.prng_seed = libhoth_prng_seed();

  return libhoth_usb_device_open(&opts, dev);
}

static int libhoth_usb_device_open(
    const struct libhoth_usb_device_init_options* options,
    struct libhoth_device* dev) {
  struct libhoth_usb_device* usb_dev = NULL;
  struct libusb_device_descriptor device_descriptor;
  int status =
      libusb_get_device_descriptor(options->usb_device, &device_descriptor);
  if (status != LIBUSB_SUCCESS) {
    return status;
  }

  // Ensure vendor ID matches
  if (device_descriptor.idVendor != LIBHOTH_USB_VENDOR_ID) {
    return LIBHOTH_ERR_UNKNOWN_VENDOR;
  }

  // Pick the correct driver based on the interface type
  struct libusb_config_descriptor* config_descriptor = NULL;
  status = libusb_get_active_config_descriptor(options->usb_device,
                                               &config_descriptor);
  if (status != LIBUSB_SUCCESS) {
    return status;
  }

  // Verify that the device has a supported interface
  struct libhoth_usb_interface_info info =
      libhoth_usb_find_interface(config_descriptor);
  if (info.type == LIBHOTH_USB_INTERFACE_TYPE_UNKNOWN) {
    status = LIBHOTH_ERR_INTERFACE_NOT_FOUND;
    goto err_out;
  }

  usb_dev = calloc(1, sizeof(struct libhoth_usb_device));
  if (usb_dev == NULL) {
    status = LIBHOTH_ERR_MALLOC_FAILED;
    goto err_out;
  }
  usb_dev->info = info;
  usb_dev->ctx = options->usb_ctx;
  usb_dev->claim_timeout_us = options->timeout_us;
  status = libusb_open(options->usb_device, &usb_dev->handle);
  if (status != LIBUSB_SUCCESS) {
    goto err_out;
  }

  dev->send = libhoth_usb_send_request;
  dev->receive = libhoth_usb_receive_response;
  dev->close = libhoth_usb_close;
  dev->claim = libhoth_usb_claim;
  dev->release = libhoth_usb_release;
  dev->reconnect = libhoth_usb_reconnect;
  dev->user_ctx = usb_dev;

  status = libhoth_claim_device(dev, options->timeout_us);
  if (status != LIBHOTH_OK) {
    goto err_out;
  }

  // Fill in driver-specific data
  switch (info.type) {
    case LIBHOTH_USB_INTERFACE_TYPE_MAILBOX:
      status = libhoth_usb_mailbox_open(usb_dev, config_descriptor);
      break;
    case LIBHOTH_USB_INTERFACE_TYPE_FIFO:
      status =
          libhoth_usb_fifo_open(usb_dev, config_descriptor, options->prng_seed);
      break;
    default:
      status = LIBHOTH_ERR_INTERFACE_NOT_FOUND;
      break;
  }

  if (status != LIBHOTH_OK) goto err_out;

  libusb_free_config_descriptor(config_descriptor);
  return LIBHOTH_OK;

err_out:
  if (dev != NULL) {
    if (usb_dev != NULL) {
      if (usb_dev->handle != NULL) {
        libusb_release_interface(usb_dev->handle, usb_dev->info.interface_id);
        libusb_close(usb_dev->handle);
      }
      free(usb_dev);
    }
  }
  libusb_free_config_descriptor(config_descriptor);
  return status;
}

int libhoth_usb_open(const struct libhoth_usb_device_init_options* options,
                     struct libhoth_device** out) {
  if (out == NULL || options == NULL || options->usb_device == NULL) {
    return LIBUSB_ERROR_INVALID_PARAM;
  }

  struct libhoth_device* dev = calloc(1, sizeof(struct libhoth_device));
  if (dev == NULL) {
    return LIBHOTH_ERR_MALLOC_FAILED;
  }

  int ret = libhoth_usb_device_open(options, dev);
  if (ret != LIBUSB_SUCCESS) {
    free(dev);
    return ret;
  }

  *out = dev;
  return LIBHOTH_OK;
}

int libhoth_usb_send_request(struct libhoth_device* dev, const void* request,
                             size_t request_size) {
  if (dev->user_ctx == NULL) {
    return LIBUSB_ERROR_INVALID_PARAM;
  }

  struct libhoth_usb_device* usb_dev =
      (struct libhoth_usb_device*)dev->user_ctx;
  switch (usb_dev->info.type) {
    case LIBHOTH_USB_INTERFACE_TYPE_MAILBOX:
      return libhoth_usb_mailbox_send_request(usb_dev, request, request_size);
    case LIBHOTH_USB_INTERFACE_TYPE_FIFO:
      return libhoth_usb_fifo_send_request(usb_dev, request, request_size);
    default:
      return LIBHOTH_ERR_INTERFACE_NOT_FOUND;
  }
  return LIBUSB_ERROR_NOT_SUPPORTED;
}

int libhoth_usb_receive_response(struct libhoth_device* dev, void* response,
                                 size_t max_response_size, size_t* actual_size,
                                 int timeout_ms) {
  if (dev->user_ctx == NULL) {
    return LIBUSB_ERROR_INVALID_PARAM;
  }

  struct libhoth_usb_device* usb_dev =
      (struct libhoth_usb_device*)dev->user_ctx;
  switch (usb_dev->info.type) {
    case LIBHOTH_USB_INTERFACE_TYPE_MAILBOX:
      return libhoth_usb_mailbox_receive_response(
          usb_dev, response, max_response_size, actual_size, timeout_ms);
    case LIBHOTH_USB_INTERFACE_TYPE_FIFO:
      return libhoth_usb_fifo_receive_response(
          usb_dev, response, max_response_size, actual_size, timeout_ms);
    default:
      return LIBHOTH_ERR_INTERFACE_NOT_FOUND;
  }
  return LIBUSB_ERROR_NOT_SUPPORTED;
}

int libhoth_usb_close(struct libhoth_device* dev) {
  int status;
  if (dev->user_ctx == NULL) {
    return LIBUSB_ERROR_INVALID_PARAM;
  }

  struct libhoth_usb_device* usb_dev =
      (struct libhoth_usb_device*)dev->user_ctx;
  dev->user_ctx = NULL;
  switch (usb_dev->info.type) {
    case LIBHOTH_USB_INTERFACE_TYPE_MAILBOX:
      status = libhoth_usb_mailbox_close(usb_dev);
      break;
    case LIBHOTH_USB_INTERFACE_TYPE_FIFO:
      status = libhoth_usb_fifo_close(usb_dev);
      break;
    default:
      return LIBHOTH_ERR_INTERFACE_NOT_FOUND;
  }
  if (status != LIBHOTH_OK) {
    return status;
  }
  if (usb_dev->handle != NULL) {
    libusb_release_interface(usb_dev->handle, usb_dev->info.interface_id);
    libusb_close(usb_dev->handle);
  }
  free(usb_dev);
  return LIBHOTH_OK;
}

enum libusb_error transfer_status_to_error(
    enum libusb_transfer_status transfer_status) {
  switch (transfer_status) {
    case LIBUSB_TRANSFER_COMPLETED:
      return LIBUSB_SUCCESS;

    case LIBUSB_TRANSFER_ERROR:
    case LIBUSB_TRANSFER_CANCELLED:
      return LIBUSB_ERROR_IO;

    case LIBUSB_TRANSFER_TIMED_OUT:
      return LIBUSB_ERROR_TIMEOUT;

    case LIBUSB_TRANSFER_STALL:
      return LIBUSB_ERROR_PIPE;

    case LIBUSB_TRANSFER_NO_DEVICE:
      return LIBUSB_ERROR_NO_DEVICE;

    case LIBUSB_TRANSFER_OVERFLOW:
      return LIBUSB_ERROR_OVERFLOW;

    default:
      return LIBUSB_ERROR_OTHER;
  }
}

bool libhoth_device_is_hoth(const struct libusb_device_descriptor* dev) {
  return dev && dev->idVendor == HOTH_VENDOR_ID &&
         (dev->idProduct == HOTH_B_PRODUCT_ID ||
          dev->idProduct == HOTH_D_PRODUCT_ID ||
          dev->idProduct == HOTH_E_PRODUCT_ID);
}

int libhoth_get_usb_loc(libusb_device* dev, struct libhoth_usb_loc* result) {
  if (dev == NULL || result == NULL) {
    return LIBUSB_ERROR_INVALID_PARAM;
  }
  result->bus = libusb_get_bus_number(dev);
  int num_ports =
      libusb_get_port_numbers(dev, result->ports, sizeof(result->ports));
  if (num_ports < 0) {
    return num_ports;
  }
  result->num_ports = num_ports;
  return 0;
}

int libhoth_usb_get_device(libusb_context* ctx,
                           const struct libhoth_usb_loc* usb_loc,
                           libusb_device** out) {
  if (ctx == NULL || usb_loc == NULL || out == NULL) {
    return LIBUSB_ERROR_INVALID_PARAM;
  }

  libusb_device** device;
  struct libhoth_usb_loc loc;
  bool found_device = false;

  ssize_t num_devices = libusb_get_device_list(ctx, &device);
  if (num_devices < 0) {
    return num_devices;
  }

  for (ssize_t i = 0; i < num_devices; i++) {
    int rev = libhoth_get_usb_loc(device[i], &loc);
    if (rev) {
      continue;
    }

    bool loc_matches = (loc.bus == usb_loc->bus) &&
                       (loc.num_ports == usb_loc->num_ports) &&
                       (memcmp(loc.ports, usb_loc->ports, loc.num_ports) == 0);

    if (!loc_matches) {
      continue;
    }

    struct libusb_device_descriptor device_descriptor;
    int rv = libusb_get_device_descriptor(device[i], &device_descriptor);
    if (rv != LIBUSB_SUCCESS) {
      continue;
    }

    if (libhoth_device_is_hoth(&device_descriptor)) {
      libusb_ref_device(device[i]);
      found_device = true;
      *out = device[i];
      break;
    }
  }

  libusb_free_device_list(device, /*unref_devices=*/1);
  return found_device ? LIBHOTH_OK : LIBHOTH_ERR_INTERFACE_NOT_FOUND;
}
