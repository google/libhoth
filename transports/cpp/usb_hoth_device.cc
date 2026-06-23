// Copyright 2026 Google LLC
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

#include "usb_hoth_device.h"
#include "protocol/util.h"

std::expected<HothDevice, libhoth_status> MakeUsbHothDevice(
    const libhoth_usb_device_init_options& options) {
  struct libhoth_device* dev = nullptr;
  int status = libhoth_usb_open(&options, &dev);
  if (status != LIBHOTH_OK) {
    return std::unexpected(static_cast<libhoth_status>(status));
  }
  return HothDevice(dev);
}

std::expected<HothDevice, libhoth_status> MakeUsbHothDevice(
    libusb_context* ctx, uint32_t timeout_us) {
  libusb_device* usb_dev = nullptr;
  int status = libhoth_usb_get_device(ctx, nullptr, &usb_dev);
  if (status != LIBHOTH_OK) {
    return std::unexpected(static_cast<libhoth_status>(status));
  }

  libhoth_usb_device_init_options opts = {};
  opts.usb_device = usb_dev;
  opts.usb_ctx = ctx;
  opts.prng_seed = libhoth_prng_seed();
  opts.timeout_us = timeout_us;

  auto dev_or_err = MakeUsbHothDevice(opts);
  libusb_unref_device(usb_dev);
  return dev_or_err;
}
