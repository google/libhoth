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

#ifndef _LIBHOTH_USB_HOTH_DEVICE_H_
#define _LIBHOTH_USB_HOTH_DEVICE_H_

#include <expected>

#include "hoth_device.h"
#include "transports/libhoth_device.h"
#include "transports/libhoth_usb.h"

std::expected<HothDevice, libhoth_status> MakeUsbHothDevice(
    const libhoth_usb_device_init_options& options);

std::expected<HothDevice, libhoth_status> MakeUsbHothDevice(
    libusb_context* ctx, uint32_t timeout_us = 5000000);

#endif // _LIBHOTH_USB_HOTH_DEVICE_H_
