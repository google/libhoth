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

#include "spi_hoth_device.h"

std::expected<HothDevice, libhoth_status> MakeSpiHothDevice(
    const libhoth_spi_device_init_options& options) {
  struct libhoth_device* dev = nullptr;
  int status = libhoth_spi_open(&options, &dev);
  if (status != LIBHOTH_OK) {
    return std::unexpected(static_cast<libhoth_status>(status));
  }
  return HothDevice(dev);
}
