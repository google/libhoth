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

#ifndef LIBHOTH_EXAMPLES_HTOOL_SPI_H_
#define LIBHOTH_EXAMPLES_HTOOL_SPI_H_

#include <stdint.h>

struct htool_progress;

struct htool_spi {
  struct libhoth_usb_device* dev;
  bool is_4_byte;
};

int htool_spi_init(struct htool_spi* spi, struct libhoth_usb_device* dev);

int htool_spi_read(const struct htool_spi* spi, uint32_t addr, void* buf,
                   size_t len);

int htool_spi_verify(const struct htool_spi* spi, uint32_t addr,
                     const void* buf, size_t len,
                     const struct htool_progress* progress);

int htool_spi_update(const struct htool_spi* spi, uint32_t addr,
                     const void* buf, size_t len,
                     const struct htool_progress* progress);

#endif  // LIBHOTH_EXAMPLES_HTOOL_SPI_H_
