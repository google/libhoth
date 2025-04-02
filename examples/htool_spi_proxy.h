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

#ifndef LIBHOTH_EXAMPLES_HTOOL_SPI_PROXY_H_
#define LIBHOTH_EXAMPLES_HTOOL_SPI_PROXY_H_

#include <stddef.h>
#include <stdint.h>

#include "protocol/spi_proxy.h"

#ifdef __cplusplus
extern "C" {
#endif

int htool_spi_proxy_init(struct htool_spi_proxy* spi,
                         struct libhoth_device* dev, bool is_4_byte,
                         bool enter_exit_4b);

int htool_spi_proxy_read(const struct htool_spi_proxy* spi, uint32_t addr,
                         void* buf, size_t len);

int htool_spi_proxy_verify(const struct htool_spi_proxy* spi, uint32_t addr,
                           const void* buf, size_t len,
                           const struct libhoth_progress* progress);

int htool_spi_proxy_update(const struct htool_spi_proxy* spi, uint32_t addr,
                           const void* buf, size_t len,
                           const struct libhoth_progress* progress);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_HTOOL_SPI_PROXY_H_
