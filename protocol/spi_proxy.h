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

#ifndef LIBHOTH_PROTOCOL_SPI_PROXY_H_
#define LIBHOTH_PROTOCOL_SPI_PROXY_H_

#include <stddef.h>
#include <stdint.h>

#include "protocol/progress.h"
#include "transports/libhoth_device.h"

#ifdef __cplusplus
extern "C" {
#endif

struct libhoth_spi_proxy {
  struct libhoth_device* dev;
  bool is_4_byte;
};

int libhoth_spi_proxy_init(struct libhoth_spi_proxy* spi,
                           struct libhoth_device* dev, bool is_4_byte,
                           bool enter_exit_4b);

int libhoth_spi_proxy_read(const struct libhoth_spi_proxy* spi, uint32_t addr,
                           void* buf, size_t len);

int libhoth_spi_proxy_update(const struct libhoth_spi_proxy* spi, uint32_t addr,
                             const void* buf, size_t len,
                             const struct libhoth_progress* progress);

int libhoth_spi_proxy_verify(const struct libhoth_spi_proxy* spi, uint32_t addr,
                             const void* buf, size_t len,
                             const struct libhoth_progress* progress);

struct ec_spi_operation_request {
  // The number of MOSI bytes we're sending
  uint16_t mosi_len;
  // The number of MISO bytes we want to receive
  uint16_t miso_len;

  // Note: The total size of the SPI transaction on the wire is
  // MAX(mosi_len, miso_len).
} __attribute__((packed));

// A EC_PRV_CMD_HOTH_SPI_OPERATION request consists of one or more SPI
// transactions. Each SPI transaction consists of a ec_spi_operation_request
// header followed by the MOSI bytes (starting with the opcode), and each
// transaction is laid-out back-to-back with no padding or alignment.
//
// The response consists of the first ec_spi_operation_request::miso_len
// MISO bytes of each SPI transaction, including the dummy MISO bytes sent while
// the opcode/addr/dummy MOSI bytes are being transmitted. All the MISO bytes
// are laid-out back-to-back with no header, padding, or alignment.
#define EC_PRV_CMD_HOTH_SPI_OPERATION 0x0020

#ifdef __cplusplus
}
#endif

#endif
