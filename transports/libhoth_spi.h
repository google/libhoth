// Copyright 2023 Google LLC
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

#ifndef _LIBHOTH_LIBHOTH_SPI_H_
#define _LIBHOTH_LIBHOTH_SPI_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct libhoth_device;

enum libhoth_spi_mode {
  LIBHOTH_SPI_MODE_SINGLE = 0,
  LIBHOTH_SPI_MODE_DUAL,
  LIBHOTH_SPI_MODE_QUAD,
};

struct libhoth_spi_device_init_options {
  // The device filepath to open
  const char* path;
  // Address where mailbox is located
  unsigned int mailbox;
  int bits;
  int mode;
  int speed;
  int atomic;
  enum libhoth_spi_mode operation_mode;
  uint32_t device_busy_wait_timeout;
  uint32_t device_busy_wait_check_interval;
  uint32_t timeout_us;
};

struct libhoth_spi_device {
  int fd;
  unsigned int mailbox_address;
  bool address_mode_4b;
  enum libhoth_spi_mode mode;
  uint32_t original_mode;

  void* buffered_request;
  size_t buffered_request_size;
  uint32_t device_busy_wait_timeout;
  uint32_t device_busy_wait_check_interval;
};

enum {
  SPI_NOR_DEVICE_STATUS_WIP_BIT = (1 << 0),
  SPI_NOR_OPCODE_READ_STATUS = 0x05,
  SPI_NOR_OPCODE_WRITE_ENABLE = 0x06,
  SPI_NOR_OPCODE_PAGE_PROGRAM = 0x02,
  SPI_NOR_OPCODE_QUAD_PAGE_PROGRAM = 0x38,
  SPI_NOR_OPCODE_SLOW_READ = 0x03,
  SPI_NOR_OPCODE_DUAL_READ = 0x3B,
  SPI_NOR_OPCODE_QUAD_READ = 0x6B,
  SPI_NOR_FLASH_PAGE_SIZE = 256,  // in bytes
};

// Note that the options struct only needs to to live for the duration of
// this function call. It can be destroyed once libhoth_spi_open returns.
int libhoth_spi_open(const struct libhoth_spi_device_init_options* options,
                     struct libhoth_device** out);
int libhoth_tpm_spi_probe(struct libhoth_device* dev);

int libhoth_spi_send_request(struct libhoth_device* dev, const void* request,
                             size_t request_size);

int libhoth_spi_receive_response(struct libhoth_device* dev, void* response,
                                 size_t max_response_size, size_t* actual_size,
                                 int timeout_ms);

int libhoth_spi_buffer_request(struct libhoth_device* dev, const void* request,
                               size_t request_size);

int libhoth_spi_send_and_receive_response(struct libhoth_device* dev,
                                          void* response,
                                          size_t max_response_size,
                                          size_t* actual_size, int timeout_ms);

int libhoth_spi_close(struct libhoth_device* dev);

#ifdef __cplusplus
}
#endif

#endif  // _LIBHOTH_LIBHOTH_SPI_H_
