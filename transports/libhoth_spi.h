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

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct libhoth_device;

struct libhoth_spi_device_init_options {
  // The device filepath to open
  const char* path;
  // Address where mailbox is located
  unsigned int mailbox;
  int bits;
  int mode;
  int speed;
  int atomic;
  uint32_t device_busy_wait_timeout;
  uint32_t device_busy_wait_check_interval;
  uint32_t timeout_us;
};

// Note that the options struct only needs to to live for the duration of
// this function call. It can be destroyed once libhoth_spi_open returns.
int libhoth_spi_open(const struct libhoth_spi_device_init_options* options,
                     struct libhoth_device** out);
int libhoth_tpm_spi_probe(struct libhoth_device* dev);

#ifdef __cplusplus
}
#endif

#endif  // _LIBHOTH_LIBHOTH_SPI_H_
