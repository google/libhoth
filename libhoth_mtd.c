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

#include "libhoth_mtd.h"

#include <fcntl.h>
#include <linux/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "libhoth.h"
#include "libhoth_ec.h"

struct libhoth_mtd_device {
  int fd;
  unsigned int mailbox_address;
};

int libhoth_mtd_send_request(struct libhoth_device* dev, const void* request,
                             size_t request_size);

int libhoth_mtd_receive_response(struct libhoth_device* dev, void* response,
                                 size_t max_response_size, size_t* actual_size,
                                 int timeout_ms);

int libhoth_mtd_close(struct libhoth_device* dev);

int libhoth_mtd_open(const struct libhoth_mtd_device_init_options* options,
                     struct libhoth_device** out) {
  if (out == NULL || options == NULL || options->path == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }
  return LIBHOTH_OK;
}

int libhoth_mtd_send_request(struct libhoth_device* dev, const void* request,
                             size_t request_size) {
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }
  return LIBHOTH_OK;
}

int libhoth_mtd_receive_response(struct libhoth_device* dev, void* response,
                                 size_t max_response_size, size_t* actual_size,
                                 int timeout_ms) {
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }

  if (max_response_size < 8) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }
  return LIBHOTH_OK;
}

int libhoth_mtd_close(struct libhoth_device* dev) {
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }
  return LIBHOTH_OK;
}
