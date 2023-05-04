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

#include <errno.h>
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

static int mtd_read(int fd, unsigned int address, void* data, size_t data_len) {
  if (fd < 0 || !data || !data_len) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }

  if (lseek(fd, address, SEEK_SET) < 0) {
    return LIBHOTH_ERR_FAIL;
  }

  while (data_len > 0) {
    int ret = read(fd, data, data_len);
    if (ret < 0) {
      if (errno == EINTR) {
        continue;  // interrupted; try again
      }
      return LIBHOTH_ERR_FAIL;
    } else if (ret == 0) {
      // EOF hit
      return LIBHOTH_ERR_IN_OVERFLOW;
    } else {
      // ret > 0
      data += ret;
      data_len -= ret;
    }
  }
  return LIBHOTH_OK;
}

static int mtd_write(int fd, unsigned int address, const void* data,
                     size_t data_len) {
  if (fd < 0 || !data || !data_len) return LIBHOTH_ERR_INVALID_PARAMETER;

  if (lseek(fd, address, SEEK_SET) < 0) {
    return LIBHOTH_ERR_FAIL;
  }

  size_t ret = -1;
  do {
    ret = write(fd, data, data_len);
    // Retry if interrupted
  } while (ret < 0 && errno == EINTR);

  if (ret < 0) {
    return LIBHOTH_ERR_FAIL;
  }

  if (ret != data_len) {
    // Fail on incomplete writes because they can confuse Hoth
    return LIBHOTH_ERR_OUT_UNDERFLOW;
  }

  return LIBHOTH_OK;
}

int libhoth_mtd_open(const struct libhoth_mtd_device_init_options* options,
                     struct libhoth_device** out) {
  if (out == NULL || options == NULL || options->path == NULL ||
      options->name == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }

  int status;
  int fd = -1;
  struct libhoth_device* dev = NULL;
  struct libhoth_mtd_device* mtd_dev = NULL;

  if (strlen(options->path) == 0) {
    // TODO(daimeng): Auto-detect mailbox devpath
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }

  fd = open(options->path, O_RDWR);
  if (fd < 0) {
    status = LIBHOTH_ERR_INTERFACE_NOT_FOUND;
    goto err_out;
  }

  dev = calloc(1, sizeof(struct libhoth_device));
  if (dev == NULL) {
    status = LIBHOTH_ERR_MALLOC_FAILED;
    goto err_out;
  }

  mtd_dev = calloc(1, sizeof(struct libhoth_mtd_device));
  if (mtd_dev == NULL) {
    status = LIBHOTH_ERR_MALLOC_FAILED;
    goto err_out;
  }

  mtd_dev->fd = fd;
  mtd_dev->mailbox_address = options->mailbox;

  dev->send = libhoth_mtd_send_request;
  dev->receive = libhoth_mtd_receive_response;
  dev->close = libhoth_mtd_close;
  dev->user_ctx = mtd_dev;

  *out = dev;
  return LIBHOTH_OK;

err_out:
  if (fd >= 0) {
    close(fd);
  }
  if (dev != NULL) {
    free(dev);
  }
  if (mtd_dev != NULL) {
    free(mtd_dev);
  }
  return status;
}

int libhoth_mtd_send_request(struct libhoth_device* dev, const void* request,
                             size_t request_size) {
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }

  struct libhoth_mtd_device* mtd_dev =
      (struct libhoth_mtd_device*)dev->user_ctx;

  return mtd_write(mtd_dev->fd, mtd_dev->mailbox_address, request,
                   request_size);
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

  size_t total_bytes;
  int status;
  struct ec_host_response host_response;
  struct libhoth_mtd_device* mtd_dev =
      (struct libhoth_mtd_device*)dev->user_ctx;

  // Read Header From Mailbox
  status = mtd_read(mtd_dev->fd, mtd_dev->mailbox_address, response, 8);
  if (status != LIBHOTH_OK) {
    return status;
  }

  total_bytes = 8;
  memcpy(&host_response, response, sizeof(host_response));
  if (actual_size) {
    *actual_size = total_bytes;
  }

  if (max_response_size < (total_bytes + host_response.data_len)) {
    return LIBHOTH_ERR_RESPONSE_BUFFER_OVERFLOW;
  }

  // Read remainder of data based on header length
  uint8_t* const data_start = (uint8_t*)response + total_bytes;
  status = mtd_read(mtd_dev->fd, mtd_dev->mailbox_address + total_bytes,
                    data_start, host_response.data_len);
  if (status != LIBHOTH_OK) {
    return status;
  }

  if (actual_size) {
    *actual_size += host_response.data_len;
  }

  return LIBHOTH_OK;
}

int libhoth_mtd_close(struct libhoth_device* dev) {
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }
  struct libhoth_mtd_device* mtd_dev =
      (struct libhoth_mtd_device*)dev->user_ctx;
  close(mtd_dev->fd);
  free(dev->user_ctx);
  return LIBHOTH_OK;
}
