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

#include "libhoth_spi.h"

#include <fcntl.h>
#include <linux/spi/spidev.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "libhoth.h"
#include "libhoth_ec.h"

struct libhoth_spi_device {
  int fd;
  unsigned int mailbox_address;
  bool address_mode_4b;

  void* buffered_request;
  size_t buffered_request_size;
};

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

static int spi_nor_address(uint8_t* buf, uint32_t address,
                           bool address_mode_4b) {
  if (address_mode_4b) {
    buf[0] = (address >> 24) & 0xFF;
    buf[1] = (address >> 16) & 0xFF;
    buf[2] = (address >> 8) & 0xFF;
    buf[3] = address & 0xFF;
    return 4;
  } else {
    buf[0] = (address >> 16) & 0xFF;
    buf[1] = (address >> 8) & 0xFF;
    buf[2] = address & 0xFF;
    return 3;
  }
}

static int spi_nor_write(int fd, bool address_mode_4b, unsigned int address,
                         const void* data, size_t data_len) {
  if (fd < 0 || !data || !data_len) return LIBHOTH_ERR_INVALID_PARAMETER;

  uint8_t wp_buf[1] = {};
  uint8_t rq_buf[5] = {};
  struct spi_ioc_transfer xfer[3] = {};

  // Write Enable Message
  wp_buf[0] = 0x06;
  xfer[0] = (struct spi_ioc_transfer){
      .tx_buf = (unsigned long)wp_buf,
      .len = 1,
      .cs_change = 1,
  };

  // Page Program OPCODE + Mailbox Address
  rq_buf[0] = 0x02;
  int address_len = spi_nor_address(&rq_buf[1], address, address_mode_4b);
  xfer[1] = (struct spi_ioc_transfer){
      .tx_buf = (unsigned long)rq_buf,
      .len = 1 + address_len,
  };

  // Write Data at mailbox address
  xfer[2] = (struct spi_ioc_transfer){
      .tx_buf = (unsigned long)data,
      .len = data_len,
  };

  int status = ioctl(fd, SPI_IOC_MESSAGE(3), xfer);
  if (status < 0) {
    return LIBHOTH_ERR_FAIL;
  }

  return LIBHOTH_OK;
}

static int spi_nor_read(int fd, bool address_mode_4b, unsigned int address,
                        void* data, size_t data_len) {
  if (fd < 0 || !data || !data_len) return LIBHOTH_ERR_INVALID_PARAMETER;

  uint8_t rd_request[5];
  struct spi_ioc_transfer xfer[2] = {};

  // Read OPCODE and mailbox address
  rd_request[0] = 0x03;  // Read
  int address_len = spi_nor_address(&rd_request[1], address, address_mode_4b);
  xfer[0] = (struct spi_ioc_transfer){
      .tx_buf = (unsigned long)rd_request,
      .len = 1 + address_len,
  };

  // Read in data
  xfer[1] = (struct spi_ioc_transfer){
      .rx_buf = (unsigned long)data,
      .len = data_len,
  };

  int status = ioctl(fd, SPI_IOC_MESSAGE(2), xfer);
  if (status < 0) {
    return LIBHOTH_ERR_FAIL;
  }

  return LIBHOTH_OK;
}

static int libhoth_spi_claim(struct libhoth_device* dev) {
  // no-op
  return LIBHOTH_OK;
}

static int libhoth_spi_release(struct libhoth_device* dev) {
  // no-op
  return LIBHOTH_OK;
}

int libhoth_spi_open(const struct libhoth_spi_device_init_options* options,
                     struct libhoth_device** out) {
  if (out == NULL || options == NULL || options->path == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }

  int status;
  int fd = -1;
  struct libhoth_device* dev = NULL;
  struct libhoth_spi_device* spi_dev = NULL;

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

  spi_dev = calloc(1, sizeof(struct libhoth_spi_device));
  if (spi_dev == NULL) {
    status = LIBHOTH_ERR_MALLOC_FAILED;
    goto err_out;
  }

  if (options->bits) {
    const uint8_t bits = (uint8_t)options->bits;
    if (ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, bits) < 0) {
      status = LIBHOTH_ERR_FAIL;
      goto err_out;
    }
  }

  if (options->mode) {
    const uint8_t mode = (uint8_t)options->mode;
    if (ioctl(fd, SPI_IOC_WR_MODE, &mode) < 0) {
      status = LIBHOTH_ERR_FAIL;
      goto err_out;
    }
  }

  if (options->speed) {
    const uint32_t speed = (uint32_t)options->speed;
    if (ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed) < 0) {
      status = LIBHOTH_ERR_FAIL;
      goto err_out;
    }
  }

  spi_dev->fd = fd;
  spi_dev->mailbox_address = options->mailbox;
  spi_dev->address_mode_4b = true;

  if (options->atomic) {
    dev->send = libhoth_spi_buffer_request;
    dev->receive = libhoth_spi_send_and_receive_response;
  } else {
    dev->send = libhoth_spi_send_request;
    dev->receive = libhoth_spi_receive_response;
  }
  dev->close = libhoth_spi_close;
  dev->claim = libhoth_spi_claim;
  dev->release = libhoth_spi_release;
  dev->user_ctx = spi_dev;

  *out = dev;
  return LIBHOTH_OK;

err_out:
  if (fd >= 0) {
    close(fd);
  }
  if (dev != NULL) {
    free(dev);
  }
  if (spi_dev != NULL) {
    free(spi_dev);
  }

  return status;
}

int libhoth_spi_send_request(struct libhoth_device* dev, const void* request,
                             size_t request_size) {
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }

  struct libhoth_spi_device* spi_dev =
      (struct libhoth_spi_device*)dev->user_ctx;

  return spi_nor_write(spi_dev->fd, spi_dev->address_mode_4b,
                       spi_dev->mailbox_address, request, request_size);
}

int libhoth_spi_receive_response(struct libhoth_device* dev, void* response,
                                 size_t max_response_size, size_t* actual_size,
                                 int timeout_ms) {
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }

  if (max_response_size < sizeof(struct ec_host_response)) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }

  size_t total_bytes;
  int status;
  struct ec_host_response host_response;
  struct libhoth_spi_device* spi_dev =
      (struct libhoth_spi_device*)dev->user_ctx;

  // Read Header From Mailbox
  status = spi_nor_read(spi_dev->fd, spi_dev->address_mode_4b,
                        spi_dev->mailbox_address, response,
                        sizeof(struct ec_host_response));
  if (status != LIBHOTH_OK) {
    return status;
  }

  total_bytes = sizeof(struct ec_host_response);
  memcpy(&host_response, response, sizeof(host_response));
  if (actual_size) {
    *actual_size = total_bytes;
  }

  if (max_response_size < (total_bytes + host_response.data_len)) {
    return LIBHOTH_ERR_RESPONSE_BUFFER_OVERFLOW;
  }

  // Read remainder of data based on header length
  uint8_t* const data_start = (uint8_t*)response + total_bytes;
  status = spi_nor_read(spi_dev->fd, spi_dev->address_mode_4b,
                        spi_dev->mailbox_address + total_bytes, data_start,
                        host_response.data_len);
  if (status != LIBHOTH_OK) {
    return status;
  }

  if (actual_size) {
    *actual_size += host_response.data_len;
  }

  return LIBHOTH_OK;
}

int libhoth_spi_buffer_request(struct libhoth_device* dev, const void* request,
                               size_t request_size) {
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }

  struct libhoth_spi_device* spi_dev =
      (struct libhoth_spi_device*)dev->user_ctx;

  if (spi_dev->buffered_request != NULL) {
    return LIBHOTH_ERR_INTERFACE_BUSY;
  }

  spi_dev->buffered_request = malloc(request_size);
  spi_dev->buffered_request_size = request_size;
  memcpy(spi_dev->buffered_request, request, request_size);

  return LIBHOTH_OK;
}

int libhoth_spi_send_and_receive_response(struct libhoth_device* dev,
                                          void* response,
                                          size_t max_response_size,
                                          size_t* actual_size, int timeout_ms) {
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }

  if (max_response_size < sizeof(struct ec_host_response)) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }

  struct libhoth_spi_device* spi_dev =
      (struct libhoth_spi_device*)dev->user_ctx;

  if (spi_dev->buffered_request == NULL) {
    return LIBHOTH_ERR_INTERFACE_BUSY;
  }

  uint32_t address = spi_dev->mailbox_address;
  bool address_mode_4b = spi_dev->address_mode_4b;

  struct spi_ioc_transfer xfer[5] = {};

  // Write Enable Message
  uint8_t wp_buf[1];
  wp_buf[0] = 0x06;
  xfer[0] = (struct spi_ioc_transfer){
      .tx_buf = (unsigned long)wp_buf,
      .len = 1,
      .cs_change = 1,
  };

  // Page Program OPCODE + Mailbox Address
  uint8_t pp_buf[5];
  pp_buf[0] = 0x02;
  int address_len = spi_nor_address(&pp_buf[1], address, address_mode_4b);
  xfer[1] = (struct spi_ioc_transfer){
      .tx_buf = (unsigned long)pp_buf,
      .len = 1 + address_len,
  };

  // Write Data at mailbox address
  xfer[2] = (struct spi_ioc_transfer){
      .tx_buf = (unsigned long)spi_dev->buffered_request,
      .len = spi_dev->buffered_request_size,
      .cs_change = 1,
  };

  // Wait for status register is handled by the spidev driver.

  // Read opcode + Mailbox Address
  uint8_t rd_buf[5];
  rd_buf[0] = 0x03;  // Read
  address_len = spi_nor_address(&rd_buf[1], address, address_mode_4b);
  xfer[3] = (struct spi_ioc_transfer){
      .tx_buf = (unsigned long)rd_buf,
      .len = 1 + address_len,
  };

  // Read entire expected response buffer
  xfer[4] = (struct spi_ioc_transfer){
      .rx_buf = (unsigned long)response,
      .len = max_response_size,
  };

  int rc = LIBHOTH_OK;
  int status = ioctl(spi_dev->fd, SPI_IOC_MESSAGE(5), xfer);
  if (status < 0) {
    rc = LIBHOTH_ERR_FAIL;
  } else {
    if (actual_size) {
      struct ec_host_response* host_response =
          (struct ec_host_response*)response;
      *actual_size =
          (size_t)host_response->data_len + sizeof(struct ec_host_response);
    }
  }

  free(spi_dev->buffered_request);
  spi_dev->buffered_request = NULL;
  spi_dev->buffered_request_size = 0;

  return rc;
}

int libhoth_spi_close(struct libhoth_device* dev) {
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }

  struct libhoth_spi_device* spi_dev =
      (struct libhoth_spi_device*)dev->user_ctx;
  close(spi_dev->fd);
  free(dev->user_ctx);
  return LIBHOTH_OK;
}
