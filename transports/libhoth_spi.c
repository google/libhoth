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

#include "transports/libhoth_spi.h"

#include <assert.h>
#include <fcntl.h>
#include <linux/spi/spidev.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <time.h>
#include <unistd.h>

#include "libhoth_device.h"
#include "libhoth_spi.h"
#include "transports/libhoth_device.h"
#include "transports/libhoth_ec.h"

#define DID_VID_ADDR 0xD40F00

struct libhoth_spi_device {
  int fd;
  unsigned int mailbox_address;
  bool address_mode_4b;

  void* buffered_request;
  size_t buffered_request_size;
  uint32_t device_busy_wait_timeout;
  uint32_t device_busy_wait_check_interval;
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

enum {
  SPI_NOR_DEVICE_STATUS_WIP_BIT = (1 << 0),
  SPI_NOR_OPCODE_READ_STATUS = 0x05,
  SPI_NOR_OPCODE_WRITE_ENABLE = 0x06,
  SPI_NOR_OPCODE_PAGE_PROGRAM = 0x02,
  SPI_NOR_OPCODE_SLOW_READ = 0x03,
  SPI_NOR_FLASH_PAGE_SIZE = 256,  // in bytes
};

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

// Helper function to get current monotonic time in milliseconds
static int get_monotonic_ms(uint64_t* time_ms) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    perror("clock_gettime failed");
    return -1;
  }
  *time_ms = (((uint64_t)ts.tv_sec * 1000) + ((uint64_t)ts.tv_nsec / 1000000));
  return 0;
}

static libhoth_status spi_nor_busy_wait(const int fd, uint32_t timeout_us,
                                        uint32_t check_interval_us) {
  uint8_t tx_buf[2];
  uint8_t rx_buf[2];
  static_assert(sizeof(tx_buf) == sizeof(rx_buf),
                "Tx and Rx buffers must have the same size");

  uint64_t start_time_ms;
  if (get_monotonic_ms(&start_time_ms) != 0) {
    return LIBHOTH_ERR_FAIL;
  }
  while (true) {
    struct spi_ioc_transfer xfer = {0};
    tx_buf[0] = SPI_NOR_OPCODE_READ_STATUS;
    xfer.tx_buf = (uint64_t)tx_buf;
    xfer.rx_buf = (uint64_t)rx_buf;
    xfer.len = sizeof(rx_buf);
    const int status = ioctl(fd, SPI_IOC_MESSAGE(1), xfer);
    if (status < 0) {
      return LIBHOTH_ERR_FAIL;
    }

    static_assert(sizeof(rx_buf) >= 2,
                  "Rx buffer must have at least 2 entries");
    const bool is_spi_device_busy = (rx_buf[1] & SPI_NOR_DEVICE_STATUS_WIP_BIT);
    if (!is_spi_device_busy) {
      return LIBHOTH_OK;
    }

    uint64_t current_time_ms;
    if (get_monotonic_ms(&current_time_ms) != 0) {
      return LIBHOTH_ERR_FAIL;
    }
    uint64_t time_elapsed_ms = 0;
    if (current_time_ms < start_time_ms) {
      // Wrap around
      time_elapsed_ms = (UINT64_MAX - start_time_ms) + current_time_ms;
    } else {
      time_elapsed_ms = current_time_ms - start_time_ms;
    }

    if (time_elapsed_ms > (timeout_us / 1000)) {
      return LIBHOTH_ERR_TIMEOUT;
    }
    usleep(check_interval_us);
  }
}

static int spi_nor_write_enable(const int fd) {
  uint8_t wp_buf[1] = {};
  struct spi_ioc_transfer xfer[1] = {};

  // Write Enable Message
  wp_buf[0] = SPI_NOR_OPCODE_WRITE_ENABLE;
  xfer[0] = (struct spi_ioc_transfer){
      .tx_buf = (unsigned long)wp_buf,
      .len = 1,
  };

  int status = ioctl(fd, SPI_IOC_MESSAGE(1), xfer);
  if (status < 0) {
    return LIBHOTH_ERR_FAIL;
  }
  return LIBHOTH_OK;
}

static int spi_nor_write(int fd, bool address_mode_4b, unsigned int address,
                         const void* data, size_t data_len,
                         uint32_t device_busy_wait_timeout,
                         uint32_t device_busy_wait_check_interval) {
  if (fd < 0 || !data || !data_len) return LIBHOTH_ERR_INVALID_PARAMETER;

  // Page program operations
  size_t bytes_sent = 0;
  while (bytes_sent < data_len) {
    // Send write enable before each Page program operation
    int status = spi_nor_write_enable(fd);
    if (status != LIBHOTH_OK) {
      return status;
    }

    struct spi_ioc_transfer xfer[2] = {};
    uint8_t rq_buf[5] = {};  // 1 for command opcode, 4 (max) for address

    // Page Program OPCODE + Address
    rq_buf[0] = SPI_NOR_OPCODE_PAGE_PROGRAM;
    int address_len = spi_nor_address(&rq_buf[1], address, address_mode_4b);
    xfer[0] = (struct spi_ioc_transfer){
        .tx_buf = (unsigned long)rq_buf,
        .len = 1 + address_len,
        .cs_change = 0,
    };

    const size_t chunk_send_size =
        MIN(SPI_NOR_FLASH_PAGE_SIZE, (data_len - bytes_sent));
    // Write Data at mailbox address
    xfer[1] = (struct spi_ioc_transfer){
        .tx_buf = ((unsigned long)(data) + bytes_sent),
        .len = chunk_send_size,
    };

    status = ioctl(fd, SPI_IOC_MESSAGE(2), xfer);
    if (status < 0) {
      return LIBHOTH_ERR_FAIL;
    }
    bytes_sent += chunk_send_size;
    address += chunk_send_size;

    // Wait for each page program operation to be handled
    libhoth_status busy_wait_status = spi_nor_busy_wait(
        fd, device_busy_wait_timeout, device_busy_wait_check_interval);
    if (busy_wait_status != LIBHOTH_OK) {
      return busy_wait_status;
    }
  }
  return LIBHOTH_OK;
}

static int spi_nor_read(int fd, bool address_mode_4b, unsigned int address,
                        void* data, size_t data_len) {
  if (fd < 0 || !data || !data_len) return LIBHOTH_ERR_INVALID_PARAMETER;

  uint8_t rd_request[5];
  struct spi_ioc_transfer xfer[2] = {};

  // Read OPCODE and mailbox address
  rd_request[0] = SPI_NOR_OPCODE_SLOW_READ;
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
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }

  const struct libhoth_spi_device* spi_dev = dev->user_ctx;
  if (spi_dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }

  if (flock(spi_dev->fd, LOCK_EX | LOCK_NB) != 0) {
    // Maybe some other process has the lock?
    return LIBHOTH_ERR_INTERFACE_BUSY;
  }
  return LIBHOTH_OK;
}

static int libhoth_spi_release(struct libhoth_device* dev) {
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }

  const struct libhoth_spi_device* spi_dev = dev->user_ctx;
  if (spi_dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }

  if (flock(spi_dev->fd, LOCK_UN) != 0) {
    // Maybe `fd` is invalid?
    return LIBHOTH_ERR_FAIL;
  }
  return LIBHOTH_OK;
}

static int libhoth_spi_reconnect(struct libhoth_device* dev) {
  // TODO: Maybe check for JEDEC ID?
  // no-op
  return 0;
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

  fd = open(options->path, O_RDWR | O_CLOEXEC);
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

  spi_dev->fd = fd;
  spi_dev->mailbox_address = options->mailbox;
  spi_dev->address_mode_4b = true;
  spi_dev->device_busy_wait_timeout = options->device_busy_wait_timeout;
  spi_dev->device_busy_wait_check_interval =
      options->device_busy_wait_check_interval;

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
  dev->reconnect = libhoth_spi_reconnect;
  dev->user_ctx = spi_dev;

  status = libhoth_claim_device(dev, options->timeout_us);
  if (status != LIBHOTH_OK) {
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
                       spi_dev->mailbox_address, request, request_size,
                       spi_dev->device_busy_wait_timeout,
                       spi_dev->device_busy_wait_check_interval);
}

int libhoth_spi_receive_response(struct libhoth_device* dev, void* response,
                                 size_t max_response_size, size_t* actual_size,
                                 int timeout_ms) {
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }

  if (max_response_size < sizeof(struct hoth_host_response)) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }

  size_t total_bytes;
  int status;
  struct hoth_host_response host_response;
  struct libhoth_spi_device* spi_dev =
      (struct libhoth_spi_device*)dev->user_ctx;

  // Read Header From Mailbox
  status = spi_nor_read(spi_dev->fd, spi_dev->address_mode_4b,
                        spi_dev->mailbox_address, response,
                        sizeof(struct hoth_host_response));
  if (status != LIBHOTH_OK) {
    return status;
  }

  total_bytes = sizeof(struct hoth_host_response);
  memcpy(&host_response, response, sizeof(host_response));
  if (actual_size) {
    *actual_size = total_bytes;
  }

  if (max_response_size < (total_bytes + host_response.data_len)) {
    return LIBHOTH_ERR_RESPONSE_BUFFER_OVERFLOW;
  }

  if (host_response.data_len > 0) {
    // Read remainder of data based on header length
    uint8_t* const data_start = (uint8_t*)response + total_bytes;
    status = spi_nor_read(spi_dev->fd, spi_dev->address_mode_4b,
                          spi_dev->mailbox_address + total_bytes, data_start,
                          host_response.data_len);
    if (status != LIBHOTH_OK) {
      return status;
    }
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

  if (max_response_size < sizeof(struct hoth_host_response)) {
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
  wp_buf[0] = SPI_NOR_OPCODE_WRITE_ENABLE;
  xfer[0] = (struct spi_ioc_transfer){
      .tx_buf = (unsigned long)wp_buf,
      .len = 1,
      .cs_change = 1,
  };

  // Page Program OPCODE + Mailbox Address
  uint8_t pp_buf[5];
  pp_buf[0] = SPI_NOR_OPCODE_PAGE_PROGRAM;
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
  rd_buf[0] = SPI_NOR_OPCODE_SLOW_READ;
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
      struct hoth_host_response* host_response =
          (struct hoth_host_response*)response;
      *actual_size =
          (size_t)host_response->data_len + sizeof(struct hoth_host_response);
    }
  }

  free(spi_dev->buffered_request);
  spi_dev->buffered_request = NULL;
  spi_dev->buffered_request_size = 0;

  return rc;
}

int libhoth_tpm_spi_probe(struct libhoth_device* dev) {
  struct libhoth_spi_device* spi_dev =
      (struct libhoth_spi_device*)dev->user_ctx;

  const uint32_t addr = DID_VID_ADDR;
  uint8_t tx_buf[4] = {0};
  uint8_t rx_buf[5] = {0};

  tx_buf[0] = 0x83;  // Read 4 bytes
  tx_buf[1] = (uint8_t)(addr >> 16);
  tx_buf[2] = (uint8_t)(addr >> 8);
  tx_buf[3] = (uint8_t)(addr >> 0);

  struct spi_ioc_transfer xfer[2] = {0};

  xfer[0].tx_buf = (uint64_t)tx_buf;
  xfer[0].len = sizeof(tx_buf);

  xfer[1].rx_buf = (uint64_t)rx_buf;
  xfer[1].len = sizeof(rx_buf);

  const int status = ioctl(spi_dev->fd, SPI_IOC_MESSAGE(2), xfer);
  if (status < 0) {
    printf("Failed to read DID_VID: %x\n", status);
    return -1;
  }

  uint16_t did = (uint16_t)rx_buf[4] << 8 | rx_buf[3];
  uint16_t vid = (uint16_t)rx_buf[2] << 8 | rx_buf[1];

  printf("DID: 0x%x\n", did);
  printf("VID: 0x%x\n", vid);

  return LIBHOTH_OK;
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
