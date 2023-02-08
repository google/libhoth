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

#include "libhoth.h"
#include "libhoth_ec.h"
#include "libhoth_spi.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/spi/spidev.h>

struct libhoth_spi_device {
  int fd;
  unsigned int mailbox_address;
  unsigned int address_mode_4b;
};

int libhoth_spi_send_request(struct libhoth_device* dev,
                             const void* request, size_t request_size);

int libhoth_spi_receive_response(struct libhoth_device* dev, void* response,
                                 size_t max_response_size, size_t* actual_size,
                                 int timeout_ms);

int libhoth_spi_close(struct libhoth_device* dev);


static int spi_nor_write(int fd, unsigned int address_mode_4b, unsigned int address, const void *data, size_t data_len)
{
    if(fd < 0 || !data || !data_len)
        return LIBHOTH_ERR_INVALID_PARAMETER;

    uint8_t wp_buf[1];
    uint8_t rq_buf[5];
    struct spi_ioc_transfer xfer[3];
    memset(xfer, 0, sizeof xfer);
    memset(wp_buf, 0, sizeof wp_buf);
    memset(rq_buf, 0, sizeof rq_buf);


    // Write Enable Message
    wp_buf[0] = 0x06;
    xfer[0].tx_buf = (unsigned long)wp_buf;
    xfer[0].len = 1;
    xfer[0].cs_change = 1;

    // Page Program OPCODE + Mailbox Address
    rq_buf[0] = 0x02;
    if(address_mode_4b)
    {
        rq_buf[1] = (address >> 24) & 0xFF;
        rq_buf[2] = (address >> 16) & 0xFF;
        rq_buf[3] = (address >> 8) & 0xFF;
        rq_buf[4] = address & 0xFF;
    
        xfer[1].len = 5;
    }
    else
    {
        rq_buf[1] = (address >> 16) & 0xFF;
        rq_buf[2] = (address >> 8) & 0xFF;
        rq_buf[3] = address & 0xFF;

        xfer[1].len = 4;
    }
    xfer[1].tx_buf = (unsigned long)rq_buf;
    

    // Write Data at mailbox address
    xfer[2].tx_buf = (unsigned long)data;
    xfer[2].len = data_len;

    int status = ioctl(fd, SPI_IOC_MESSAGE(3), xfer);
    if (status < 0) {
        return LIBHOTH_ERR_FAIL;
    }

    return LIBHOTH_OK;
}

static int spi_nor_read(int fd, unsigned int address_mode_4b, unsigned int address, void *data, size_t data_len)
{
    if(fd < 0 || !data || !data_len)
        return LIBHOTH_ERR_INVALID_PARAMETER;

    uint8_t rd_request[5];
    struct spi_ioc_transfer xfer[2];
    memset(xfer, 0, sizeof xfer);

    // Read OPCODE and mailbox address
    rd_request[0] = 0x03; // Read
    if(address_mode_4b)
    {
        rd_request[1] = (address >> 24) & 0xFF;
        rd_request[2] = (address >> 16) & 0xFF;
        rd_request[3] = (address >> 8) & 0xFF;
        rd_request[4] = address & 0xFF;
    
        xfer[0].len = 5;
    }
    else
    {
        rd_request[1] = (address >> 16) & 0xFF;
        rd_request[2] = (address >> 8) & 0xFF;
        rd_request[3] = address & 0xFF;

        xfer[0].len = 4;
    }
    xfer[0].tx_buf = (unsigned long)rd_request;
    
    // Read in data
    xfer[1].rx_buf = (unsigned long)data;
    xfer[1].len = data_len;

    int status = ioctl(fd, SPI_IOC_MESSAGE(2), xfer);
    if (status < 0) {
        return LIBHOTH_ERR_FAIL;
    }

    return LIBHOTH_OK;   
}


int libhoth_spi_open(const struct libhoth_spi_device_init_options* options,
                     struct libhoth_device** out) {
  if (out == NULL || options == NULL || options->path == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }
    int status;
    int fd;
    struct libhoth_device* dev = NULL;
    struct libhoth_spi_device* spi_dev = NULL;

    fd = open(options->path,O_RDWR);
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

    if(options->bits)
    {
        const uint8_t bits = (uint8_t)options->bits;
        if (ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, bits) < 0)
        {
            status = LIBHOTH_ERR_FAIL;
            goto err_out;
        }
    }

    if(options->mode)
    {
        const uint8_t mode = (uint8_t)options->mode;
        if (ioctl(fd, SPI_IOC_WR_MODE, &mode) < 0)
        {
            status = LIBHOTH_ERR_FAIL;
            goto err_out;
        }
    }

    if(options->speed)
    {
        const uint32_t speed = (uint32_t)options->speed;
        if (ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed) < 0)
        {
            status = LIBHOTH_ERR_FAIL;
            goto err_out;
        }
    }

    spi_dev->fd = fd;
    spi_dev->mailbox_address = options->mailbox;
    spi_dev->address_mode_4b = 1;

    dev->send = libhoth_spi_send_request;
    dev->receive = libhoth_spi_receive_response;
    dev->close = libhoth_spi_close;
    dev->user_ctx = spi_dev;

    *out = dev;
    return LIBHOTH_OK;

    err_out:
    if (dev != NULL) {
        free(dev);
    }
    if(spi_dev != NULL){
        close(fd);
        free(spi_dev);
    }

    return status;
}

int libhoth_spi_send_request(struct libhoth_device* dev,
                                const void* request, size_t request_size) {
    if(dev == NULL) {
        return LIBHOTH_ERR_INVALID_PARAMETER;
    }

    struct libhoth_spi_device* spi_dev = (struct libhoth_spi_device*)dev->user_ctx;
    
    return spi_nor_write(spi_dev->fd, spi_dev->address_mode_4b, spi_dev->mailbox_address, request, request_size);
}

int libhoth_spi_receive_response(struct libhoth_device* dev, void *response,
                                size_t max_response_size, size_t* actual_size,
                                int timeout_ms) {
    if(dev == NULL) {
        return LIBHOTH_ERR_INVALID_PARAMETER;
    }

    if(max_response_size < 8){
        return LIBHOTH_ERR_INVALID_PARAMETER;
    }

    size_t total_bytes;
    int status;
    struct ec_host_response host_response;
    struct libhoth_spi_device* spi_dev = (struct libhoth_spi_device*)dev->user_ctx;
    
    // Read Header From Mailbox
    status = spi_nor_read(spi_dev->fd, spi_dev->address_mode_4b, spi_dev->mailbox_address, response, 8);
    if(status != LIBHOTH_OK){
        return status;
    }

    total_bytes = 8;
    memcpy(&host_response, response, 8);
    if(actual_size)
        *actual_size = total_bytes;

    if(max_response_size < (total_bytes + host_response.data_len)){
        return LIBHOTH_ERR_INVALID_PARAMETER;
    }

    // Read remainder of data based on header length
    status = spi_nor_read(spi_dev->fd, spi_dev->address_mode_4b, spi_dev->mailbox_address + total_bytes, response + total_bytes, host_response.data_len);
    if(status != LIBHOTH_OK){
        return status;
    }

    if(actual_size)
        *actual_size += host_response.data_len;

    return LIBHOTH_OK;
}

int libhoth_spi_close(struct libhoth_device* dev) {
    if(dev == NULL) {
        return LIBHOTH_ERR_INVALID_PARAMETER;
    }

    struct libhoth_spi_device* spi_dev = (struct libhoth_spi_device*)dev->user_ctx;
    close(spi_dev->fd);
    free(dev->user_ctx);
    return LIBHOTH_OK;
}