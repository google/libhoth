// Copyright 2025 Google LLC
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

#ifndef LIBHOTH_PROTOCOL_I2C_H_
#define LIBHOTH_PROTOCOL_I2C_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "transports/libhoth_device.h"

/*
 * I2C Detect. This scans for I2C devices on the Hoth's I2C Bus
 */
#define EC_PRV_CMD_HOTH_I2C_DETECT 0x0045
#define I2C_DETECT_DATA_MAX_SIZE_BYTES (16)  // 128 bits (addresses)
#define I2C_DETECT_MAX_DEVICES 128

struct ec_request_i2c_detect {
  // Which I2C bus to run the scan on
  uint8_t bus_number;

  // What 7-bit addresses to start and end scan on?
  uint8_t start_address;
  uint8_t end_address;
} __attribute__((packed, aligned(4)));

struct ec_response_i2c_detect {
  // Non-zero code for error on the i2c bus
  uint8_t bus_response;

  // How many devices were found
  uint8_t devices_count;

  // Bit mask for detected 7-bit addresses
  uint8_t devices_mask[I2C_DETECT_DATA_MAX_SIZE_BYTES];
} __attribute__((packed, aligned(4)));

int libhoth_i2c_detect(struct libhoth_device* dev,
                       struct ec_request_i2c_detect* req,
                       struct ec_response_i2c_detect* resp);

// Converts the above devices_mask into a list of devices addresses
// The first `devices_count` entries of `device_list` will be populated
// with a detected device address.  `device_list` must be a buffer at least
// `devices_count` in length.
void libhoth_i2c_device_list(uint8_t* devices_mask, uint32_t devices_count,
                             uint8_t* device_list);

/*
 * I2C Transfer. This runs an I2C transaction on the Hoth's I2C bus
 */
#define EC_PRV_CMD_HOTH_I2C_TRANSFER 0x0046
#define I2C_TRANSFER_DATA_MAX_SIZE_BYTES (256)

#define I2C_BITS_WRITE (1 << 0)
#define I2C_BITS_NO_STOP (1 << 1)
#define I2C_BITS_NO_START (1 << 2)
#define I2C_BITS_REPEATED_START (1 << 3)

struct ec_request_i2c_transfer {
  // Which I2C bus to run the transfer on
  uint8_t bus_number;

  // Override default bus speed. (100, 400, 1000)
  uint16_t speed_khz;

  // What 7-bit device address to transact to
  uint8_t dev_address;

  // Any I2C flags needed. Use `I2C_BITS_*`
  uint32_t flags;

  // Number of bytes to write
  uint16_t size_write;

  // Number of bytes to read
  uint16_t size_read;

  // Byte array to send if write
  uint8_t arg_bytes[I2C_TRANSFER_DATA_MAX_SIZE_BYTES];
} __attribute__((packed, aligned(4)));

struct ec_response_i2c_transfer {
  // // Non-zero code for error on the i2c bus
  uint8_t bus_response;

  // How many bytes were read
  uint16_t read_bytes;

  // Byte array to send if write
  uint8_t resp_bytes[I2C_TRANSFER_DATA_MAX_SIZE_BYTES];
} __attribute__((packed, aligned(4)));

int libhoth_i2c_transfer(struct libhoth_device* dev,
                         struct ec_request_i2c_transfer* req,
                         struct ec_response_i2c_transfer* resp);

#ifdef __cplusplus
}
#endif

#endif
