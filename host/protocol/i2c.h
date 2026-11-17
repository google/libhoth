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

#include <stddef.h>
#include <stdint.h>

#include "protocol/status.h"
#include "transports/libhoth_device.h"

/*
 * I2C Detect. This scans for I2C devices on the Hoth's I2C Bus
 */
#define HOTH_PRV_CMD_HOTH_I2C_DETECT 0x0045
#define I2C_DETECT_DATA_MAX_SIZE_BYTES (16)  // 128 bits (addresses)
#define I2C_DETECT_MAX_DEVICES 128

struct hoth_request_i2c_detect {
  // Which I2C bus to run the scan on
  uint8_t bus_number;

  // What 7-bit addresses to start and end scan on?
  uint8_t start_address;
  uint8_t end_address;
} __attribute__((packed, aligned(4)));

struct hoth_response_i2c_detect {
  // Non-zero code for error on the i2c bus
  uint8_t bus_response;

  // How many devices were found
  uint8_t devices_count;

  // Bit mask for detected 7-bit addresses
  uint8_t devices_mask[I2C_DETECT_DATA_MAX_SIZE_BYTES];
} __attribute__((packed, aligned(4)));

libhoth_error libhoth_i2c_detect(struct libhoth_device* dev,
                                 struct hoth_request_i2c_detect* req,
                                 struct hoth_response_i2c_detect* resp);

// Converts the above devices_mask into a list of devices addresses
// The first `devices_count` entries of `device_list` will be populated
// with a detected device address.  `device_list` must be a buffer at least
// `devices_count` in length.
void libhoth_i2c_device_list(uint8_t* devices_mask, uint32_t devices_count,
                             uint8_t* device_list);

/*
 * I2C Transfer. This runs an I2C transaction on the Hoth's I2C bus
 */
#define HOTH_PRV_CMD_HOTH_I2C_TRANSFER 0x0046
#define I2C_TRANSFER_DATA_MAX_SIZE_BYTES (256)

#define I2C_BITS_WRITE (1 << 0)
#define I2C_BITS_NO_STOP (1 << 1)
#define I2C_BITS_NO_START (1 << 2)
#define I2C_BITS_REPEATED_START (1 << 3)

struct hoth_request_i2c_transfer {
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

struct hoth_response_i2c_transfer {
  // // Non-zero code for error on the i2c bus
  uint8_t bus_response;

  // How many bytes were read
  uint16_t read_bytes;

  // Byte array to send if write
  uint8_t resp_bytes[I2C_TRANSFER_DATA_MAX_SIZE_BYTES];
} __attribute__((packed, aligned(4)));

libhoth_error libhoth_i2c_transfer(struct libhoth_device* dev,
                                   struct hoth_request_i2c_transfer* req,
                                   struct hoth_response_i2c_transfer* resp);

// Select I2C endpoints in the virtual I2C hierarchy that will be enabled when
// RoT firmware activates filtering rules for the protected I2C endpoints.
// For all remaining unselected endpoints, all write and write-then-read
// operations will be dropped but read operations will be allowed.

// Takes `struct hoth_request_enable_i2c_endpoints_for_filtering` as input and
// returns `struct hoth_response_i2c_endpoints_enabled_for_filtering` as output.
#define HOTH_PRV_CMD_ENABLE_I2C_ENDPOINTS_FOR_FILTERING 0x0061

// No input. Returns `struct hoth_response_i2c_endpoints_enabled_for_filtering`
// as output.
#define HOTH_PRV_CMD_GET_ENABLED_I2C_ENDPOINTS_FOR_FILTERING 0x0062

struct hoth_request_enable_i2c_endpoints_for_filtering {
  uint8_t
      ids_count;  // Number of endpoint identifiers in this request.
                  // `ids_count=0` is allowed and will disable all I2C endpoints
  uint8_t reserved[3];  // Padding for alignment for rest of the data; must be 0
  // Variable length sequence:
  // - Repeat `ids_count` times (i.e. for each identifier):
  //   - First byte represents I2C port (Port0 is encoded as 0)
  //   - The next byte (N) represents number of I2C switches in the path to the
  //     endpoint
  //   - The next `2*N` bytes represent the path along I2C switches
  //     - Each byte pair is (I2C switch address, Channel number)
  //   - Next 1 byte represents I2C endpoint address
  //   - Next byte (I) represents 1-byte identifier for the endpoint
} __attribute__((packed, aligned(4)));

struct hoth_response_i2c_endpoints_enabled_for_filtering {
  uint8_t ids_count;    // Number of endpoints that have been enabled
  uint8_t reserved[3];  // Padding for alignment for rest of the data; must be 0
  // Variable length sequence similar to request representing enabled I2C
  // endpoints
} __attribute__((packed, aligned(4)));

libhoth_error libhoth_i2c_filtering_enable_endpoints(
    struct libhoth_device* dev,
    const struct hoth_request_enable_i2c_endpoints_for_filtering* req,
    size_t req_len,
    struct hoth_response_i2c_endpoints_enabled_for_filtering* resp,
    size_t max_resp_len, size_t* resp_len);

libhoth_error libhoth_i2c_filtering_get_enabled_endpoints(
    struct libhoth_device* dev,
    struct hoth_response_i2c_endpoints_enabled_for_filtering* resp,
    size_t max_resp_len, size_t* resp_len);

#ifdef __cplusplus
}
#endif

#endif
