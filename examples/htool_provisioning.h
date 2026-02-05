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
#ifndef LIBHOTH_EXAMPLES_HTOOL_PROVISIONING_H_
#define LIBHOTH_EXAMPLES_HTOOL_PROVISIONING_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration
struct htool_invocation;

#define PROVISIONING_LOG_MAX_SIZE 2048

#define PROVISIONING_LOG_CHUNK_MAX_SIZE 1008

#define PROVISIONING_CERT_MAX_SIZE 240

struct hoth_provisioning_log_header {
  uint8_t version;  // 1
  uint8_t reserved;
  uint16_t size;      // size of the log content
  uint32_t checksum;  // CRC32 checksum of |size| bytes of log data
} __attribute__((packed));

struct hoth_provisioning_log_request {
  uint8_t version;    // 1
  uint8_t operation;  // enum provisioning_log_op
  uint16_t reserved;
  uint16_t offset;    // Chunked read/write offset
  uint16_t size;      // Chunked read/write size
  uint32_t checksum;  // CRC32 checksum of the full provisioning log
} __attribute__((packed));

struct hoth_provisioning_log {
  struct hoth_provisioning_log_header hdr;
  uint8_t data[PROVISIONING_LOG_CHUNK_MAX_SIZE];
} __attribute__((packed));

enum provisioning_log_op {
  PROVISIONING_LOG_READ = 0,
  PROVISIONING_LOG_VALIDATE_AND_SIGN = 3,
};

// This is a standalone CRC32 that matches Titan Firmware.
// A table-free bit-level implementation is okay since there are no
// performance constraints in it's use in htool_validate_and_sign.
uint32_t crc32(uint32_t initial_value, const uint8_t* buf, size_t size);

// Retrieve the provisioning log from the device.
int htool_get_provisioning_log(const struct htool_invocation* inv);

// Validate and Sign the provisioning log.
int htool_validate_and_sign(const struct htool_invocation* inv);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_HTOOL_PROVISIONING_H_
