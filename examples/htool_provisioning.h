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

#include "host_commands.h"
#include "protocol/host_cmd.h"
#include "transports/libhoth_device.h"

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration
struct htool_invocation;

#define HOTH_KEY_PROVISIONING_REQUEST_VERSION 1

enum hoth_key_provisioning_command {
  HOTH_KEY_PROVISIONING_GET_ENCRYPTION_KEY = 0,
  HOTH_KEY_PROVISIONING_STORE_SECRETS = 1,
  HOTH_KEY_PROVISIONING_LOAD_MLDSA_PUBLIC_KEY = 2,
};

struct hoth_key_provisioning_request_header {
  uint8_t version;
  uint8_t command;  // enum hoth_key_provisioning_command
  uint16_t size;
} __attribute__((packed));

#define HOTH_KEY_PROVISIONING_MAX_SECRETS_SIZE               \
  (LIBHOTH_MAILBOX_SIZE - sizeof(struct hoth_host_request) - \
   sizeof(struct hoth_key_provisioning_request_header))

struct hoth_key_provisioning_store_secrets_request {
  struct hoth_key_provisioning_request_header hdr;
  uint8_t secrets[HOTH_KEY_PROVISIONING_MAX_SECRETS_SIZE];
} __attribute__((packed));

#define HOTH_KEY_PROVISIONING_MLDSA44_PUBLIC_KEY_BYTES 1312

struct hoth_key_provisioning_load_key_args {
  uint16_t offset;
  uint16_t size;
} __attribute__((packed));

#define HOTH_KEY_PROVISIONING_LOAD_KEY_CHUNK_MAX_SIZE        \
  (LIBHOTH_MAILBOX_SIZE - sizeof(struct hoth_host_request) - \
   sizeof(struct hoth_key_provisioning_request_header) -     \
   sizeof(struct hoth_key_provisioning_load_key_args))

struct hoth_key_provisioning_load_key_request {
  struct hoth_key_provisioning_request_header hdr;
  struct hoth_key_provisioning_load_key_args args;
  uint8_t data[HOTH_KEY_PROVISIONING_LOAD_KEY_CHUNK_MAX_SIZE];
} __attribute__((packed));

// Loads secrets that were encrypted to the provisioning encryption key.
int htool_provisioning_store_secrets(const struct htool_invocation* inv);

#define PROVISIONING_LOG_MAX_SIZE 6144

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

#define PROVISIONING_LOG_WRITE_CHUNK_MAX_SIZE                \
  (LIBHOTH_MAILBOX_SIZE - sizeof(struct hoth_host_request) - \
   sizeof(struct hoth_provisioning_log_request))

struct hoth_provisioning_log_write_request {
  struct hoth_provisioning_log_request req;
  uint8_t data[PROVISIONING_LOG_WRITE_CHUNK_MAX_SIZE];
} __attribute__((packed));

enum provisioning_log_op {
  PROVISIONING_LOG_READ = 0,
  PROVISIONING_LOG_WRITE = 1,
  PROVISIONING_LOG_COMMIT = 2,
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

// Writes and commits the provisioning log.
int htool_provisioning_write(const struct htool_invocation* inv);

// Loads the ML-DSA-44 public key to the RoT.
int htool_provisioning_load_mldsa_key(const struct htool_invocation* inv);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_HTOOL_PROVISIONING_H_
