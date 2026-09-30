// Copyright 2026 Google LLC
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

#ifndef LIBHOTH_PROTOCOL_PROVISIONING_H_
#define LIBHOTH_PROTOCOL_PROVISIONING_H_

#include <stddef.h>
#include <stdint.h>

#include "protocol/host_cmd.h"
#include "protocol/status.h"
#include "transports/libhoth_device.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The major command identifier for the Provisioning Log host command. */
#define HOTH_PRV_CMD_HOTH_PROVISIONING_LOG 0x0040

/* The major command identifier for the Key Provisioning host command. */
#define HOTH_PRV_CMD_HOTH_KEY_PROVISIONING 0x0043

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
// performance constraints in its use by the provisioning commands.
uint32_t libhoth_provisioning_crc32(uint32_t initial_value, const uint8_t* buf,
                                    size_t size);

// Reads the full provisioning log into |buf|, which must be able to hold
// |buf_size| bytes. On success |out_size| receives the number of bytes read.
//
// Returns 0 on success, 1 if the device reported an unexpected response size
// or the log is larger than |buf_size|, and a legacy libhoth status code
// (see libhoth_hostcmd_exec) on a transport or device failure.
int libhoth_provisioning_log_read(struct libhoth_device* dev, uint8_t* buf,
                                  size_t buf_size, size_t* out_size);

// Asks the device to validate and sign the personalization blob in |blob|,
// returning the resulting certificate in |cert|. On success |out_cert_size|
// receives the number of bytes written to |cert|.
//
// Returns 0 on success, and a legacy libhoth status code (see
// libhoth_hostcmd_exec) on a transport or device failure. Returns -1 if the
// device returned more than |cert_capacity| bytes.
int libhoth_provisioning_log_validate_and_sign(struct libhoth_device* dev,
                                               const uint8_t* blob,
                                               size_t blob_size, uint8_t* cert,
                                               size_t cert_capacity,
                                               size_t* out_cert_size);

// Writes |size| bytes of provisioning log from |data| to the device. The log
// is not durable until libhoth_provisioning_log_commit() is called.
libhoth_error libhoth_provisioning_log_write(struct libhoth_device* dev,
                                             const uint8_t* data, size_t size);

// Commits a previously written provisioning log. |data| and |size| describe
// the same buffer passed to libhoth_provisioning_log_write() and are used to
// compute the checksum the device verifies.
libhoth_error libhoth_provisioning_log_commit(struct libhoth_device* dev,
                                              const uint8_t* data, size_t size);

// Stores |size| bytes of secrets that were encrypted with the provisioning
// encryption key.
libhoth_error libhoth_key_provisioning_store_secrets(struct libhoth_device* dev,
                                                     const uint8_t* secrets,
                                                     size_t size);

// Loads an ML-DSA-44 public key onto the device. |size| must be
// HOTH_KEY_PROVISIONING_MLDSA44_PUBLIC_KEY_BYTES.
libhoth_error libhoth_key_provisioning_load_mldsa_key(
    struct libhoth_device* dev, const uint8_t* key, size_t size);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_PROTOCOL_PROVISIONING_H_
