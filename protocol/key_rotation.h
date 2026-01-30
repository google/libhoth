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

#ifndef _LIBHOTH_PROTOCOL_KEY_ROTATION_H_
#define _LIBHOTH_PROTOCOL_KEY_ROTATION_H_

#include <assert.h>
#include <stdint.h>

#include "protocol/host_cmd.h"
#include "transports/libhoth_device.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HOTH_PRV_CMD_HAVEN_KEY_ROTATION_OP 0x004d
#define KEY_ROTATION_HASH_DIGEST_SIZE 32
#define KEY_ROTATION_FLASH_AREA_SIZE 2048
#define KEY_ROTATION_MAX_RECORD_SIZE \
  (KEY_ROTATION_FLASH_AREA_SIZE - KEY_ROTATION_HASH_DIGEST_SIZE)

#define KEY_ROTATION_RECORD_WRITE_MAX_SIZE                   \
  (LIBHOTH_MAILBOX_SIZE - sizeof(struct hoth_host_request) - \
   sizeof(struct hoth_request_key_rotation_record))
#define KEY_ROTATION_RECORD_READ_MAX_SIZE                     \
  (LIBHOTH_MAILBOX_SIZE - sizeof(struct hoth_host_response) - \
   sizeof(struct hoth_request_key_rotation_record) -          \
   sizeof(struct hoth_request_key_rotation_record_read))
#define KEY_ROTATION_RECORD_READ_CHUNK_TYPE_MAX_SIZE                 \
  (LIBHOTH_MAILBOX_SIZE - sizeof(struct hoth_host_response) -        \
   sizeof(struct hoth_request_key_rotation_record) -                 \
   sizeof(struct hoth_request_key_rotation_record_read_chunk_type) - \
   sizeof(uint32_t))
#define KEY_ROTATION_RECORD_SIGNATURE_SIZE 96
#define STRUCT_CHUNK_SIZE 8

enum key_rotation_err {
  KEY_ROTATION_CMD_SUCCESS = 0,
  KEY_ROTATION_ERR,
  KEY_ROTATION_ERR_INVALID_PARAM,
  KEY_ROTATION_ERR_UNIMPLEMENTED,
  KEY_ROTATION_ERR_INVALID_RESPONSE_SIZE,
  KEY_ROTATION_INITIATE_FAIL,
  KEY_ROTATION_COMMIT_FAIL,
};

enum key_rotation_record_read_half {
  KEY_ROTATION_RECORD_READ_HALF_ACTIVE = 0,
  KEY_ROTATION_RECORD_READ_HALF_STAGING = 1,
  KEY_ROTATION_RECORD_READ_HALF_A = 2,
  KEY_ROTATION_RECORD_READ_HALF_B = 3,
};

enum key_rotation_record_op {
  KEY_ROTATION_RECORD_INITIATE = 0,     // Erases staging half
  KEY_ROTATION_RECORD_WRITE = 1,        // Write to staging half
  KEY_ROTATION_RECORD_COMMIT = 2,       // Commits staging half to active half
  KEY_ROTATION_RECORD_GET_VERSION = 3,  // Get current version of key
                                        // rotation record
  KEY_ROTATION_RECORD_READ = 4,  // Read from key rotation record from flash
                                 // (offset, size, A/B/Active/Staging)
  KEY_ROTATION_RECORD_GET_STATUS = 5,  // Read key rotation record version,
                                       // image family, variant,
                                       // validation method, key data,
                                       // hash data
  KEY_ROTATION_RECORD_READ_CHUNK_TYPE =
      6,  // Gets the ith chunk of given chunk_typecode and returns the
          // chunk_size starting from the chunk_offset (chunk_index,
          // chunk_offset, chunk_typecode, chunk_size)
  KEY_ROTATION_RECORD_PAYLOAD_STATUS = 7,    // Get validation method and data
  KEY_ROTATION_RECORD_CHUNK_TYPE_COUNT = 8,  // Get the number of chunks of a
                                             // given chunk_typecode
  KEY_ROTATION_RECORD_ERASE_RECORD = 9,  // Erase the key rotation record from
                                         // both halves of the flash if the mauv
                                         // allows
  KEY_ROTATION_RECORD_SET_MAUV = 10,     // Set Key Rotation Record MAUV
  KEY_ROTATION_RECORD_GET_MAUV = 11,     // Get Key Rotation Record MAUV
};

#define KEY_ROTATION_CHUNK_TYPE_CODE_PKEY (0x59454B50)
#define KEY_ROTATION_CHUNK_TYPE_CODE_HASH (0x48534148)
#define KEY_ROTATION_CHUNK_TYPE_CODE_BKEY (0x59454B42)
#define KEY_ROTATION_CHUNK_TYPE_CODE_BASH (0x48534142)

struct hoth_request_key_rotation_record {
  uint16_t operation;      // enum key_rotation_record_op
  uint16_t packet_offset;  // Chunked read/write offset
  uint16_t packet_size;    // Chunked read/write size excluding this header
  uint16_t reserved;
} __hoth_align4;

struct hoth_request_key_rotation_record_read {
  uint32_t read_half;  // enum key_rotation_record_read_half
} __hoth_align4;

struct hoth_request_key_rotation_record_read_chunk_type {
  uint32_t chunk_typecode;  // enum key_rotation_typecode
  uint32_t chunk_index;     // Index of the chunk to read
} __hoth_align4;

struct hoth_request_key_rotation_record_chunk_type_count {
  uint32_t chunk_typecode;  // enum key_rotation_typecode
} __hoth_align4;

struct hoth_request_key_rotation_record_set_mauv {
  uint32_t mauv;
} __hoth_align4;

struct hoth_response_key_rotation_record_version {
  uint32_t version;
} __hoth_align4;

struct hoth_response_key_rotation_payload_status {
  uint32_t validation_method;    // enum key_rotation_validation_method
  uint32_t validation_key_data;  // If validation method is embedded key or
                                 // payload key, first 32 bits of modulus of the
                                 // key used to validate the payload
  uint32_t validation_hash_data;  // If validation method is hash, first 32 bits
                                  // of cr51 hash
} __hoth_align4;

struct hoth_response_key_rotation_status {
  uint32_t version;       // Config package version, used for anti-rollback
  uint16_t image_family;  // Image family of the payload keys this record is for
  uint16_t image_family_variant;  // Variant of the image family if any.
  uint32_t validation_method;     // enum key_rotation_validation_method
  uint32_t validation_key_data;   // If validation method is embedded key or
                                 // payload key, first 32 bits of modulus of the
                                 // key used to validate the payload
  uint32_t validation_hash_data;  // If validation method is hash, first 32 bits
                                  // of cr51 hash
} __hoth_align4;

struct hoth_response_key_rotation_mauv {
  uint32_t mauv;
} __hoth_align4;

struct hoth_response_key_rotation_record_read {
  uint8_t data[KEY_ROTATION_FLASH_AREA_SIZE];
} __hoth_align4;

struct key_rotation_chunk_header {
  uint32_t chunk_typecode;
  uint32_t chunk_data_size;
  uint8_t chunk_data[];
};

typedef uint8_t sha256[32];
struct bios_verifiction_key_fingerprint {
  uint16_t image_family;
  uint16_t key_index;
  uint16_t key_sign_scheme;
  uint16_t hash_type;
  sha256 key_fingerprint;  // verification key fignerprint = sha256(n||e)
};
static_assert(sizeof(struct bios_verifiction_key_fingerprint) == 40,
              "bios_verifiction_key_fingerprint size is not 40 bytes!");

struct bios_allowed_hash_list {
  uint32_t hash_count;
  sha256 hash_list[];  // only support sha256 hash for bios
};

enum key_rotation_err libhoth_key_rotation_get_version(
    struct libhoth_device* dev,
    struct hoth_response_key_rotation_record_version* record_version);
enum key_rotation_err libhoth_key_rotation_get_status(
    struct libhoth_device* dev,
    struct hoth_response_key_rotation_status* record_status);
enum key_rotation_err libhoth_key_rotation_payload_status(
    struct libhoth_device* dev,
    struct hoth_response_key_rotation_payload_status* payload_status);
enum key_rotation_err libhoth_key_rotation_update(struct libhoth_device* dev,
                                                  const uint8_t* image,
                                                  size_t size);
enum key_rotation_err libhoth_key_rotation_read(
    struct libhoth_device* dev, uint16_t offset, uint16_t size,
    uint32_t read_half,
    struct hoth_response_key_rotation_record_read* read_response);
enum key_rotation_err libhoth_key_rotation_read_chunk_type(
    struct libhoth_device* dev, uint32_t chunk_typecode, uint32_t chunk_index,
    uint16_t offset, uint16_t size,
    struct hoth_response_key_rotation_record_read* read_response,
    uint16_t* response_size);
enum key_rotation_err libhoth_key_rotation_chunk_type_count(
    struct libhoth_device* dev, uint32_t chunk_typecode, uint16_t* chunk_count);
enum key_rotation_err libhoth_key_rotation_erase_record(
    struct libhoth_device* dev);
enum key_rotation_err libhoth_key_rotation_set_mauv(struct libhoth_device* dev,
                                                    uint32_t mauv);
enum key_rotation_err libhoth_key_rotation_get_mauv(
    struct libhoth_device* dev, struct hoth_response_key_rotation_mauv* mauv);
#ifdef __cplusplus
}
#endif

#endif  // _LIBHOTH_PROTOCOL_KEY_ROTATION_H_
