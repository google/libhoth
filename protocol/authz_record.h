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

#ifndef _LIBHOTH_PROTOCOL_AUTHZ_RECORD_H_
#define _LIBHOTH_PROTOCOL_AUTHZ_RECORD_H_

#include <assert.h>

#include "host_cmd.h"
#include "transports/libhoth_device.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AUTHORIZATION_RECORD_MAGIC_SIZE 8
#define AUTHORIZATION_RECORD_SIGNATURE_SIZE (96 * 4)
#define AUTHORIZATION_RECORD_VERSION 1
#define AUTHORIZATION_RECORD_FAUX_FUSES_SIZE 4
#define AUTHORIZATION_RECORD_CAPABILITIES_SIZE 8
#define AUTHORIZATION_RECORD_NONCE_SIZE 32

// All multi-byte fields are little endian.
struct authorization_record {
  uint8_t magic[AUTHORIZATION_RECORD_MAGIC_SIZE];
  uint32_t signature[AUTHORIZATION_RECORD_SIGNATURE_SIZE / sizeof(uint32_t)];
  uint32_t version;
  uint32_t reserved_0;
  uint32_t size;
  uint32_t key_id;
  uint32_t flags;
  uint8_t faux_fuses[AUTHORIZATION_RECORD_FAUX_FUSES_SIZE];
  uint8_t capabilities[AUTHORIZATION_RECORD_CAPABILITIES_SIZE];
  uint32_t dev_id_0;
  uint32_t dev_id_1;
  uint32_t
      authorization_nonce[AUTHORIZATION_RECORD_NONCE_SIZE / sizeof(uint32_t)];
} __attribute__((packed, aligned(4)));

#define AUTHORIZATION_RECORD_MAGIC ("AUTHZREC")
#define AUTHORIZATION_RECORD_SIZE (sizeof(struct authorization_record))

// Note that changing the size of this structure may cause compatability issues;
// the authorization infrastructure expects the above structure format.
static_assert(AUTHORIZATION_RECORD_SIZE == 464,
              "unexpected authorization_record size");

/* Program authorization records */
#define EC_PRV_CMD_HOTH_SET_AUTHZ_RECORD 0x0017

struct ec_authz_record_set_request {
  // Authorization record index to program or erase. Currently only index=0 is
  // supported.
  uint8_t index;

  // When `erase` is a non-zero value, the authorization record at `index` is
  // erased and the value of `record` is ignored by firmware.
  uint8_t erase;

  uint8_t reserved[2];

  // Authorization record to program.
  struct authorization_record record;
} __attribute__((packed, aligned(4)));

#define EC_PRV_CMD_HOTH_GET_AUTHZ_RECORD 0x0018

struct ec_authz_record_get_request {
  // Authorization record index to get. Currently only index=0 is
  // supported.
  uint8_t index;
  uint8_t reserved[3];
} __attribute__((packed));

struct ec_authz_record_get_response {
  // Index of authorization record in the response. This value matches the
  // `index` in the corresponding host command request.
  uint8_t index;

  // When `valid` is non-zero value, the `record` at `index` in this
  // response is valid.
  uint8_t valid;
  uint8_t reserved[2];
  struct authorization_record record;
} __attribute__((packed, aligned(4)));

#define EC_PRV_CMD_HOTH_GET_AUTHZ_RECORD_NONCE 0x0019

struct ec_authz_record_get_nonce_response {
  uint32_t authorization_nonce[8];

  // key_id supported by RO and RW. These key_id's are expected to match one
  // another to successfully program an authorization record. key_id == 0 should
  // be interpreted as an unknown key_id.
  uint32_t ro_supported_key_id;
  uint32_t rw_supported_key_id;
} __attribute__((packed));

int libhoth_authz_record_erase(struct libhoth_device* dev);
int libhoth_authz_record_read(struct libhoth_device* dev,
                              struct ec_authz_record_get_response* resp);
int libhoth_authz_record_build(struct libhoth_device* dev,
                               uint32_t capabilities,
                               struct authorization_record* record);
int libhoth_authz_record_set(struct libhoth_device* dev,
                             const struct authorization_record* record);

int libhoth_authorization_record_print_hex_string(
    const struct authorization_record* record);
int libhoth_authorization_record_from_hex_string(
    struct authorization_record* record, const char* buf, size_t length);

#ifdef __cplusplus
}
#endif

#endif  // _LIBHOTH_PROTOCOL_AUTHZ_RECORD_H_
