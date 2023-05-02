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

#ifndef LIBHOTH_EXAMPLES_AUTHORIZATION_RECORD_H_
#define LIBHOTH_EXAMPLES_AUTHORIZATION_RECORD_H_

#include <stddef.h>
#include <stdint.h>

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

int authorization_record_print_hex_string(
    const struct authorization_record* record);

int authorization_record_from_hex_string(struct authorization_record* record,
                                         const char* buf, size_t length);

#endif  // LIBHOTH_EXAMPLES_AUTHORIZATION_RECORD_H_
