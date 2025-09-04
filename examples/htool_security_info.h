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
#ifndef LIBHOTH_EXAMPLES_HTOOL_INFO_H_
#define LIBHOTH_EXAMPLES_HTOOL_INFO_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration
struct htool_invocation;

#define HOTH_INFO_FW_MINOR_VERSION_SIZE 32

struct hoth_info_id_v0 {
  uint64_t hardware_id;
  uint16_t hardware_category;
  uint8_t reserved_0[2];
} __attribute__((packed));

struct hoth_info_id_v1 {
  struct hoth_info_id_v0 id;
  uint32_t bootloader_tag;
  uint32_t fw_epoch;
  uint16_t fw_major_version;
  uint8_t reserved_0[2];
} __attribute__((packed));

struct hoth_info {
  struct hoth_info_id_v1 id;
  uint16_t fw_minor_version;
  uint8_t signature_version;
  uint8_t wrapper_version;
  uint16_t inbound_mailbox_size;
  uint16_t outbound_mailbox_size;
} __attribute__((packed));

// Retrieve the Info from firmware.
int htool_info(const struct htool_invocation* inv);
#ifdef __cplusplus
}
#endif
#endif  // LIBHOTH_EXAMPLES_HTOOL_INFO_H_
