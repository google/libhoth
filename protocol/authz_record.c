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

#include "authz_record.h"

#include <stdlib.h>
#include <string.h>

#include "chipinfo.h"

int libhoth_authz_record_erase(struct libhoth_device* dev) {
  struct hoth_authz_record_set_request request = {
      .index = 0,
      .erase = 1,
  };
  return libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_SET_AUTHZ_RECORD,
      /*version=*/0, &request, sizeof(request), NULL, 0, NULL);
}

int libhoth_authz_record_read(struct libhoth_device* dev,
                              struct hoth_authz_record_get_response* resp) {
  struct hoth_authz_record_get_request request = {.index = 0};
  return libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_GET_AUTHZ_RECORD,
      /*version=*/0, &request, sizeof(request), resp, sizeof(*resp), NULL);
}

int libhoth_authz_record_build(struct libhoth_device* dev,
                               uint32_t capabilities,
                               struct authorization_record* record) {
  memset(record, 0, sizeof(*record));
  memcpy(&record->magic, AUTHORIZATION_RECORD_MAGIC, sizeof(record->magic));
  record->version = 1;
  record->size = AUTHORIZATION_RECORD_SIZE;
  record->flags = 0;

  *(uint32_t*)record->capabilities = capabilities;

  struct hoth_response_chip_info chipinfo_resp;
  int status = libhoth_chipinfo(dev, &chipinfo_resp);
  if (status != 0) {
    return -1;
  }
  record->dev_id_0 = chipinfo_resp.hardware_identity & 0xfffffffful;
  record->dev_id_1 = (chipinfo_resp.hardware_identity >> 32);

  struct hoth_authz_record_get_nonce_response nonce_resp;
  status = libhoth_hostcmd_exec(
      dev,
      HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_GET_AUTHZ_RECORD_NONCE,
      /*version=*/0, NULL, 0, &nonce_resp, sizeof(nonce_resp), NULL);
  if (status != 0) {
    return status;
  }
  if (nonce_resp.ro_supported_key_id == 0) {
    fprintf(stderr,
            "ro_supported_key_id = 0. Please reset the chip and retry\n");
    return -1;
  }
  if (nonce_resp.ro_supported_key_id != nonce_resp.rw_supported_key_id) {
    fprintf(
        stderr,
        "RO and RW supported key_ids do not match: (RO) 0x%x != (RW) 0x%x\n",
        nonce_resp.ro_supported_key_id, nonce_resp.rw_supported_key_id);
    return -1;
  }
  record->key_id = nonce_resp.ro_supported_key_id;
  if (sizeof(record->authorization_nonce) !=
      sizeof(nonce_resp.authorization_nonce)) {
    fprintf(stderr, "Nonce size does not match. Expecting %ld, got %ld",
            sizeof(nonce_resp.authorization_nonce),
            sizeof(record->authorization_nonce));
    return -1;
  }
  memcpy(record->authorization_nonce, nonce_resp.authorization_nonce,
         sizeof(record->authorization_nonce));

  return 0;
}

int libhoth_authz_record_set(struct libhoth_device* dev,
                             const struct authorization_record* record) {
  struct hoth_authz_record_set_request request = {
      .index = 0,
      .erase = 0,
  };

  memcpy(&request.record, record, sizeof(struct authorization_record));

  return libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_SET_AUTHZ_RECORD,
      /*version=*/0, &request, sizeof(request), NULL, 0, NULL);
}

int libhoth_authorization_record_print_hex_string(
    const struct authorization_record* record) {
  if (record == NULL) {
    return -1;
  }
  int i;
  const uint8_t* buf = (const uint8_t*)record;
  for (i = 0; i < sizeof(*record); ++i) {
    printf("%02x", buf[i]);
  }
  printf("\n");
  return 0;
}

int libhoth_authorization_record_from_hex_string(
    struct authorization_record* record, const char* buf, size_t length) {
  if (record == NULL || buf == NULL ||
      length != 2 * AUTHORIZATION_RECORD_SIZE) {
    return -1;
  }
  char* out = (char*)record;
  char value_hex[3] = {};
  int i, j;
  for (i = 0, j = 0; i < length; i += 2, j += 1) {
    value_hex[0] = buf[i];
    value_hex[1] = buf[i + 1];
    out[j] = strtoul(value_hex, NULL, 16);
    // strtoul() returns 0 if input string cannot be parsed.
    if (out[j] == 0 && (value_hex[0] != '0' || value_hex[1] != '0')) {
      fprintf(stderr, "Invalid byte: %s\n", value_hex);
      return -1;
    }
  }
  return 0;
}
