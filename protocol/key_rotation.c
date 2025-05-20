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

#include "key_rotation.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "protocol/host_cmd.h"
#include "transports/libhoth_device.h"

int libhoth_key_rotation_initiate(struct libhoth_device* dev) {
  const struct hoth_request_key_rotation_record request = {
      .operation = KEY_ROTATION_RECORD_INITIATE,
      .packet_offset = 0,
      .packet_size = 0,
      .reserved = 0,
  };

  size_t rlen = 0;
  int ret = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HAVEN_KEY_ROTATION_OP, 0,
      &request, sizeof(request), NULL, 0, &rlen);

  if (ret != 0) {
    fprintf(stderr, "HOTH_KEY_ROTATION_INITIATE error code: %d\n", ret);
    return ret;
  }

  if (rlen != 0) {
    fprintf(stderr,
            "HOTH_KEY_ROTATION_INITIATE expected exactly %d response "
            "bytes, got %ld\n",
            0, rlen);
    return -1;
  }

  return 0;
}

int libhoth_key_rotation_get_version(
    struct libhoth_device* dev,
    struct hoth_response_key_rotation_record_version* record_version) {
  const struct hoth_request_key_rotation_record request = {
      .operation = KEY_ROTATION_RECORD_GET_VERSION,
      .packet_offset = 0,
      .packet_size = 0,
      .reserved = 0,
  };

  size_t rlen = 0;
  int ret = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HAVEN_KEY_ROTATION_OP, 0,
      &request, sizeof(request), record_version, sizeof(*record_version),
      &rlen);

  if (ret != 0) {
    fprintf(stderr, "HOTH_KEY_ROTATION_GET_VERSION error code: %d\n", ret);
    return ret;
  }

  if (rlen != sizeof(*record_version)) {
    fprintf(stderr,
            "HOTH_KEY_ROTATION_GET_VERSION expected exactly %ld response "
            "bytes, got %ld\n",
            sizeof(*record_version), rlen);
    return -1;
  }

  return 0;
}

int libhoth_key_rotation_get_status(
    struct libhoth_device* dev,
    struct hoth_response_key_rotation_status* record_status) {
  const struct hoth_request_key_rotation_record request = {
      .operation = KEY_ROTATION_RECORD_GET_STATUS,
      .packet_offset = 0,
      .packet_size = 0,
      .reserved = 0,
  };

  size_t rlen = 0;
  int ret = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HAVEN_KEY_ROTATION_OP, 0,
      &request, sizeof(request), record_status, sizeof(*record_status), &rlen);

  if (ret != 0) {
    fprintf(stderr, "HOTH_KEY_ROTATION_GET_STATUS error code: %d\n", ret);
    return ret;
  }

  if (rlen != sizeof(*record_status)) {
    fprintf(stderr,
            "HOTH_KEY_ROTATION_GET_STATUS expected exactly %ld response "
            "bytes, got %ld\n",
            sizeof(*record_status), rlen);
    return -1;
  }

  return 0;
}

int libhoth_key_rotation_payload_status(
    struct libhoth_device* dev,
    struct hoth_response_key_rotation_payload_status* payload_status) {
  const struct hoth_request_key_rotation_record request = {
      .operation = KEY_ROTATION_RECORD_PAYLOAD_STATUS,
      .packet_offset = 0,
      .packet_size = 0,
      .reserved = 0,
  };

  size_t rlen = 0;
  int ret = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HAVEN_KEY_ROTATION_OP, 0,
      &request, sizeof(request), payload_status, sizeof(*payload_status),
      &rlen);

  if (ret != 0) {
    fprintf(stderr, "HOTH_KEY_ROTATION_PAYLOAD_STATUS error code: %d\n", ret);
    return ret;
  }

  if (rlen != sizeof(*payload_status)) {
    fprintf(stderr,
            "HOTH_KEY_ROTATION_PAYLOAD_STATUS expected exactly %ld response "
            "bytes, got %ld\n",
            sizeof(*payload_status), rlen);
    return -1;
  }

  return 0;
}
