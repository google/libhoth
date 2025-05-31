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

struct hoth_request_variable_length {
  struct hoth_request_key_rotation_record hdr;
  uint8_t data[KEY_ROTATION_RECORD_WRITE_MAX_SIZE];
} __hoth_align4;

static enum key_rotation_err send_key_rotation_request(
    struct libhoth_device* dev, uint16_t command) {
  const struct hoth_request_key_rotation_record request = {
      .operation = command,
      .packet_offset = 0,
      .packet_size = 0,
      .reserved = 0,
  };
  size_t rlen = 0;
  int ret = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HAVEN_KEY_ROTATION_OP, 0,
      &request, sizeof(request), NULL, 0, &rlen);
  if (ret != 0) {
    fprintf(stderr, "HOTH_KEY_ROTATION_COMMAND %d error code: %d\n", command,
            ret);
    return KEY_ROTATION_ERR;
  }
  if (rlen != 0) {
    fprintf(stderr,
            "HOTH_KEY_ROTATION_COMMAND: %d expected exactly %d response "
            "bytes, got %ld\n",
            command, 0, rlen);
    return KEY_ROTATION_ERR_INVALID_RESPONSE_SIZE;
  }
  return KEY_ROTATION_CMD_SUCCESS;
}

enum key_rotation_err libhoth_key_rotation_get_version(
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
    return KEY_ROTATION_ERR;
  }

  if (rlen != sizeof(*record_version)) {
    fprintf(stderr,
            "HOTH_KEY_ROTATION_GET_VERSION expected exactly %ld response "
            "bytes, got %ld\n",
            sizeof(*record_version), rlen);
    return KEY_ROTATION_ERR_INVALID_RESPONSE_SIZE;
  }

  return KEY_ROTATION_CMD_SUCCESS;
}

enum key_rotation_err libhoth_key_rotation_get_status(
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
    return KEY_ROTATION_ERR;
  }

  if (rlen != sizeof(*record_status)) {
    fprintf(stderr,
            "HOTH_KEY_ROTATION_GET_STATUS expected exactly %ld response "
            "bytes, got %ld\n",
            sizeof(*record_status), rlen);
    return KEY_ROTATION_ERR_INVALID_RESPONSE_SIZE;
  }

  return KEY_ROTATION_CMD_SUCCESS;
}

enum key_rotation_err libhoth_key_rotation_payload_status(
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
    return KEY_ROTATION_ERR;
  }

  if (rlen != sizeof(*payload_status)) {
    fprintf(stderr,
            "HOTH_KEY_ROTATION_PAYLOAD_STATUS expected exactly %ld response "
            "bytes, got %ld\n",
            sizeof(*payload_status), rlen);
    return KEY_ROTATION_ERR_INVALID_RESPONSE_SIZE;
  }

  return KEY_ROTATION_CMD_SUCCESS;
}

enum key_rotation_err libhoth_key_rotation_update(struct libhoth_device* dev,
                                                  const uint8_t* image,
                                                  size_t size) {
  if (size <= KEY_ROTATION_RECORD_SIGNATURE_SIZE) {
    fprintf(stderr, "Data chunk size invalid.\n");
    return KEY_ROTATION_ERR_INVALID_PARAM;
  }
  if (size > KEY_ROTATION_FLASH_AREA_SIZE) {
    fprintf(stderr, "Data chunk size invalid.\n");
    return KEY_ROTATION_ERR_INVALID_PARAM;
  }
  fprintf(stderr, "Initiating key rotation update protocol with libhoth.\n");
  if (send_key_rotation_request(dev, KEY_ROTATION_RECORD_INITIATE) !=
      KEY_ROTATION_CMD_SUCCESS) {
    fprintf(stderr, "Failed to initiate key rotation.\n");
    return KEY_ROTATION_INITIATE_FAIL;
  }
  fprintf(stderr, "Writing the image to hoth.\n");
  struct hoth_request_variable_length request;
  uint16_t offset = 0;
  const uint8_t* packet_data = image;
  while (size > 0) {
    size_t size_to_send = (size < KEY_ROTATION_RECORD_WRITE_MAX_SIZE
                               ? (uint16_t)(size)
                               : KEY_ROTATION_RECORD_WRITE_MAX_SIZE);
    request.hdr.operation = KEY_ROTATION_RECORD_WRITE;
    request.hdr.packet_offset = offset;
    request.hdr.packet_size = size_to_send;
    memcpy(request.data, packet_data, size_to_send);
    size_t response_length;
    int ret = libhoth_hostcmd_exec(
        dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HAVEN_KEY_ROTATION_OP,
        0, &request, sizeof(request.hdr) + request.hdr.packet_size, NULL, 0,
        &response_length);
    if (ret != 0) {
      fprintf(stderr, "Error code from hoth: %d\n", ret);
      return KEY_ROTATION_ERR;
    }
    if (response_length != 0) {
      fprintf(stderr, "Expected exactly %d response bytes, got %ld\n", 0,
              response_length);
      return KEY_ROTATION_ERR_INVALID_RESPONSE_SIZE;
    }
    offset += size_to_send;
    size -= size_to_send;
    packet_data += size_to_send;
  }
  fprintf(stderr, "Finalizing key rotation update.\n");
  if (send_key_rotation_request(dev, KEY_ROTATION_RECORD_COMMIT) !=
      KEY_ROTATION_CMD_SUCCESS) {
    fprintf(stderr, "Failed to commit key rotation.\n");
    return KEY_ROTATION_COMMIT_FAIL;
  }
  return KEY_ROTATION_CMD_SUCCESS;
}

static enum key_rotation_err send_key_rotation_read_helper(
    struct libhoth_device* dev, uint8_t operation, uint16_t offset,
    uint16_t size, const void* request_payload, size_t request_payload_size,
    uint8_t* response_data, size_t response_data_size) {
  struct hoth_request_variable_length request;
  request.hdr.operation = operation;
  request.hdr.packet_offset = offset;
  request.hdr.packet_size = size;
  if (request_payload != NULL && request_payload_size > 0) {
    if (request_payload_size > sizeof(request.data)) {
      fprintf(stderr, "Request payload size invalid.\n");
      return KEY_ROTATION_ERR_INVALID_PARAM;
    } else if (operation == KEY_ROTATION_RECORD_READ &&
               request_payload_size !=
                   sizeof(struct hoth_request_key_rotation_record_read)) {
      fprintf(stderr, "Request payload size invalid.\n");
      return KEY_ROTATION_ERR_INVALID_PARAM;
    }
    if (operation == KEY_ROTATION_RECORD_READ_CHUNK_TYPE &&
        request_payload_size !=
            sizeof(struct hoth_request_key_rotation_record_read_chunk_type)) {
      fprintf(stderr, "Request payload size invalid.\n");
      return KEY_ROTATION_ERR_INVALID_PARAM;
    }
    memcpy(request.data, request_payload, request_payload_size);
  }

  size_t rlen = 0;
  int ret = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HAVEN_KEY_ROTATION_OP, 0,
      &request, sizeof(request.hdr) + request_payload_size, response_data,
      response_data_size, &rlen);
  if (ret != 0) {
    fprintf(stderr, "HOTH_KEY_ROTATION_READ error code: %d\n", ret);
    return KEY_ROTATION_ERR;
  }
  if (rlen != response_data_size) {
    fprintf(stderr,
            "HOTH_KEY_ROTATION_READ expected exactly %ld response "
            "bytes, got %ld\n",
            response_data_size, rlen);
    return KEY_ROTATION_ERR_INVALID_RESPONSE_SIZE;
  }
  return KEY_ROTATION_CMD_SUCCESS;
}

enum key_rotation_err libhoth_key_rotation_read(
    struct libhoth_device* dev, uint16_t record_offset, uint16_t read_size,
    uint32_t read_half,
    struct hoth_response_key_rotation_record_read* read_response) {
  if (read_size > KEY_ROTATION_FLASH_AREA_SIZE || read_size == 0) {
    fprintf(stderr, "Read size invalid.\n");
    return KEY_ROTATION_ERR_INVALID_PARAM;
  }
  uint16_t read_offset = 0;

  const struct hoth_request_key_rotation_record_read request = {
      .read_half = read_half,
  };
  uint8_t* response_data = read_response->data;
  while (read_size > 0) {
    uint16_t packet_size = (read_size > KEY_ROTATION_RECORD_READ_MAX_SIZE)
                               ? KEY_ROTATION_RECORD_READ_MAX_SIZE
                               : read_size;
    enum key_rotation_err err = send_key_rotation_read_helper(
        dev, KEY_ROTATION_RECORD_READ, read_offset + record_offset, packet_size,
        &request, sizeof(request), response_data, packet_size);
    if (err != KEY_ROTATION_CMD_SUCCESS) {
      return err;
    }
    read_offset += packet_size;
    read_size -= packet_size;
    response_data += packet_size;
  }
  return KEY_ROTATION_CMD_SUCCESS;
}
