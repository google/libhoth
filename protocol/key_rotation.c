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
#include <sys/param.h>

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
    size_t* response_length, uint8_t* response_data,
    size_t response_buffer_size) {
  struct hoth_request_variable_length request;
  request.hdr.operation = operation;
  request.hdr.packet_offset = offset;
  request.hdr.packet_size = size;
  if (request_payload != NULL && request_payload_size > 0) {
    if (request_payload_size > sizeof(request.data)) {
      fprintf(stderr,
              "Request packet size larger than request size: %zu Expected less "
              "than %zu\n",
              request_payload_size, sizeof(request.data));
      return KEY_ROTATION_ERR_INVALID_PARAM;
    } else if (operation == KEY_ROTATION_RECORD_READ &&
               request_payload_size !=
                   sizeof(struct hoth_request_key_rotation_record_read)) {
      fprintf(stderr, "Request payload size invalid: %zu Expected %zu\n",
              request_payload_size,
              sizeof(struct hoth_request_key_rotation_record_read));
      return KEY_ROTATION_ERR_INVALID_PARAM;
    }
    if (operation == KEY_ROTATION_RECORD_READ_CHUNK_TYPE &&
        request_payload_size !=
            sizeof(struct hoth_request_key_rotation_record_read_chunk_type)) {
      fprintf(stderr, "Request payload size invalid: %zu Expected %zu\n",
              request_payload_size,
              sizeof(struct hoth_request_key_rotation_record_read_chunk_type));
      return KEY_ROTATION_ERR_INVALID_PARAM;
    }
    memcpy(request.data, request_payload, request_payload_size);
  }

  *response_length = 0;
  int ret = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HAVEN_KEY_ROTATION_OP, 0,
      &request, sizeof(request.hdr) + request_payload_size, response_data,
      response_buffer_size, response_length);
  if (ret != 0) {
    fprintf(stderr, "HOTH_KEY_ROTATION_READ error code: %x\n", ret);
    return KEY_ROTATION_ERR;
  }
  return KEY_ROTATION_CMD_SUCCESS;
}

enum key_rotation_err libhoth_key_rotation_read(
    struct libhoth_device* dev, uint16_t record_offset, uint16_t read_size,
    uint32_t read_half,
    struct hoth_response_key_rotation_record_read* read_response) {
  if (read_size > KEY_ROTATION_FLASH_AREA_SIZE || read_size == 0) {
    fprintf(stderr, "Read size invalid. Read size: %d\n", read_size);
    return KEY_ROTATION_ERR_INVALID_PARAM;
  }
  uint16_t read_offset = 0;

  const struct hoth_request_key_rotation_record_read request = {
      .read_half = read_half,
  };
  uint8_t* response_data = read_response->data;
  while (read_size > 0) {
    if (read_offset + read_size > KEY_ROTATION_FLASH_AREA_SIZE) {
      fprintf(
          stderr,
          "Read offset + read size invalid. Read offset: %d, read size: %d\n",
          read_offset, read_size);
      return KEY_ROTATION_ERR_INVALID_PARAM;
    }
    uint16_t packet_size = (read_size > KEY_ROTATION_RECORD_READ_MAX_SIZE)
                               ? KEY_ROTATION_RECORD_READ_MAX_SIZE
                               : read_size;
    size_t response_length = 0;
    enum key_rotation_err err = send_key_rotation_read_helper(
        dev, KEY_ROTATION_RECORD_READ, read_offset + record_offset, packet_size,
        &request, sizeof(request), &response_length,
        &response_data[read_offset], packet_size);
    if (err != KEY_ROTATION_CMD_SUCCESS) {
      return err;
    }
    if (response_length != packet_size) {
      fprintf(stderr,
              "HOTH_KEY_ROTATION_READ expected exactly %d response "
              "bytes, got %ld\n",
              packet_size, response_length);
      return KEY_ROTATION_ERR_INVALID_RESPONSE_SIZE;
    }
    read_offset += packet_size;
    read_size -= packet_size;
  }
  return KEY_ROTATION_CMD_SUCCESS;
}

enum key_rotation_err libhoth_key_rotation_read_chunk_type(
    struct libhoth_device* dev, uint32_t chunk_typecode, uint32_t chunk_index,
    uint16_t chunk_offset, uint16_t read_size,
    struct hoth_response_key_rotation_record_read* read_response,
    uint16_t* response_size) {
  if (read_size > KEY_ROTATION_MAX_RECORD_SIZE) {
    fprintf(stderr, "Read size invalid: %d Read size must be less than %d\n",
            read_size, KEY_ROTATION_MAX_RECORD_SIZE);
    return KEY_ROTATION_ERR_INVALID_PARAM;
  }
  if (chunk_offset > KEY_ROTATION_MAX_RECORD_SIZE) {
    fprintf(stderr,
            "Chunk offset invalid: %d Chunk offset must be less than %d\n",
            chunk_offset, KEY_ROTATION_MAX_RECORD_SIZE);
    return KEY_ROTATION_ERR_INVALID_PARAM;
  }
  struct hoth_request_key_rotation_record_read_chunk_type request = {
      .chunk_typecode = chunk_typecode,
      .chunk_index = chunk_index,
  };
  uint16_t read_offset = 0;
  uint8_t* response = read_response->data;
  uint16_t chunk_length = 0;
  do {
    if (read_offset + read_size > KEY_ROTATION_FLASH_AREA_SIZE) {
      fprintf(
          stderr,
          "Read offset + read size invalid. Read offset: %d, read size: %d\n",
          read_offset, read_size);
      return KEY_ROTATION_ERR_INVALID_PARAM;
    }
    uint16_t packet_size =
        (read_size > KEY_ROTATION_RECORD_READ_CHUNK_TYPE_MAX_SIZE)
            ? KEY_ROTATION_RECORD_READ_CHUNK_TYPE_MAX_SIZE
            : read_size;
    size_t response_length = 0;
    enum key_rotation_err err = send_key_rotation_read_helper(
        dev, KEY_ROTATION_RECORD_READ_CHUNK_TYPE, read_offset + chunk_offset,
        packet_size, &request, sizeof(request), &response_length,
        &response[read_offset],
        KEY_ROTATION_RECORD_READ_CHUNK_TYPE_MAX_SIZE + sizeof(uint32_t));
    if (err != KEY_ROTATION_CMD_SUCCESS) {
      return err;
    }
    // The last 4 bytes of the response is the chunk size. This is used to
    // determine if the read size needs to be adjusted.
    if (response_length < sizeof(uint32_t)) {
      fprintf(stderr,
              "Unexpected host command response size. Expecting "
              "non-zero; Got %lu\n",
              response_length);
      return KEY_ROTATION_ERR_INVALID_RESPONSE_SIZE;
    }
    response_length -= sizeof(uint32_t);
    memcpy(&chunk_length, &response[response_length], sizeof(uint16_t));
    // If the read size is 0, the chunk size is returned in the last 4 bytes
    // of the response. This is used to determine the read size for the next
    // iteration.
    if (chunk_length < STRUCT_CHUNK_SIZE) {
      fprintf(stderr,
              "Chunk length invalid: %d Chunk length must be greater than %d\n",
              chunk_length, STRUCT_CHUNK_SIZE);
      return KEY_ROTATION_ERR;
    }
    if (read_size == 0) {
      read_size =
          chunk_length -
          chunk_offset;  // This is the total number of bytes to be read.
      packet_size =
          MIN(read_size, KEY_ROTATION_RECORD_READ_CHUNK_TYPE_MAX_SIZE);
    }
    if (response_length != packet_size) {
      fprintf(stderr,
              "Unexpected host command response size. Expecting %u; Got %lu\n",
              packet_size, response_length);
    }
    read_offset += packet_size;
    read_size -= packet_size;
  } while (read_size > 0);
  *response_size = read_offset;
  return KEY_ROTATION_CMD_SUCCESS;
}

enum key_rotation_err libhoth_key_rotation_chunk_type_count(
    struct libhoth_device* dev, uint32_t chunk_typecode,
    uint16_t* chunk_count) {
  struct hoth_request_variable_length request;
  request.hdr.operation = KEY_ROTATION_RECORD_CHUNK_TYPE_COUNT;
  request.hdr.packet_offset = 0;
  request.hdr.packet_size = 0;
  struct hoth_request_key_rotation_record_chunk_type_count*
      request_chunk_type_count =
          (struct hoth_request_key_rotation_record_chunk_type_count*)&(
              request.data);
  request_chunk_type_count->chunk_typecode = chunk_typecode;
  uint32_t response = 0;
  size_t rlen = 0;
  int ret = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HAVEN_KEY_ROTATION_OP, 0,
      &request, sizeof(request), &response, sizeof(response), &rlen);
  if (ret != 0) {
    fprintf(stderr, "HOTH_KEY_ROTATION_CHUNK_TYPE_COUNT error code: %d\n", ret);
    return KEY_ROTATION_ERR;
  }
  if (rlen != sizeof(response)) {
    fprintf(stderr,
            "HOTH_KEY_ROTATION_CHUNK_TYPE_COUNT expected exactly %ld response "
            "bytes, got %ld\n",
            sizeof(response), rlen);
    return KEY_ROTATION_ERR_INVALID_RESPONSE_SIZE;
  }
  *chunk_count = response;
  return KEY_ROTATION_CMD_SUCCESS;
}

enum key_rotation_err libhoth_key_rotation_erase_record(
    struct libhoth_device* dev) {
  return send_key_rotation_request(dev, KEY_ROTATION_RECORD_ERASE_RECORD);
}

enum key_rotation_err libhoth_key_rotation_set_mauv(struct libhoth_device* dev,
                                                    uint32_t mauv) {
  struct hoth_request_variable_length request;
  request.hdr.operation = KEY_ROTATION_RECORD_SET_MAUV;
  request.hdr.packet_offset = 0;
  request.hdr.packet_size = 0;
  struct hoth_request_key_rotation_record_set_mauv* request_set_mauv =
      (struct hoth_request_key_rotation_record_set_mauv*)&(request.data);
  request_set_mauv->mauv = mauv;
  size_t rlen = 0;
  int ret = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HAVEN_KEY_ROTATION_OP, 0,
      &request,
      sizeof(request.hdr) +
          sizeof(struct hoth_request_key_rotation_record_set_mauv),
      NULL, 0, &rlen);
  if (ret != 0) {
    fprintf(stderr, "HOTH_KEY_ROTATION_SET_MAUV error code: %d\n", ret);
    return KEY_ROTATION_ERR;
  }
  if (rlen != 0) {
    fprintf(stderr,
            "HOTH_KEY_ROTATION_SET_MAUV expected exactly %d response "
            "bytes, got %ld\n",
            0, rlen);
    return KEY_ROTATION_ERR_INVALID_RESPONSE_SIZE;
  }
  return KEY_ROTATION_CMD_SUCCESS;
}

enum key_rotation_err libhoth_key_rotation_get_mauv(
    struct libhoth_device* dev, struct hoth_response_key_rotation_mauv* mauv) {
  const struct hoth_request_key_rotation_record request = {
      .operation = KEY_ROTATION_RECORD_GET_MAUV,
      .packet_offset = 0,
      .packet_size = 0,
      .reserved = 0,
  };

  size_t rlen = 0;
  int ret = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HAVEN_KEY_ROTATION_OP, 0,
      &request, sizeof(request), mauv, sizeof(*mauv), &rlen);

  if (ret != 0) {
    fprintf(stderr, "HOTH_KEY_ROTATION_GET_MAUV error code: %d\n", ret);
    return KEY_ROTATION_ERR;
  }

  if (rlen != sizeof(*mauv)) {
    fprintf(stderr,
            "HOTH_KEY_ROTATION_GET_MAUV expected exactly %ld response "
            "bytes, got %ld\n",
            sizeof(*mauv), rlen);
    return KEY_ROTATION_ERR_INVALID_RESPONSE_SIZE;
  }

  return KEY_ROTATION_CMD_SUCCESS;
}
