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

#include "provisioning.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "host_cmd.h"

uint32_t libhoth_provisioning_crc32(uint32_t initial_value, const uint8_t* buf,
                                    size_t size) {
  const uint32_t polynomial = 0xEDB88320;

  uint32_t crc = ~initial_value;
  for (size_t i = 0; i < size; i++) {
    uint8_t byte = buf[i];
    crc = crc ^ byte;
    for (int j = 0; j < 8; j++, byte >>= 1) {
      crc = (crc >> 1) ^ ((crc & 1) ? polynomial : 0);
    }
  }
  return ~crc;
}

// Helper function used to return the lowest value integer given two integers
static uint16_t min_u16(uint16_t a, uint16_t b) { return (a < b) ? a : b; }

// Executes a command on the provisioning log host command (0x3E40)
static libhoth_error exec_provisioning_log_cmd(struct libhoth_device* dev,
                                               const void* req_payload,
                                               size_t req_payload_size,
                                               void* resp_buf,
                                               size_t resp_buf_size,
                                               size_t* out_resp_size) {
  return libhoth_hostcmd_exec_v2(dev,
                                 /*command=*/HOTH_CMD_BOARD_SPECIFIC_BASE +
                                     HOTH_PRV_CMD_HOTH_PROVISIONING_LOG,
                                 /*version=*/0, req_payload, req_payload_size,
                                 resp_buf, resp_buf_size, out_resp_size);
}

// Runs a provisioning log command, returning the legacy status code.
static int exec_provisioning_log_cmd_legacy(struct libhoth_device* dev,
                                            const void* req_payload,
                                            size_t req_payload_size,
                                            void* resp_buf,
                                            size_t resp_buf_size,
                                            size_t* out_resp_size) {
  return libhoth_hostcmd_exec(dev,
                              /*command=*/HOTH_CMD_BOARD_SPECIFIC_BASE +
                                  HOTH_PRV_CMD_HOTH_PROVISIONING_LOG,
                              /*version=*/0, req_payload, req_payload_size,
                              resp_buf, resp_buf_size, out_resp_size);
}

// Executes a key provisioning host command (0x3E43)
static libhoth_error exec_key_provisioning_cmd(struct libhoth_device* dev,
                                               const void* req_payload,
                                               size_t req_payload_size) {
  size_t response_size = 0;
  return libhoth_hostcmd_exec_v2(dev,
                                 /*command=*/HOTH_CMD_BOARD_SPECIFIC_BASE +
                                     HOTH_PRV_CMD_HOTH_KEY_PROVISIONING,
                                 /*version=*/0, req_payload, req_payload_size,
                                 NULL, 0, &response_size);
}

int libhoth_provisioning_log_read(struct libhoth_device* dev, uint8_t* buf,
                                  size_t buf_size, size_t* out_size) {
  struct hoth_provisioning_log_header prov_log_hdr_resp;
  memset(&prov_log_hdr_resp, 0, sizeof(prov_log_hdr_resp));
  struct hoth_provisioning_log_request request = {
      .version = 1,
      .operation = PROVISIONING_LOG_READ,
      .reserved = 0,
      .offset = 0,
      .size = 0,
      .checksum = 0,
  };

  // Get Provisioning Log Header
  size_t response_size = 0;
  int exec_status = exec_provisioning_log_cmd_legacy(
      dev, &request, sizeof(request), &prov_log_hdr_resp,
      sizeof(prov_log_hdr_resp), &response_size);
  if (exec_status != 0) {
    return exec_status;
  }

  // Get Provisioning Log
  uint16_t bytes_read = 0;
  while (bytes_read < prov_log_hdr_resp.size) {
    // Read the provisioning log in chunks
    struct hoth_provisioning_log response;
    memset(&response, 0, sizeof(response));
    // Get the size of the data to be requested
    uint16_t chunk_size = min_u16(prov_log_hdr_resp.size - bytes_read,
                                  PROVISIONING_LOG_CHUNK_MAX_SIZE);
    // Update the request to the appropriate size
    request.offset = bytes_read;
    request.size = chunk_size;
    response_size = 0;

    exec_status = exec_provisioning_log_cmd_legacy(
        dev, &request, sizeof(request), &response, sizeof(response),
        &response_size);
    if (exec_status != 0) {
      fprintf(stderr,
              "Unexpected Error: Returned status %d,  while trying to send "
              "command to "
              "read the provisioning_log\n",
              exec_status);
      return exec_status;
    }
    // Check if read bytes matches chunk size
    if (response_size != chunk_size + sizeof(prov_log_hdr_resp)) {
      fprintf(stderr,
              "Unexpected host command response size. Expecting %lu; Got "
              "%lu\n",
              chunk_size + sizeof(prov_log_hdr_resp), response_size);
      return 1;
    }

    if (bytes_read + chunk_size > buf_size) {
      fprintf(stderr,
              "Unexpected Error: Bytes returned: %hu > "
              "PROVISIONING_LOG_MAX_SIZE: %zu\n",
              (uint16_t)(bytes_read + chunk_size), buf_size);
      return -1;
    }

    // Copy the read bytes into the caller's buffer
    memcpy(buf + bytes_read, response.data, chunk_size);
    // Increment the amount of bytes of the provisioning_log that have
    // been consumed
    bytes_read += chunk_size;
  }

  if (out_size != NULL) {
    *out_size = bytes_read;
  }
  return 0;
}

int libhoth_provisioning_log_validate_and_sign(struct libhoth_device* dev,
                                               const uint8_t* blob,
                                               size_t blob_size, uint8_t* cert,
                                               size_t cert_capacity,
                                               size_t* out_cert_size) {
  uint32_t checksum = libhoth_provisioning_crc32(0, blob, blob_size);
  struct hoth_provisioning_log_request request = {
      .version = 1,
      .operation = PROVISIONING_LOG_VALIDATE_AND_SIGN,
      .reserved = 0,
      .offset = 0,
      .size = (uint16_t)blob_size,
      .checksum = checksum,
  };

  size_t response_size = 0;
  int exec_status = exec_provisioning_log_cmd_legacy(
      dev, &request, sizeof(request), cert, cert_capacity, &response_size);
  if (exec_status != 0) {
    fprintf(stderr,
            "Unexpected Error: Returned status %d,  while trying to send "
            "command to "
            "read the provisioning_log\n",
            exec_status);
    return exec_status;
  }

  if (response_size > cert_capacity) {
    fprintf(stderr,
            "Unexpected Error: Bytes returned: %lu > "
            "PROVISIONING_CERT_MAX_SIZE: %zu\n",
            response_size, cert_capacity);
    return -1;
  }

  if (out_cert_size != NULL) {
    *out_cert_size = response_size;
  }
  return 0;
}

libhoth_error libhoth_provisioning_log_write(struct libhoth_device* dev,
                                             const uint8_t* data, size_t size) {
  uint16_t bytes_written = 0;
  while (bytes_written < size) {
    uint16_t chunk_size = (uint16_t)(size - bytes_written);
    if (chunk_size > PROVISIONING_LOG_WRITE_CHUNK_MAX_SIZE) {
      chunk_size = PROVISIONING_LOG_WRITE_CHUNK_MAX_SIZE;
    }

    struct hoth_provisioning_log_write_request write_req = {
        .req =
            {
                .version = 1,
                .operation = PROVISIONING_LOG_WRITE,
                .reserved = 0,
                .offset = bytes_written,
                .size = chunk_size,
                .checksum = 0,
            },
    };
    memcpy(write_req.data, data + bytes_written, chunk_size);

    size_t response_size = 0;
    libhoth_error err = exec_provisioning_log_cmd(
        dev, &write_req, sizeof(write_req.req) + chunk_size, NULL, 0,
        &response_size);
    if (err != HOTH_SUCCESS) {
      return err;
    }
    bytes_written += chunk_size;
  }

  return HOTH_SUCCESS;
}

libhoth_error libhoth_provisioning_log_commit(struct libhoth_device* dev,
                                              const uint8_t* data,
                                              size_t size) {
  struct hoth_provisioning_log_request commit_req = {
      .version = 1,
      .operation = PROVISIONING_LOG_COMMIT,
      .reserved = 0,
      .offset = 0,
      .size = (uint16_t)size,
      .checksum = libhoth_provisioning_crc32(0, data, size),
  };
  size_t response_size = 0;
  return exec_provisioning_log_cmd(dev, &commit_req, sizeof(commit_req), NULL,
                                   0, &response_size);
}

libhoth_error libhoth_key_provisioning_store_secrets(struct libhoth_device* dev,
                                                     const uint8_t* secrets,
                                                     size_t size) {
  const size_t request_size =
      sizeof(struct hoth_key_provisioning_request_header) + size;

  struct hoth_key_provisioning_store_secrets_request req = {
      .hdr =
          {
              .version = HOTH_KEY_PROVISIONING_REQUEST_VERSION,
              .command = HOTH_KEY_PROVISIONING_STORE_SECRETS,
              .size = (uint16_t)request_size,
          },
  };
  memcpy(req.secrets, secrets, size);

  return exec_key_provisioning_cmd(dev, &req, request_size);
}

libhoth_error libhoth_key_provisioning_load_mldsa_key(
    struct libhoth_device* dev, const uint8_t* key, size_t size) {
  uint16_t offset = 0;
  while (offset < size) {
    uint16_t chunk_size = (uint16_t)(size - offset);
    if (chunk_size > HOTH_KEY_PROVISIONING_LOAD_KEY_CHUNK_MAX_SIZE) {
      chunk_size = HOTH_KEY_PROVISIONING_LOAD_KEY_CHUNK_MAX_SIZE;
    }

    const size_t req_size =
        sizeof(struct hoth_key_provisioning_request_header) +
        sizeof(struct hoth_key_provisioning_load_key_args) + chunk_size;

    struct hoth_key_provisioning_load_key_request req = {
        .hdr =
            {
                .version = HOTH_KEY_PROVISIONING_REQUEST_VERSION,
                .command = HOTH_KEY_PROVISIONING_LOAD_MLDSA_PUBLIC_KEY,
                .size = (uint16_t)req_size,
            },
        .args =
            {
                .offset = offset,
                .size = chunk_size,
            },
    };
    memcpy(req.data, key + offset, chunk_size);

    libhoth_error err = exec_key_provisioning_cmd(dev, &req, req_size);
    if (err != HOTH_SUCCESS) {
      return err;
    }

    offset += chunk_size;
  }

  return HOTH_SUCCESS;
}
