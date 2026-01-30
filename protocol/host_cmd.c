// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "host_cmd.h"

#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void hex_dump(FILE* out, const void* buffer, size_t size) {
  if (!buffer || !size) {
    fprintf(stderr, "hex_dump with null or empty buffer.\n");
    return;
  }

  enum { BYTES_PER_LINE = 16 };
  const uint8_t* bytes = (const uint8_t*)buffer;
  char line_ascii[BYTES_PER_LINE + 1] = {0};

  for (size_t offset = 0; offset < size; offset += BYTES_PER_LINE) {
    fprintf(out, "0x%04lx: ", offset);
    const size_t remaining = size - offset;
    const size_t chunk_size =
        remaining < BYTES_PER_LINE ? remaining : BYTES_PER_LINE;

    for (size_t i = 0; i < BYTES_PER_LINE; ++i) {
      if (i > 0 && (i % 8) == 0) {
        // Insert a gap between sets of 8 bytes.
        fprintf(out, " ");
      }

      if (i < chunk_size) {
        uint8_t byte = bytes[offset + i];
        fprintf(out, "%02x ", byte);
        line_ascii[i] = isgraph(byte) ? byte : '.';
      } else {
        fprintf(out, "   ");  // filler instead of hex digits
        line_ascii[i] = ' ';
      }
    }

    fprintf(out, "|%s|\n", line_ascii);
  }
}

uint8_t libhoth_calculate_checksum(const void* header, size_t header_size,
                                   const void* data, size_t data_size) {
  size_t i;
  uint8_t sum = 0;

  for (i = 0; i < header_size; ++i) {
    sum += ((const uint8_t*)(header))[i];
  }

  if (data != NULL) {
    for (i = 0; i < data_size; ++i) {
      sum += ((const uint8_t*)(data))[i];
    }
  }

  return 0x100 - sum;
}

static int populate_ec_request_header(
    uint16_t command, uint8_t command_version, const void* request,
    size_t request_size, struct hoth_host_request* request_header) {
  if (!request_header) {
    fprintf(stderr, "Request header argument cannot be NULL\n");
    return -EINVAL;
  }

  if (request_size > 0 && !request) {
    fprintf(stderr, "Request data argument cannot be NULL with size > 0\n");
    return -EINVAL;
  }

  if (request_size > UINT16_MAX) {
    fprintf(stderr, "Error, request_size (%lu) > max (%lu)\n",
            (unsigned long)request_size, (unsigned long)UINT16_MAX);
    return -EINVAL;
  }

  request_header->struct_version = HOTH_HOST_REQUEST_VERSION;
  request_header->checksum = 0;
  request_header->command = command;
  request_header->command_version = command_version;
  request_header->reserved = 0;
  request_header->data_len = (uint16_t)request_size;
  // Note that we've set `checksum` to zero earlier, so this is deterministic.
  request_header->checksum = libhoth_calculate_checksum(
      request_header, sizeof(*request_header), request, request_size);

  return 0;
}

static int validate_ec_response_header(
    const struct hoth_host_response* response_header, const void* response,
    size_t response_size) {
  uint8_t response_checksum;

  if (!response_header) {
    fprintf(stderr, "response_header cannot be NULL\n");
    return -EINVAL;
  }

  if (!response && response_header->data_len > 0) {
    fprintf(
        stderr,
        "response cannot be NULL if the response data_len is greater than 0\n");
    return -EINVAL;
  }

  if (response_header->struct_version != HOTH_HOST_RESPONSE_VERSION) {
    fprintf(stderr, "Error: unexpected struct_version. Got %u, expected %u\n",
            response_header->struct_version, HOTH_HOST_RESPONSE_VERSION);
    return -EINVAL;
  }

  if (response_header->data_len > response_size) {
    fprintf(stderr,
            "Error: insufficient response buffer size. Have %zu, need %u\n",
            response_size, response_header->data_len);
    return -EINVAL;
  }

  response_checksum =
      libhoth_calculate_checksum(response_header, sizeof(*response_header),
                                 response, response_header->data_len);

  // Since this checksum includes the `checksum` field in `response_header`, it
  // should be zero.
  if (response_checksum != 0) {
    fprintf(stderr, "Error: response checksum (%u) != 0\n", response_checksum);
    fprintf(stderr, "Response header:\n");
    hex_dump(stderr, response_header, sizeof(*response_header));
    fprintf(stderr, "Response body:\n");
    hex_dump(stderr, response, response_header->data_len);
    return -EINVAL;
  }

  return 0;
}

int libhoth_hostcmd_exec(struct libhoth_device* dev, uint16_t command,
                         uint8_t version, const void* req_payload,
                         size_t req_payload_size, void* resp_buf,
                         size_t resp_buf_size, size_t* out_resp_size) {
  struct {
    struct hoth_host_request hdr;
    uint8_t
        payload_buf[LIBHOTH_MAILBOX_SIZE - sizeof(struct hoth_host_request)];
  } req;
  if (req_payload_size > sizeof(req.payload_buf)) {
    fprintf(stderr, "req_payload_size too large: %d > %d\n",
            (int)req_payload_size, (int)sizeof(req.payload_buf));
    return -1;
  }
  if (req_payload) {
    memcpy(req.payload_buf, req_payload, req_payload_size);
  }
  int status = populate_ec_request_header(command, version, req.payload_buf,
                                          req_payload_size, &req.hdr);
  if (status != 0) {
    fprintf(stderr, "populate_ec_request_header() failed: %d\n", status);
    return -1;
  }
  status = libhoth_send_request(dev, &req, sizeof(req.hdr) + req_payload_size);
  if (status != LIBHOTH_OK) {
    fprintf(stderr, "libhoth_send_request() failed: %d\n", status);
    return -1;
  }
  struct {
    struct hoth_host_response hdr;
    uint8_t
        payload_buf[LIBHOTH_MAILBOX_SIZE - sizeof(struct hoth_host_response)];
  } resp;
  size_t resp_size;
  status = libhoth_receive_response(dev, &resp, sizeof(resp), &resp_size,
                                    HOTH_CMD_TIMEOUT_MS_DEFAULT);
  if (status != LIBHOTH_OK) {
    fprintf(stderr, "libhoth_receive_response() failed: %d\n", status);
    return -1;
  }
  status = validate_ec_response_header(&resp.hdr, resp.payload_buf, resp_size);
  if (status != 0) {
    fprintf(stderr, "EC response header invalid: %d\n", status);
    return -1;
  }
  if (resp.hdr.result != HOTH_RES_SUCCESS) {
    fprintf(stderr, "EC response contained error: %d", resp.hdr.result);
    if (resp.hdr.data_len >= 4) {
      uint32_t error_code;
      memcpy(&error_code, resp.payload_buf, sizeof(error_code));
      fprintf(stderr, " (extended: 0x%08x)\n", error_code);
    } else {
      fprintf(stderr, "\n");
    }
    return HTOOL_ERROR_HOST_COMMAND_START + resp.hdr.result;
  }

  size_t resp_payload_size = resp_size - sizeof(struct hoth_host_response);
  if (out_resp_size) {
    if (resp_payload_size > resp_buf_size) {
      fprintf(
          stderr,
          "Response payload too large to fit in supplied buffer: %zu > %zu\n",
          resp_payload_size, resp_buf_size);
      return -1;
    }
  } else {
    if (resp_payload_size != resp_buf_size) {
      fprintf(stderr,
              "Unexpected response payload size: got %zu expected %zu\n",
              resp_payload_size, resp_buf_size);
      return -1;
    }
  }
  if (resp_buf) {
    memcpy(resp_buf, resp.payload_buf, resp_payload_size);
  }
  if (out_resp_size) {
    *out_resp_size = resp_payload_size;
  }
  return 0;
}
