// Copyright 2022 Google LLC
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

#include "ec_util.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

uint8_t calculate_ec_command_checksum(const void* header, size_t header_size,
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

int populate_ec_request_header(uint16_t command, uint8_t command_version,
                               const void* request, size_t request_size,
                               struct ec_host_request* request_header) {
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

  request_header->struct_version = EC_HOST_REQUEST_VERSION;
  request_header->checksum = 0;
  request_header->command = command;
  request_header->command_version = command_version;
  request_header->reserved = 0;
  request_header->data_len = (uint16_t)request_size;
  // Note that we've set `checksum` to zero earlier, so this is deterministic.
  request_header->checksum = calculate_ec_command_checksum(
      request_header, sizeof(*request_header), request, request_size);

  return 0;
}

int validate_ec_response_header(const struct ec_host_response* response_header,
                                const void* response, size_t response_size) {
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

  if (response_header->struct_version != EC_HOST_RESPONSE_VERSION) {
    fprintf(stderr, "Error: unexpected struct_version. Got %u, expected %u\n",
            response_header->struct_version, EC_HOST_RESPONSE_VERSION);
    return -EINVAL;
  }

  if (response_header->data_len > response_size) {
    fprintf(stderr,
            "Error: insufficient response buffer size. Have %zu, need %u\n",
            response_size, response_header->data_len);
    return -EINVAL;
  }

  response_checksum =
      calculate_ec_command_checksum(response_header, sizeof(*response_header),
                                    response, response_header->data_len);

  // Since this checksum includes the `checksum` field in `response_header`, it
  // should be zero.
  if (response_checksum != 0) {
    fprintf(stderr, "Error: response checksum (%u) != 0\n", response_checksum);
    return -EINVAL;
  }

  return 0;
}
