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

#include <libusb-1.0/libusb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "bind.h"
#include "ec_util.h"
#include "host_commands.h"
#include "libhoth_usb.h"

const char *usage = "ec_hello <bus number> <device address>\n";

#define EC_HELLO_INCREMENT 0x01020304;

static int do_hello(struct libhoth_usb_device *dev) {
  const size_t req_buf_size =
      sizeof(struct ec_host_request) + sizeof(struct ec_params_hello);
  const size_t req_buf_words = (req_buf_size % sizeof(uint32_t))
                                   ? req_buf_size / 4 + 1
                                   : req_buf_size / 4;
  uint32_t request_buf[req_buf_words];
  struct ec_host_request *request_hdr =
      (struct ec_host_request *)(&request_buf[0]);
  struct ec_params_hello *request = (struct ec_params_hello *)(&request_hdr[1]);
  request->in_data = 0;

  int status = populate_ec_request_header(EC_CMD_HELLO, /*version=*/0, request,
                                          sizeof(*request), request_hdr);
  if (status != 0) {
    return status;
  }

  const size_t resp_buf_size =
      sizeof(struct ec_host_response) + sizeof(struct ec_response_hello);
  const size_t resp_buf_words = (resp_buf_size % sizeof(uint32_t))
                                    ? resp_buf_size / 4 + 1
                                    : resp_buf_size / 4;
  uint32_t response_buf[resp_buf_words];
  struct ec_host_response *response_hdr =
      (struct ec_host_response *)(&response_buf[0]);
  struct ec_response_hello *response =
      (struct ec_response_hello *)(&response_hdr[1]);
  size_t response_size = 0;

  status = libhoth_usb_send_request(dev, request_hdr, req_buf_size);
  if (status != LIBHOTH_OK) {
    fprintf(stderr, "libhoth_usb_send() failed: %d\n", status);
    return status;
  }

  status = libhoth_usb_receive_response(dev, response_hdr, resp_buf_size,
                                        &response_size, /*timeout_ms=*/5000);
  if (status != LIBHOTH_OK) {
    fprintf(stderr, "libhoth_usb_receive() failed: %d\n", status);
    return status;
  }

  status = validate_ec_response_header(response_hdr, response, response_size);
  if (status != 0) {
    fprintf(stderr, "EC response header invalid: %d\n", status);
    return status;
  }

  printf("Got EC_HELLO response: 0x%08x\n", response->out_data);
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "Invalid arguments.\n");
    fprintf(stderr, "Usage:\n\t%s", usage);
    return -1;
  }
  uint8_t bus, address;
  char *endptr;
  bus = strtoul(argv[1], &endptr, 0);
  if (endptr == argv[1] || *endptr != '\0') {
    fprintf(stderr, "Failed to parse bus number.\n");
    fprintf(stderr, "Usage:\n\t%s", usage);
    return -1;
  }
  address = strtoul(argv[2], &endptr, 0);
  if (endptr == argv[2] || *endptr != '\0') {
    fprintf(stderr, "Failed to parse device address.\n");
    fprintf(stderr, "Usage:\n\t%s", usage);
    return -1;
  }

  struct libhoth_usb_device *dev = NULL;
  int status = hoth_usb_probe(&dev, bus, address, /*verbose=*/true);
  if (status != LIBHOTH_OK) {
    fprintf(stderr, "probe() failed: %d\n", status);
    return status;
  }

  status = do_hello(dev);
  if (status != LIBHOTH_OK) {
    fprintf(stderr, "do_hello() failed: %d\n", status);
    return status;
  }

  status = hoth_usb_remove(dev, /*verbose=*/true);
  if (status != LIBHOTH_OK) {
    fprintf(stderr, "remove() failed: %d\n", status);
    return status;
  }
  return 0;
}
