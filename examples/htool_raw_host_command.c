// Copyright 2024 Google LLC
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "host_commands.h"
#include "htool.h"
#include "htool_cmd.h"
#include "protocol/host_cmd.h"
#include "transports/libhoth_device.h"

// Return -1 on IO error.
// Otherwise, return number of bytes of read.
static int fd_read(int fd, void* buf, size_t count) {
  ssize_t rc = read(fd, buf, count);
  if (rc == -1) {
    perror("read() failed");
  }
  return rc;
}

// Return -1 on IO error.
// Return 1 on EOF.
// Return 0 on success, i.e., reading `count` bytes into `buf`.
static int fd_read_exact(int fd, void* buf, size_t count) {
  uint8_t* buf_u8 = (uint8_t*)buf;
  while (count > 0) {
    ssize_t bytes_read = fd_read(fd, buf_u8, count);
    if (bytes_read == -1) {
      // IO error
      return -1;
    }
    if (bytes_read == 0) {
      // EOF
      return 1;
    }
    count -= bytes_read;
    buf_u8 += bytes_read;
  }
  return 0;
}

// Return -1 on IO error.
// Otherwise, return number of written bytes.
static int fd_write(int fd, const void* buf, size_t count) {
  ssize_t rc = write(fd, buf, count);
  if (rc == -1) {
    perror("write() failed");
  }
  return rc;
}

static int fd_write_exact(int fd, const void* buf, size_t count) {
  while (count > 0) {
    ssize_t bytes_written = fd_write(fd, buf, count);
    if (bytes_written <= 0) {
      return -1;
    }
    buf = (const uint8_t*)(buf) + bytes_written;
    count -= bytes_written;
  }
  return 0;
}

int command_raw_host_command(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  while (true) {
    struct ec_host_request req;
    int rv = fd_read_exact(STDIN_FILENO, &req, sizeof(req));
    if (rv == -1) {
      // IO error.
      return rv;
    } else if (rv == 1) {
      // EOF. We can bail successfully because there are no more request
      // headers on stdin.
      return 0;
    }

    uint8_t req_payload[LIBHOTH_MAILBOX_SIZE - sizeof(struct ec_host_request)] =
        {0};

    if (req.data_len > sizeof(req_payload)) {
      fprintf(stderr, "request payload size too large: %d > %ld\n",
              req.data_len, sizeof(req_payload));
      return -1;
    }

    rv = fd_read_exact(STDIN_FILENO, req_payload, req.data_len);
    if (rv) {
      // Either IO error or EOF.
      // We treat EOF as an error in this case because the request is
      // incomplete: we read the header but failed to read its payload.
      return rv;
    }

    uint8_t checksum = libhoth_calculate_checksum(&req, sizeof(req),
                                                     req_payload, req.data_len);
    if (checksum != 0) {
      fprintf(stderr, "bad request checksum; expected 0, got %d\n", checksum);
      return -1;
    }

    struct ec_host_response resp = {
        .struct_version = 3,
    };

    enum { RESP_BUF_LEN = 2048 };
    uint8_t resp_payload[RESP_BUF_LEN] = {0};

    size_t actual_resp_size = 0;
    rv = libhoth_hostcmd_exec(dev, req.command, req.command_version, req_payload,
                      req.data_len, resp_payload, RESP_BUF_LEN,
                      &actual_resp_size);
    if (rv && rv < HTOOL_ERROR_HOST_COMMAND_START) {
      return rv;
    }
    if (rv > HTOOL_ERROR_HOST_COMMAND_START) {
      resp.result = rv - HTOOL_ERROR_HOST_COMMAND_START;
    }

    resp.data_len = actual_resp_size;
    resp.checksum = libhoth_calculate_checksum(
        &resp, sizeof(resp), resp_payload, actual_resp_size);

    rv = fd_write_exact(STDOUT_FILENO, &resp, sizeof(resp));
    if (rv) {
      fprintf(stderr, "failed to write response header to stdout.\n");
      return rv;
    }

    rv = fd_write_exact(STDOUT_FILENO, resp_payload, actual_resp_size);
    if (rv) {
      fprintf(stderr, "failed to write response payload to stdout.\n");
      return rv;
    }
  }

  return 0;
}
