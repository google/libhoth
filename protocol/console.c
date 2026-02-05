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

#include "protocol/console.h"

#include <fcntl.h>
#include <unistd.h>

#include "host_cmd.h"
#include "protocol/util.h"

void libhoth_print_erot_console(struct libhoth_device* const dev) {
  uint32_t current_offset = 0;

  // Init the opts and set it to EROT channel
  struct libhoth_htool_console_opts opts = {0};
  opts.channel_id = EROT_CHANNEL_ID;

  int status = libhoth_get_channel_status(dev, &opts, &current_offset);
  if (status != LIBHOTH_OK) {
    fprintf(stderr, "libhoth_get_channel_status() failed: %d\n", status);
    return;
  }

  // Start reading at the earliest history the eRoT has in its buffer (since the
  // buffer is much smaller than 2GB).
  uint32_t offset = current_offset - 0x80000000;

  while (true) {
    status = libhoth_read_console(dev, STDOUT_FILENO, true, opts.channel_id,
                                  &offset);
    if (status != LIBHOTH_OK) {
      break;
    }
    // Extra check in case UINT32_MAX wrap-around.
    if (!(offset < current_offset || offset - current_offset > 0x80000000)) {
      break;
    }
  }
}

int libhoth_get_channel_status(struct libhoth_device* dev,
                               const struct libhoth_htool_console_opts* opts,
                               uint32_t* offset) {
  struct hoth_channel_status_request req = {
      .channel_id = opts->channel_id,
  };
  struct hoth_channel_status_response resp;

  int status = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_CHANNEL_STATUS,
      /*version=*/0, &req, sizeof(req), &resp, sizeof(resp), NULL);
  if (status) {
    if (status == HTOOL_ERROR_HOST_COMMAND_START + HOTH_RES_INVALID_COMMAND) {
      fprintf(stderr,
              "This is likely because the running RoT firmware doesn't have "
              "support for channels enabled\n");
    }
    if (status == HTOOL_ERROR_HOST_COMMAND_START + HOTH_RES_INVALID_PARAM) {
      fprintf(stderr,
              "This is likely because the requested channel doesn't exist.\n");
    }
    return status;
  }

  *offset = resp.write_offset;
  return 0;
}

int libhoth_read_console(struct libhoth_device* dev, int fd,
                         bool prototext_format_enabled, uint32_t channel_id,
                         uint32_t* offset) {
  struct hoth_channel_read_request req = {
      .channel_id = channel_id,
      .offset = *offset,
      .size = HOTH_FIFO_MAX_REQUEST_SIZE -
              sizeof(struct hoth_channel_read_response),
      .timeout_us = 10000,
  };

  struct {
    struct hoth_channel_read_response resp;
    uint8_t buffer[HOTH_FIFO_MAX_REQUEST_SIZE -
                   sizeof(struct hoth_host_response) -
                   sizeof(struct hoth_channel_read_response)];
  } resp;
  _Static_assert(sizeof(resp) + sizeof(struct hoth_host_response) ==
                     HOTH_FIFO_MAX_REQUEST_SIZE,
                 "unexpected layout");

  size_t response_size = 0;
  int status = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_CHANNEL_READ,
      /*version=*/0, &req, sizeof(req), &resp, sizeof(resp), &response_size);
  if (status != 0) {
    return status;
  }

  int len = response_size - sizeof(resp.resp);
  if (len > 0) {
    // formatted prototext
    if (prototext_format_enabled) {
      for (int i = 0; i < len; i++) {
        if (resp.buffer[i] == '\n') {
          printf("\"");
          printf("%c", resp.buffer[i]);
          printf("\" ");
        } else if (resp.buffer[i] == '\r') {
          printf(" ");
        } else {
          printf("%c", resp.buffer[i]);
        }
      }
    }
    // raw output
    else {
      if (libhoth_force_write(fd, resp.buffer, len) != 0) {
        perror("Unable to write console output");
        return -1;
      }
    }
    *offset = resp.resp.offset + len;
  }

  return 0;
}

static int unescape(char* buf, int in, struct unescape_flags* flags) {
  static bool escaped = false;
  int out = 0;
  for (int i = 0; i < in; i++) {
    if (!escaped) {
      switch (buf[i]) {
        case ESCAPE_CHAR:
          escaped = true;
          break;
        default:
          buf[out++] = buf[i];
          break;
      }
    } else {
      escaped = false;
      switch (buf[i]) {
        case ESCAPE_CHAR:
          buf[out++] = buf[i];
          break;
        case 'Q':
        case 'q':
          flags->quit = true;
          return 0;
        case 'B':
        case 'b':
          flags->uart_break = true;
          return 0;
        default:
          fprintf(stderr, "unsupported escape key.\n");
          break;
      }
    }
  }
  return out;
}

int libhoth_write_console(struct libhoth_device* dev, uint32_t channel_id,
                          bool force_drive_tx, bool* quit) {
  struct {
    struct hoth_channel_write_request_v1 req;
    char buffer[64];
  } req;

  fcntl(STDIN_FILENO, F_SETFL, fcntl(0, F_GETFL) | O_NONBLOCK);
  int numRead = read(0, req.buffer, sizeof(req.buffer));
  // clear non-blocking, as it can affect STDOUT.
  fcntl(STDIN_FILENO, F_SETFL, fcntl(0, F_GETFL) & ~O_NONBLOCK);
  if (numRead <= 0) {
    return 0;
  }

  struct unescape_flags flags = {};
  int numWrite = unescape(req.buffer, numRead, &flags);
  if ((*quit = flags.quit) || (numWrite == 0 && !flags.uart_break)) return 0;

  req.req.channel_id = channel_id;
  req.req.flags =
      force_drive_tx ? HOTH_CHANNEL_WRITE_REQUEST_FLAG_FORCE_DRIVE_TX : 0;
  req.req.flags |=
      flags.uart_break ? HOTH_CHANNEL_WRITE_REQUEST_FLAG_SEND_BREAK : 0;

  int status = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_CHANNEL_WRITE,
      /*version=*/1, &req, sizeof(req.req) + numWrite, NULL, 0, NULL);

  if (status != 0) {
    if (status == HTOOL_ERROR_HOST_COMMAND_START + HOTH_RES_UNAVAILABLE) {
      fprintf(stderr,
              "This is likely because the RoT was unable to confirm that no "
              "other device is driving the UART TX net. If you are certain "
              "that nothing else is driving, use the -f flag to override.\n");
    }
    return status;
  }

  return 0;
}

int libhoth_get_uart_config(struct libhoth_device* dev,
                            const struct libhoth_htool_console_opts* opts,
                            struct hoth_channel_uart_config* resp) {
  struct hoth_channel_uart_config_get_req req = {
      .channel_id = opts->channel_id,
  };
  return libhoth_hostcmd_exec(
      dev,
      HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_CHANNEL_UART_CONFIG_GET,
      /*version=*/0, &req, sizeof(req), resp, sizeof(*resp), NULL);
}
int libhoth_set_uart_config(struct libhoth_device* dev,
                            const struct libhoth_htool_console_opts* opts,
                            struct hoth_channel_uart_config* config) {
  struct hoth_channel_uart_config_set_req req = {
      .channel_id = opts->channel_id,
      .config = *config,
  };
  return libhoth_hostcmd_exec(
      dev,
      HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_CHANNEL_UART_CONFIG_SET,
      /*version=*/0, &req, sizeof(req), NULL, 0, NULL);
}
