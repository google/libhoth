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

#include "htool_console.h"

#include <ctype.h>
#include <fcntl.h>
#include <libusb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "../transports/libhoth_device.h"
#include "host_commands.h"
#include "htool.h"
#include "htool_console.h"

const char kAnsiReset[] = "\033[0m";
const char kAnsiRed[] = "\033[31m";

static bool set_raw_terminal(int fd, struct termios* old_termios,
                             const struct libhoth_htool_console_opts* opts) {
  struct termios new_termios;
  if (tcgetattr(fd, old_termios) < 0) {
    return false;
  }
  new_termios = *old_termios;
  new_termios.c_iflag &=
      ~(IGNBRK | BRKINT | PARMRK | ISTRIP | ICRNL | INLCR | IGNCR | IXON);
  new_termios.c_oflag &= ~OPOST;
  if (opts->onlcr) {
    new_termios.c_oflag |= ONLCR | OPOST;
  }
  new_termios.c_lflag &= ~(ECHO | ECHONL | ICANON | IEXTEN | ISIG);
  new_termios.c_cflag &= ~(CSIZE | PARENB);
  new_termios.c_cflag |= CS8;
  new_termios.c_cc[VMIN] = 1;
  new_termios.c_cc[VTIME] = 0;
  if (tcsetattr(fd, TCSANOW, &new_termios) < 0) {
    return false;
  }
  return true;
}

void restore_terminal(int fd, const struct termios* old_termios) {
  tcsetattr(fd, TCSANOW, old_termios);
}

int htool_console_run(struct libhoth_device* dev,
                      const struct libhoth_htool_console_opts* opts) {
  printf("%sStarting Interactive Console\n", kAnsiRed);

  struct hoth_channel_uart_config uart_config = {};
  int status = libhoth_get_uart_config(dev, opts, &uart_config);
  if (status == LIBHOTH_OK) {
    if (opts->baud_rate != 0) {
      uart_config.baud_rate = opts->baud_rate;
      status = libhoth_set_uart_config(dev, opts, &uart_config);
      if (status != LIBHOTH_OK) {
        fprintf(
            stderr,
            "libhoth_set_uart_config() failed: %d; unable to set baud-rate\n",
            status);
        return status;
      }
      status = libhoth_get_uart_config(dev, opts, &uart_config);
    }
  }
  if (status == LIBHOTH_OK) {
    printf("Using baud-rate %d\n", uart_config.baud_rate);
  }
  printf("[ Use Ctrl+T-Q to quit ]%s\n", kAnsiReset);

  // Get the channel write pointer. (any new serial data received after this
  // will be stored at this offset)
  uint32_t offset;
  status = libhoth_get_channel_status(dev, opts, &offset);
  if (status != LIBHOTH_OK) {
    fprintf(stderr, "libhoth_get_channel_status() failed: %d\n", status);
    return status;
  }

  // Change terminal settings to raw, and make read from stdio non-blocking.
  struct termios old_termios;
  set_raw_terminal(STDIN_FILENO, &old_termios, opts);

  // Start reading at the earliest history the eRoT has in its buffer (since the
  // buffer is much smaller than 2GB).
  if (opts->history) offset -= 0x80000000;
  bool quit = false;

  while (!quit) {
    status = libhoth_read_console(dev, STDOUT_FILENO, false, opts->channel_id,
                                  &offset);
    if (status != LIBHOTH_OK) {
      break;
    }

    status = libhoth_write_console(dev, opts->channel_id, opts->force_drive_tx,
                                   &quit);
    if (status != LIBHOTH_OK) {
      break;
    }

    libhoth_release_device(dev);

    // Give an opportunity for other clients to use the interface.
    usleep(1000 * opts->yield_ms);

    status = libhoth_claim_device(dev, 1000 * 1000 * opts->claim_timeout_secs);
    if (status != LIBHOTH_OK) {
      break;
    }
  }

  restore_terminal(STDIN_FILENO, &old_termios);
  printf("\n");
  return status;
}

int htool_console_snapshot_legacy(struct libhoth_device* dev) {
  size_t response_bytes_written;
  int status = libhoth_hostcmd_exec(dev, HOTH_CMD_CONSOLE_REQUEST, 0, NULL, 0,
                                    NULL, 0, &response_bytes_written);
  if (status != LIBHOTH_OK) {
    fprintf(stderr, "HOTH_CMD_CONSOLE_REQUEST status: %d\n", status);
    return status;
  }

  struct hoth_params_console_read_v1 read_request = {.subcmd =
                                                         CONSOLE_READ_NEXT};
  const size_t max_bytes_per_read =
      MAILBOX_SIZE - sizeof(struct hoth_host_response);
  while (true) {
    char buf[MAILBOX_SIZE];
    status = libhoth_hostcmd_exec(dev, HOTH_CMD_CONSOLE_READ, 0, &read_request,
                                  sizeof(read_request), buf, max_bytes_per_read,
                                  &response_bytes_written);
    if (status != LIBHOTH_OK) {
      fprintf(stderr, "HOTH_CMD_CONSOLE_READ status: %d\n", status);
      return status;
    }
    fwrite(buf, strnlen(buf, sizeof(buf)), 1, stdout);
    if (response_bytes_written < max_bytes_per_read) break;
  }
  printf("\n");
  return status;
}

int htool_console_snapshot(struct libhoth_device* dev,
                           const struct libhoth_htool_console_opts* opts) {
  // Legacy host commands for console snapshot.
  if (!opts->channel_id) {
    return htool_console_snapshot_legacy(dev);
  }
  // Modern host commands similar to htool_console_run.
  // Starting from current_offset - 0x80000000 so it's guaranteed to be outside
  // of the Hoth buffer. Repeat read until reaching current offset.
  uint32_t current_offset;
  int status = libhoth_get_channel_status(dev, opts, &current_offset);
  if (status != LIBHOTH_OK) {
    fprintf(stderr, "libhoth_get_channel_status) failed: %d\n", status);
    return status;
  }
  uint32_t offset = current_offset - 0x80000000;

  while (true) {
    status = libhoth_read_console(dev, STDOUT_FILENO, false, opts->channel_id,
                                  &offset);
    if (status != LIBHOTH_OK) {
      break;
    }
    // Extra check in case UINT32_MAX wrap-around.
    if (!(offset < current_offset || offset - current_offset > 0x80000000)) {
      break;
    }
  }
  return status;
}
