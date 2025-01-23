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
#include "ec_util.h"
#include "host_commands.h"
#include "htool.h"
#include "htool_console.h"

#define HOTH_FIFO_MAX_REQUEST_SIZE 1024
#define MAX_CONSOLE_BUFFER_SIZE 0x3000

const char kAnsiReset[] = "\033[0m";
const char kAnsiRed[] = "\033[31m";

static int get_channel_status(struct libhoth_device *dev,
                              const struct htool_console_opts *opts,
                              uint32_t *offset) {
  struct ec_channel_status_request req = {
      .channel_id = opts->channel_id,
  };
  struct ec_channel_status_response resp;

  int status = htool_exec_hostcmd(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_CHANNEL_STATUS,
      /*version=*/0, &req, sizeof(req), &resp, sizeof(resp), NULL);
  if (status) {
    if (status == HTOOL_ERROR_HOST_COMMAND_START + EC_RES_INVALID_COMMAND) {
      fprintf(stderr,
              "This is likely because the running RoT firmware doesn't have "
              "support for channels enabled\n");
    }
    if (status == HTOOL_ERROR_HOST_COMMAND_START + EC_RES_INVALID_PARAM) {
      fprintf(stderr,
              "This is likely because the requested channel doesn't exist.\n");
    }
    return status;
  }

  *offset = resp.write_offset;
  return 0;
}

static int force_write(int fd, const void *buf, size_t count) {
  const char *cbuf = buf;
  while (count > 0) {
    ssize_t bytes_written = write(fd, cbuf, count);
    if (bytes_written < 0) {
      return -1;
    }
    cbuf += bytes_written;
    count -= bytes_written;
  }
  return 0;
}

static int read_console(struct libhoth_device *dev,
                        const struct htool_console_opts *opts,
                        uint32_t *offset) {
  struct ec_channel_read_request req = {
      .channel_id = opts->channel_id,
      .offset = *offset,
      .size =
          HOTH_FIFO_MAX_REQUEST_SIZE - sizeof(struct ec_channel_read_response),
      .timeout_us = 10000,
  };

  struct {
    struct ec_channel_read_response resp;
    uint8_t buffer[HOTH_FIFO_MAX_REQUEST_SIZE -
                   sizeof(struct ec_host_response) -
                   sizeof(struct ec_channel_read_response)];
  } resp;
  _Static_assert(sizeof(resp) + sizeof(struct ec_host_response) ==
                     HOTH_FIFO_MAX_REQUEST_SIZE,
                 "unexpected layout");

  size_t response_size = 0;
  int status = htool_exec_hostcmd(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_CHANNEL_READ,
      /*version=*/0, &req, sizeof(req), &resp, sizeof(resp), &response_size);
  if (status != 0) {
    return status;
  }

  int len = response_size - sizeof(resp.resp);
  if (len > 0) {
    if (force_write(STDOUT_FILENO, resp.buffer, len) != 0) {
      perror("Unable to write console output");
      return -1;
    }
    *offset = resp.resp.offset + len;
  }

  return 0;
}

static bool set_raw_terminal(int fd, struct termios *old_termios,
                             const struct htool_console_opts *opts) {
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

void restore_terminal(int fd, const struct termios *old_termios) {
  tcsetattr(fd, TCSANOW, old_termios);
}

// in-place escape sequence processing.
// looks for ctrl-T + escape character. q - quit, b - send break
#define ESCAPE_CHAR '\24'
struct unescape_flags {
  bool quit;
  bool uart_break;
};

static int unescape(char *buf, int in, struct unescape_flags *flags) {
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

static int write_console(struct libhoth_device *dev,
                         const struct htool_console_opts *opts, bool *quit) {
  struct {
    struct ec_channel_write_request_v1 req;
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

  req.req.channel_id = opts->channel_id;
  req.req.flags =
      opts->force_drive_tx ? EC_CHANNEL_WRITE_REQUEST_FLAG_FORCE_DRIVE_TX : 0;
  req.req.flags |=
      flags.uart_break ? EC_CHANNEL_WRITE_REQUEST_FLAG_SEND_BREAK : 0;

  int status = htool_exec_hostcmd(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_CHANNEL_WRITE,
      /*version=*/1, &req, sizeof(req.req) + numWrite, NULL, 0, NULL);

  if (status != 0) {
    if (status == HTOOL_ERROR_HOST_COMMAND_START + EC_RES_UNAVAILABLE) {
      fprintf(stderr,
              "This is likely because the RoT was unable to confirm that no "
              "other device is driving the UART TX net. If you are certain "
              "that nothing else is driving, use the -f flag to override.\n");
    }
    return status;
  }

  return 0;
}

static int get_uart_config(struct libhoth_device *dev,
                           const struct htool_console_opts *opts,
                           struct ec_channel_uart_config *resp) {
  struct ec_channel_uart_config_get_req req = {
      .channel_id = opts->channel_id,
  };
  return htool_exec_hostcmd(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_CHANNEL_UART_CONFIG_GET,
      /*version=*/0, &req, sizeof(req), resp, sizeof(*resp), NULL);
}
static int set_uart_config(struct libhoth_device *dev,
                           const struct htool_console_opts *opts,
                           struct ec_channel_uart_config *config) {
  struct ec_channel_uart_config_set_req req = {
      .channel_id = opts->channel_id,
      .config = *config,
  };
  return htool_exec_hostcmd(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_CHANNEL_UART_CONFIG_SET,
      /*version=*/0, &req, sizeof(req), NULL, 0, NULL);
}

// Try to claim `dev`. If `dev` is already claimed, then try to claim later by
// waiting an exponentially backed off amount of time.
static int claim_device(struct libhoth_device *dev, uint32_t timeout_us) {
  enum {
    // The maximum time to sleep per attempt.
    // Limited by `usleep()` to <1 second.
    MAX_SINGLE_SLEEP_US = 1000 * 1000 - 1,
    BACKOFF_FACTOR = 2,
    INITIAL_WAIT_US = 10 * 1000,
  };

  uint32_t wait_us = INITIAL_WAIT_US;
  uint32_t total_waiting_us = 0;

  while (true) {
    int status = dev->claim(dev);

    if (status != LIBHOTH_ERR_INTERFACE_BUSY) {
      // We either claimed the device or encountered an unexpected error. Let
      // the caller know.
      return status;
    }

    if (total_waiting_us >= timeout_us) {
      // We've exhausted our waiting budget. We couldn't claim the device
      // within the configured timeout.
      return LIBHOTH_ERR_INTERFACE_BUSY;
    }

    usleep(wait_us);

    if (total_waiting_us <= UINT32_MAX - wait_us) {
      total_waiting_us += wait_us;
    } else {
      // Saturate at integer upper bound to prevent overflow.
      total_waiting_us = UINT32_MAX;
    }

    if (wait_us <= MAX_SINGLE_SLEEP_US / BACKOFF_FACTOR) {
      wait_us *= BACKOFF_FACTOR;
    } else {
      // Saturate at the `usleep()` max sleep bound.
      wait_us = MAX_SINGLE_SLEEP_US;
    }
  }
}

int htool_console_run(struct libhoth_device *dev,
                      const struct htool_console_opts *opts) {
  printf("%sStarting Interactive Console\n", kAnsiRed);

  struct ec_channel_uart_config uart_config = {};
  int status = get_uart_config(dev, opts, &uart_config);
  if (status == LIBHOTH_OK) {
    if (opts->baud_rate != 0) {
      uart_config.baud_rate = opts->baud_rate;
      status = set_uart_config(dev, opts, &uart_config);
      if (status != LIBHOTH_OK) {
        fprintf(stderr,
                "set_uart_config() failed: %d; unable to set baud-rate\n",
                status);
        return status;
      }
      status = get_uart_config(dev, opts, &uart_config);
    }
  }
  if (status == LIBHOTH_OK) {
    printf("Using baud-rate %d\n", uart_config.baud_rate);
  }
  printf("[ Use Ctrl+T-Q to quit ]\n%s", kAnsiReset);

  // Get the channel write pointer. (any new serial data received after this
  // will be stored at this offset)
  uint32_t offset;
  status = get_channel_status(dev, opts, &offset);
  if (status != LIBHOTH_OK) {
    fprintf(stderr, "get_channel_status() failed: %d\n", status);
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
    status = read_console(dev, opts, &offset);
    if (status != LIBHOTH_OK) {
      break;
    }

    status = write_console(dev, opts, &quit);
    if (status != LIBHOTH_OK) {
      break;
    }

    dev->release(dev);

    // Give an opportunity for other clients to use the interface.
    usleep(1000 * opts->yield_ms);

    status = claim_device(dev, 1000 * 1000 * opts->claim_timeout_secs);
    if (status != LIBHOTH_OK) {
      break;
    }
  }

  restore_terminal(STDIN_FILENO, &old_termios);
  printf("\n");
  return status;
}

int htool_console_snapshot_legacy(struct libhoth_device *dev) {
  size_t response_bytes_written;
  int status = htool_exec_hostcmd(dev, EC_CMD_CONSOLE_REQUEST, 0, NULL, 0, NULL,
                                  0, &response_bytes_written);
  if (status != LIBHOTH_OK) {
    fprintf(stderr, "EC_CMD_CONSOLE_REQUEST status: %d\n", status);
    return status;
  }

  struct ec_params_console_read_v1 read_request = {.subcmd = CONSOLE_READ_NEXT};
  const size_t max_bytes_per_read =
      MAILBOX_SIZE - sizeof(struct ec_host_response);
  while (true) {
    char buf[MAILBOX_SIZE];
    status = htool_exec_hostcmd(dev, EC_CMD_CONSOLE_READ, 0, &read_request,
                                sizeof(read_request), buf, max_bytes_per_read,
                                &response_bytes_written);
    if (status != LIBHOTH_OK) {
      fprintf(stderr, "EC_CMD_CONSOLE_READ status: %d\n", status);
      return status;
    }
    fwrite(buf, strnlen(buf, sizeof(buf)), 1, stdout);
    if (response_bytes_written < max_bytes_per_read) break;
  }
  printf("\n");
  return status;
}

int htool_console_snapshot(struct libhoth_device *dev,
                           const struct htool_console_opts *opts) {
  // Legacy host commands for console snapshot.
  if (!opts->channel_id) {
    return htool_console_snapshot_legacy(dev);
  }
  // Modern host commands similar to htool_console_run.
  // Starting from current_offset - 0x80000000 so it's guaranteed to be outside
  // of the Hoth buffer. Repeat read until reaching current offset.
  uint32_t current_offset;
  int status = get_channel_status(dev, opts, &current_offset);
  if (status != LIBHOTH_OK) {
    fprintf(stderr, "get_channel_status() failed: %d\n", status);
    return status;
  }
  uint32_t offset = current_offset - 0x80000000;

  while (true) {
    status = read_console(dev, opts, &offset);
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
