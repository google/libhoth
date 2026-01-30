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

#ifndef LIBHOTH_PROTOCOL_CONSOLE_H_
#define LIBHOTH_PROTOCOL_CONSOLE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <termios.h>

#include "transports/libhoth_device.h"

#define EROT_CHANNEL_ID 0x45524F54  // 'EROT'
#define HOTH_FIFO_MAX_REQUEST_SIZE 1024
#define HOTH_PRV_CMD_HOTH_CHANNEL_STATUS 0x0037
#define HOTH_PRV_CMD_HOTH_CHANNEL_READ 0x0036
#define MAX_CONSOLE_BUFFER_SIZE 0x3000
#define HOTH_PRV_CMD_HOTH_CHANNEL_WRITE 0x0038

// Takes struct hoth_channel_uart_config_get_req as
// input and returns hoth_channel_uart_config as output.
#define HOTH_PRV_CMD_HOTH_CHANNEL_UART_CONFIG_GET 0x0039

// Takes struct hoth_channel_uart_config_set_req as input.
#define HOTH_PRV_CMD_HOTH_CHANNEL_UART_CONFIG_SET 0x003a
#define HOTH_CHANNEL_WRITE_REQUEST_FLAG_FORCE_DRIVE_TX (1 << 0)
#define HOTH_CHANNEL_WRITE_REQUEST_FLAG_SEND_BREAK (1 << 1)

// in-place escape sequence processing.
// looks for ctrl-T + escape character. q - quit, b - send break
#define ESCAPE_CHAR '\24'

struct unescape_flags {
  bool quit;
  bool uart_break;
};

struct hoth_channel_read_request {
  uint32_t channel_id;

  // The 32-bit offset from the start of the stream to retrieve data from. If no
  // data is available at this offset, it will be incremented to the first
  // available data. The caller can detect discontinuities by observing the
  // returned offset.
  //
  // This value will wrap around once the channel has delivered 4GiB of data.
  uint32_t offset;
  // the amount of data to return
  uint32_t size;
  // Maximum time to wait for new data to show up. If timeout is hit, command
  // will succeed but will return 0 bytes.
  uint32_t timeout_us;
} __attribute__((packed, aligned(4)));

struct hoth_channel_read_response {
  // The actual offset where the returned data was found.
  // This won't match the offset in the read request if the requested data
  // wasn't available. Instead, it will be the offset of the first available
  // data.
  uint32_t offset;

  // followed by the requested bytes.
} __attribute__((packed, aligned(4)));

struct hoth_channel_status_request {
  uint32_t channel_id;
} __attribute__((packed, aligned(4)));

struct hoth_channel_status_response {
  // The offset where the next data received in the channel will be written
  uint32_t write_offset;
} __attribute__((packed, aligned(4)));

struct hoth_channel_write_request_v1 {
  uint32_t channel_id;

  // One of HOTH_CHANNEL_WRITE_REQUEST_FLAG_*
  uint32_t flags;

  // followed by the bytes to write
} __attribute__((packed, aligned(4)));

struct hoth_channel_write_request_v0 {
  uint32_t channel_id;

  // followed by the bytes to write
} __attribute__((packed, aligned(4)));

struct hoth_channel_uart_config_get_req {
  uint32_t channel_id;
} __attribute__((packed, aligned(4)));

struct hoth_channel_uart_config {
  uint32_t baud_rate;
  // must be 0
  uint32_t reserved;
} __attribute__((packed, aligned(4)));

struct hoth_channel_uart_config_set_req {
  uint32_t channel_id;
  struct hoth_channel_uart_config config;
} __attribute__((packed, aligned(4)));

struct libhoth_htool_console_opts {
  uint32_t channel_id;
  bool force_drive_tx;
  bool history;
  bool onlcr;
  uint32_t baud_rate;
  bool snapshot;
  uint32_t claim_timeout_secs;
  uint32_t yield_ms;
};

void libhoth_print_erot_console(struct libhoth_device* const dev);

int libhoth_get_channel_status(struct libhoth_device* dev,
                               const struct libhoth_htool_console_opts* opts,
                               uint32_t* offset);

int libhoth_read_console(struct libhoth_device* dev, int fd,
                         bool prototext_format_enabled, uint32_t channel_id,
                         uint32_t* offset);

int libhoth_write_console(struct libhoth_device* dev, uint32_t channel_id,
                          bool force_drive_tx, bool* quit);

int libhoth_get_uart_config(struct libhoth_device* dev,
                            const struct libhoth_htool_console_opts* opts,
                            struct hoth_channel_uart_config* resp);

int libhoth_set_uart_config(struct libhoth_device* dev,
                            const struct libhoth_htool_console_opts* opts,
                            struct hoth_channel_uart_config* config);

#ifdef __cplusplus
}
#endif

#endif
