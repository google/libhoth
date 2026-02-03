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

#ifndef _LIBHOTH_TRANSPORTS_LIBHOTH_DEVICE_H_
#define _LIBHOTH_TRANSPORTS_LIBHOTH_DEVICE_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LIBHOTH_MAILBOX_SIZE 1024
#define LIBHOTH_REBOOT_DELAY_MS 1000

typedef enum {
  LIBHOTH_OK = 0,
  LIBHOTH_ERR_UNKNOWN_VENDOR = 1,
  LIBHOTH_ERR_INTERFACE_NOT_FOUND = 2,
  LIBHOTH_ERR_MALLOC_FAILED = 3,
  LIBHOTH_ERR_TIMEOUT = 4,
  LIBHOTH_ERR_OUT_UNDERFLOW = 5,
  LIBHOTH_ERR_IN_OVERFLOW = 6,
  LIBHOTH_ERR_UNSUPPORTED_VERSION = 7,
  LIBHOTH_ERR_INVALID_PARAMETER = 8,
  LIBHOTH_ERR_FAIL = 9,
  LIBHOTH_ERR_RESPONSE_BUFFER_OVERFLOW = 10,
  LIBHOTH_ERR_INTERFACE_BUSY = 11,
} libhoth_status;

struct libhoth_device {
  int (*send)(struct libhoth_device* dev, const void* request,
              size_t request_size);
  int (*receive)(struct libhoth_device* dev, void* response,
                 size_t max_response_size, size_t* actual_size, int timeout_ms);
  int (*close)(struct libhoth_device* dev);
  int (*claim)(struct libhoth_device* dev);
  int (*release)(struct libhoth_device* dev);
  int (*reconnect)(struct libhoth_device* dev);

  void* user_ctx;
};

// Request is a buffer containing the EC request header and trailing payload.
// This function is not thread-safe. In multi-threaded contexts, callers must
// ensure libhoth_send_request() and libhoth_receive_response() occur
// atomically (with respect to other calls to those functions).
int libhoth_send_request(struct libhoth_device* dev, const void* request,
                         size_t request_size);

// Response is a buffer where the EC response header and trailing payload will
// be written. Errors if libhoth_send_request() wasn't called previously.
// Returns LIBHOTH_ERR_TIMEOUT if the response is not ready by the
// specified timeout, and the user can call again later. If timeout_ms is zero,
// returns immediately.
// This function is not thread-safe. In multi-threaded contexts, callers must
// ensure libhoth_send_request() and libhoth_receive_response() occur
// atomically (with respect to other calls to those functions).
int libhoth_receive_response(struct libhoth_device* dev, void* response,
                             size_t max_response_size, size_t* actual_size,
                             int timeout_ms);

int libhoth_device_reconnect(struct libhoth_device* dev);

int libhoth_device_close(struct libhoth_device* dev);

// Try to claim `dev`. If `dev` is already claimed, then try to claim later by
// waiting an exponentially backed off amount of time.
int libhoth_claim_device(struct libhoth_device* dev, uint32_t timeout_us);

int libhoth_release_device(struct libhoth_device* dev);

#ifdef __cplusplus
}
#endif

#endif  // _LIBHOTH_TRANSPORTS_LIBHOTH_DEVICE_H_
