// Copyright 2025 Google LLC
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

#include "transports/libhoth_device.h"

#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include "libhoth_device.h"

int libhoth_send_request(struct libhoth_device* dev, const void* request,
                         size_t request_size) {
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }
  return dev->send(dev, request, request_size);
}

int libhoth_receive_response(struct libhoth_device* dev, void* response,
                             size_t max_response_size, size_t* actual_size,
                             int timeout_ms) {
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }
  return dev->receive(dev, response, max_response_size, actual_size,
                      timeout_ms);
}

int libhoth_device_reconnect(struct libhoth_device* dev) {
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }

  if (dev->reconnect == NULL) {
    return LIBHOTH_ERR_UNSUPPORTED_VERSION;
  }

  return dev->reconnect(dev);
}

int libhoth_device_close(struct libhoth_device* dev) {
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }

  int status = dev->close(dev);
  free(dev);
  return status;
}

int libhoth_claim_device(struct libhoth_device* dev, uint32_t timeout_us) {
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

  // Unreachable
  return LIBHOTH_ERR_FAIL;
}

int libhoth_release_device(struct libhoth_device* dev) {
  return dev->release(dev);
}
