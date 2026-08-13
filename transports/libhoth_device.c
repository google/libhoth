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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "libhoth_device.h"

static libhoth_error libhoth_error_from_legacy(uint16_t context, int status) {
  if (status == 0) {
    return HOTH_SUCCESS;
  }
  if (status < 0) {
    return LIBHOTH_ERR_CONSTRUCT(context, HOTH_HOST_SPACE_POSIX, -status);
  }
  return LIBHOTH_ERR_CONSTRUCT(context, HOTH_HOST_SPACE_LIBHOTH,
                               (uint32_t)status);
}

static int libhoth_error_to_legacy(libhoth_error err) {
  if (err == HOTH_SUCCESS) {
    return 0;
  }
  uint32_t space = LIBHOTH_ERR_GET_SPACE(err);
  uint32_t code = LIBHOTH_ERR_GET_CODE(err);

  if (space == HOTH_HOST_SPACE_LIBHOTH) {
    return (int)code;
  }
  if (space == HOTH_HOST_SPACE_POSIX || space == HOTH_HOST_SPACE_LIBUSB) {
    return -(int)code;
  }
  return LIBHOTH_ERR_FAIL;
}

int libhoth_send_request(struct libhoth_device* dev, const void* request,
                         size_t request_size) {
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }
  if (dev->send != NULL) {
    return dev->send(dev, request, request_size);
  }
  if (dev->send_v2 != NULL) {
    libhoth_error err = dev->send_v2(dev, request, request_size);
    return libhoth_error_to_legacy(err);
  }
  return LIBHOTH_ERR_FAIL;
}

int libhoth_receive_response(struct libhoth_device* dev, void* response,
                             size_t max_response_size, size_t* actual_size,
                             int timeout_ms) {
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }
  if (dev->receive != NULL) {
    return dev->receive(dev, response, max_response_size, actual_size,
                        timeout_ms);
  }
  if (dev->receive_v2 != NULL) {
    libhoth_error err = dev->receive_v2(dev, response, max_response_size,
                                        actual_size, timeout_ms);
    return libhoth_error_to_legacy(err);
  }
  return LIBHOTH_ERR_FAIL;
}

libhoth_error libhoth_send_request_v2(struct libhoth_device* dev,
                                      const void* request,
                                      size_t request_size) {
  if (dev == NULL) {
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_INIT, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_INVALID_PARAMETER);
  }
  if (dev->send_v2 != NULL) {
    return dev->send_v2(dev, request, request_size);
  }
  if (dev->send != NULL) {
    int status = dev->send(dev, request, request_size);
    return libhoth_error_from_legacy(HOTH_CTX_NONE, status);
  }
  return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_INIT, HOTH_HOST_SPACE_LIBHOTH,
                               LIBHOTH_ERR_FAIL);
}

libhoth_error libhoth_receive_response_v2(struct libhoth_device* dev,
                                          void* response,
                                          size_t max_response_size,
                                          size_t* actual_size, int timeout_ms) {
  if (dev == NULL) {
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_INIT, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_INVALID_PARAMETER);
  }
  if (dev->receive_v2 != NULL) {
    return dev->receive_v2(dev, response, max_response_size, actual_size,
                           timeout_ms);
  }
  if (dev->receive != NULL) {
    int status =
        dev->receive(dev, response, max_response_size, actual_size, timeout_ms);
    return libhoth_error_from_legacy(HOTH_CTX_NONE, status);
  }
  return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_INIT, HOTH_HOST_SPACE_LIBHOTH,
                               LIBHOTH_ERR_FAIL);
}

int libhoth_device_reconnect(struct libhoth_device* dev) {
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }
  if (dev->reconnect != NULL) {
    return dev->reconnect(dev);
  }
  if (dev->reconnect_v2 != NULL) {
    libhoth_error err = dev->reconnect_v2(dev);
    return libhoth_error_to_legacy(err);
  }
  return LIBHOTH_ERR_UNSUPPORTED_VERSION;
}

int libhoth_device_close(struct libhoth_device* dev) {
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }
  int status = 0;
  if (dev->close != NULL) {
    status = dev->close(dev);
  } else if (dev->close_v2 != NULL) {
    libhoth_error err = dev->close_v2(dev);
    status = libhoth_error_to_legacy(err);
  } else {
    status = LIBHOTH_ERR_FAIL;
  }
  free(dev);
  return status;
}

libhoth_error libhoth_device_reconnect_v2(struct libhoth_device* dev) {
  if (dev == NULL) {
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_INIT, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_INVALID_PARAMETER);
  }
  if (dev->reconnect_v2 != NULL) {
    return dev->reconnect_v2(dev);
  }
  if (dev->reconnect != NULL) {
    int status = dev->reconnect(dev);
    return libhoth_error_from_legacy(HOTH_CTX_NONE, status);
  }
  return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_INIT, HOTH_HOST_SPACE_LIBHOTH,
                               LIBHOTH_ERR_UNSUPPORTED_VERSION);
}

libhoth_error libhoth_device_close_v2(struct libhoth_device* dev) {
  if (dev == NULL) {
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_INIT, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_INVALID_PARAMETER);
  }
  libhoth_error err = HOTH_SUCCESS;
  if (dev->close_v2 != NULL) {
    err = dev->close_v2(dev);
  } else if (dev->close != NULL) {
    int status = dev->close(dev);
    err = libhoth_error_from_legacy(HOTH_CTX_NONE, status);
  }
  free(dev);
  return err;
}

int libhoth_claim_device(struct libhoth_device* dev, uint32_t timeout_us) {
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }
  libhoth_error err = libhoth_claim_device_v2(dev, timeout_us);
  return libhoth_error_to_legacy(err);
}

int libhoth_release_device(struct libhoth_device* dev) {
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }
  if (dev->release != NULL) {
    return dev->release(dev);
  }
  if (dev->release_v2 != NULL) {
    libhoth_error err = dev->release_v2(dev);
    return libhoth_error_to_legacy(err);
  }
  return LIBHOTH_ERR_FAIL;
}

libhoth_error libhoth_claim_device_v2(struct libhoth_device* dev,
                                      uint32_t timeout_us) {
  if (dev == NULL) {
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_INIT, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_INVALID_PARAMETER);
  }

  enum {
    MAX_SINGLE_SLEEP_US = 1000 * 1000 - 1,
    BACKOFF_FACTOR = 2,
    INITIAL_WAIT_US = 10 * 1000,
  };

  uint32_t wait_us = INITIAL_WAIT_US;
  uint32_t total_waiting_us = 0;

  while (true) {
    libhoth_error err = HOTH_SUCCESS;
    if (dev->claim_v2 != NULL) {
      err = dev->claim_v2(dev);
    } else if (dev->claim != NULL) {
      int status = dev->claim(dev);
      err = libhoth_error_from_legacy(HOTH_CTX_NONE, status);
    } else {
      err = LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_INIT, HOTH_HOST_SPACE_LIBHOTH,
                                  LIBHOTH_ERR_FAIL);
    }

    uint32_t space = LIBHOTH_ERR_GET_SPACE(err);
    uint32_t code = LIBHOTH_ERR_GET_CODE(err);
    if (err == HOTH_SUCCESS || space != HOTH_HOST_SPACE_LIBHOTH ||
        code != LIBHOTH_ERR_INTERFACE_BUSY) {
      return err;
    }

    if (total_waiting_us >= timeout_us) {
      fprintf(stderr, "libhoth: timed out claiming transport after %dus\n",
              timeout_us);
      return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_INIT, HOTH_HOST_SPACE_LIBHOTH,
                                   LIBHOTH_ERR_INTERFACE_BUSY);
    }

    usleep(wait_us);

    if (total_waiting_us <= UINT32_MAX - wait_us) {
      total_waiting_us += wait_us;
    } else {
      total_waiting_us = UINT32_MAX;
    }

    if (wait_us <= MAX_SINGLE_SLEEP_US / BACKOFF_FACTOR) {
      wait_us *= BACKOFF_FACTOR;
    } else {
      wait_us = MAX_SINGLE_SLEEP_US;
    }
  }

  return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_INIT, HOTH_HOST_SPACE_LIBHOTH,
                               LIBHOTH_ERR_FAIL);
}

libhoth_error libhoth_release_device_v2(struct libhoth_device* dev) {
  if (dev == NULL) {
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_INIT, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_INVALID_PARAMETER);
  }
  if (dev->release_v2 != NULL) {
    return dev->release_v2(dev);
  }
  if (dev->release != NULL) {
    int status = dev->release(dev);
    return libhoth_error_from_legacy(HOTH_CTX_NONE, status);
  }
  return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_INIT, HOTH_HOST_SPACE_LIBHOTH,
                               LIBHOTH_ERR_FAIL);
}
