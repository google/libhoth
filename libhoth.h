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

#ifndef _LIBHOTH_LIBHOTH_H_
#define _LIBHOTH_LIBHOTH_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "transports/libhoth_device.h"

// Request is a buffer containing the EC request header and trailing payload.
// This function is not thread-safe. In multi-threaded contexts, callers must
// ensure libhoth_send_request() and libhoth_receive_response() occur
// atomically (with respect to other calls to those functions).
int libhoth_send_request(struct libhoth_device *dev, const void *request,
                         size_t request_size);

// Response is a buffer where the EC response header and trailing payload will
// be written. Errors if libhoth_send_request() wasn't called previously.
// Returns LIBHOTH_ERR_TIMEOUT if the response is not ready by the
// specified timeout, and the user can call again later. If timeout_ms is zero,
// returns immediately.
// This function is not thread-safe. In multi-threaded contexts, callers must
// ensure libhoth_send_request() and libhoth_receive_response() occur
// atomically (with respect to other calls to those functions).
int libhoth_receive_response(struct libhoth_device *dev, void *response,
                             size_t max_response_size, size_t *actual_size,
                             int timeout_ms);

int libhoth_device_close(struct libhoth_device *dev);

#ifdef __cplusplus
}
#endif

#endif  // _LIBHOTH_LIBHOTH_H_
