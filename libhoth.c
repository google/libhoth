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

#include "libhoth.h"

#include <stdlib.h>

int libhoth_send_request(struct libhoth_device* dev,
                             const void* request, size_t request_size) {
  int status;
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }
  status = dev->send(dev, request, request_size);
  return status;
}

int libhoth_receive_response(struct libhoth_device* dev, void* response,
                                 size_t max_response_size, size_t* actual_size,
                                 int timeout_ms) {
  int status;
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }
  status = dev->receive(dev, response, max_response_size, actual_size, timeout_ms);
  return status;
}

int libhoth_close(struct libhoth_device* dev) {
  int status;
  if (dev == NULL) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }
  
  status = dev->close(dev);
  free(dev);
  return status;
}