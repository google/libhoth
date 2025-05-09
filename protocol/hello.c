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

#include "hello.h"

#include <stdint.h>

int libhoth_hello(struct libhoth_device* const dev, const uint32_t input,
                  uint32_t* const output) {
  const struct hoth_request_hello request = {
      .input = input,
  };
  struct hoth_response_hello response;
  const int rv =
      libhoth_hostcmd_exec(dev, HOTH_CMD_HELLO, /*version=*/0, &request,
                           sizeof(request), &response, sizeof(response), NULL);
  *output = response.output;
  return rv;
}
