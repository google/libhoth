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

#ifndef LIBHOTH_EXAMPLES_HTOOL_CONSOLE_H_
#define LIBHOTH_EXAMPLES_HTOOL_CONSOLE_H_

#include <stdbool.h>
#include <stdint.h>

struct libhoth_device;

struct htool_console_opts {
  uint32_t channel_id;
  bool force_drive_tx;
  bool history;
  bool onlcr;
  uint32_t baud_rate;
  bool snapshot;
  uint32_t claim_timeout_secs;
  uint32_t yield_ms;
};

int htool_console_run(struct libhoth_device* dev,
                      const struct htool_console_opts* opts);

int htool_console_snapshot(struct libhoth_device* dev);

#endif  // LIBHOTH_EXAMPLES_HTOOL_CONSOLE_H_
