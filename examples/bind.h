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

#ifndef LIBHOTH_EXAMPLES_BIND_H_
#define LIBHOTH_EXAMPLES_BIND_H_

#include <stdbool.h>
#include <stdint.h>

#include "libhoth_usb.h"

int hoth_usb_probe(struct libhoth_usb_device **dev, uint8_t bus,
                   uint8_t address, bool verbose);

int hoth_usb_remove(struct libhoth_usb_device *dev, bool verbose);

#endif  // LIBHOTH_EXAMPLES_BIND_H_
