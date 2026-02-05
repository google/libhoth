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

#ifndef LIBHOTH_EXAMPLES_HTOOL_DFU_CHECK_H_
#define LIBHOTH_EXAMPLES_HTOOL_DFU_CHECK_H_

#include <stddef.h>
#include <stdint.h>

#include "protocol/console.h"
#include "protocol/opentitan_version.h"

#ifdef __cplusplus
extern "C" {
#endif

int libhoth_dfu_check(struct libhoth_device* const dev, const uint8_t* image,
                      size_t image_size,
                      struct opentitan_get_version_resp* resp);
void libhoth_print_boot_log(struct opentitan_image_version* booted_rom_ext,
                            struct opentitan_image_version* booted_app,
                            struct opentitan_image_version* desired_rom_ext,
                            struct opentitan_image_version* desired_app);
void libhoth_print_dfu_error(struct libhoth_device* const dev,
                             struct opentitan_get_version_resp* resp);
void libhoth_print_erot_console(struct libhoth_device* const dev);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_HTOOL_DFU_CHECKH_
