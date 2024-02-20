// Copyright 2023 Google LLC
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

#ifndef LIBHOTH_EXAMPLES_HTOOL_H_
#define LIBHOTH_EXAMPLES_HTOOL_H_

#include <stddef.h>
#include <stdint.h>

#define HTOOL_ERROR_HOST_COMMAND_START 537200

#ifdef __cplusplus
extern "C" {
#endif

struct libhoth_device;

struct libhoth_device* htool_libhoth_dbus_device(void);
struct libhoth_device* htool_libhoth_mtd_device(void);
struct libhoth_device* htool_libhoth_spi_device(void);
struct libhoth_device* htool_libhoth_usb_device(void);
struct libhoth_device* htool_libhoth_device(void);

int htool_exec_hostcmd(struct libhoth_device* dev, uint16_t command,
                       uint8_t version, const void* req_payload,
                       size_t req_payload_size, void* resp_buf,
                       size_t resp_buf_size, size_t* out_resp_size);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // LIBHOTH_EXAMPLES_HTOOL_H_
