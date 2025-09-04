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

#ifndef LIBHOTH_EXAMPLES_HTOOL_SECURITY_VERSION_H_
#define LIBHOTH_EXAMPLES_HTOOL_SECURITY_VERSION_H_

#ifdef __cplusplus
extern "C" {
#endif

struct libhoth_device;

typedef enum {
  LIBHOTH_SECURITY_UNKNOWN = 0,
  LIBHOTH_SECURITY_NONE = 1,
  LIBHOTH_SECURITY_V2 = 2,
  LIBHOTH_SECURITY_V3 = 3,
} libhoth_security_version;

// Returns the security version of the connected Hoth device.
libhoth_security_version htool_get_security_version(struct libhoth_device* dev);

#ifdef __cplusplus
}
#endif

#endif
