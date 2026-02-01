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

#include "rot_firmware_version.h"

int libhoth_get_rot_fw_version(struct libhoth_device* dev,
                               struct hoth_response_get_version* ver) {
  return libhoth_hostcmd_exec(dev, HOTH_CMD_GET_VERSION, /*version=*/0,
                              /*req_payload=*/NULL, /*req_payload_size=*/0, ver,
                              sizeof(*ver), /*out_resp_size=*/NULL);
}
