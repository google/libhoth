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

#include "chipinfo.h"

#include "host_cmd.h"

int libhoth_chipinfo(struct libhoth_device* dev,
                     struct ec_response_chip_info* chipinfo) {
  return libhoth_hostcmd_exec(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_CHIP_INFO,
      /*version=*/0, NULL, 0, chipinfo, sizeof(*chipinfo), NULL);
}
