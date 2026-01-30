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

#include "command_version.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>

#include "test/libhoth_device_mock.h"
#include "transports/libhoth_device.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

TEST_F(LibHothTest, command_version_test) {
  uint32_t version_mask_exp = 0x3;
  EXPECT_CALL(mock_, send(_, UsesCommand(HOTH_CMD_GET_CMD_VERSIONS), _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&version_mask_exp, sizeof(version_mask_exp)),
                      Return(LIBHOTH_OK)));

  uint32_t version_mask;
  EXPECT_EQ(libhoth_get_command_versions(&hoth_dev_, 0x3, &version_mask),
            LIBHOTH_OK);
  EXPECT_EQ(version_mask, version_mask_exp);
}
