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

#include "protocol/rot_firmware_version.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "test/libhoth_device_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::StrEq;

TEST_F(LibHothTest, firmware_version_test) {
  struct hoth_response_get_version exp_ver = {};

  strcpy(exp_ver.version_string_ro, "0.0.343/36e0ecd5 ok");
  strcpy(exp_ver.version_string_rw, "0.6.2024102310/platform ok");
  exp_ver.current_image = 0;

  EXPECT_CALL(mock_, send(_, UsesCommand(HOTH_CMD_GET_VERSION), _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&exp_ver, sizeof(exp_ver)), Return(LIBHOTH_OK)));

  struct hoth_response_get_version ver;
  EXPECT_EQ(libhoth_get_rot_fw_version(&hoth_dev_, &ver), LIBHOTH_OK);

  ASSERT_THAT(exp_ver.version_string_ro, StrEq(ver.version_string_ro));
  ASSERT_THAT(exp_ver.version_string_rw, StrEq(ver.version_string_rw));
  EXPECT_EQ(exp_ver.current_image, ver.current_image);
}
