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

#include "protocol/secure_boot.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>

#include "test/libhoth_device_mock.h"

namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

TEST_F(LibHothTest, GetSecureBootEnforcementSuccess) {
  secure_boot_enforcement_state expected_enforcement = {
      .enabled = SECURE_BOOT_ENFORCEMENT_ENABLED};
  EXPECT_CALL(mock_,
              send(_,
                   UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                               HOTH_PRV_CMD_HOTH_GET_SECURE_BOOT_ENFORCEMENT),
                   _))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(&expected_enforcement, sizeof(expected_enforcement)),
                Return(LIBHOTH_OK)));
  enum secure_boot_enforcement_status actual_enforcement =
      SECURE_BOOT_ENFORCEMENT_DISABLED;
  EXPECT_EQ(
      libhoth_secure_boot_get_enforcement(&hoth_dev_, &actual_enforcement),
      HOTH_SUCCESS);
  EXPECT_EQ(actual_enforcement, expected_enforcement.enabled);
}

TEST_F(LibHothTest, EnableSecureBootEnforcementSuccess) {
  EXPECT_CALL(mock_,
              send(_,
                   UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                               HOTH_PRV_CMD_HOTH_SET_SECURE_BOOT_ENFORCEMENT),
                   _))
      .WillOnce(Return(LIBHOTH_OK));
  uint32_t dummy;
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&dummy, 0), Return(LIBHOTH_OK)));
  EXPECT_EQ(libhoth_secure_boot_enable_enforcement(&hoth_dev_), HOTH_SUCCESS);
}

TEST_F(LibHothTest, GetSecureBootEnforcementNullParam) {
  libhoth_error err = libhoth_secure_boot_get_enforcement(&hoth_dev_, nullptr);
  EXPECT_NE(err, HOTH_SUCCESS);
  EXPECT_EQ(LIBHOTH_ERR_GET_CTX(err), HOTH_CTX_CMD_EXEC);
  EXPECT_EQ(LIBHOTH_ERR_GET_SPACE(err), HOTH_HOST_SPACE_LIBHOTH);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_INVALID_PARAMETER);
}

}  // namespace
