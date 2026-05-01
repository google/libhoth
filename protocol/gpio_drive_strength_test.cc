// Copyright 2026 Google LLC
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

#include "protocol/gpio_drive_strength.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "protocol/test/libhoth_device_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

TEST_F(LibHothTest, set_gpio_drive_strength_success) {
  EXPECT_CALL(mock_, send(_, UsesCommand(HOTH_CMD_SET_GPIO_DRIVE_STRENGTH), _))
      .WillOnce(Return(LIBHOTH_OK));

  uint32_t dummy;
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&dummy, 0), Return(LIBHOTH_OK)));

  EXPECT_EQ(libhoth_set_gpio_drive_strength(&hoth_dev_, 10, 5), LIBHOTH_OK);
}
