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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "test/libhoth_device_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

TEST_F(LibHothTest, chipinfo_test) {
  struct ec_response_chip_info chipinfo_exp = {};

  chipinfo_exp.hardware_identity = 0xABCD1234;
  chipinfo_exp.hardware_category = 1234;
  chipinfo_exp.info_variant = 2;

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(EC_CMD_BOARD_SPECIFIC_BASE +
                                      EC_PRV_CMD_HOTH_CHIP_INFO),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&chipinfo_exp, sizeof(chipinfo_exp)),
                      Return(LIBHOTH_OK)));

  struct ec_response_chip_info chipinfo;
  EXPECT_EQ(libhoth_chipinfo(&hoth_dev_, &chipinfo), LIBHOTH_OK);

  EXPECT_EQ(chipinfo_exp.hardware_identity, chipinfo.hardware_identity);
  EXPECT_EQ(chipinfo_exp.hardware_category, chipinfo.hardware_category);
  EXPECT_EQ(chipinfo_exp.info_variant, chipinfo.info_variant);
}
