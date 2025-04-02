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

#include "statistics.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "test/libhoth_device_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::StrEq;

TEST_F(LibHothTest, statistics_test) {
  struct hoth_response_statistics exp_stat = {};

  exp_stat.valid_words = 0;
  exp_stat.time_since_hoth_boot_us = 100;
  exp_stat.scratch_value = 0x1;

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_GET_STATISTICS),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(&exp_stat, sizeof(exp_stat)), Return(LIBHOTH_OK)));

  struct hoth_response_statistics stat = {};
  EXPECT_EQ(libhoth_get_statistics(&hoth_dev_, &stat), LIBHOTH_OK);

  EXPECT_EQ(exp_stat.valid_words, stat.valid_words);
  EXPECT_EQ(exp_stat.time_since_hoth_boot_us, stat.time_since_hoth_boot_us);
  EXPECT_EQ(exp_stat.scratch_value, stat.scratch_value);
}
