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

#include "protocol/mauv.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>

#include "protocol/test/libhoth_device_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

TEST_F(LibHothTest, update_mauv_success) {
  struct haven_mauv record = {};
  record.struct_version = HAVEN_MAUV_STRUCT_VERSION;
  record.mauv_version = 42;
  record.minimum_acceptable_update_version.epoch = 1;
  record.minimum_acceptable_update_version.major = 2;
  record.minimum_acceptable_update_version.minor = 3;
  record.denylist_num_entries = 1;
  record.denylist[0].epoch = 4;
  record.denylist[0].major = 5;
  record.denylist[0].minor = 6;

  EXPECT_CALL(mock_, send(_, UsesCommand(0x3E57), _))
      .WillOnce(Return(LIBHOTH_OK));
  uint32_t dummy;
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&dummy, 0), Return(LIBHOTH_OK)));

  EXPECT_EQ(libhoth_update_mauv(&hoth_dev_, &record, sizeof(record)),
            HOTH_SUCCESS);
}

TEST_F(LibHothTest, update_mauv_too_large) {
  uint8_t record[MAUV_MAX_RECORD_SIZE + 1] = {0};
  EXPECT_EQ(libhoth_update_mauv(&hoth_dev_, record, sizeof(record)),
            LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                  LIBHOTH_ERR_INVALID_PARAMETER));
}
