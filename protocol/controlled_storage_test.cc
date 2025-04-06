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

#include "controlled_storage.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>

#include "test/libhoth_device_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::ElementsAreArray;

TEST_F(LibHothTest, controlled_storage_read_test) {
  struct hoth_payload_controlled_storage ex_resp = {};
  const size_t ex_payload_len = 3;

  ex_resp.data[0] = 0xAB;
  ex_resp.data[1] = 0xCD;
  ex_resp.data[2] = 0xEF;

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_CONTROLLED_STORAGE),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&ex_resp, ex_payload_len), Return(LIBHOTH_OK)));

  struct hoth_payload_controlled_storage resp = {};
  size_t payload_len = 0;

  EXPECT_EQ(libhoth_controlled_storage_read(&hoth_dev_, 0, &resp, &payload_len),
            LIBHOTH_OK);

  EXPECT_EQ(payload_len, ex_payload_len);
  EXPECT_THAT(std::vector<uint8_t>(ex_resp.data, ex_resp.data + ex_payload_len),
      ElementsAreArray(resp.data, payload_len));
}

TEST_F(LibHothTest, controlled_storage_write_test) {
  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_CONTROLLED_STORAGE),
                          _))
      .WillOnce(Return(LIBHOTH_OK))
      .WillOnce(Return(-1));

  uint32_t dummy = 0;
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&dummy, 0), Return(LIBHOTH_OK)));

  uint8_t payload[] = {0xAB, 0xCD, 0xEF};

  EXPECT_EQ(
      libhoth_controlled_storage_write(&hoth_dev_, 0, payload, sizeof(payload)),
      LIBHOTH_OK);
  EXPECT_EQ(
      libhoth_controlled_storage_write(&hoth_dev_, 0, payload, sizeof(payload)),
      -1);
}

TEST_F(LibHothTest, controlled_storage_delete_test) {
  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_CONTROLLED_STORAGE),
                          _))
      .WillOnce(Return(LIBHOTH_OK))
      .WillOnce(Return(-1));

  uint32_t dummy = 0;
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&dummy, 0), Return(LIBHOTH_OK)));

  EXPECT_EQ(libhoth_controlled_storage_delete(&hoth_dev_, 0), LIBHOTH_OK);
  EXPECT_EQ(libhoth_controlled_storage_delete(&hoth_dev_, 0), -1);
}
