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
#include <cstring>

#include "protocol/test/libhoth_device_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

constexpr int kFetchMauvCmd =
    HOTH_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HAVEN_MAUV;

TEST_F(LibHothTest, fetch_mauv_haven_success) {
  struct haven_mauv expected = {};
  expected.struct_version = HAVEN_MAUV_STRUCT_VERSION;
  expected.mauv_version = 42;
  expected.minimum_acceptable_update_version.major = 7;
  expected.denylist_num_entries = 1;
  expected.denylist[0].minor = 9;

  EXPECT_CALL(mock_, send(_, UsesCommand(kFetchMauvCmd), _))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(&expected, sizeof(expected)), Return(LIBHOTH_OK)));

  struct hoth_response_mauv mauv = {};
  EXPECT_EQ(
      libhoth_fetch_mauv(&hoth_dev_, MAUV_STATE_EFFECTIVE, HAVEN_MAUV, &mauv),
      HOTH_SUCCESS);
  EXPECT_EQ(static_cast<uint32_t>(mauv.haven.struct_version),
            HAVEN_MAUV_STRUCT_VERSION);
  EXPECT_EQ(static_cast<uint32_t>(mauv.haven.mauv_version), 42u);
  EXPECT_EQ(
      static_cast<uint32_t>(mauv.haven.minimum_acceptable_update_version.major),
      7u);
  EXPECT_EQ(static_cast<uint32_t>(mauv.haven.denylist_num_entries), 1u);
  EXPECT_EQ(static_cast<uint64_t>(mauv.haven.denylist[0].minor), 9u);
}

TEST_F(LibHothTest, fetch_mauv_image_success) {
  struct image_mauv header = {};
  header.mauv_struct_version = 1;
  header.payload_security_version = 5;
  header.mauv_update_timestamp = 1700000000;
  header.version_denylist_num_entries = 1;
  const uint64_t denylisted_version = 3;
  uint8_t response[sizeof(header) + sizeof(denylisted_version)];
  std::memcpy(response, &header, sizeof(header));
  std::memcpy(response + sizeof(header), &denylisted_version,
              sizeof(denylisted_version));

  EXPECT_CALL(mock_, send(_, UsesCommand(kFetchMauvCmd), _))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(response, sizeof(response)), Return(LIBHOTH_OK)));

  struct hoth_response_mauv mauv = {};
  EXPECT_EQ(
      libhoth_fetch_mauv(&hoth_dev_, MAUV_STATE_COMPILED, IMAGE_MAUV, &mauv),
      HOTH_SUCCESS);
  EXPECT_EQ(static_cast<uint64_t>(mauv.image.payload_security_version), 5u);
  EXPECT_EQ(static_cast<uint64_t>(mauv.image.mauv_update_timestamp),
            1700000000u);
  EXPECT_EQ(static_cast<uint32_t>(mauv.image.version_denylist_num_entries), 1u);
  EXPECT_EQ(static_cast<uint64_t>(mauv.image.version_denylist[0]), 3u);
}

TEST_F(LibHothTest, fetch_mauv_haven_wrong_size) {
  struct haven_mauv expected = {};
  EXPECT_CALL(mock_, send(_, UsesCommand(kFetchMauvCmd), _))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(&expected, sizeof(expected) - 1), Return(LIBHOTH_OK)));

  struct hoth_response_mauv mauv = {};
  EXPECT_EQ(
      libhoth_fetch_mauv(&hoth_dev_, MAUV_STATE_EFFECTIVE, HAVEN_MAUV, &mauv),
      LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                            LIBHOTH_ERR_FAIL));
}

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
