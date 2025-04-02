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

#include "payload_update.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "test/libhoth_device_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

constexpr int kCmd =
    HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_PAYLOAD_UPDATE;
constexpr int64_t kMagic = 0x5F435344474D495F;
constexpr int64_t kAlign = 1 << 16;
constexpr int64_t kDummy = 0;

TEST_F(LibHothTest, payload_update_bad_image_test) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillRepeatedly(Return(LIBHOTH_OK));

  uint8_t bad_buffer[100] = {0};

  EXPECT_EQ(libhoth_payload_update(&hoth_dev_, bad_buffer, sizeof(bad_buffer)),
            PAYLOAD_UPDATE_BAD_IMG);
}

TEST_F(LibHothTest, payload_update_test) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillRepeatedly(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillRepeatedly(DoAll(CopyResp(&kDummy, 0), Return(LIBHOTH_OK)));

  std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(2 * kAlign);
  std::memcpy(buffer.get() + kAlign, &kMagic, sizeof(kMagic));

  EXPECT_EQ(libhoth_payload_update(&hoth_dev_, buffer.get(), 2 * kAlign),
            PAYLOAD_UPDATE_OK);
}

TEST_F(LibHothTest, payload_update_initiate_fail) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillRepeatedly(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive).WillOnce(Return(-1));

  uint8_t buffer[100] = {0};
  std::memcpy(buffer, &kMagic, sizeof(kMagic));

  EXPECT_EQ(libhoth_payload_update(&hoth_dev_, buffer, sizeof(buffer)),
            PAYLOAD_UPDATE_INITIATE_FAIL);
}

TEST_F(LibHothTest, payload_update_flash_fail) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillRepeatedly(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&kDummy, 0), Return(LIBHOTH_OK)))
      .WillOnce(DoAll(CopyResp(&kDummy, 0), Return(-1)));

  uint8_t buffer[100] = {0};
  std::memcpy(buffer, &kMagic, sizeof(kMagic));

  EXPECT_EQ(libhoth_payload_update(&hoth_dev_, buffer, sizeof(buffer)),
            PAYLOAD_UPDATE_FLASH_FAIL);
}

TEST_F(LibHothTest, payload_update_finalize_fail) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillRepeatedly(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&kDummy, 0), Return(LIBHOTH_OK)))
      .WillOnce(DoAll(CopyResp(&kDummy, 0), Return(LIBHOTH_OK)))
      .WillOnce(DoAll(CopyResp(&kDummy, 0), Return(-1)));

  uint8_t buffer[100] = {0};
  std::memcpy(buffer, &kMagic, sizeof(kMagic));

  EXPECT_EQ(libhoth_payload_update(&hoth_dev_, buffer, sizeof(buffer)),
            PAYLOAD_UPDATE_FINALIZE_FAIL);
}

TEST_F(LibHothTest, payload_update_status) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));

  struct payload_update_status exp_us = {0};
  exp_us.a_valid = 1;
  exp_us.active_half = 1;

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&exp_us, sizeof(exp_us)), Return(LIBHOTH_OK)));

  struct payload_update_status us = {0};
  EXPECT_EQ(libhoth_payload_update_getstatus(&hoth_dev_, &us), LIBHOTH_OK);

  EXPECT_EQ(exp_us.a_valid, us.a_valid);
  EXPECT_EQ(exp_us.active_half, us.active_half);
}
