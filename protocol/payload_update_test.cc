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

#include <cstdint>

#include "command_version.h"
#include "payload_info.h"
#include "test/libhoth_device_mock.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::DoAll;
using ::testing::InSequence;
using ::testing::Return;
using ::testing::Sequence;

constexpr int kCmd =
    HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_PAYLOAD_UPDATE;
constexpr int64_t kMagic = 0x5F435344474D495F;
constexpr int64_t kAlign = 1 << 16;
constexpr int64_t kDummy = 0;

MATCHER_P2(IsEraseRequest, offset, len, "") {
  const uint8_t* data = static_cast<const uint8_t*>(arg);
  const struct payload_update_packet* p =
      reinterpret_cast<const struct payload_update_packet*>(
          data + sizeof(struct hoth_host_request));
  return p->type == PAYLOAD_UPDATE_ERASE &&
         p->offset == static_cast<uint32_t>(offset) &&
         p->len == static_cast<uint32_t>(len);
}

TEST_F(LibHothTest, payload_update_bad_image_test) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillRepeatedly(Return(LIBHOTH_OK));

  uint8_t bad_buffer[100] = {0};

  EXPECT_EQ(libhoth_payload_update(&hoth_dev_, bad_buffer, sizeof(bad_buffer), false),
            PAYLOAD_UPDATE_BAD_IMG);
}

TEST_F(LibHothTest, payload_update_test) {
  {
    Sequence s_send, s_receive;

    EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
        .InSequence(s_send)
        .WillRepeatedly(Return(LIBHOTH_OK));
    EXPECT_CALL(mock_, receive)
        .InSequence(s_receive)
        .WillRepeatedly(DoAll(CopyResp(&kDummy, 0), Return(LIBHOTH_OK)));

    static constexpr uint32_t kVersionMask = 0x3;
    EXPECT_CALL(mock_, send(_, UsesCommand(HOTH_CMD_GET_CMD_VERSIONS), _))
        .InSequence(s_send, s_receive)
        .WillOnce(Return(LIBHOTH_OK));
    EXPECT_CALL(mock_, receive)
        .InSequence(s_send, s_receive)
        .WillOnce(DoAll(CopyResp(&kVersionMask, sizeof(kVersionMask)),
                        Return(LIBHOTH_OK)));

    static constexpr uint8_t kPldNeedsReinitialization = 1;
    EXPECT_CALL(mock_, send(_, UsesCommandWithVersion(kCmd, 1), _))
        .InSequence(s_send, s_receive)
        .WillOnce(Return(LIBHOTH_OK));
    EXPECT_CALL(mock_, receive)
        .InSequence(s_send, s_receive)
        .WillOnce(DoAll(CopyResp(&kPldNeedsReinitialization,
                                 sizeof(kPldNeedsReinitialization)),
                        Return(LIBHOTH_OK)));
  }

  std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(2 * kAlign);
  std::memcpy(buffer.get() + kAlign, &kMagic, sizeof(kMagic));

  EXPECT_EQ(libhoth_payload_update(&hoth_dev_, buffer.get(), 2 * kAlign, false),
            PAYLOAD_UPDATE_OK);
}

TEST_F(LibHothTest, payload_update_command_version_unsupported) {
  {
    InSequence s;

    EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
        .WillOnce(Return(LIBHOTH_OK));
    EXPECT_CALL(mock_, send(_, UsesCommand(HOTH_CMD_GET_CMD_VERSIONS), _))
        .WillOnce(Return(LIBHOTH_OK));
    EXPECT_CALL(mock_, send(_, UsesCommandWithVersion(kCmd, 0), _))
        .WillOnce(Return(LIBHOTH_OK));
  }

  static constexpr uint32_t kVersionMask = 0x1;
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&kDummy, 0), Return(LIBHOTH_OK)))
      .WillOnce(DoAll(CopyResp(&kVersionMask, sizeof(kVersionMask)),
                      Return(LIBHOTH_OK)))
      .WillOnce(DoAll(CopyResp(&kDummy, 0), Return(LIBHOTH_OK)));

  uint8_t buffer[100] = {0};
  std::memcpy(buffer, &kMagic, sizeof(kMagic));

  EXPECT_EQ(libhoth_payload_update(&hoth_dev_, buffer, sizeof(buffer), true),
            PAYLOAD_UPDATE_OK);
}

TEST_F(LibHothTest, payload_update_erase_fail) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillRepeatedly(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive).WillOnce(Return(-1));

  uint8_t buffer[4096] = {0};
  std::memcpy(buffer, &kMagic, sizeof(kMagic));

  EXPECT_EQ(libhoth_payload_update(&hoth_dev_, buffer, sizeof(buffer), false),
            PAYLOAD_UPDATE_ERASE_FAIL);
}

TEST_F(LibHothTest, payload_update_flash_fail) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillRepeatedly(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(Return(-1));

  uint8_t buffer[100] = {0};
  std::memcpy(buffer, &kMagic, sizeof(kMagic));

  EXPECT_EQ(libhoth_payload_update(&hoth_dev_, buffer, sizeof(buffer), true),
            PAYLOAD_UPDATE_FLASH_FAIL);
}

TEST_F(LibHothTest, payload_update_command_version_fail) {
  {
    InSequence s;

    EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
        .WillOnce(Return(LIBHOTH_OK));
    EXPECT_CALL(mock_, send(_, UsesCommand(HOTH_CMD_GET_CMD_VERSIONS), _))
        .WillOnce(Return(LIBHOTH_OK));
  }

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&kDummy, 0), Return(LIBHOTH_OK)))
      .WillOnce(DoAll(CopyResp(&kDummy, 0), Return(-1)));

  uint8_t buffer[100] = {0};
  std::memcpy(buffer, &kMagic, sizeof(kMagic));

  EXPECT_EQ(libhoth_payload_update(&hoth_dev_, buffer, sizeof(buffer), true),
            PAYLOAD_UPDATE_FINALIZE_FAIL);
}

TEST_F(LibHothTest, payload_update_finalize_fail) {
  {
    InSequence s;

    EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
        .WillOnce(Return(LIBHOTH_OK));
    EXPECT_CALL(mock_, send(_, UsesCommand(HOTH_CMD_GET_CMD_VERSIONS), _))
        .WillOnce(Return(LIBHOTH_OK));
    EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
        .WillOnce(Return(LIBHOTH_OK));
  }

  static constexpr uint32_t kVersionMask = 0x1;
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&kDummy, 0), Return(LIBHOTH_OK)))
      .WillOnce(DoAll(CopyResp(&kVersionMask, sizeof(kVersionMask)),
                      Return(LIBHOTH_OK)))
      .WillOnce(DoAll(CopyResp(&kDummy, 0), Return(-1)));

  uint8_t buffer[100] = {0};
  std::memcpy(buffer, &kMagic, sizeof(kMagic));

  EXPECT_EQ(libhoth_payload_update(&hoth_dev_, buffer, sizeof(buffer), true),
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

TEST_F(LibHothTest, payload_update_erase_test) {
  constexpr size_t kBlockErase = 64 * 1024;
  constexpr size_t kSectorErase = 4 * 1024;
  constexpr size_t kSize = kBlockErase + kSectorErase;
  uint8_t buffer[kSize];
  std::memset(buffer, 0xFF, kSize);

  struct image_descriptor desc = {};
  desc.descriptor_magic = TITAN_IMAGE_DESCRIPTOR_MAGIC;
  desc.descriptor_area_size = sizeof(desc);
  std::memcpy(buffer, &desc, sizeof(desc));

  {
    InSequence s;

    // Block Erase
    EXPECT_CALL(mock_, send(_, IsEraseRequest(0, kBlockErase), _))
        .WillOnce(Return(LIBHOTH_OK));
    EXPECT_CALL(mock_, receive)
        .WillOnce(DoAll(CopyResp(&kDummy, 0), Return(LIBHOTH_OK)));

    // Sector Erase
    EXPECT_CALL(mock_, send(_, IsEraseRequest(kBlockErase, kSectorErase), _))
        .WillOnce(Return(LIBHOTH_OK));
    EXPECT_CALL(mock_, receive)
        .WillOnce(DoAll(CopyResp(&kDummy, 0), Return(LIBHOTH_OK)));

    // Flash
    EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
        .WillOnce(Return(LIBHOTH_OK));
    EXPECT_CALL(mock_, receive)
        .WillOnce(DoAll(CopyResp(&kDummy, 0), Return(LIBHOTH_OK)));

    // Finalize version check
    static constexpr uint32_t kVersionMask = 0;
    EXPECT_CALL(mock_, send(_, UsesCommand(HOTH_CMD_GET_CMD_VERSIONS), _))
        .WillOnce(Return(LIBHOTH_OK));
    EXPECT_CALL(mock_, receive)
        .WillOnce(DoAll(CopyResp(&kVersionMask, sizeof(kVersionMask)),
                        Return(LIBHOTH_OK)));

    // Finalize
    EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
        .WillOnce(Return(LIBHOTH_OK));
    EXPECT_CALL(mock_, receive)
        .WillOnce(DoAll(CopyResp(&kDummy, 0), Return(LIBHOTH_OK)));
  }

  EXPECT_EQ(libhoth_payload_update(&hoth_dev_, buffer, kSize, false),
            PAYLOAD_UPDATE_OK);
}
