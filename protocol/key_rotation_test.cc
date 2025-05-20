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

#include "protocol/key_rotation.h"

#include "test/libhoth_device_mock.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "protocol/host_cmd.h"
#include "transports/libhoth_device.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

constexpr int kCmd =
    HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HAVEN_KEY_ROTATION_OP;

const struct hoth_response_key_rotation_record_version kDefaultVersion = {
    .version = 0xa1b2c3d4,
};
const struct hoth_response_key_rotation_status kDefaultStatus = {
    .version = 0x12345678,
    .image_family = 0xabcd,
    .image_family_variant = 0x01,
    .validation_method = 0x02,
    .validation_key_data = 0x03,
    .validation_hash_data = 0x04,
};

const struct hoth_response_key_rotation_payload_status kDefaultPayloadStatus = {
    .validation_method = 0x05,
    .validation_key_data = 0x06,
    .validation_hash_data = 0x07,
};

TEST_F(LibHothTest, key_rotation_get_version_success) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&kDefaultVersion, sizeof(kDefaultVersion)),
                      Return(LIBHOTH_OK)));

  struct hoth_response_key_rotation_record_version actual_response;
  EXPECT_EQ(libhoth_key_rotation_get_version(&hoth_dev_, &actual_response),
            LIBHOTH_OK);
  EXPECT_EQ(actual_response.version, kDefaultVersion.version);
}

TEST_F(LibHothTest, key_rotation_get_version_failure_io) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive).WillOnce(Return(LIBHOTH_ERR_FAIL));

  struct hoth_response_key_rotation_record_version actual_response;
  EXPECT_EQ(libhoth_key_rotation_get_version(&hoth_dev_, &actual_response), -1);
}

TEST_F(LibHothTest, key_rotation_get_version_failure_wrong_size) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&kDefaultVersion, sizeof(kDefaultVersion) - 1),
                      Return(LIBHOTH_OK)));

  struct hoth_response_key_rotation_record_version actual_response;
  EXPECT_EQ(libhoth_key_rotation_get_version(&hoth_dev_, &actual_response), -1);
}

TEST_F(LibHothTest, key_rotation_get_status_success) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&kDefaultStatus, sizeof(kDefaultStatus)),
                      Return(LIBHOTH_OK)));

  struct hoth_response_key_rotation_status actual_status;
  EXPECT_EQ(libhoth_key_rotation_get_status(&hoth_dev_, &actual_status),
            LIBHOTH_OK);
  EXPECT_EQ(actual_status.version, kDefaultStatus.version);
  EXPECT_EQ(actual_status.image_family, kDefaultStatus.image_family);
  EXPECT_EQ(actual_status.image_family_variant,
            kDefaultStatus.image_family_variant);
  EXPECT_EQ(actual_status.validation_method, kDefaultStatus.validation_method);
  EXPECT_EQ(actual_status.validation_key_data,
            kDefaultStatus.validation_key_data);
  EXPECT_EQ(actual_status.validation_hash_data,
            kDefaultStatus.validation_hash_data);
}

TEST_F(LibHothTest, key_rotation_get_status_failure_io) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive).WillOnce(Return(LIBHOTH_ERR_FAIL));

  struct hoth_response_key_rotation_status actual_status;
  EXPECT_EQ(libhoth_key_rotation_get_status(&hoth_dev_, &actual_status), -1);
}

TEST_F(LibHothTest, key_rotation_get_status_failure_wrong_size) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&kDefaultStatus, sizeof(kDefaultStatus) - 1),
                      Return(LIBHOTH_OK)));

  struct hoth_response_key_rotation_status actual_status;
  EXPECT_EQ(libhoth_key_rotation_get_status(&hoth_dev_, &actual_status), -1);
}

TEST_F(LibHothTest, key_rotation_payload_status_success) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(&kDefaultPayloadStatus, sizeof(kDefaultPayloadStatus)),
                Return(LIBHOTH_OK)));

  struct hoth_response_key_rotation_payload_status actual_payload_status;
  EXPECT_EQ(
      libhoth_key_rotation_payload_status(&hoth_dev_, &actual_payload_status),
      LIBHOTH_OK);
  EXPECT_EQ(actual_payload_status.validation_method,
            kDefaultPayloadStatus.validation_method);
  EXPECT_EQ(actual_payload_status.validation_key_data,
            kDefaultPayloadStatus.validation_key_data);
  EXPECT_EQ(actual_payload_status.validation_hash_data,
            kDefaultPayloadStatus.validation_hash_data);
}

TEST_F(LibHothTest, key_rotation_payload_status_failure_io) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive).WillOnce(Return(LIBHOTH_ERR_FAIL));

  struct hoth_response_key_rotation_payload_status actual_payload_status;
  EXPECT_EQ(
      libhoth_key_rotation_payload_status(&hoth_dev_, &actual_payload_status),
      -1);
}

TEST_F(LibHothTest, key_rotation_payload_status_failure_wrong_size) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(
          CopyResp(&kDefaultPayloadStatus, sizeof(kDefaultPayloadStatus) - 1),
          Return(LIBHOTH_OK)));

  struct hoth_response_key_rotation_payload_status actual_payload_status;
  EXPECT_EQ(
      libhoth_key_rotation_payload_status(&hoth_dev_, &actual_payload_status),
      -1);
}
