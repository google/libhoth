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

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

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

constexpr int kCmdRotPublicKey = 0x59454B50;

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

const struct hoth_response_key_rotation_record_read kDefaultReadResponse = {
    .data = {0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
};
constexpr int64_t kDummy = 0;
constexpr int kChunkSize = 2;
unsigned int seed = 0;
void fill_with_data(uint8_t* data, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    data[i] = rand_r(&seed) % 256;
  }
}

TEST_F(LibHothTest, key_rotation_get_version_success) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&kDefaultVersion, sizeof(kDefaultVersion)),
                      Return(LIBHOTH_OK)));

  struct hoth_response_key_rotation_record_version actual_response;
  EXPECT_EQ(libhoth_key_rotation_get_version(&hoth_dev_, &actual_response),
            KEY_ROTATION_CMD_SUCCESS);
  EXPECT_EQ(actual_response.version, kDefaultVersion.version);
}

TEST_F(LibHothTest, key_rotation_get_version_failure_io) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive).WillOnce(Return(LIBHOTH_ERR_FAIL));

  struct hoth_response_key_rotation_record_version actual_response;
  EXPECT_EQ(libhoth_key_rotation_get_version(&hoth_dev_, &actual_response),
            KEY_ROTATION_ERR);
}

TEST_F(LibHothTest, key_rotation_get_version_failure_wrong_size) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&kDefaultVersion, sizeof(kDefaultVersion) - 1),
                      Return(LIBHOTH_OK)));

  struct hoth_response_key_rotation_record_version actual_response;
  EXPECT_EQ(libhoth_key_rotation_get_version(&hoth_dev_, &actual_response),
            KEY_ROTATION_ERR_INVALID_RESPONSE_SIZE);
}

TEST_F(LibHothTest, key_rotation_get_status_success) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&kDefaultStatus, sizeof(kDefaultStatus)),
                      Return(KEY_ROTATION_CMD_SUCCESS)));

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
  EXPECT_EQ(libhoth_key_rotation_get_status(&hoth_dev_, &actual_status),
            KEY_ROTATION_ERR);
}

TEST_F(LibHothTest, key_rotation_get_status_failure_wrong_size) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&kDefaultStatus, sizeof(kDefaultStatus) - 1),
                      Return(LIBHOTH_OK)));

  struct hoth_response_key_rotation_status actual_status;
  EXPECT_EQ(libhoth_key_rotation_get_status(&hoth_dev_, &actual_status),
            KEY_ROTATION_ERR_INVALID_RESPONSE_SIZE);
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
      KEY_ROTATION_ERR);
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
      KEY_ROTATION_ERR_INVALID_RESPONSE_SIZE);
}

TEST_F(LibHothTest, key_rotation_read_success) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&kDefaultReadResponse, 8), Return(LIBHOTH_OK)));
  struct hoth_response_key_rotation_record_read actual_read_response;
  EXPECT_EQ(libhoth_key_rotation_read(&hoth_dev_, 0, 8,
                                      KEY_ROTATION_RECORD_READ_HALF_ACTIVE,
                                      &actual_read_response),
            KEY_ROTATION_CMD_SUCCESS);
  EXPECT_EQ(memcmp(actual_read_response.data, kDefaultReadResponse.data, 8), 0);
}

TEST_F(LibHothTest, key_rotation_read_max_size_success) {
  uint8_t data[KEY_ROTATION_RECORD_READ_MAX_SIZE] = {0};
  fill_with_data(data, KEY_ROTATION_RECORD_READ_MAX_SIZE);
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&data, KEY_ROTATION_RECORD_READ_MAX_SIZE),
                      Return(LIBHOTH_OK)));
  struct hoth_response_key_rotation_record_read actual_read_response;
  EXPECT_EQ(libhoth_key_rotation_read(
                &hoth_dev_, 0, KEY_ROTATION_RECORD_READ_MAX_SIZE,
                KEY_ROTATION_RECORD_READ_HALF_ACTIVE, &actual_read_response),
            KEY_ROTATION_CMD_SUCCESS);
  EXPECT_EQ(memcmp(actual_read_response.data, data,
                   KEY_ROTATION_RECORD_READ_MAX_SIZE),
            0);
}

TEST_F(LibHothTest, key_rotation_read_record_size_success) {
  uint8_t data[KEY_ROTATION_MAX_RECORD_SIZE] = {0};
  fill_with_data(data, KEY_ROTATION_MAX_RECORD_SIZE);
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillRepeatedly(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&data, KEY_ROTATION_RECORD_READ_MAX_SIZE),
                      Return(LIBHOTH_OK)))
      .WillOnce(DoAll(CopyResp(&data[KEY_ROTATION_RECORD_READ_MAX_SIZE],
                               KEY_ROTATION_RECORD_READ_MAX_SIZE),
                      Return(LIBHOTH_OK)))
      .WillOnce(DoAll(CopyResp(&data[2 * KEY_ROTATION_RECORD_READ_MAX_SIZE], 8),
                      Return(LIBHOTH_OK)));
  struct hoth_response_key_rotation_record_read actual_read_response;
  EXPECT_EQ(libhoth_key_rotation_read(
                &hoth_dev_, 0, KEY_ROTATION_MAX_RECORD_SIZE,
                KEY_ROTATION_RECORD_READ_HALF_ACTIVE, &actual_read_response),
            KEY_ROTATION_CMD_SUCCESS);
  EXPECT_EQ(
      memcmp(actual_read_response.data, data, KEY_ROTATION_MAX_RECORD_SIZE), 0);
}

TEST_F(LibHothTest, key_rotation_read_flash_size_success) {
  uint8_t data[KEY_ROTATION_FLASH_AREA_SIZE] = {0};
  fill_with_data(data, KEY_ROTATION_FLASH_AREA_SIZE);
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillRepeatedly(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&data, KEY_ROTATION_RECORD_READ_MAX_SIZE),
                      Return(LIBHOTH_OK)))
      .WillOnce(DoAll(CopyResp(&data[KEY_ROTATION_RECORD_READ_MAX_SIZE],
                               KEY_ROTATION_RECORD_READ_MAX_SIZE),
                      Return(LIBHOTH_OK)))
      .WillOnce(
          DoAll(CopyResp(&data[2 * KEY_ROTATION_RECORD_READ_MAX_SIZE], 40),
                Return(LIBHOTH_OK)));
  struct hoth_response_key_rotation_record_read actual_read_response;
  EXPECT_EQ(libhoth_key_rotation_read(
                &hoth_dev_, 0, KEY_ROTATION_FLASH_AREA_SIZE,
                KEY_ROTATION_RECORD_READ_HALF_ACTIVE, &actual_read_response),
            KEY_ROTATION_CMD_SUCCESS);
  EXPECT_EQ(
      memcmp(actual_read_response.data, data, KEY_ROTATION_FLASH_AREA_SIZE), 0);
}

TEST_F(LibHothTest, key_rotation_read_failure_io) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive).WillOnce(Return(LIBHOTH_ERR_FAIL));

  struct hoth_response_key_rotation_record_read actual_read_response;
  EXPECT_EQ(libhoth_key_rotation_read(&hoth_dev_, 0, 8,
                                      KEY_ROTATION_RECORD_READ_HALF_ACTIVE,
                                      &actual_read_response),
            KEY_ROTATION_ERR);
}

TEST_F(LibHothTest, key_rotation_read_failure_wrong_size) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(&kDefaultReadResponse, 8 - 1), Return(LIBHOTH_OK)));
  struct hoth_response_key_rotation_record_read actual_read_response;
  EXPECT_EQ(libhoth_key_rotation_read(&hoth_dev_, 0, 8,
                                      KEY_ROTATION_RECORD_READ_HALF_ACTIVE,
                                      &actual_read_response),
            KEY_ROTATION_ERR_INVALID_RESPONSE_SIZE);
}

TEST_F(LibHothTest, key_rotation_read_failure_invalid_size) {
  struct hoth_response_key_rotation_record_read actual_read_response;
  EXPECT_EQ(libhoth_key_rotation_read(&hoth_dev_, 0, 0,
                                      KEY_ROTATION_RECORD_READ_HALF_ACTIVE,
                                      &actual_read_response),
            KEY_ROTATION_ERR_INVALID_PARAM);
}

TEST_F(LibHothTest, key_rotation_read_failure_invalid_size_too_large) {
  struct hoth_response_key_rotation_record_read actual_read_response;
  EXPECT_EQ(libhoth_key_rotation_read(
                &hoth_dev_, 0, KEY_ROTATION_FLASH_AREA_SIZE + 1,
                KEY_ROTATION_RECORD_READ_HALF_ACTIVE, &actual_read_response),
            KEY_ROTATION_ERR_INVALID_PARAM);
}

TEST_F(LibHothTest, key_rotation_update_success) {
  uint8_t data[KEY_ROTATION_MAX_RECORD_SIZE] = {0};
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillRepeatedly(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillRepeatedly(DoAll(CopyResp(&kDummy, 0), Return(LIBHOTH_OK)));

  EXPECT_EQ(libhoth_key_rotation_update(&hoth_dev_, &data[0],
                                        KEY_ROTATION_MAX_RECORD_SIZE),
            LIBHOTH_OK);
}

TEST_F(LibHothTest, key_rotation_update_failure) {
  uint8_t data[500] = {0};
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillRepeatedly(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&kDummy, 0), Return(LIBHOTH_OK)))
      .WillOnce(DoAll(CopyResp(&kDummy, 0), Return(-1)));
  EXPECT_EQ(libhoth_key_rotation_update(&hoth_dev_, &data[0], sizeof(data)),
            KEY_ROTATION_ERR);
}

TEST_F(LibHothTest, key_rotation_update_initiate_failure) {
  uint8_t data[KEY_ROTATION_RECORD_WRITE_MAX_SIZE];

  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillRepeatedly(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive).WillOnce(Return(-1));

  EXPECT_EQ(libhoth_key_rotation_update(&hoth_dev_, &data[0], sizeof(data)),
            KEY_ROTATION_INITIATE_FAIL);
}

TEST_F(LibHothTest, key_rotation_update_commit_failure) {
  uint8_t data[KEY_ROTATION_RECORD_WRITE_MAX_SIZE] = {0};
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillRepeatedly(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&kDummy, 0), Return(LIBHOTH_OK)))
      .WillOnce(DoAll(CopyResp(&kDummy, 0), Return(LIBHOTH_OK)))
      .WillOnce(DoAll(CopyResp(&kDummy, 0), Return(-1)));
  EXPECT_EQ(libhoth_key_rotation_update(&hoth_dev_, &data[0], sizeof(data)),
            KEY_ROTATION_COMMIT_FAIL);
}

TEST_F(LibHothTest, key_rotation_update_failure_invalid_size_too_large) {
  uint8_t data[KEY_ROTATION_FLASH_AREA_SIZE + 1] = {0};
  EXPECT_EQ(libhoth_key_rotation_update(&hoth_dev_, &data[0], sizeof(data)),
            KEY_ROTATION_ERR_INVALID_PARAM);
}

TEST_F(LibHothTest, key_rotation_update_failure_invalid_size_too_small) {
  uint8_t data[KEY_ROTATION_RECORD_SIGNATURE_SIZE - 1] = {0};
  EXPECT_EQ(libhoth_key_rotation_update(&hoth_dev_, &data[0], sizeof(data)),
            KEY_ROTATION_ERR_INVALID_PARAM);
}

TEST_F(LibHothTest, key_rotation_update_failure_invalid_response_size) {
  uint8_t data[100] = {0};
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillRepeatedly(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&kDummy, 0), Return(LIBHOTH_OK)))
      .WillOnce(DoAll(CopyResp(&kDummy, 2), Return(LIBHOTH_OK)));
  EXPECT_EQ(libhoth_key_rotation_update(&hoth_dev_, &data[0], sizeof(data)),
            KEY_ROTATION_ERR);
}

TEST_F(LibHothTest, key_rotation_read_chunk_type_success) {
  uint8_t data[KEY_ROTATION_RECORD_READ_CHUNK_TYPE_MAX_SIZE] = {0};
  fill_with_data(data, KEY_ROTATION_RECORD_READ_CHUNK_TYPE_MAX_SIZE);
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(&data, KEY_ROTATION_RECORD_READ_CHUNK_TYPE_MAX_SIZE),
                Return(LIBHOTH_OK)));
  struct hoth_response_key_rotation_record_read actual_read_response;
  uint16_t response_size = 0;
  EXPECT_EQ(libhoth_key_rotation_read_chunk_type(
                &hoth_dev_, kCmdRotPublicKey, 0, 0,
                KEY_ROTATION_RECORD_READ_CHUNK_TYPE_MAX_SIZE,
                &actual_read_response, &response_size),
            KEY_ROTATION_CMD_SUCCESS);
  EXPECT_EQ(memcmp(actual_read_response.data, data,
                   KEY_ROTATION_RECORD_READ_CHUNK_TYPE_MAX_SIZE),
            0);
  EXPECT_EQ(response_size, KEY_ROTATION_RECORD_READ_CHUNK_TYPE_MAX_SIZE);
}

TEST_F(LibHothTest, key_rotation_read_chunk_type_failure_io) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive).WillOnce(Return(LIBHOTH_ERR_FAIL));
  struct hoth_response_key_rotation_record_read actual_read_response;
  uint16_t response_size = 0;
  EXPECT_EQ(libhoth_key_rotation_read_chunk_type(
                &hoth_dev_, kCmdRotPublicKey, 0, 0,
                KEY_ROTATION_RECORD_READ_CHUNK_TYPE_MAX_SIZE,
                &actual_read_response, &response_size),
            KEY_ROTATION_ERR);
}

TEST_F(LibHothTest, key_rotation_read_chunk_type_failure_invalid_size) {
  struct hoth_response_key_rotation_record_read actual_read_response;
  uint16_t response_size = 0;
  EXPECT_EQ(
      libhoth_key_rotation_read_chunk_type(
          &hoth_dev_, kCmdRotPublicKey, 0, 0, KEY_ROTATION_FLASH_AREA_SIZE + 1,
          &actual_read_response, &response_size),
      KEY_ROTATION_ERR_INVALID_PARAM);
}

TEST_F(LibHothTest,
       key_rotation_read_chunk_type_failure_invalid_response_size) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&kDummy, 0), Return(LIBHOTH_OK)));
  struct hoth_response_key_rotation_record_read actual_read_response;
  uint16_t response_size = 0;
  EXPECT_EQ(libhoth_key_rotation_read_chunk_type(
                &hoth_dev_, kCmdRotPublicKey, 0, 0,
                KEY_ROTATION_RECORD_READ_CHUNK_TYPE_MAX_SIZE,
                &actual_read_response, &response_size),
            KEY_ROTATION_ERR_INVALID_RESPONSE_SIZE);
}

TEST_F(LibHothTest, key_rotation_read_chunk_type_failure_invalid_chunk_offset) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&kDummy, 0), Return(LIBHOTH_OK)));
  struct hoth_response_key_rotation_record_read actual_read_response;
  uint16_t response_size = 0;
  EXPECT_EQ(libhoth_key_rotation_read_chunk_type(
                &hoth_dev_, kCmdRotPublicKey,
                KEY_ROTATION_RECORD_READ_CHUNK_TYPE_MAX_SIZE, 0, 0,
                &actual_read_response, &response_size),
            KEY_ROTATION_ERR_INVALID_RESPONSE_SIZE);
}

TEST_F(LibHothTest, key_rotation_chunk_type_count_success) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&kChunkSize, 4), Return(LIBHOTH_OK)));
  uint16_t chunk_count = 0;
  EXPECT_EQ(libhoth_key_rotation_chunk_type_count(&hoth_dev_, kCmdRotPublicKey,
                                                  &chunk_count),
            KEY_ROTATION_CMD_SUCCESS);
  EXPECT_EQ(chunk_count, 2);
}

TEST_F(LibHothTest, key_rotation_chunk_type_count_failure_io) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive).WillOnce(Return(LIBHOTH_ERR_FAIL));
  uint16_t chunk_count = 0;
  EXPECT_EQ(libhoth_key_rotation_chunk_type_count(&hoth_dev_, kCmdRotPublicKey,
                                                  &chunk_count),
            KEY_ROTATION_ERR);
}

TEST_F(LibHothTest,
       key_rotation_chunk_type_count_failure_invalid_response_size) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&kDummy, 0), Return(LIBHOTH_OK)));
  uint16_t chunk_count = 0;
  EXPECT_EQ(libhoth_key_rotation_chunk_type_count(&hoth_dev_, kCmdRotPublicKey,
                                                  &chunk_count),
            KEY_ROTATION_ERR_INVALID_RESPONSE_SIZE);
}
