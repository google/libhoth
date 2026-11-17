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

#include "protocol/flash_uid.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>

#include "protocol/test/libhoth_device_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

TEST_F(LibHothTest, get_flash_uid_success_test) {
  struct hoth_response_get_flash_uid exp_resp = {};
  exp_resp.device_count = 2;
  exp_resp.devices[0].uid_len = 16;
  exp_resp.devices[0].jedec_id[0] = 0xc2;
  exp_resp.devices[0].jedec_id[1] = 0x20;
  exp_resp.devices[0].jedec_id[2] = 0x1a;
  for (uint8_t i = 0; i < exp_resp.devices[0].uid_len; ++i) {
    exp_resp.devices[0].uid[i] = static_cast<uint8_t>(0x10 + i);
  }
  exp_resp.devices[1].uid_len = 0;

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_GET_FLASH_UID),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(&exp_resp, sizeof(exp_resp)), Return(LIBHOTH_OK)));

  struct hoth_response_get_flash_uid resp = {};
  EXPECT_EQ(libhoth_get_flash_uid(&hoth_dev_, &resp), HOTH_SUCCESS);
  EXPECT_EQ(resp.device_count, exp_resp.device_count);
  EXPECT_EQ(resp.devices[0].uid_len, exp_resp.devices[0].uid_len);
  EXPECT_EQ(std::memcmp(resp.devices[0].jedec_id, exp_resp.devices[0].jedec_id,
                        HOTH_FLASH_JEDEC_ID_LEN),
            0);
  EXPECT_EQ(std::memcmp(resp.devices[0].uid, exp_resp.devices[0].uid,
                        exp_resp.devices[0].uid_len),
            0);
  EXPECT_EQ(resp.devices[1].uid_len, 0);
}

TEST_F(LibHothTest, get_flash_uid_null_param_test) {
  libhoth_error err = libhoth_get_flash_uid(&hoth_dev_, nullptr);
  EXPECT_NE(err, HOTH_SUCCESS);
  EXPECT_EQ(LIBHOTH_ERR_GET_CTX(err), HOTH_CTX_CMD_EXEC);
  EXPECT_EQ(LIBHOTH_ERR_GET_SPACE(err), HOTH_HOST_SPACE_LIBHOTH);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_INVALID_PARAMETER);
}

TEST_F(LibHothTest, get_flash_uid_null_device_test) {
  struct hoth_response_get_flash_uid resp = {};
  libhoth_error err = libhoth_get_flash_uid(nullptr, &resp);
  EXPECT_NE(err, HOTH_SUCCESS);
  EXPECT_EQ(LIBHOTH_ERR_GET_CTX(err), HOTH_CTX_CMD_EXEC);
  EXPECT_EQ(LIBHOTH_ERR_GET_SPACE(err), HOTH_HOST_SPACE_LIBHOTH);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_INVALID_PARAMETER);
}

TEST_F(LibHothTest, get_flash_uid_short_response_test) {
  uint8_t short_resp[4] = {0};

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_GET_FLASH_UID),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(short_resp, sizeof(short_resp)), Return(LIBHOTH_OK)));

  struct hoth_response_get_flash_uid resp = {};
  libhoth_error err = libhoth_get_flash_uid(&hoth_dev_, &resp);
  EXPECT_NE(err, HOTH_SUCCESS);
  EXPECT_EQ(LIBHOTH_ERR_GET_CTX(err), HOTH_CTX_CMD_EXEC);
  EXPECT_EQ(LIBHOTH_ERR_GET_SPACE(err), HOTH_HOST_SPACE_LIBHOTH);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_FAIL);
}

TEST_F(LibHothTest, get_flash_uid_invalid_device_count_test) {
  struct hoth_response_get_flash_uid exp_resp = {};
  exp_resp.device_count = HOTH_FLASH_MAX_DEVICES + 1;

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_GET_FLASH_UID),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(&exp_resp, sizeof(exp_resp)), Return(LIBHOTH_OK)));

  struct hoth_response_get_flash_uid resp = {};
  libhoth_error err = libhoth_get_flash_uid(&hoth_dev_, &resp);
  EXPECT_NE(err, HOTH_SUCCESS);
  EXPECT_EQ(LIBHOTH_ERR_GET_CTX(err), HOTH_CTX_CMD_EXEC);
  EXPECT_EQ(LIBHOTH_ERR_GET_SPACE(err), HOTH_HOST_SPACE_LIBHOTH);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_FAIL);
}

TEST_F(LibHothTest, get_flash_uid_invalid_uid_len_test) {
  struct hoth_response_get_flash_uid exp_resp = {};
  exp_resp.device_count = 1;
  exp_resp.devices[0].uid_len = HOTH_FLASH_UID_MAX_LEN + 1;

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_GET_FLASH_UID),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(&exp_resp, sizeof(exp_resp)), Return(LIBHOTH_OK)));

  struct hoth_response_get_flash_uid resp = {};
  libhoth_error err = libhoth_get_flash_uid(&hoth_dev_, &resp);
  EXPECT_NE(err, HOTH_SUCCESS);
  EXPECT_EQ(LIBHOTH_ERR_GET_CTX(err), HOTH_CTX_CMD_EXEC);
  EXPECT_EQ(LIBHOTH_ERR_GET_SPACE(err), HOTH_HOST_SPACE_LIBHOTH);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_FAIL);
}

TEST_F(LibHothTest, get_flash_uid_max_uid_len_boundary_test) {
  struct hoth_response_get_flash_uid exp_resp = {};
  exp_resp.device_count = HOTH_FLASH_MAX_DEVICES;
  exp_resp.devices[1].uid_len = HOTH_FLASH_UID_MAX_LEN;
  for (uint8_t i = 0; i < HOTH_FLASH_UID_MAX_LEN; ++i) {
    exp_resp.devices[1].uid[i] = static_cast<uint8_t>(0xa0 + i);
  }

  EXPECT_CALL(mock_,
              send(_,
                   UsesCommandWithVersion(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                              HOTH_PRV_CMD_HOTH_GET_FLASH_UID,
                                          0),
                   sizeof(struct hoth_host_request)))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(&exp_resp, sizeof(exp_resp)), Return(LIBHOTH_OK)));

  struct hoth_response_get_flash_uid resp = {};
  EXPECT_EQ(libhoth_get_flash_uid(&hoth_dev_, &resp), HOTH_SUCCESS);
  EXPECT_EQ(resp.devices[1].uid_len, HOTH_FLASH_UID_MAX_LEN);
  EXPECT_EQ(std::memcmp(resp.devices[1].uid, exp_resp.devices[1].uid,
                        HOTH_FLASH_UID_MAX_LEN),
            0);
}

TEST_F(LibHothTest, get_flash_uid_second_device_invalid_uid_len_test) {
  struct hoth_response_get_flash_uid exp_resp = {};
  exp_resp.device_count = 2;
  exp_resp.devices[0].uid_len = 16;
  exp_resp.devices[1].uid_len = HOTH_FLASH_UID_MAX_LEN + 1;

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_GET_FLASH_UID),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(&exp_resp, sizeof(exp_resp)), Return(LIBHOTH_OK)));

  struct hoth_response_get_flash_uid resp = {};
  libhoth_error err = libhoth_get_flash_uid(&hoth_dev_, &resp);
  EXPECT_NE(err, HOTH_SUCCESS);
  EXPECT_EQ(LIBHOTH_ERR_GET_CTX(err), HOTH_CTX_CMD_EXEC);
  EXPECT_EQ(LIBHOTH_ERR_GET_SPACE(err), HOTH_HOST_SPACE_LIBHOTH);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_FAIL);
}

TEST_F(LibHothTest, get_flash_uid_transport_error_propagated_test) {
  const libhoth_error kTimeoutErr = LIBHOTH_ERR_CONSTRUCT(
      HOTH_CTX_USB, HOTH_HOST_SPACE_LIBHOTH, LIBHOTH_ERR_TIMEOUT);
  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_GET_FLASH_UID),
                          _))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive).WillOnce(Return(kTimeoutErr));

  struct hoth_response_get_flash_uid resp = {};
  EXPECT_EQ(libhoth_get_flash_uid(&hoth_dev_, &resp), kTimeoutErr);
}
