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

#include "protocol/authz_record.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstring>

#include "protocol/chipinfo.h"
#include "test/libhoth_device_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

TEST_F(LibHothTest, authz_erase_test) {
  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_SET_AUTHZ_RECORD),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  uint32_t dummy;
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&dummy, 0), Return(LIBHOTH_OK)));

  EXPECT_EQ(libhoth_authz_record_erase(&hoth_dev_), LIBHOTH_OK);

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_SET_AUTHZ_RECORD),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive).WillOnce(DoAll(CopyResp(&dummy, 0), Return(-1)));

  EXPECT_EQ(libhoth_authz_record_erase(&hoth_dev_), -1);
}

TEST_F(LibHothTest, authz_read_test) {
  struct hoth_authz_record_get_response resp = {};
  resp.index = 0;
  resp.valid = 1;

  memset(&resp.record, 0xAB, sizeof(resp.record));

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_GET_AUTHZ_RECORD),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&resp, sizeof(resp)), Return(LIBHOTH_OK)));

  struct hoth_authz_record_get_response act_resp;
  EXPECT_EQ(libhoth_authz_record_read(&hoth_dev_, &act_resp), LIBHOTH_OK);
  EXPECT_EQ(resp.index, act_resp.index);
  EXPECT_EQ(resp.valid, act_resp.valid);
  EXPECT_EQ(resp.valid, act_resp.valid);

  EXPECT_EQ(std::memcmp(&resp.record, &act_resp.record, sizeof(resp.record)),
            0);
}

TEST_F(LibHothTest, authz_build_test) {
  struct hoth_response_chip_info chipinfo = {};
  chipinfo.hardware_identity = 0xABCD;
  chipinfo.hardware_identity |= (0x1234UL << 32);

  struct hoth_authz_record_get_nonce_response nonce_resp = {};
  nonce_resp.ro_supported_key_id = 1;
  nonce_resp.rw_supported_key_id = 1;

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_CHIP_INFO),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_GET_AUTHZ_RECORD_NONCE),
                          _));

  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(&chipinfo, sizeof(chipinfo)), Return(LIBHOTH_OK)))
      .WillOnce(
          DoAll(CopyResp(&nonce_resp, sizeof(nonce_resp)), Return(LIBHOTH_OK)));

  uint32_t cap = 123;
  struct authorization_record record = {};

  EXPECT_EQ(libhoth_authz_record_build(&hoth_dev_, cap, &record), LIBHOTH_OK);
  EXPECT_EQ(record.version, 1);
  EXPECT_EQ(record.flags, 0);
  EXPECT_EQ(*(uint32_t*)record.capabilities, cap);
  EXPECT_EQ(record.dev_id_0, 0xABCD);
  EXPECT_EQ(record.dev_id_1, 0x1234);
  EXPECT_EQ(record.key_id, 1);
}

TEST_F(LibHothTest, authz_build_fail_test) {
  struct hoth_response_chip_info chipinfo = {};
  chipinfo.hardware_identity = 0xABCD;
  chipinfo.hardware_identity |= (0x1234UL << 32);

  // key_id supported by RO and RW. These key_id's are expected to match one
  // another to successfully program an authorization record. key_id == 0 should
  // be interpreted as an unknown key_id. Here we set both to 0 to trigger failure.
  struct hoth_authz_record_get_nonce_response nonce_resp = {};
  nonce_resp.ro_supported_key_id = 0;
  nonce_resp.rw_supported_key_id = 0;

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_CHIP_INFO),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_GET_AUTHZ_RECORD_NONCE),
                          _));

  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(&chipinfo, sizeof(chipinfo)), Return(LIBHOTH_OK)))
      .WillOnce(
          DoAll(CopyResp(&nonce_resp, sizeof(nonce_resp)), Return(LIBHOTH_OK)));

  uint32_t cap = 123;
  struct authorization_record record = {};

  EXPECT_EQ(libhoth_authz_record_build(&hoth_dev_, cap, &record), -1);
}

TEST_F(LibHothTest, authz_mismatch_key_id_test) {
  struct hoth_response_chip_info chipinfo = {};
  chipinfo.hardware_identity = 0xABCD;
  chipinfo.hardware_identity |= (0x1234UL << 32);

  // key_id supported by RO and RW. These key_id's are expected to match one
  // another to successfully program an authorization record. key_id == 0 should
  // be interpreted as an unknown key_id. Here we set both to different values to
  // trigger failure.
  struct hoth_authz_record_get_nonce_response nonce_resp = {};
  nonce_resp.ro_supported_key_id = 0;
  nonce_resp.rw_supported_key_id = 1;

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_CHIP_INFO),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_GET_AUTHZ_RECORD_NONCE),
                          _));

  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(&chipinfo, sizeof(chipinfo)), Return(LIBHOTH_OK)))
      .WillOnce(
          DoAll(CopyResp(&nonce_resp, sizeof(nonce_resp)), Return(LIBHOTH_OK)));

  uint32_t cap = 123;
  struct authorization_record record = {};

  EXPECT_EQ(libhoth_authz_record_build(&hoth_dev_, cap, &record), -1);
}

TEST_F(LibHothTest, authz_nonce_fail_test) {
  struct hoth_response_chip_info chipinfo = {};
  chipinfo.hardware_identity = 0xABCD;
  chipinfo.hardware_identity |= (0x1234UL << 32);

  struct hoth_authz_record_get_nonce_response nonce_resp = {};
  nonce_resp.ro_supported_key_id = 0;
  nonce_resp.rw_supported_key_id = 1;

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_CHIP_INFO),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_GET_AUTHZ_RECORD_NONCE),
                          _));

  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(&chipinfo, sizeof(chipinfo)), Return(LIBHOTH_OK)))
      .WillOnce(
          DoAll(CopyResp(&nonce_resp, sizeof(nonce_resp)), Return(LIBHOTH_OK)));

  uint32_t cap = 123;
  struct authorization_record record;

  EXPECT_EQ(libhoth_authz_record_build(&hoth_dev_, cap, &record), -1);
}

TEST_F(LibHothTest, authz_set_test) {
  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_SET_AUTHZ_RECORD),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  uint32_t dummy;
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&dummy, 0), Return(LIBHOTH_OK)));

  struct authorization_record record = {};
  EXPECT_EQ(libhoth_authz_record_set(&hoth_dev_, &record), LIBHOTH_OK);
}

