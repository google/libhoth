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

#include "jtag.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <stdlib.h>

#include <cstdint>
#include <cstdlib>

#include "protocol/test/libhoth_device_mock.h"
#include "transports/libhoth_device.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

TEST_F(LibHothTest, jtag_read_idcode_success) {
  // Version = 0
  // Part ID = 0
  // Manufacturer ID = 0b00001111111 which is invalid as per IEEE1149.1 2013
  // Last bit is expected to be 1 in IDCODE
  uint32_t expected_idcode = 0b0000'0000'0000'0000'0000'0000'1111'111'1;
  struct hoth_response_jtag_read_idcode_operation good_response = {
      .idcode = expected_idcode,
  };

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_JTAG_OPERATION),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&good_response, sizeof(good_response)),
                      Return(LIBHOTH_OK)));

  uint32_t received_idcode;
  uint16_t clk_idiv = 0;
  EXPECT_EQ(libhoth_jtag_read_idcode(&hoth_dev_, clk_idiv, &received_idcode),
            LIBHOTH_OK);
  EXPECT_EQ(received_idcode, expected_idcode);
}

TEST_F(LibHothTest, jtag_read_idcode_receive_error) {
  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_JTAG_OPERATION),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive).WillOnce(Return(LIBHOTH_ERR_TIMEOUT));

  uint32_t received_idcode;
  uint16_t clk_idiv = 0;
  EXPECT_EQ(libhoth_jtag_read_idcode(&hoth_dev_, clk_idiv, &received_idcode),
            -1);
}

TEST_F(LibHothTest, jtag_read_idcode_receive_unexpected_length) {
  uint32_t expected_idcode = 0b0000'0000'0000'0000'0000'0000'1111'111'1;
  struct hoth_response_jtag_read_idcode_operation good_response = {
      .idcode = expected_idcode,
  };
  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_JTAG_OPERATION),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&good_response, sizeof(good_response) - 1),
                      Return(LIBHOTH_OK)));

  uint32_t received_idcode;
  uint16_t clk_idiv = 0;
  EXPECT_EQ(libhoth_jtag_read_idcode(&hoth_dev_, clk_idiv, &received_idcode),
            -1);
}

TEST_F(LibHothTest, jtag_test_bypass_success_with_tdi_tdo_data_match) {
  uint8_t tdi_bytes[HOTH_JTAG_TEST_BYPASS_PATTERN_LEN];
  struct hoth_response_jtag_test_bypass_operation good_matching_response;
  for (uint8_t i = 0; i < HOTH_JTAG_TEST_BYPASS_PATTERN_LEN; i++) {
    tdi_bytes[i] = i;
    good_matching_response.tdo_pattern[i] = i;
  }

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_JTAG_OPERATION),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(
          CopyResp(&good_matching_response, sizeof(good_matching_response)),
          Return(LIBHOTH_OK)));

  uint8_t tdo_bytes[HOTH_JTAG_TEST_BYPASS_PATTERN_LEN];
  uint16_t clk_idiv = 0;
  EXPECT_EQ(
      libhoth_jtag_test_bypass(&hoth_dev_, clk_idiv, tdi_bytes, tdo_bytes),
      LIBHOTH_OK);
  EXPECT_THAT(tdo_bytes, testing::ElementsAreArray(tdi_bytes));
}

TEST_F(LibHothTest, jtag_test_bypass_success_with_tdi_tdo_data_mismatch) {
  uint8_t tdi_bytes[HOTH_JTAG_TEST_BYPASS_PATTERN_LEN];
  struct hoth_response_jtag_test_bypass_operation good_non_matching_response;
  for (uint8_t i = 0; i < HOTH_JTAG_TEST_BYPASS_PATTERN_LEN; i++) {
    tdi_bytes[i] = i;
    good_non_matching_response.tdo_pattern[i] = i + 1;
  }

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_JTAG_OPERATION),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&good_non_matching_response,
                               sizeof(good_non_matching_response)),
                      Return(LIBHOTH_OK)));

  uint8_t tdo_bytes[HOTH_JTAG_TEST_BYPASS_PATTERN_LEN];
  uint16_t clk_idiv = 0;
  EXPECT_EQ(
      libhoth_jtag_test_bypass(&hoth_dev_, clk_idiv, tdi_bytes, tdo_bytes),
      LIBHOTH_OK);
  EXPECT_THAT(tdo_bytes, testing::Not(testing::ElementsAreArray(tdi_bytes)));
}

TEST_F(LibHothTest, jtag_test_bypass_receive_error) {
  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_JTAG_OPERATION),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive).WillOnce(Return(LIBHOTH_ERR_TIMEOUT));

  uint8_t tdi_bytes[HOTH_JTAG_TEST_BYPASS_PATTERN_LEN];
  uint8_t tdo_bytes[HOTH_JTAG_TEST_BYPASS_PATTERN_LEN];
  uint16_t clk_idiv = 0;
  EXPECT_EQ(
      libhoth_jtag_test_bypass(&hoth_dev_, clk_idiv, tdi_bytes, tdo_bytes), -1);
}

TEST_F(LibHothTest, jtag_test_bypass_receive_unexpected_length) {
  uint8_t tdi_bytes[HOTH_JTAG_TEST_BYPASS_PATTERN_LEN];
  struct hoth_response_jtag_test_bypass_operation good_matching_response;
  for (uint8_t i = 0; i < HOTH_JTAG_TEST_BYPASS_PATTERN_LEN; i++) {
    tdi_bytes[i] = i;
    good_matching_response.tdo_pattern[i] = i;
  }

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_JTAG_OPERATION),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(
          CopyResp(&good_matching_response, sizeof(good_matching_response) - 1),
          Return(LIBHOTH_OK)));

  uint8_t tdo_bytes[HOTH_JTAG_TEST_BYPASS_PATTERN_LEN];
  uint16_t clk_idiv = 0;
  EXPECT_EQ(
      libhoth_jtag_test_bypass(&hoth_dev_, clk_idiv, tdi_bytes, tdo_bytes), -1);
}

TEST_F(LibHothTest, jtag_program_and_verify_pld_success) {
  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_JTAG_OPERATION),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  uint8_t unused;
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&unused, 0), Return(LIBHOTH_OK)));

  uint32_t offset = 0;
  EXPECT_EQ(libhoth_jtag_program_and_verify_pld(&hoth_dev_, offset),
            LIBHOTH_OK);
}

TEST_F(LibHothTest, jtag_program_and_verify_pld_receive_error) {
  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_JTAG_OPERATION),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive).WillOnce(Return(LIBHOTH_ERR_TIMEOUT));

  uint32_t offset = 0;
  EXPECT_EQ(libhoth_jtag_program_and_verify_pld(&hoth_dev_, offset), -1);
}

TEST_F(LibHothTest, jtag_program_and_verify_pld_receive_unexpected_length) {
  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_JTAG_OPERATION),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  uint8_t unused;
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&unused, sizeof(unused)), Return(LIBHOTH_OK)));

  uint32_t offset = 0;
  EXPECT_EQ(libhoth_jtag_program_and_verify_pld(&hoth_dev_, offset), -1);
}

TEST_F(LibHothTest, jtag_verify_pld_success) {
  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_JTAG_OPERATION),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  uint8_t unused;
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&unused, 0), Return(LIBHOTH_OK)));

  uint32_t offset = 0;
  EXPECT_EQ(libhoth_jtag_verify_pld(&hoth_dev_, offset), LIBHOTH_OK);
}

TEST_F(LibHothTest, jtag_verify_pld_receive_error) {
  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_JTAG_OPERATION),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive).WillOnce(Return(LIBHOTH_ERR_TIMEOUT));

  uint32_t offset = 0;
  EXPECT_EQ(libhoth_jtag_verify_pld(&hoth_dev_, offset), -1);
}

TEST_F(LibHothTest, jtag_verify_pld_receive_unexpected_length) {
  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_JTAG_OPERATION),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  uint8_t unused;
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&unused, sizeof(unused)), Return(LIBHOTH_OK)));

  uint32_t offset = 0;
  EXPECT_EQ(libhoth_jtag_verify_pld(&hoth_dev_, offset), -1);
}
