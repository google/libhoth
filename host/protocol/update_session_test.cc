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

#include "protocol/update_session.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>

#include "protocol/host_cmd.h"
#include "protocol/status.h"
#include "protocol/test/libhoth_device_mock.h"

namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::StrEq;

MATCHER_P(UsesStartTimeout, expected_timeout, "") {
  const auto* req = static_cast<const struct hoth_host_request*>(arg);
  if (req->command !=
      HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_UPDATE_SESSION_START) {
    return false;
  }
  if (req->data_len != sizeof(struct update_session_start_request)) {
    return false;
  }
  const auto* payload =
      reinterpret_cast<const struct update_session_start_request*>(
          reinterpret_cast<const uint8_t*>(arg) +
          sizeof(struct hoth_host_request));
  return payload->timeout_seconds == expected_timeout;
}

TEST_F(LibHothTest, UpdateSessionStartSuccess) {
  constexpr uint32_t kTimeoutSeconds = 60;
  EXPECT_CALL(mock_, send(_, UsesStartTimeout(kTimeoutSeconds), _))
      .WillOnce(Return(LIBHOTH_OK));

  uint32_t dummy = 0;
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&dummy, 0), Return(LIBHOTH_OK)));

  EXPECT_EQ(libhoth_update_session_start(&hoth_dev_, kTimeoutSeconds),
            HOTH_SUCCESS);
}

TEST_F(LibHothTest, UpdateSessionStartZeroTimeout) {
  libhoth_error err = libhoth_update_session_start(&hoth_dev_, 0);
  EXPECT_NE(err, HOTH_SUCCESS);
  EXPECT_EQ(LIBHOTH_ERR_GET_CTX(err), HOTH_CTX_CMD_EXEC);
  EXPECT_EQ(LIBHOTH_ERR_GET_SPACE(err), HOTH_HOST_SPACE_LIBHOTH);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_INVALID_PARAMETER);
}

TEST_F(LibHothTest, UpdateSessionStartNullDevice) {
  libhoth_error err = libhoth_update_session_start(nullptr, 60);
  EXPECT_NE(err, HOTH_SUCCESS);
  EXPECT_EQ(LIBHOTH_ERR_GET_CTX(err), HOTH_CTX_CMD_EXEC);
  EXPECT_EQ(LIBHOTH_ERR_GET_SPACE(err), HOTH_HOST_SPACE_LIBHOTH);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_INVALID_PARAMETER);
}

TEST_F(LibHothTest, UpdateSessionFinalizeSuccess) {
  EXPECT_CALL(mock_,
              send(_,
                   UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                               HOTH_PRV_CMD_HOTH_UPDATE_SESSION_FINALIZE),
                   _))
      .WillOnce(Return(LIBHOTH_OK));

  uint32_t dummy = 0;
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&dummy, 0), Return(LIBHOTH_OK)));

  EXPECT_EQ(libhoth_update_session_finalize(&hoth_dev_), HOTH_SUCCESS);
}

TEST_F(LibHothTest, UpdateSessionFinalizeNullDevice) {
  libhoth_error err = libhoth_update_session_finalize(nullptr);
  EXPECT_NE(err, HOTH_SUCCESS);
  EXPECT_EQ(LIBHOTH_ERR_GET_CTX(err), HOTH_CTX_CMD_EXEC);
  EXPECT_EQ(LIBHOTH_ERR_GET_SPACE(err), HOTH_HOST_SPACE_LIBHOTH);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_INVALID_PARAMETER);
}

TEST_F(LibHothTest, UpdateSessionGetStatusSuccess) {
  struct update_session_status_response expected_status = {
      .current_state = UPDATE_SESSION_UPDATING,
      .timeout_seconds_left = 42,
  };

  EXPECT_CALL(mock_,
              send(_,
                   UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                               HOTH_PRV_CMD_HOTH_UPDATE_SESSION_GET_STATUS),
                   _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&expected_status, sizeof(expected_status)),
                      Return(LIBHOTH_OK)));

  struct update_session_status_response actual_status = {};
  EXPECT_EQ(libhoth_update_session_get_status(&hoth_dev_, &actual_status),
            HOTH_SUCCESS);
  EXPECT_EQ(actual_status.current_state, UPDATE_SESSION_UPDATING);
  EXPECT_EQ(actual_status.timeout_seconds_left, 42);
}

TEST_F(LibHothTest, UpdateSessionGetStatusNullParam) {
  libhoth_error err = libhoth_update_session_get_status(&hoth_dev_, nullptr);
  EXPECT_NE(err, HOTH_SUCCESS);
  EXPECT_EQ(LIBHOTH_ERR_GET_CTX(err), HOTH_CTX_CMD_EXEC);
  EXPECT_EQ(LIBHOTH_ERR_GET_SPACE(err), HOTH_HOST_SPACE_LIBHOTH);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_INVALID_PARAMETER);
}

TEST_F(LibHothTest, UpdateSessionGetStatusNullDevice) {
  struct update_session_status_response status = {};
  libhoth_error err = libhoth_update_session_get_status(nullptr, &status);
  EXPECT_NE(err, HOTH_SUCCESS);
  EXPECT_EQ(LIBHOTH_ERR_GET_CTX(err), HOTH_CTX_CMD_EXEC);
  EXPECT_EQ(LIBHOTH_ERR_GET_SPACE(err), HOTH_HOST_SPACE_LIBHOTH);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_INVALID_PARAMETER);
}

TEST_F(LibHothTest, UpdateSessionGetStatusShortResponse) {
  EXPECT_CALL(mock_,
              send(_,
                   UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                               HOTH_PRV_CMD_HOTH_UPDATE_SESSION_GET_STATUS),
                   _))
      .WillOnce(Return(LIBHOTH_OK));

  uint32_t short_data = 1;
  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(&short_data, sizeof(short_data)), Return(LIBHOTH_OK)));

  struct update_session_status_response status = {};
  libhoth_error err = libhoth_update_session_get_status(&hoth_dev_, &status);
  EXPECT_NE(err, HOTH_SUCCESS);
  EXPECT_EQ(LIBHOTH_ERR_GET_CTX(err), HOTH_CTX_CMD_EXEC);
  EXPECT_EQ(LIBHOTH_ERR_GET_SPACE(err), HOTH_HOST_SPACE_LIBHOTH);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_FAIL);
}

TEST(UpdateSessionTest, StateString) {
  EXPECT_STREQ(libhoth_update_session_state_string(UPDATE_SESSION_NONE),
               "NONE");
  EXPECT_STREQ(
      libhoth_update_session_state_string(UPDATE_SESSION_PENDING_START),
      "PENDING_START");
  EXPECT_STREQ(libhoth_update_session_state_string(UPDATE_SESSION_UPDATING),
               "UPDATING");
  EXPECT_STREQ(libhoth_update_session_state_string(UPDATE_SESSION_FINALIZED),
               "FINALIZED");
  EXPECT_STREQ(
      libhoth_update_session_state_string(UPDATE_SESSION_START_TIMEOUT),
      "START_TIMEOUT");
  EXPECT_STREQ(
      libhoth_update_session_state_string(UPDATE_SESSION_UPDATE_TIMEOUT),
      "UPDATE_TIMEOUT");
  EXPECT_STREQ(libhoth_update_session_state_string(
                   static_cast<enum update_session_state>(99)),
               "UNKNOWN");
}

}  // namespace
