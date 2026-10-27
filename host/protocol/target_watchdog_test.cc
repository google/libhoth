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

#include "protocol/target_watchdog.h"

#include <endian.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>

#include "protocol/host_cmd.h"
#include "protocol/status.h"
#include "protocol/test/libhoth_device_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

namespace {

// Matcher to verify the host request command, payload size, little-endian wire
// format, and payload content. We use safe std::memcpy on the packed struct
// to avoid unaligned 64-bit reference binding under UBSan/ASan.
MATCHER_P(UsesWatchdogCookie, expected_cookie, "") {
  const auto* req = static_cast<const struct hoth_host_request*>(arg);
  if (req->command !=
      (HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_PET_TARGET_WATCHDOG)) {
    return false;
  }
  if (req->data_len != sizeof(struct ec_request_pet_target_watchdog)) {
    return false;
  }
  const uint8_t* req_data =
      static_cast<const uint8_t*>(arg) + sizeof(struct hoth_host_request);

  // Safe memcpy access to packed struct
  struct ec_request_pet_target_watchdog payload;
  std::memcpy(&payload, req_data, sizeof(payload));

  // Check little-endian wire encoding directly
  uint8_t expected_bytes[8];
  for (int i = 0; i < 8; ++i) {
    expected_bytes[i] =
        static_cast<uint8_t>((expected_cookie >> (i * 8)) & 0xff);
  }
  if (std::memcmp(req_data, expected_bytes, sizeof(expected_bytes)) != 0) {
    return false;
  }

  return le64toh(payload.notify_cookie) == expected_cookie;
}

TEST_F(LibHothTest, PetTargetWatchdogDefaultCookie) {
  EXPECT_CALL(mock_, send(_, UsesWatchdogCookie(0ULL), _))
      .WillOnce(Return(LIBHOTH_OK));

  uint32_t dummy = 0;
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&dummy, 0), Return(LIBHOTH_OK)));

  EXPECT_EQ(libhoth_pet_target_watchdog(&hoth_dev_, 0), HOTH_SUCCESS);
}

TEST_F(LibHothTest, PetTargetWatchdogNonZeroCookie) {
  constexpr uint64_t kCookie = 0x0123456789abcdefULL;
  EXPECT_CALL(mock_, send(_, UsesWatchdogCookie(kCookie), _))
      .WillOnce(Return(LIBHOTH_OK));

  uint32_t dummy = 0;
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&dummy, 0), Return(LIBHOTH_OK)));

  EXPECT_EQ(libhoth_pet_target_watchdog(&hoth_dev_, kCookie), HOTH_SUCCESS);
}

TEST_F(LibHothTest, PetTargetWatchdogNullDevice) {
  libhoth_error err = libhoth_pet_target_watchdog(nullptr, 0);
  EXPECT_NE(err, HOTH_SUCCESS);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_INVALID_PARAMETER);
}

TEST_F(LibHothTest, PetTargetWatchdogSendFailure) {
  EXPECT_CALL(mock_, send(_, _, _)).WillOnce(Return(LIBHOTH_ERR_FAIL));

  EXPECT_NE(libhoth_pet_target_watchdog(&hoth_dev_, 0), HOTH_SUCCESS);
}

TEST_F(LibHothTest, PetTargetWatchdogReceiveFailure) {
  EXPECT_CALL(mock_, send(_, _, _)).WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive).WillOnce(Return(LIBHOTH_ERR_TIMEOUT));

  EXPECT_NE(libhoth_pet_target_watchdog(&hoth_dev_, 0), HOTH_SUCCESS);
}
}  // namespace
