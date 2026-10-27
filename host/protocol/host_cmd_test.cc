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

#include "protocol/host_cmd.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <vector>

#include "test/libhoth_device_mock.h"
#include "transports/libhoth_device.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

constexpr int kCmd = 0xff42;

uint8_t const ERROR_RESPONSE_EXTENDED[] = {
    0x03, 0xa2, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0xc7, 0x89,
};

uint8_t const ERROR_RESPONSE_LEGACY[] = {
    0x03, 0xfb, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
};

TEST_F(LibHothTest, response_failure_legacy) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(
          CopyRespRaw(&ERROR_RESPONSE_LEGACY, sizeof(ERROR_RESPONSE_LEGACY)),
          Return(LIBHOTH_OK)));

  uint8_t resp_buf[1024];
  size_t out_resp_size;
  libhoth_error err =
      libhoth_hostcmd_exec(&hoth_dev_, kCmd, 0, nullptr, 0, resp_buf,
                           sizeof(resp_buf), &out_resp_size);
  EXPECT_NE(err, HOTH_SUCCESS);
  EXPECT_EQ(LIBHOTH_ERR_GET_CTX(err), HOTH_CTX_CMD_EXEC);
  EXPECT_EQ(LIBHOTH_ERR_GET_SPACE(err), HOTH_HOST_SPACE_EC);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), 2);
}

TEST_F(LibHothTest, response_failure_extended) {
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyRespRaw(&ERROR_RESPONSE_EXTENDED,
                                  sizeof(ERROR_RESPONSE_EXTENDED)),
                      Return(LIBHOTH_OK)));

  uint8_t resp_buf[1024];
  size_t out_resp_size;
  libhoth_error err =
      libhoth_hostcmd_exec(&hoth_dev_, kCmd, 0, nullptr, 0, resp_buf,
                           sizeof(resp_buf), &out_resp_size);
  EXPECT_NE(err, HOTH_SUCCESS);
  EXPECT_EQ(LIBHOTH_ERR_GET_CTX(err), HOTH_CTX_CMD_EXEC);
  EXPECT_EQ(LIBHOTH_ERR_GET_SPACE(err), HOTH_HOST_SPACE_PIEROT_ERR);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), 0x89c70005);
}

TEST_F(LibHothTest, large_request_accepted_up_to_max_mailbox) {
  std::vector<uint8_t> payload(4096);
  for (size_t i = 0; i < payload.size(); i++) {
    payload[i] = static_cast<uint8_t>(i);
  }

  size_t sent_size = 0;
  std::vector<uint8_t> sent_payload;
  EXPECT_CALL(mock_, send(_, UsesCommand(kCmd), _))
      .WillOnce([&](struct libhoth_device*, const void* request,
                    size_t request_size) {
        const uint8_t* bytes = static_cast<const uint8_t*>(request);
        sent_size = request_size;
        sent_payload.assign(bytes + sizeof(struct hoth_host_request),
                            bytes + request_size);
        return LIBHOTH_OK;
      });
  const uint8_t empty_resp = 0;
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&empty_resp, 0), Return(LIBHOTH_OK)));

  EXPECT_EQ(libhoth_hostcmd_exec(&hoth_dev_, kCmd, 0, payload.data(),
                                 payload.size(), nullptr, 0, nullptr),
            HOTH_SUCCESS);

  EXPECT_EQ(sent_size, sizeof(struct hoth_host_request) + payload.size());
  EXPECT_EQ(sent_payload, payload);
}

TEST_F(LibHothTest, oversized_request_rejected_above_max_mailbox) {
  EXPECT_CALL(mock_, send).Times(0);

  const size_t max_payload =
      LIBHOTH_MAX_MAILBOX_SIZE - sizeof(struct hoth_host_request);
  std::vector<uint8_t> payload(max_payload + 1, 0);
  libhoth_error err = libhoth_hostcmd_exec(&hoth_dev_, kCmd, 0, payload.data(),
                                           payload.size(), nullptr, 0, nullptr);

  EXPECT_NE(err, HOTH_SUCCESS);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_OUT_UNDERFLOW);
}
