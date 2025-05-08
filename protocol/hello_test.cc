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

#include "hello.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>

#include "test/libhoth_device_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::ElementsAreArray;
using ::testing::Return;

TEST_F(LibHothTest, hello_test) {
  EXPECT_CALL(mock_, send(_, UsesCommand(HOTH_CMD_HELLO), _))
      .WillOnce(Return(LIBHOTH_OK));

  struct hoth_response_hello response = {
      .output = 0xa1b2c3d4,
  };
  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(&response, sizeof(response)), Return(LIBHOTH_OK)));

  const uint32_t input = 0xa0b0c0d0;
  uint32_t output = 0;
  EXPECT_EQ(libhoth_hello(&hoth_dev_, input, &output), LIBHOTH_OK);
  EXPECT_EQ(output, response.output);
}
