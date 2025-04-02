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

#include "i2c.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>

#include "test/libhoth_device_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

TEST_F(LibHothTest, i2c_detect_test) {
  struct hoth_response_i2c_detect ex_resp = {
      .bus_response = 0,
      .devices_count = 3,
  };

  ex_resp.devices_mask[0] = 0xA0;
  ex_resp.devices_mask[1] = 0x80;

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_I2C_DETECT),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&ex_resp, sizeof(ex_resp)), Return(LIBHOTH_OK)));

  struct hoth_request_i2c_detect req = {
      .bus_number = 42,
      .start_address = 0,
      .end_address = 0x7F,
  };
  struct hoth_response_i2c_detect resp;
  EXPECT_EQ(libhoth_i2c_detect(&hoth_dev_, &req, &resp), LIBHOTH_OK);

  EXPECT_EQ(resp.bus_response, ex_resp.bus_response);
  EXPECT_EQ(resp.devices_count, ex_resp.devices_count);
  EXPECT_EQ(resp.devices_mask[0], ex_resp.devices_mask[0]);
  EXPECT_EQ(resp.devices_mask[1], ex_resp.devices_mask[1]);

  uint8_t device_list[I2C_DETECT_MAX_DEVICES] = {0};
  libhoth_i2c_device_list(resp.devices_mask, resp.devices_count, device_list);

  EXPECT_EQ(device_list[0], 5);
  EXPECT_EQ(device_list[1], 7);
  EXPECT_EQ(device_list[2], 15);
}

TEST_F(LibHothTest, i2c_transfer_test) {
  struct hoth_response_i2c_transfer ex_resp = {
      .bus_response = 0,
      .read_bytes = 10,
  };

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_I2C_TRANSFER),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&ex_resp, sizeof(ex_resp)), Return(LIBHOTH_OK)));

  struct hoth_request_i2c_transfer xfer = {
      .bus_number = 3,
      .dev_address = 10,
      .size_write = 10,
      .size_read = 10,
  };

  struct hoth_response_i2c_transfer resp;
  EXPECT_EQ(libhoth_i2c_transfer(&hoth_dev_, &xfer, &resp), LIBHOTH_OK);

  EXPECT_EQ(resp.bus_response, ex_resp.bus_response);
  // EXPECT_EQ does funny things with its arguments and may cause them to
  // lose their attributes.  This can cause test failures due to unaligned
  // access, so we explicitly add casts here.
  EXPECT_EQ(static_cast<uint16_t>(resp.read_bytes),
            static_cast<uint16_t>(ex_resp.read_bytes));
}
