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

#include <cstddef>
#include <cstdint>

#include "protocol/host_cmd.h"
#include "protocol/status.h"
#include "protocol/test/libhoth_device_mock.h"

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
  EXPECT_EQ(libhoth_i2c_detect(&hoth_dev_, &req, &resp), HOTH_SUCCESS);

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
  EXPECT_EQ(libhoth_i2c_transfer(&hoth_dev_, &xfer, &resp), HOTH_SUCCESS);

  EXPECT_EQ(resp.bus_response, ex_resp.bus_response);
  // EXPECT_EQ does funny things with its arguments and may cause them to
  // lose their attributes.  This can cause test failures due to unaligned
  // access, so we explicitly add casts here.
  EXPECT_EQ(static_cast<uint16_t>(resp.read_bytes),
            static_cast<uint16_t>(ex_resp.read_bytes));
}

TEST_F(LibHothTest, i2c_detect_null_param_test) {
  struct hoth_response_i2c_detect resp;
  libhoth_error err = libhoth_i2c_detect(&hoth_dev_, nullptr, &resp);
  EXPECT_NE(err, HOTH_SUCCESS);
  EXPECT_EQ(LIBHOTH_ERR_GET_CTX(err), HOTH_CTX_CMD_EXEC);
  EXPECT_EQ(LIBHOTH_ERR_GET_SPACE(err), HOTH_HOST_SPACE_LIBHOTH);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_INVALID_PARAMETER);
}

TEST_F(LibHothTest, i2c_transfer_null_param_test) {
  struct hoth_response_i2c_transfer resp;
  libhoth_error err = libhoth_i2c_transfer(&hoth_dev_, nullptr, &resp);
  EXPECT_NE(err, HOTH_SUCCESS);
  EXPECT_EQ(LIBHOTH_ERR_GET_CTX(err), HOTH_CTX_CMD_EXEC);
  EXPECT_EQ(LIBHOTH_ERR_GET_SPACE(err), HOTH_HOST_SPACE_LIBHOTH);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_INVALID_PARAMETER);
}

TEST_F(LibHothTest, i2c_filtering_enable_endpoints_test) {
  alignas(4) uint8_t req_buf[8] = {
      1,    0,    0,    0,  // ids_count = 1, reserved = {0, 0, 0}
      0x00, 0x00, 0x34, 0x01,
  };
  alignas(4) uint8_t ex_resp_buf[8] = {
      1,    0,    0,    0,  // ids_count = 1, reserved = {0, 0, 0}
      0x00, 0x00, 0x34, 0x01,
  };

  EXPECT_CALL(mock_,
              send(_,
                   UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                               HOTH_PRV_CMD_ENABLE_I2C_ENDPOINTS_FOR_FILTERING),
                   _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(ex_resp_buf, sizeof(ex_resp_buf)),
                      Return(LIBHOTH_OK)));

  alignas(4) uint8_t resp_buf[16] = {0};
  size_t resp_len = 0;
  EXPECT_EQ(
      libhoth_i2c_filtering_enable_endpoints(
          &hoth_dev_,
          reinterpret_cast<
              const struct hoth_request_enable_i2c_endpoints_for_filtering*>(
              req_buf),
          sizeof(req_buf),
          reinterpret_cast<
              struct hoth_response_i2c_endpoints_enabled_for_filtering*>(
              resp_buf),
          sizeof(resp_buf), &resp_len),
      HOTH_SUCCESS);
  EXPECT_EQ(resp_len, sizeof(ex_resp_buf));
  EXPECT_EQ(resp_buf[0], 1);
  EXPECT_EQ(resp_buf[6], 0x34);
  EXPECT_EQ(resp_buf[7], 0x01);
}

TEST_F(LibHothTest, i2c_filtering_get_enabled_endpoints_test) {
  alignas(4) uint8_t ex_resp_buf[8] = {
      1,    0,    0,    0,  // ids_count = 1, reserved = {0, 0, 0}
      0x00, 0x00, 0x34, 0x01,
  };

  EXPECT_CALL(
      mock_,
      send(_,
           UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                       HOTH_PRV_CMD_GET_ENABLED_I2C_ENDPOINTS_FOR_FILTERING),
           _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(ex_resp_buf, sizeof(ex_resp_buf)),
                      Return(LIBHOTH_OK)));

  alignas(4) uint8_t resp_buf[16] = {0};
  size_t resp_len = 0;
  EXPECT_EQ(libhoth_i2c_filtering_get_enabled_endpoints(
                &hoth_dev_,
                reinterpret_cast<
                    struct hoth_response_i2c_endpoints_enabled_for_filtering*>(
                    resp_buf),
                sizeof(resp_buf), &resp_len),
            HOTH_SUCCESS);
  EXPECT_EQ(resp_len, sizeof(ex_resp_buf));
  EXPECT_EQ(resp_buf[0], 1);
  EXPECT_EQ(resp_buf[6], 0x34);
  EXPECT_EQ(resp_buf[7], 0x01);
}

TEST_F(LibHothTest, i2c_filtering_enable_endpoints_invalid_param_test) {
  struct hoth_request_enable_i2c_endpoints_for_filtering req = {};
  struct hoth_response_i2c_endpoints_enabled_for_filtering resp = {};
  size_t resp_len = 0;

  libhoth_error err = libhoth_i2c_filtering_enable_endpoints(
      nullptr, &req, sizeof(req), &resp, sizeof(resp), &resp_len);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_INVALID_PARAMETER);

  err = libhoth_i2c_filtering_enable_endpoints(&hoth_dev_, nullptr, sizeof(req),
                                               &resp, sizeof(resp), &resp_len);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_INVALID_PARAMETER);

  err = libhoth_i2c_filtering_enable_endpoints(
      &hoth_dev_, &req, sizeof(req), nullptr, sizeof(resp), &resp_len);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_INVALID_PARAMETER);

  err = libhoth_i2c_filtering_enable_endpoints(
      &hoth_dev_, &req, sizeof(req) - 1, &resp, sizeof(resp), &resp_len);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_INVALID_PARAMETER);

  err = libhoth_i2c_filtering_enable_endpoints(
      &hoth_dev_, &req, sizeof(req), &resp, sizeof(resp) - 1, &resp_len);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_INVALID_PARAMETER);
}

TEST_F(LibHothTest, i2c_filtering_enable_endpoints_truncated_resp_test) {
  struct hoth_request_enable_i2c_endpoints_for_filtering req = {};
  uint8_t short_resp[2] = {0, 0};

  EXPECT_CALL(mock_,
              send(_,
                   UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                               HOTH_PRV_CMD_ENABLE_I2C_ENDPOINTS_FOR_FILTERING),
                   _))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(short_resp, sizeof(short_resp)), Return(LIBHOTH_OK)));

  struct hoth_response_i2c_endpoints_enabled_for_filtering resp = {};
  size_t resp_len = 0;
  libhoth_error err = libhoth_i2c_filtering_enable_endpoints(
      &hoth_dev_, &req, sizeof(req), &resp, sizeof(resp), &resp_len);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_FAIL);
}

TEST_F(LibHothTest, i2c_filtering_get_enabled_endpoints_invalid_param_test) {
  struct hoth_response_i2c_endpoints_enabled_for_filtering resp = {};
  size_t resp_len = 0;

  libhoth_error err = libhoth_i2c_filtering_get_enabled_endpoints(
      nullptr, &resp, sizeof(resp), &resp_len);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_INVALID_PARAMETER);

  err = libhoth_i2c_filtering_get_enabled_endpoints(&hoth_dev_, nullptr,
                                                    sizeof(resp), &resp_len);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_INVALID_PARAMETER);

  err = libhoth_i2c_filtering_get_enabled_endpoints(
      &hoth_dev_, &resp, sizeof(resp) - 1, &resp_len);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_INVALID_PARAMETER);
}

TEST_F(LibHothTest, i2c_filtering_get_enabled_endpoints_truncated_resp_test) {
  uint8_t short_resp[2] = {0, 0};

  EXPECT_CALL(
      mock_,
      send(_,
           UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                       HOTH_PRV_CMD_GET_ENABLED_I2C_ENDPOINTS_FOR_FILTERING),
           _))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(short_resp, sizeof(short_resp)), Return(LIBHOTH_OK)));

  struct hoth_response_i2c_endpoints_enabled_for_filtering resp = {};
  size_t resp_len = 0;
  libhoth_error err = libhoth_i2c_filtering_get_enabled_endpoints(
      &hoth_dev_, &resp, sizeof(resp), &resp_len);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), LIBHOTH_ERR_FAIL);
}
