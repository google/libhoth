#include "htool_security_v2.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <vector>

#include "examples/host_commands.h"
#include "examples/test/test_util.h"
#include "protocol/test/libhoth_device_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::SetArrayArgument;

// Mocking htool_libhoth_device
struct libhoth_device* mock_dev = nullptr;
struct libhoth_device* htool_libhoth_device() { return mock_dev; }

int libhoth_hostcmd_exec(struct libhoth_device* dev, uint16_t command,
                         uint8_t version, const void* request,
                         size_t request_size, void* response,
                         size_t max_response_size, size_t* bytes_read) {
  LibHothDeviceMock* mock = (LibHothDeviceMock*)dev->user_ctx;
  return mock->hostcmd_exec(dev, command, version, request, request_size,
                            response, max_response_size, bytes_read);
}

class HtoolSecurityV2Test : public LibHothTest {
 protected:
  void SetUp() override { mock_dev = &hoth_dev_; }

  void TearDown() override { mock_dev = nullptr; }
};

TEST_F(HtoolSecurityV2Test, ExecCmdSuccess) {
  uint8_t request_storage[128];
  uint8_t response_storage[128];
  struct security_v2_buffer request_buffer = {.data = request_storage,
                                              .size = sizeof(request_storage)};
  struct security_v2_buffer response_buffer = {
      .data = response_storage, .size = sizeof(response_storage)};

  // Request
  uint32_t req_param_val = 0xdeadbeef;
  struct security_v2_param request_params[] = {
      {.data = &req_param_val, .size = sizeof(req_param_val)}};

  // Response
  uint8_t resp_param_val[] = {1, 2, 3, 4, 5};
  uint8_t resp_param_buf[sizeof(resp_param_val)] = {0};
  struct security_v2_param response_params[] = {
      {.data = resp_param_buf, .size = sizeof(resp_param_buf)}};

  // Construct expected response from device
  std::vector<uint8_t> device_response;
  struct hoth_security_v2_response_header resp_hdr = {.param_count = 1,
                                                      .reserved = 0};
  device_response.insert(device_response.end(), (uint8_t*)&resp_hdr,
                         (uint8_t*)&resp_hdr + sizeof(resp_hdr));

  struct hoth_security_v2_parameter resp_param_hdr = {
      .size = sizeof(resp_param_val), .reserved = 0};
  device_response.insert(device_response.end(), (uint8_t*)&resp_param_hdr,
                         (uint8_t*)&resp_param_hdr + sizeof(resp_param_hdr));
  device_response.insert(device_response.end(), resp_param_val,
                         resp_param_val + sizeof(resp_param_val));
  size_t padding = padding_size(sizeof(resp_param_val));
  ASSERT_EQ(padding, 3);
  device_response.insert(device_response.end(), padding, 0);

  EXPECT_CALL(mock_, hostcmd_exec(mock_dev, 3, 0, _, _, _, _, _))
      .WillOnce(DoAll(SetHostCmdResponse(device_response), Return(0)));

  int status = htool_exec_security_v2_cmd(mock_dev, 1, 2, 3, &request_buffer,
                                          request_params, 1, &response_buffer,
                                          response_params, 1);

  ASSERT_EQ(status, 0);
  EXPECT_EQ(memcmp(resp_param_buf, resp_param_val, sizeof(resp_param_val)), 0);
}

TEST_F(HtoolSecurityV2Test, ExecCmdHostCmdFailure) {
  uint8_t request_storage[128];
  uint8_t response_storage[128];
  struct security_v2_buffer request_buffer = {.data = request_storage,
                                              .size = sizeof(request_storage)};
  struct security_v2_buffer response_buffer = {
      .data = response_storage, .size = sizeof(response_storage)};

  EXPECT_CALL(mock_, hostcmd_exec(_, _, _, _, _, _, _, _)).WillOnce(Return(-1));

  int status =
      htool_exec_security_v2_cmd(mock_dev, 1, 2, 3, &request_buffer, nullptr, 0,
                                 &response_buffer, nullptr, 0);

  ASSERT_EQ(status, -1);
}

TEST_F(HtoolSecurityV2Test, SerializedCmdSuccess) {
  uint8_t request_storage[128];
  uint8_t response_storage[128];
  struct security_v2_buffer request_buffer = {.data = request_storage,
                                              .size = sizeof(request_storage)};
  struct security_v2_buffer response_buffer = {
      .data = response_storage, .size = sizeof(response_storage)};

  // Construct expected response
  std::vector<uint8_t> response;
  struct security_v2_serialized_response_hdr hdr = {.param_count = 2,
                                                    .reserved = 0};
  response.insert(response.end(), (uint8_t*)&hdr, (uint8_t*)&hdr + sizeof(hdr));

  // Param 1
  uint32_t param1_val = 0xdeadbeef;
  struct security_v2_serialized_param param1_hdr = {.size = sizeof(param1_val),
                                                    .reserved = 0};
  response.insert(response.end(), (uint8_t*)&param1_hdr,
                  (uint8_t*)&param1_hdr + sizeof(param1_hdr));
  response.insert(response.end(), (uint8_t*)&param1_val,
                  (uint8_t*)&param1_val + sizeof(param1_val));
  // No padding for size 4

  // Param 2
  uint8_t param2_val[] = {1, 2, 3, 4, 5};
  struct security_v2_serialized_param param2_hdr = {.size = sizeof(param2_val),
                                                    .reserved = 0};
  response.insert(response.end(), (uint8_t*)&param2_hdr,
                  (uint8_t*)&param2_hdr + sizeof(param2_hdr));
  response.insert(response.end(), param2_val, param2_val + sizeof(param2_val));
  size_t padding2 = padding_size(sizeof(param2_val));
  ASSERT_EQ(padding2, 3);
  response.insert(response.end(), padding2, 0);

  EXPECT_CALL(mock_, hostcmd_exec(mock_dev, 3, 0, _, request_buffer.size, _,
                                  response_buffer.size, _))
      .WillOnce(DoAll(SetHostCmdResponse(response), Return(0)));

  const struct security_v2_serialized_param* param_out1 = nullptr;
  const struct security_v2_serialized_param* param_out2 = nullptr;
  const struct security_v2_serialized_param** response_params[] = {&param_out1,
                                                                   &param_out2};

  int status = htool_exec_security_v2_serialized_cmd(
      mock_dev, 1, 2, 3, &request_buffer, nullptr, 0, &response_buffer,
      response_params, 2);

  ASSERT_EQ(status, 0);
  ASSERT_NE(param_out1, nullptr);
  EXPECT_EQ(param_out1->size, sizeof(param1_val));
  EXPECT_EQ(memcmp(param_out1->value, &param1_val, sizeof(param1_val)), 0);

  ASSERT_NE(param_out2, nullptr);
  EXPECT_EQ(param_out2->size, sizeof(param2_val));
  EXPECT_EQ(memcmp(param_out2->value, param2_val, sizeof(param2_val)), 0);
}

TEST_F(HtoolSecurityV2Test, SerializedCmdExecFailure) {
  uint8_t request_storage[128];
  uint8_t response_storage[128];
  struct security_v2_buffer request_buffer = {.data = request_storage,
                                              .size = sizeof(request_storage)};
  struct security_v2_buffer response_buffer = {
      .data = response_storage, .size = sizeof(response_storage)};

  EXPECT_CALL(mock_, hostcmd_exec(_, _, _, _, _, _, _, _)).WillOnce(Return(-1));

  const struct security_v2_serialized_param* param_out1 = nullptr;
  const struct security_v2_serialized_param** response_params[] = {&param_out1};

  int status = htool_exec_security_v2_serialized_cmd(
      mock_dev, 1, 2, 3, &request_buffer, nullptr, 0, &response_buffer,
      response_params, 1);

  ASSERT_EQ(status, -1);
}

TEST_F(HtoolSecurityV2Test, SerializedCmdWrongParamCount) {
  uint8_t request_storage[128];
  uint8_t response_storage[128];
  struct security_v2_buffer request_buffer = {.data = request_storage,
                                              .size = sizeof(request_storage)};
  struct security_v2_buffer response_buffer = {
      .data = response_storage, .size = sizeof(response_storage)};

  // Construct response with param_count = 1
  std::vector<uint8_t> response;
  struct security_v2_serialized_response_hdr hdr = {.param_count = 1,
                                                    .reserved = 0};
  response.insert(response.end(), (uint8_t*)&hdr, (uint8_t*)&hdr + sizeof(hdr));

  uint32_t param1_val = 0xdeadbeef;
  struct security_v2_serialized_param param1_hdr = {.size = sizeof(param1_val),
                                                    .reserved = 0};
  response.insert(response.end(), (uint8_t*)&param1_hdr,
                  (uint8_t*)&param1_hdr + sizeof(param1_hdr));
  response.insert(response.end(), (uint8_t*)&param1_val,
                  (uint8_t*)&param1_val + sizeof(param1_val));
  EXPECT_CALL(mock_, hostcmd_exec(_, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SetHostCmdResponse(response), Return(0)));

  const struct security_v2_serialized_param* param_out1 = nullptr;
  const struct security_v2_serialized_param* param_out2 = nullptr;
  // We expect 2 params
  const struct security_v2_serialized_param** response_params[] = {&param_out1,
                                                                   &param_out2};

  int status = htool_exec_security_v2_serialized_cmd(
      mock_dev, 1, 2, 3, &request_buffer, nullptr, 0, &response_buffer,
      response_params, 2);

  ASSERT_EQ(status, -1);
}

TEST_F(HtoolSecurityV2Test, SerializedCmdBadPadding) {
  uint8_t request_storage[128];
  uint8_t response_storage[128];
  struct security_v2_buffer request_buffer = {.data = request_storage,
                                              .size = sizeof(request_storage)};
  struct security_v2_buffer response_buffer = {
      .data = response_storage, .size = sizeof(response_storage)};

  // Construct response
  std::vector<uint8_t> response;
  struct security_v2_serialized_response_hdr hdr = {.param_count = 1,
                                                    .reserved = 0};
  response.insert(response.end(), (uint8_t*)&hdr, (uint8_t*)&hdr + sizeof(hdr));

  // Param with non-zero padding
  uint8_t param1_val[] = {1, 2, 3, 4, 5};
  struct security_v2_serialized_param param1_hdr = {.size = sizeof(param1_val),
                                                    .reserved = 0};
  response.insert(response.end(), (uint8_t*)&param1_hdr,
                  (uint8_t*)&param1_hdr + sizeof(param1_hdr));
  response.insert(response.end(), param1_val, param1_val + sizeof(param1_val));
  size_t padding1 = padding_size(sizeof(param1_val));
  ASSERT_EQ(padding1, 3);
  // Add bad padding
  response.push_back(0);
  response.push_back(1);  // non-zero
  response.push_back(0);

  EXPECT_CALL(mock_, hostcmd_exec(_, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SetHostCmdResponse(response), Return(0)));

  const struct security_v2_serialized_param* param_out1 = nullptr;
  const struct security_v2_serialized_param** response_params[] = {&param_out1};

  int status = htool_exec_security_v2_serialized_cmd(
      mock_dev, 1, 2, 3, &request_buffer, nullptr, 0, &response_buffer,
      response_params, 1);

  ASSERT_EQ(status, -1);
}

TEST_F(HtoolSecurityV2Test, SerializedCmdInsufficientBytesForValue) {
  uint8_t request_storage[128];
  uint8_t response_storage[128];
  struct security_v2_buffer request_buffer = {.data = request_storage,
                                              .size = sizeof(request_storage)};
  struct security_v2_buffer response_buffer = {
      .data = response_storage, .size = sizeof(response_storage)};

  // Construct response
  std::vector<uint8_t> response;
  struct security_v2_serialized_response_hdr hdr = {.param_count = 1,
                                                    .reserved = 0};
  response.insert(response.end(), (uint8_t*)&hdr, (uint8_t*)&hdr + sizeof(hdr));

  // Param with size larger than available data
  uint32_t param1_val = 0xdeadbeef;
  struct security_v2_serialized_param param1_hdr = {.size = sizeof(param1_val),
                                                    .reserved = 0};
  response.insert(response.end(), (uint8_t*)&param1_hdr,
                  (uint8_t*)&param1_hdr + sizeof(param1_hdr));
  // Only add 2 bytes of value instead of 4
  response.push_back(0xef);
  response.push_back(0xbe);

  EXPECT_CALL(mock_, hostcmd_exec(_, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SetHostCmdResponse(response), Return(0)));

  const struct security_v2_serialized_param* param_out1 = nullptr;
  const struct security_v2_serialized_param** response_params[] = {&param_out1};

  int status = htool_exec_security_v2_serialized_cmd(
      mock_dev, 1, 2, 3, &request_buffer, nullptr, 0, &response_buffer,
      response_params, 1);

  ASSERT_EQ(status, -1);
}

TEST_F(HtoolSecurityV2Test, CopyParamSuccess) {
  uint8_t param_storage[sizeof(struct security_v2_serialized_param) + 5];
  struct security_v2_serialized_param* param =
      (struct security_v2_serialized_param*)param_storage;
  param->size = 5;
  param->reserved = 0;
  uint8_t value[] = {1, 2, 3, 4, 5};
  memcpy(param->value, value, sizeof(value));

  uint8_t output[5];
  int status = copy_param(param, output, sizeof(output));

  ASSERT_EQ(status, 0);
  EXPECT_EQ(memcmp(output, value, sizeof(value)), 0);
}

TEST_F(HtoolSecurityV2Test, CopyParamSizeMismatch) {
  uint8_t param_storage[sizeof(struct security_v2_serialized_param) + 5];
  struct security_v2_serialized_param* param =
      (struct security_v2_serialized_param*)param_storage;
  param->size = 5;
  param->reserved = 0;
  uint8_t value[] = {1, 2, 3, 4, 5};
  memcpy(param->value, value, sizeof(value));

  uint8_t output[4];  // smaller output buffer
  int status = copy_param(param, output, sizeof(output));

  ASSERT_EQ(status, -1);
}
