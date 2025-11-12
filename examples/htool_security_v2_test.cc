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

  int status = htool_exec_security_v2_cmd(
      mock_dev, 1, 2, 3, &request_buffer, request_params, 1, &response_buffer,
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

  EXPECT_CALL(mock_, hostcmd_exec(_, _, _, _, _, _, _, _))
      .WillOnce(Return(-1));

  int status = htool_exec_security_v2_cmd(
      mock_dev, 1, 2, 3, &request_buffer, nullptr, 0, &response_buffer,
      nullptr, 0);

  ASSERT_EQ(status, -1);
}
