#ifndef LIBHOTH_EXAMPLES_TEST_TEST_UTIL_H_
#define LIBHOTH_EXAMPLES_TEST_TEST_UTIL_H_

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

#include "examples/host_commands.h"
#include "examples/htool.h"
#include "examples/htool_cmd.h"
#include "examples/htool_security_v2.h"
#include "examples/htool_security_version.h"
#include "protocol/host_cmd.h"
#include "protocol/test/libhoth_device_mock.h"
#include "transports/libhoth_device.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::SetArrayArgument;

// Prints a memory block of a given size in hexadecimal format.
std::string print_hex_dump(const void* data_ptr, size_t size_bytes);

// Custom matcher for the send data
MATCHER_P2(MatchesSentData, expected_data, expected_size, "") {
  if (!arg) {
    *result_listener << "sent_data is NULL";
    return false;
  }
  if (memcmp(arg, expected_data.data(), expected_size) != 0) {
    *result_listener << "sent data does not match expected data\n"
                     << "EXPECTED: "
                     << print_hex_dump(expected_data.data(), expected_size)
                     << "\n"
                     << "ACTUAL:   " << print_hex_dump(arg, expected_size);
    return false;
  }
  return true;
}

// Mocking htool_invocation and its functions
class HtoolInvocationMock {
 public:
  virtual ~HtoolInvocationMock() = default;
  MOCK_METHOD(int, GetParamString,
              (const std::string& name, const char** value));
  MOCK_METHOD(int, GetParamU32, (const std::string& name, uint32_t* value));
};

// Declare an instance of htool_get_security_version for unit tests to define
// there own version of this function.
// This decleration is needed for code(e.g. htool_provisioning.c), where it
// is used but not defined.
// The definition exists in the calling tests (e.g. htool_provisioning_test.cc)
libhoth_security_version htool_get_security_version(struct libhoth_device* dev);

// Mock for htool_exec_security_v2_cmd
class HtoolSecurityV2Mock {
 public:
  virtual ~HtoolSecurityV2Mock() = default;
  MOCK_METHOD(int, htool_exec_security_v2_cmd,
              (struct libhoth_device * dev, uint8_t major, uint8_t minor,
               uint16_t base_command,
               struct security_v2_buffer* request_buffer,
               const struct security_v2_param* request_params,
               uint16_t request_param_count,
               struct security_v2_buffer* response_buffer,
               struct security_v2_param* response_params,
               uint16_t response_param_count));
};

// Custom matcher for htool_exec_security_v2_cmd arguments.
MATCHER_P5(IsSecurityV2Command, expected_major, expected_minor,
           expected_base_command, expected_request_buffer_size,
           expected_response_buffer_size, "") {
  if (std::get<1>(arg) != expected_major) {
    *result_listener << "major is " << (int)std::get<1>(arg) << ", expected "
                     << (int)expected_major;
    return false;
  }
  if (std::get<2>(arg) != expected_minor) {
    *result_listener << "minor is " << (int)std::get<2>(arg) << ", expected "
                     << (int)expected_minor;
    return false;
  }
  if (std::get<3>(arg) != expected_base_command) {
    *result_listener << "base_command is " << std::get<3>(arg)
                     << ", expected " << expected_base_command;
    return false;
  }
  const struct security_v2_buffer* request_buffer = std::get<4>(arg);
  if (request_buffer == nullptr) {
    *result_listener << "request_buffer is null";
    return false;
  }
  if (request_buffer->size != expected_request_buffer_size) {
    *result_listener << "request_buffer->size is " << request_buffer->size
                     << ", expected " << expected_request_buffer_size;
    return false;
  }
  if (request_buffer->data == nullptr) {
    *result_listener << "request_buffer->data is null";
    return false;
  }
  const struct security_v2_buffer* response_buffer = std::get<7>(arg);
  if (response_buffer == nullptr) {
    *result_listener << "response_buffer is null";
    return false;
  }
  if (response_buffer->size != expected_response_buffer_size) {
    *result_listener << "response_buffer->size is " << response_buffer->size
                     << ", expected " << expected_response_buffer_size;
    return false;
  }
  if (response_buffer->data == nullptr) {
    *result_listener << "response_buffer->data is null";
    return false;
  }
  return true;
}


#endif  // LIBHOTH_EXAMPLES_TEST_TEST_UTIL_H_
