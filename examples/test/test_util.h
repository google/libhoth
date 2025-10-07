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
#include <vector>

#include "examples/host_commands.h"
#include "examples/htool.h"
#include "examples/htool_cmd.h"
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
};

// Declare an instance of htool_get_security_version for unit tests to define
// there own version of this function.
// This decleration is needed for code(e.g. htool_provisioning.c), where it
// is used but not defined.
// The definition exists in the calling tests (e.g. htool_provisioning_test.cc)
libhoth_security_version htool_get_security_version(struct libhoth_device* dev);

#endif  // LIBHOTH_EXAMPLES_TEST_TEST_UTIL_H_
