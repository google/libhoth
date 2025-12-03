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
#include "htool_cmd.h"
#include "htool_security_v2.h"
#include "htool_security_version.h"
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

// Mock for htool_exec_security_v2_serialized_cmd
class HtoolSecurityV2SerializedMock {
 public:
  virtual ~HtoolSecurityV2SerializedMock() = default;
  MOCK_METHOD(int, htool_exec_security_v2_serialized_cmd,
              (struct libhoth_device * dev, uint8_t major, uint8_t minor,
               uint16_t base_command,
               struct security_v2_buffer* request_buffer,
               const struct security_v2_param* request_params,
               uint16_t request_param_count,
               struct security_v2_buffer* response_buffer,
               const struct security_v2_serialized_param** response_params[],
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

// Custom matcher for htool_exec_security_v2_serialized_cmd arguments.
MATCHER_P5(IsSecurityV2SerializedCommand, expected_major, expected_minor,
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

// Custom matcher for security_v2_param arrays.
MATCHER_P(RequestParamsMatch, expected_params, "") {
  const struct security_v2_param* request_params = std::get<5>(arg);
  uint16_t request_param_count = std::get<6>(arg);

  if (request_param_count != expected_params.size()) {
    *result_listener << "request_param_count is " << request_param_count
                     << ", expected " << expected_params.size();
    return false;
  }

  for (size_t i = 0; i < expected_params.size(); ++i) {
    if (request_params[i].size != expected_params[i].size) {
      *result_listener << "request_params[" << i << "].size is "
                       << request_params[i].size << ", expected "
                       << expected_params[i].size;
      return false;
    }
   // We are not comparing the request data since most of the security_v2_param
   // are randomly generated, so there is no value in comparing the data.
  }
  return true;
}

ACTION_P(SetSerializedV2TokenResponse, tokens) {
  // arg7 is response_buffer, arg8 is response_params
  struct security_v2_buffer* response_buffer = std::get<7>(args);
  const struct security_v2_serialized_param*** response_params_ptr =
      (const struct security_v2_serialized_param***)std::get<8>(args);

  std::vector<uint8_t> response;
  struct security_v2_serialized_response_hdr hdr = {.param_count = 3,
                                                    .reserved = 0};
  response.insert(response.end(), (uint8_t*)&hdr, (uint8_t*)&hdr + sizeof(hdr));

  // Param 1: tokens
  struct security_v2_serialized_param tokens_param_hdr = {
      .size = (uint16_t)tokens.size(), .reserved = 0};
  response.insert(response.end(), (uint8_t*)&tokens_param_hdr,
                  (uint8_t*)&tokens_param_hdr + sizeof(tokens_param_hdr));
  response.insert(response.end(), tokens.begin(), tokens.end());
  size_t padding = padding_size(tokens.size());
  response.insert(response.end(), padding, 0);

  // Param 2: boot_nonce (dummy)
  struct boot_nonce dummy_nonce = {};
  struct security_v2_serialized_param nonce_param_hdr = {
      .size = sizeof(dummy_nonce), .reserved = 0};
  response.insert(response.end(), (uint8_t*)&nonce_param_hdr,
                  (uint8_t*)&nonce_param_hdr + sizeof(nonce_param_hdr));
  response.insert(response.end(), (uint8_t*)&dummy_nonce,
                  (uint8_t*)&dummy_nonce + sizeof(dummy_nonce));
  padding = padding_size(sizeof(dummy_nonce));
  response.insert(response.end(), padding, 0);

  // Param 3: signature (dummy)
  struct detached_challenge_response_signature dummy_sig = {};
  struct security_v2_serialized_param sig_param_hdr = {.size = sizeof(dummy_sig),
                                                       .reserved = 0};
  response.insert(response.end(), (uint8_t*)&sig_param_hdr,
                  (uint8_t*)&sig_param_hdr + sizeof(sig_param_hdr));
  response.insert(response.end(), (uint8_t*)&dummy_sig,
                  (uint8_t*)&dummy_sig + sizeof(dummy_sig));
  padding = padding_size(sizeof(dummy_sig));
  response.insert(response.end(), padding, 0);

  memcpy(response_buffer->data, response.data(), response.size());
  response_buffer->size = response.size();

  uint8_t* current = response_buffer->data;
  current += sizeof(hdr);  // skip response header

  *response_params_ptr[0] =
      (const struct security_v2_serialized_param*)current;
  current += sizeof(tokens_param_hdr) + tokens_param_hdr.size +
             padding_size(tokens_param_hdr.size);

  *response_params_ptr[1] =
      (const struct security_v2_serialized_param*)current;
  current += sizeof(nonce_param_hdr) + nonce_param_hdr.size +
             padding_size(nonce_param_hdr.size);

  *response_params_ptr[2] =
      (const struct security_v2_serialized_param*)current;
}

ACTION_P3(SetSecurityV2Response, num_ids, boot_nonce, signature) {
  // arg8 is response_params
  struct security_v2_param* response_params =
      (struct security_v2_param*)std::get<8>(args);
  memcpy(response_params[0].data, &num_ids, sizeof(num_ids));
  memcpy(response_params[1].data, &boot_nonce, sizeof(boot_nonce));
  memcpy(response_params[2].data, &signature, sizeof(signature));
}

ACTION_P(SetSecurityV2TokenSetInfoResponse, info) {
  // arg8 is response_params
  struct security_v2_param* response_params =
      (struct security_v2_param*)std::get<8>(args);
  memcpy(response_params[0].data, &info, sizeof(struct token_set_info));
  struct boot_nonce dummy_nonce = {};
  memcpy(response_params[1].data, &dummy_nonce, sizeof(dummy_nonce));
  struct detached_challenge_response_signature dummy_sig = {};
  memcpy(response_params[2].data, &dummy_sig, sizeof(dummy_sig));
}

ACTION_P(SetHostCmdResponse, response_data) {
  // Corresponds to hostcmd_exec(dev, command, version, request, request_size,
  //                            response, response_size, bytes_read)
  void* response_buffer = arg5;
  size_t response_size = arg6;
  size_t* bytes_read = arg7;

  ASSERT_LE(response_data.size(), response_size);
  memcpy(response_buffer, response_data.data(), response_data.size());
  *bytes_read = response_data.size();
}

#endif  // LIBHOTH_EXAMPLES_TEST_TEST_UTIL_H_
