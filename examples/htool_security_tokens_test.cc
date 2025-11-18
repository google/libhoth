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

#include "htool_security_tokens.h"

#include <errno.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include "examples/test/test_util.h"
#include "htool_security_v2.h"
#include "htool_security_version.h"
#include "protocol/test/libhoth_device_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::SetArrayArgument;

static HtoolInvocationMock* g_htool_invocation_mock = nullptr;
static HtoolSecurityV2Mock* g_htool_security_v2_mock = nullptr;
static HtoolSecurityV2SerializedMock* g_htool_security_v2_serialized_mock =
    nullptr;

extern "C" int htool_get_param_string(const struct htool_invocation* inv,
                                      const char* name, const char** value) {
  if (g_htool_invocation_mock) {
    return g_htool_invocation_mock->GetParamString(name, value);
  }
  return -1;
}

extern "C" int htool_get_param_u32(const struct htool_invocation* inv,
                                   const char* name, uint32_t* value) {
  if (g_htool_invocation_mock) {
    return g_htool_invocation_mock->GetParamU32(name, value);
  }
  return -1;
}

extern "C" int htool_exec_security_v2_cmd(
    struct libhoth_device* dev, uint8_t major, uint8_t minor,
    uint16_t base_command, struct security_v2_buffer* request_buffer,
    const struct security_v2_param* request_params,
    uint16_t request_param_count, struct security_v2_buffer* response_buffer,
    struct security_v2_param* response_params, uint16_t response_param_count) {
  if (g_htool_security_v2_mock) {
    return g_htool_security_v2_mock->htool_exec_security_v2_cmd(
        dev, major, minor, base_command, request_buffer, request_params,
        request_param_count, response_buffer, response_params,
        response_param_count);
  }
  return -1;
}

extern "C" int htool_exec_security_v2_serialized_cmd(
    struct libhoth_device* dev, uint8_t major, uint8_t minor,
    uint16_t base_command, struct security_v2_buffer* request_buffer,
    const struct security_v2_param* request_params,
    uint16_t request_param_count, struct security_v2_buffer* response_buffer,
    const struct security_v2_serialized_param** response_params[],
    uint16_t response_param_count) {
  if (g_htool_security_v2_serialized_mock) {
    return g_htool_security_v2_serialized_mock
        ->htool_exec_security_v2_serialized_cmd(
            dev, major, minor, base_command, request_buffer, request_params,
            request_param_count, response_buffer, response_params,
            response_param_count);
  }
  return -1;
}

// Mocking htool_libhoth_device
struct libhoth_device* mock_dev = nullptr;
struct libhoth_device* htool_libhoth_device() { return mock_dev; }

// Mocking htool_get_security_version
static libhoth_security_version mock_security_version = LIBHOTH_SECURITY_V2;
libhoth_security_version htool_get_security_version(
    struct libhoth_device* dev) {
  return mock_security_version;
}

class HtoolSecurityTokensTest : public LibHothTest {
 protected:
  void SetUp() override {
    tmp_dir_path_.clear();
    mock_dev = &hoth_dev_;
    g_htool_invocation_mock = &invocation_mock_;
    g_htool_security_v2_mock = &security_v2_mock_;
    g_htool_security_v2_serialized_mock = &security_v2_serialized_mock_;
    // To support multiple build systems, check for TEST_TMPDIR (used by
    // Bazel) first, then MESON_BUILD_ROOT (used by Meson). If neither is
    // set, default to the current directory.
    std::string build_root;
    const char* test_tmpdir = std::getenv("TEST_TMPDIR");
    const char* meson_root = std::getenv("MESON_BUILD_ROOT");

    if (test_tmpdir != nullptr) {
      build_root = test_tmpdir;
    } else if (meson_root != nullptr) {
      build_root = meson_root;
    } else {
      build_root = ".";
    }
    std::string tmpl = build_root + "/htool_security_tokens_test_dir.XXXXXX";
    ASSERT_NE(mkdtemp(&tmpl[0]), nullptr)
        << "mkdtemp failed: " << strerror(errno);
    tmp_dir_path_ = tmpl;
  }

  void TearDown() override {
    g_htool_invocation_mock = nullptr;
    g_htool_security_v2_mock = nullptr;
    g_htool_security_v2_serialized_mock = nullptr;
    mock_dev = nullptr;
    if (!tmp_dir_path_.empty()) {
      std::filesystem::remove_all(tmp_dir_path_);
    }
  }

  HtoolInvocationMock invocation_mock_;
  HtoolSecurityV2Mock security_v2_mock_;
  HtoolSecurityV2SerializedMock security_v2_serialized_mock_;
  std::string tmp_dir_path_;
};


TEST_F(HtoolSecurityTokensTest, GetTokensInSetSuccess) {
  struct htool_invocation inv {};
  std::string tmp_output_file =
      tmp_dir_path_ + "/tokens.GetTokensInSetSuccess.bin";
  std::string tmp_boot_nonce_file =
      tmp_dir_path_ + "/boot_nonce.GetTokensInSetSuccess.bin";
  std::string tmp_signature_file =
      tmp_dir_path_ + "/signature.GetTokensInSetSuccess.bin";

  EXPECT_CALL(invocation_mock_, GetParamString("token_output", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_output_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("signature_output", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_signature_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("boot_nonce_output", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_boot_nonce_file.c_str()), Return(0)));

  uint32_t set_idx = 5;
  EXPECT_CALL(invocation_mock_, GetParamU32("set_index", _))
      .WillOnce(DoAll(SetArgPointee<1>(set_idx), Return(0)));

  struct nonce challenge = {};
  memset(&challenge, 0xAB, sizeof(challenge));

  std::vector<uint8_t> tokens(TOKEN_BYTE_SIZE * 3);  // 3 tokens
  for (size_t i = 0; i < tokens.size(); ++i) {
    tokens[i] = i;
  }

  std::vector<struct security_v2_param> expected_params;
  expected_params.push_back({.data = &set_idx, .size = sizeof(set_idx)});
  expected_params.push_back({.data = &challenge, .size = sizeof(challenge)});

  EXPECT_CALL(security_v2_serialized_mock_,
              htool_exec_security_v2_serialized_cmd(_, _, _, _, _, _, _, _, _,
                                                    _))
      .With(RequestParamsMatch(expected_params))
      .WillOnce(DoAll(SetSerializedV2TokenResponse(tokens), Return(0)));

  ASSERT_EQ(htool_get_tokens_in_set(&inv), 0);

  // Verify output file
  FILE* fp = fopen(tmp_output_file.c_str(), "rb");
  ASSERT_NE(fp, nullptr);
  std::vector<uint8_t> file_contents(tokens.size());
  ASSERT_EQ(fread(file_contents.data(), 1, tokens.size(), fp), tokens.size());
  EXPECT_EQ(memcmp(file_contents.data(), tokens.data(), tokens.size()), 0);
  fclose(fp);
}

TEST_F(HtoolSecurityTokensTest, GetTokensInSetCommandFailure) {
  struct htool_invocation inv {};
  std::string tmp_output_file = tmp_dir_path_ + "/tokens.GetTokensInSetCommandFailure.bin";
  std::string tmp_signature_file = tmp_dir_path_ + "/signature.GetTokensInSetCommandFailure.bin";
  std::string tmp_boot_nonce_file = tmp_dir_path_ + "/boot_nonce.GetTokensInSetCommandFailure.bin";


  EXPECT_CALL(invocation_mock_, GetParamString("token_output", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_output_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("signature_output", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_signature_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("boot_nonce_output", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_boot_nonce_file.c_str()), Return(0)));

  uint32_t set_idx = 5;
  EXPECT_CALL(invocation_mock_, GetParamU32("set_index", _))
      .WillOnce(DoAll(SetArgPointee<1>(set_idx), Return(0)));

  struct nonce challenge = {};
  memset(&challenge, 0xAB, sizeof(challenge));

  std::vector<struct security_v2_param> expected_params;
  expected_params.push_back({.data = &set_idx, .size = sizeof(set_idx)});
  expected_params.push_back({.data = &challenge, .size = sizeof(challenge)});

  EXPECT_CALL(security_v2_serialized_mock_,
              htool_exec_security_v2_serialized_cmd(_, _, _, _, _, _, _, _, _,
                                                    _))
      .With(RequestParamsMatch(expected_params))
      .WillOnce(Return(-1)); // Simulate command failure

  EXPECT_EQ(htool_get_tokens_in_set(&inv), -1);
}

TEST_F(HtoolSecurityTokensTest, GetTokenSetCountSuccess) {
  struct htool_invocation inv {};
  std::string num_ids_file = tmp_dir_path_ + "/num_ids.bin";
  std::string boot_nonce_file = tmp_dir_path_ + "/boot_nonce.bin";
  std::string signature_file = tmp_dir_path_ + "/signature.bin";

  EXPECT_CALL(invocation_mock_, GetParamString("num_ids_output", _))
      .WillOnce(DoAll(SetArgPointee<1>(num_ids_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("boot_nonce_output", _))
      .WillOnce(DoAll(SetArgPointee<1>(boot_nonce_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("signature_output", _))
      .WillOnce(DoAll(SetArgPointee<1>(signature_file.c_str()), Return(0)));

  uint32_t num_ids = 10;
  struct boot_nonce boot_nonce = {};
  memset(&boot_nonce, 0xBB, sizeof(boot_nonce));
  struct detached_challenge_response_signature signature = {};
  memset(&signature, 0xCC, sizeof(signature));


  struct nonce challenge = {};
  memset(&challenge, 0xAB, sizeof(challenge));

  std::vector<struct security_v2_param> expected_params;
  expected_params.push_back({.data = &challenge, .size = sizeof(struct nonce)});

  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .With(RequestParamsMatch(expected_params))
      .WillOnce(DoAll(SetSecurityV2Response(num_ids, boot_nonce, signature),
                      Return(0)));

  ASSERT_EQ(htool_get_token_set_count(&inv), 0);

  // Verify output files
  FILE* fp_num_ids = fopen(num_ids_file.c_str(), "rb");
  ASSERT_NE(fp_num_ids, nullptr);
  uint32_t read_num_ids;
  ASSERT_EQ(fread(&read_num_ids, sizeof(read_num_ids), 1, fp_num_ids), 1);
  EXPECT_EQ(read_num_ids, num_ids);
  fclose(fp_num_ids);

  FILE* fp_boot_nonce = fopen(boot_nonce_file.c_str(), "rb");
  ASSERT_NE(fp_boot_nonce, nullptr);
  struct boot_nonce read_boot_nonce;
  ASSERT_EQ(fread(&read_boot_nonce, sizeof(read_boot_nonce), 1, fp_boot_nonce),
            1);
  EXPECT_EQ(memcmp(&read_boot_nonce, &boot_nonce, sizeof(boot_nonce)), 0);
  fclose(fp_boot_nonce);

  FILE* fp_signature = fopen(signature_file.c_str(), "rb");
  ASSERT_NE(fp_signature, nullptr);
  struct detached_challenge_response_signature read_signature;
  ASSERT_EQ(
      fread(&read_signature, sizeof(read_signature), 1, fp_signature), 1);
  EXPECT_EQ(memcmp(&read_signature, &signature, sizeof(signature)), 0);
  fclose(fp_signature);
}

TEST_F(HtoolSecurityTokensTest, GetTokenSetCountCommandFailure) {
  struct htool_invocation inv {};
  std::string num_ids_file = tmp_dir_path_ + "/num_ids.GetTokenSetCountCommandFailure.bin";
  std::string boot_nonce_file = tmp_dir_path_ + "/boot_nonce.GetTokenSetCountCommandFailure.bin";
  std::string signature_file = tmp_dir_path_ + "/signature.GetTokenSetCountCommandFailure.bin";

  EXPECT_CALL(invocation_mock_, GetParamString("num_ids_output", _))
      .WillOnce(DoAll(SetArgPointee<1>(num_ids_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("boot_nonce_output", _))
      .WillOnce(DoAll(SetArgPointee<1>(boot_nonce_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("signature_output", _))
      .WillOnce(DoAll(SetArgPointee<1>(signature_file.c_str()), Return(0)));

  struct nonce challenge = {};
  memset(&challenge, 0xAB, sizeof(challenge));

  std::vector<struct security_v2_param> expected_params;
  expected_params.push_back({.data = &challenge, .size = sizeof(struct nonce)});

  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .With(RequestParamsMatch(expected_params))
      .WillOnce(Return(-1)); // Simulate command failure

  EXPECT_EQ(htool_get_token_set_count(&inv), -1);
}

TEST_F(HtoolSecurityTokensTest, GetTokenSetInfoSuccess) {
  struct htool_invocation inv {};
  std::string tmp_info_file =
      tmp_dir_path_ + "/info.GetTokenSetInfoSuccess.bin";

  EXPECT_CALL(invocation_mock_, GetParamString("token_set_info", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_info_file.c_str()), Return(0)));

  uint32_t set_idx = 5;
  EXPECT_CALL(invocation_mock_, GetParamU32("set_index", _))
      .WillOnce(DoAll(SetArgPointee<1>(set_idx), Return(0)));

  struct nonce challenge = {};
  memset(&challenge, 0xAB, sizeof(challenge));

  struct token_set_info info = {
      .category = 1,
      .num_tokens = 2,
      .is_frozen = 1,
      .reserved_0 = {0},
  };

  std::vector<struct security_v2_param> expected_params;
  expected_params.push_back({.data = &set_idx, .size = sizeof(set_idx)});
  expected_params.push_back({.data = &challenge, .size = sizeof(challenge)});

  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .With(RequestParamsMatch(expected_params))
      .WillOnce(DoAll(SetSecurityV2TokenSetInfoResponse(info), Return(0)));

  ASSERT_EQ(htool_get_token_set_info(&inv), 0);

  // Verify output file
  FILE* fp = fopen(tmp_info_file.c_str(), "rb");
  ASSERT_NE(fp, nullptr);
  struct token_set_info read_info;
  ASSERT_EQ(fread(&read_info, sizeof(read_info), 1, fp), 1);
  EXPECT_EQ(memcmp(&read_info, &info, sizeof(info)), 0);
  fclose(fp);
}

TEST_F(HtoolSecurityTokensTest, GetTokenSetInfoCommandFailure) {
  struct htool_invocation inv {};
  std::string tmp_info_file = tmp_dir_path_ + "/info.GetTokenSetInfoCommandFailure.bin";

  EXPECT_CALL(invocation_mock_, GetParamString("token_set_info", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_info_file.c_str()), Return(0)));

  uint32_t set_idx = 5;
  EXPECT_CALL(invocation_mock_, GetParamU32("set_index", _))
      .WillOnce(DoAll(SetArgPointee<1>(set_idx), Return(0)));

  struct nonce challenge = {};
  memset(&challenge, 0xAB, sizeof(challenge));

  std::vector<struct security_v2_param> expected_params;
  expected_params.push_back({.data = &set_idx, .size = sizeof(set_idx)});
  expected_params.push_back({.data = &challenge, .size = sizeof(challenge)});

  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .With(RequestParamsMatch(expected_params))
      .WillOnce(Return(-1)); // Simulate command failure

  EXPECT_EQ(htool_get_token_set_info(&inv), -1);
}
