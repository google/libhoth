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

TEST_F(HtoolSecurityTokensTest, FetchAttestationSuccess) {
  struct htool_invocation inv{};
  std::string token_output_file_base = tmp_dir_path_ + "/tokens.bin";
  std::string signature_output_file_base =
      tmp_dir_path_ + "/token_signature.bin";
  std::string boot_nonce_output_file_base =
      tmp_dir_path_ + "/token_boot_nonce.bin";
  std::string token_set_info_file_base = tmp_dir_path_ + "/token_set_info.bin";
  std::string token_count_output_file = tmp_dir_path_ + "/token_count.bin";
  std::string token_count_boot_nonce_output_file =
      tmp_dir_path_ + "/token_count_boot_nonce.bin";
  std::string token_count_signature_output_file =
      tmp_dir_path_ + "/token_count_signature.bin";

  EXPECT_CALL(invocation_mock_, GetParamString("attestation_file", _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(""), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("token_output", _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(token_output_file_base.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("token_signature_output", _))
      .WillRepeatedly(DoAll(
          SetArgPointee<1>(signature_output_file_base.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("token_boot_nonce_output", _))
      .WillRepeatedly(DoAll(
          SetArgPointee<1>(boot_nonce_output_file_base.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("token_set_info", _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(token_set_info_file_base.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("token_count_output", _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(token_count_output_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_,
              GetParamString("token_count_boot_nonce_output", _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(token_count_boot_nonce_output_file.c_str()),
                Return(0)));
  EXPECT_CALL(invocation_mock_,
              GetParamString("token_count_signature_output", _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(token_count_signature_output_file.c_str()),
                Return(0)));

  // Mock for htool_get_token_set_count
  uint32_t num_ids = 2;
  struct boot_nonce boot_nonce = {};
  memset(&boot_nonce, 0xBB, sizeof(boot_nonce));
  struct detached_challenge_response_signature signature = {};
  memset(&signature, 0xCC, sizeof(signature));

  // Mock for htool_get_token_set_info
  struct token_set_info info = {
      .category = 1,
      .num_tokens = 2,
      .is_frozen = 1,
      .reserved_0 = {0},
  };

  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SetSecurityV2Response(num_ids, boot_nonce, signature),
                      Return(0)))
      .WillRepeatedly(
          DoAll(SetSecurityV2TokenSetInfoResponse(info), Return(0)));

  // Mock for htool_get_tokens_in_set
  std::vector<uint8_t> tokens(TOKEN_BYTE_SIZE * 3);  // 3 tokens
  for (size_t i = 0; i < tokens.size(); ++i) {
    tokens[i] = i;
  }
  EXPECT_CALL(
      security_v2_serialized_mock_,
      htool_exec_security_v2_serialized_cmd(_, _, _, _, _, _, _, _, _, _))
      .Times(num_ids)
      .WillRepeatedly(DoAll(SetSerializedV2TokenResponse(tokens), Return(0)));

  ASSERT_EQ(htool_fetch_attestation(&inv), 0);

  for (uint32_t i = 0; i < num_ids; ++i) {
    std::string suffix = std::to_string(i);
    // Verify tokens file
    std::string token_file = token_output_file_base + suffix;
    FILE* fp_token = fopen(token_file.c_str(), "rb");
    ASSERT_NE(fp_token, nullptr) << "Failed to open " << token_file;
    std::vector<uint8_t> token_contents(tokens.size());
    ASSERT_EQ(fread(token_contents.data(), 1, tokens.size(), fp_token),
              tokens.size());
    EXPECT_EQ(memcmp(token_contents.data(), tokens.data(), tokens.size()), 0);
    fclose(fp_token);

    // Verify token set info file
    std::string info_file = token_set_info_file_base + suffix;
    FILE* fp_info = fopen(info_file.c_str(), "rb");
    ASSERT_NE(fp_info, nullptr) << "Failed to open " << info_file;
    struct token_set_info read_info;
    ASSERT_EQ(fread(&read_info, sizeof(read_info), 1, fp_info), 1);
    EXPECT_EQ(memcmp(&read_info, &info, sizeof(info)), 0);
    fclose(fp_info);
  }
}

TEST_F(HtoolSecurityTokensTest, FetchAttestationGetCountFails) {
  struct htool_invocation inv{};

  std::string token_count_output_file = tmp_dir_path_ + "/token_count.bin";
  std::string token_count_boot_nonce_output_file =
      tmp_dir_path_ + "/token_count_boot_nonce.bin";
  std::string token_count_signature_output_file =
      tmp_dir_path_ + "/token_count_signature.bin";

  EXPECT_CALL(invocation_mock_, GetParamString("attestation_file", _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(""), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("token_count_output", _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(token_count_output_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_,
              GetParamString("token_count_boot_nonce_output", _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(token_count_boot_nonce_output_file.c_str()),
                Return(0)));
  EXPECT_CALL(invocation_mock_,
              GetParamString("token_count_signature_output", _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(token_count_signature_output_file.c_str()),
                Return(0)));

  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(Return(-1));

  ASSERT_NE(htool_fetch_attestation(&inv), 0);
}

TEST_F(HtoolSecurityTokensTest, FetchAttestationGetTokensFails) {
  struct htool_invocation inv{};
  std::string token_output_file_base = tmp_dir_path_ + "/tokens.bin";
  std::string signature_output_file_base =
      tmp_dir_path_ + "/token_signature.bin";
  std::string boot_nonce_output_file_base =
      tmp_dir_path_ + "/token_boot_nonce.bin";
  std::string token_count_output_file = tmp_dir_path_ + "/token_count.bin";
  std::string token_count_boot_nonce_output_file =
      tmp_dir_path_ + "/token_count_boot_nonce.bin";
  std::string token_count_signature_output_file =
      tmp_dir_path_ + "/token_count_signature.bin";

  EXPECT_CALL(invocation_mock_, GetParamString("attestation_file", _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(""), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("token_count_output", _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(token_count_output_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_,
              GetParamString("token_count_boot_nonce_output", _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(token_count_boot_nonce_output_file.c_str()),
                Return(0)));
  EXPECT_CALL(invocation_mock_,
              GetParamString("token_count_signature_output", _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(token_count_signature_output_file.c_str()),
                Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("token_output", _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(token_output_file_base.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("token_signature_output", _))
      .WillRepeatedly(DoAll(
          SetArgPointee<1>(signature_output_file_base.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("token_boot_nonce_output", _))
      .WillRepeatedly(DoAll(
          SetArgPointee<1>(boot_nonce_output_file_base.c_str()), Return(0)));

  // Mock for htool_get_token_set_count
  uint32_t num_ids = 2;
  struct boot_nonce boot_nonce = {};
  struct detached_challenge_response_signature signature = {};
  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SetSecurityV2Response(num_ids, boot_nonce, signature),
                      Return(0)));

  // Mock for htool_get_tokens_in_set to fail
  EXPECT_CALL(
      security_v2_serialized_mock_,
      htool_exec_security_v2_serialized_cmd(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(Return(-1));

  ASSERT_NE(htool_fetch_attestation(&inv), 0);
}

TEST_F(HtoolSecurityTokensTest, FetchAttestationGetInfoFails) {
  struct htool_invocation inv{};
  std::string token_output_file_base = tmp_dir_path_ + "/tokens.bin";
  std::string signature_output_file_base =
      tmp_dir_path_ + "/token_signature.bin";
  std::string boot_nonce_output_file_base =
      tmp_dir_path_ + "/token_boot_nonce.bin";
  std::string token_set_info_file_base = tmp_dir_path_ + "/token_set_info.bin";
  std::string token_count_output_file = tmp_dir_path_ + "/token_count.bin";
  std::string token_count_boot_nonce_output_file =
      tmp_dir_path_ + "/token_count_boot_nonce.bin";
  std::string token_count_signature_output_file =
      tmp_dir_path_ + "/token_count_signature.bin";

  EXPECT_CALL(invocation_mock_, GetParamString("attestation_file", _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(""), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("token_output", _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(token_output_file_base.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("token_signature_output", _))
      .WillRepeatedly(DoAll(
          SetArgPointee<1>(signature_output_file_base.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("token_boot_nonce_output", _))
      .WillRepeatedly(DoAll(
          SetArgPointee<1>(boot_nonce_output_file_base.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("token_set_info", _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(token_set_info_file_base.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("token_count_output", _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(token_count_output_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_,
              GetParamString("token_count_boot_nonce_output", _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(token_count_boot_nonce_output_file.c_str()),
                Return(0)));
  EXPECT_CALL(invocation_mock_,
              GetParamString("token_count_signature_output", _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(token_count_signature_output_file.c_str()),
                Return(0)));

  // Mock for htool_get_token_set_count
  uint32_t num_ids = 2;
  struct boot_nonce boot_nonce = {};
  struct detached_challenge_response_signature signature = {};
  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SetSecurityV2Response(num_ids, boot_nonce, signature),
                      Return(0)))
      .WillOnce(Return(-1));

  // Mock for htool_get_tokens_in_set to succeed
  std::vector<uint8_t> tokens(TOKEN_BYTE_SIZE * 3);  // 3 tokens
  EXPECT_CALL(
      security_v2_serialized_mock_,
      htool_exec_security_v2_serialized_cmd(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SetSerializedV2TokenResponse(tokens), Return(0)));

  ASSERT_NE(htool_fetch_attestation(&inv), 0);
}

TEST_F(HtoolSecurityTokensTest, FetchAttestationSuccessWithAttestationFile) {
  struct htool_invocation inv{};
  std::string attestation_file = tmp_dir_path_ + "/attestation.bin";
  std::string token_output_file_base = tmp_dir_path_ + "/tokens.bin";
  std::string signature_output_file_base =
      tmp_dir_path_ + "/token_signature.bin";
  std::string boot_nonce_output_file_base =
      tmp_dir_path_ + "/token_boot_nonce.bin";

  EXPECT_CALL(invocation_mock_, GetParamString("attestation_file", _))
      .WillOnce(DoAll(SetArgPointee<1>(attestation_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("token_output", _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(token_output_file_base.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("token_signature_output", _))
      .WillRepeatedly(DoAll(
          SetArgPointee<1>(signature_output_file_base.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("token_boot_nonce_output", _))
      .WillRepeatedly(DoAll(
          SetArgPointee<1>(boot_nonce_output_file_base.c_str()), Return(0)));

  // Mock for htool_get_token_set_count
  uint32_t num_ids = 1;
  struct boot_nonce boot_nonce = {};
  memset(&boot_nonce, 0xBB, sizeof(boot_nonce));
  struct detached_challenge_response_signature signature = {};
  memset(&signature, 0xCC, sizeof(signature));

  // Mock for htool_get_token_set_info
  struct token_set_info info = {
      .category = 1,
      .num_tokens = 2,
      .is_frozen = 1,
      .reserved_0 = {0},
  };

  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SetSecurityV2Response(num_ids, boot_nonce, signature),
                      Return(0)))
      .WillOnce(DoAll(SetSecurityV2TokenSetInfoResponse(info), Return(0)));

  // Mock for htool_get_tokens_in_set
  std::vector<uint8_t> tokens(TOKEN_BYTE_SIZE * 2);
  for (size_t i = 0; i < tokens.size(); ++i) {
    tokens[i] = i;
  }

  EXPECT_CALL(
      security_v2_serialized_mock_,
      htool_exec_security_v2_serialized_cmd(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SetSerializedV2TokenResponse(tokens), Return(0)));

  ASSERT_EQ(htool_fetch_attestation(&inv), 0);

  // Verify file contents
  FILE* fp = fopen(attestation_file.c_str(), "rb");
  ASSERT_NE(fp, nullptr);

  fseek(fp, 0, SEEK_END);
  long file_size = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  std::vector<uint8_t> file_contents(file_size);
  ASSERT_EQ(fread(file_contents.data(), 1, file_size, fp), file_size);
  fclose(fp);

  // The expected size is the sum of all data written to the buffer.
  size_t expected_size = sizeof(num_ids) + sizeof(boot_nonce) +
                         sizeof(signature) + tokens.size() +
                         sizeof(boot_nonce) + sizeof(signature) + sizeof(info);
  ASSERT_EQ(file_contents.size(), expected_size);
}
