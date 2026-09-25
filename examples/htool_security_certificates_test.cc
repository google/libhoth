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

#include "examples/htool_security_certificates.h"

#include <errno.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

#include "examples/test/test_util.h"
#include "htool_security_v2.h"
#include "htool_security_version.h"
#include "protocol/test/libhoth_device_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SetArgPointee;

// Mock for htool_invocation
static HtoolInvocationMock* g_htool_invocation_mock = nullptr;

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

// Mocking htool_libhoth_device
struct libhoth_device* mock_dev = nullptr;
struct libhoth_device* htool_libhoth_device() { return mock_dev; }

// Mocking htool_get_security_version
static libhoth_security_version mock_security_version = LIBHOTH_SECURITY_V2;
libhoth_security_version htool_get_security_version(
    struct libhoth_device* dev) {
  return mock_security_version;
}

// Mock for htool_exec_security_v2_cmd
static HtoolSecurityV2Mock* g_htool_security_v2_mock = nullptr;
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

class HtoolSecurityCertificatesTest : public ::testing::Test {
 protected:
  void SetUp() override {
    tmp_dir_path_.clear();
    mock_dev = &dummy_dev;
    g_htool_invocation_mock = &invocation_mock_;
    g_htool_security_v2_mock = &security_v2_mock_;
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
    std::string tmpl =
        build_root + "/htool_security_certificates_test_dir.XXXXXX";
    ASSERT_NE(mkdtemp(&tmpl[0]), nullptr)
        << "mkdtemp failed: " << strerror(errno);
    tmp_dir_path_ = tmpl;
  }

  void TearDown() override {
    g_htool_invocation_mock = nullptr;
    g_htool_security_v2_mock = nullptr;
    mock_dev = nullptr;
    if (!tmp_dir_path_.empty()) {
      std::filesystem::remove_all(tmp_dir_path_);
    }
  }

  HtoolInvocationMock invocation_mock_;
  HtoolSecurityV2Mock security_v2_mock_;
  std::string tmp_dir_path_;
  struct libhoth_device dummy_dev;
};

TEST_F(HtoolSecurityCertificatesTest, GetAttestationPubCertSuccess) {
  struct htool_invocation inv{};
  std::string tmp_output_file = tmp_dir_path_ + "/attestation_pub_cert.bin";
  EXPECT_CALL(invocation_mock_, GetParamString("output", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_output_file.c_str()), Return(0)));

  uint8_t expected_cert[ATTESTATION_CERT_SIZE] = {};
  for (size_t i = 0; i < sizeof(expected_cert); ++i) {
    ((uint8_t*)&expected_cert)[i] = i;
  }

  EXPECT_CALL(security_v2_mock_, htool_exec_security_v2_cmd)
      .With(IsSecurityV2Command(
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_ATTESTATION_PUB_CERT_MINOR_COMMAND,
          HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          HOTH_SECURITY_V2_REQUEST_SIZE(0),
          HOTH_SECURITY_V2_RESPONSE_SIZE(1) + sizeof(expected_cert)))
      .WillOnce([&](struct libhoth_device* dev, uint8_t major, uint8_t minor,
                    uint16_t base_command,
                    struct security_v2_buffer* request_buffer,
                    const struct security_v2_param* request_params,
                    uint16_t request_param_count,
                    struct security_v2_buffer* response_buffer,
                    struct security_v2_param* response_params,
                    uint16_t response_param_count) {
        EXPECT_EQ(response_param_count, 1);
        EXPECT_EQ(response_params[0].size, sizeof(expected_cert));
        memcpy(response_params[0].data, &expected_cert, sizeof(expected_cert));
        return 0;
      });

  ASSERT_EQ(htool_get_attestation_pub_cert(&inv), 0);

  FILE* fp = fopen(tmp_output_file.c_str(), "rb");
  ASSERT_NE(fp, nullptr);
  uint8_t file_contents[ATTESTATION_CERT_SIZE];
  ASSERT_EQ(fread(&file_contents, 1, sizeof(file_contents), fp),
            sizeof(file_contents));
  EXPECT_EQ(memcmp(&file_contents, &expected_cert, sizeof(expected_cert)), 0);
  fclose(fp);
}

TEST_F(HtoolSecurityCertificatesTest, GetAttestationPubCertCommandFails) {
  struct htool_invocation inv{};
  std::string tmp_output_file = tmp_dir_path_ + "/attestation_pub_cert.bin";
  EXPECT_CALL(invocation_mock_, GetParamString("output", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_output_file.c_str()), Return(0)));

  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(Return(-1));

  EXPECT_EQ(htool_get_attestation_pub_cert(&inv), -1);
}

TEST_F(HtoolSecurityCertificatesTest, GetSignedAttestationPubCertSuccess) {
  struct htool_invocation inv{};
  std::string tmp_output_file =
      tmp_dir_path_ + "/signed_attestation_pub_cert.bin";
  EXPECT_CALL(invocation_mock_, GetParamString("output", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_output_file.c_str()), Return(0)));

  uint8_t expected_cert[ATTESTATION_CERT_SIZE] = {};
  for (size_t i = 0; i < sizeof(expected_cert); ++i) {
    ((uint8_t*)&expected_cert)[i] = i;
  }

  EXPECT_CALL(security_v2_mock_, htool_exec_security_v2_cmd)
      .With(IsSecurityV2Command(
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_SIGNED_ATTESTATION_PUB_CERT_MINOR_COMMAND,
          HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          HOTH_SECURITY_V2_REQUEST_SIZE(0),
          HOTH_SECURITY_V2_RESPONSE_SIZE(1) + sizeof(expected_cert)))
      .WillOnce([&](struct libhoth_device* dev, uint8_t major, uint8_t minor,
                    uint16_t base_command,
                    struct security_v2_buffer* request_buffer,
                    const struct security_v2_param* request_params,
                    uint16_t request_param_count,
                    struct security_v2_buffer* response_buffer,
                    struct security_v2_param* response_params,
                    uint16_t response_param_count) {
        EXPECT_EQ(response_param_count, 1);
        EXPECT_EQ(response_params[0].size, sizeof(expected_cert));
        memcpy(response_params[0].data, &expected_cert, sizeof(expected_cert));
        return 0;
      });

  ASSERT_EQ(htool_get_signed_attestation_pub_cert(&inv), 0);

  FILE* fp = fopen(tmp_output_file.c_str(), "rb");
  ASSERT_NE(fp, nullptr);
  uint8_t file_contents[ATTESTATION_CERT_SIZE];
  ASSERT_EQ(fread(&file_contents, 1, sizeof(file_contents), fp),
            sizeof(file_contents));
  EXPECT_EQ(memcmp(&file_contents, &expected_cert, sizeof(expected_cert)), 0);
  fclose(fp);
}

TEST_F(HtoolSecurityCertificatesTest, GetSignedAttestationPubCertCommandFails) {
  struct htool_invocation inv{};
  std::string tmp_output_file =
      tmp_dir_path_ + "/signed_attestation_pub_cert.bin";
  EXPECT_CALL(invocation_mock_, GetParamString("output", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_output_file.c_str()), Return(0)));

  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(Return(-1));

  EXPECT_EQ(htool_get_signed_attestation_pub_cert(&inv), -1);
}

TEST_F(HtoolSecurityCertificatesTest, GetAliasKeyV0CertSuccess) {
  struct htool_invocation inv{};
  std::string tmp_output_file = tmp_dir_path_ + "/alias_key_v0.bin";
  EXPECT_CALL(invocation_mock_, GetParamString("output", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_output_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamU32("version", _))
      .WillOnce(DoAll(SetArgPointee<1>(0), Return(0)));

  uint8_t expected_key[ALIAS_KEY_V0_SIZE];
  for (size_t i = 0; i < sizeof(expected_key); ++i) {
    expected_key[i] = i;
  }

  EXPECT_CALL(security_v2_mock_, htool_exec_security_v2_cmd)
      .With(IsSecurityV2Command(
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_ALIAS_KEY_MINOR_COMMAND,
          HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          HOTH_SECURITY_V2_REQUEST_SIZE(0),
          HOTH_SECURITY_V2_RESPONSE_SIZE(1) + ALIAS_KEY_V0_SIZE))
      .WillOnce([&](struct libhoth_device* dev, uint8_t major, uint8_t minor,
                    uint16_t base_command,
                    struct security_v2_buffer* request_buffer,
                    const struct security_v2_param* request_params,
                    uint16_t request_param_count,
                    struct security_v2_buffer* response_buffer,
                    struct security_v2_param* response_params,
                    uint16_t response_param_count) {
        EXPECT_EQ(response_param_count, 1);
        EXPECT_EQ(response_params[0].size, ALIAS_KEY_V0_SIZE);
        memcpy(response_params[0].data, expected_key, sizeof(expected_key));
        return 0;
      });

  ASSERT_EQ(htool_get_alias_key_cert(&inv), 0);

  FILE* fp = fopen(tmp_output_file.c_str(), "rb");
  ASSERT_NE(fp, nullptr);
  uint8_t file_contents[ALIAS_KEY_V0_SIZE];
  ASSERT_EQ(fread(file_contents, 1, sizeof(file_contents), fp),
            sizeof(file_contents));
  EXPECT_EQ(memcmp(file_contents, expected_key, sizeof(expected_key)), 0);
  fclose(fp);
}

TEST_F(HtoolSecurityCertificatesTest, GetAliasKeyV1CertSuccess) {
  struct htool_invocation inv{};
  std::string tmp_output_file = tmp_dir_path_ + "/alias_key_v1.bin";
  EXPECT_CALL(invocation_mock_, GetParamString("output", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_output_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamU32("version", _))
      .WillOnce(DoAll(SetArgPointee<1>(1), Return(0)));

  uint8_t expected_key[ALIAS_KEY_V1_SIZE];
  for (size_t i = 0; i < sizeof(expected_key); ++i) {
    expected_key[i] = i;
  }

  EXPECT_CALL(security_v2_mock_, htool_exec_security_v2_cmd)
      .With(IsSecurityV2Command(
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_ALIAS_KEY_MINOR_COMMAND,
          HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          HOTH_SECURITY_V2_REQUEST_SIZE(0),
          HOTH_SECURITY_V2_RESPONSE_SIZE(1) + ALIAS_KEY_V1_SIZE))
      .WillOnce([&](struct libhoth_device* dev, uint8_t major, uint8_t minor,
                    uint16_t base_command,
                    struct security_v2_buffer* request_buffer,
                    const struct security_v2_param* request_params,
                    uint16_t request_param_count,
                    struct security_v2_buffer* response_buffer,
                    struct security_v2_param* response_params,
                    uint16_t response_param_count) {
        EXPECT_EQ(response_param_count, 1);
        EXPECT_EQ(response_params[0].size, ALIAS_KEY_V1_SIZE);
        memcpy(response_params[0].data, expected_key, sizeof(expected_key));
        return 0;
      });

  ASSERT_EQ(htool_get_alias_key_cert(&inv), 0);

  FILE* fp = fopen(tmp_output_file.c_str(), "rb");
  ASSERT_NE(fp, nullptr);
  uint8_t file_contents[ALIAS_KEY_V1_SIZE];
  ASSERT_EQ(fread(file_contents, 1, sizeof(file_contents), fp),
            sizeof(file_contents));
  EXPECT_EQ(memcmp(file_contents, expected_key, sizeof(expected_key)), 0);
  fclose(fp);
}

TEST_F(HtoolSecurityCertificatesTest, GetAliasKeyV0CertCommandFails) {
  struct htool_invocation inv{};
  std::string tmp_output_file = tmp_dir_path_ + "/alias_key.bin";
  EXPECT_CALL(invocation_mock_, GetParamString("output", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_output_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamU32("version", _))
      .WillOnce(DoAll(SetArgPointee<1>(0), Return(0)));

  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(Return(-1));

  EXPECT_EQ(htool_get_alias_key_cert(&inv), -1);
}

TEST_F(HtoolSecurityCertificatesTest, GetAliasKeyV1CertCommandFails) {
  struct htool_invocation inv{};
  std::string tmp_output_file = tmp_dir_path_ + "/alias_key.bin";
  EXPECT_CALL(invocation_mock_, GetParamString("output", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_output_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamU32("version", _))
      .WillOnce(DoAll(SetArgPointee<1>(1), Return(0)));

  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(Return(-1));

  EXPECT_EQ(htool_get_alias_key_cert(&inv), -1);
}

TEST_F(HtoolSecurityCertificatesTest, GetDeviceIdCertSuccess) {
  struct htool_invocation inv{};
  std::string cert_output_file = tmp_dir_path_ + "/device_id_cert.bin";
  std::string endorsement_output_file =
      tmp_dir_path_ + "/device_id_endorsement.bin";

  EXPECT_CALL(invocation_mock_, GetParamString("cert_output", _))
      .WillOnce(DoAll(SetArgPointee<1>(cert_output_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("endorsement_cert_output", _))
      .WillOnce(
          DoAll(SetArgPointee<1>(endorsement_output_file.c_str()), Return(0)));

  uint8_t expected_cert[DEVICE_CERT_SIZE] = {};
  for (size_t i = 0; i < sizeof(expected_cert); ++i) {
    ((uint8_t*)&expected_cert)[i] = i;
  }
  uint8_t expected_endorsement[DEVICE_ENDORSEMENT_CERT_SIZE] = {};
  for (size_t i = 0; i < sizeof(expected_endorsement); ++i) {
    ((uint8_t*)&expected_endorsement)[i] = i;
  }

  EXPECT_CALL(security_v2_mock_, htool_exec_security_v2_cmd)
      .With(IsSecurityV2Command(
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_DEVICE_ID_MINOR_COMMAND,
          HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          HOTH_SECURITY_V2_REQUEST_SIZE(0),
          HOTH_SECURITY_V2_RESPONSE_SIZE(2) + sizeof(expected_cert) +
              sizeof(expected_endorsement)))
      .WillOnce([&](struct libhoth_device* dev, uint8_t major, uint8_t minor,
                    uint16_t base_command,
                    struct security_v2_buffer* request_buffer,
                    const struct security_v2_param* request_params,
                    uint16_t request_param_count,
                    struct security_v2_buffer* response_buffer,
                    struct security_v2_param* response_params,
                    uint16_t response_param_count) {
        EXPECT_EQ(response_param_count, 2);
        EXPECT_EQ(response_params[0].size, sizeof(expected_cert));
        memcpy(response_params[0].data, &expected_cert, sizeof(expected_cert));
        EXPECT_EQ(response_params[1].size, sizeof(expected_endorsement));
        memcpy(response_params[1].data, &expected_endorsement,
               sizeof(expected_endorsement));
        return 0;
      });

  ASSERT_EQ(htool_get_device_id_cert(&inv), 0);

  // Verify cert output file
  FILE* fp_cert = fopen(cert_output_file.c_str(), "rb");
  ASSERT_NE(fp_cert, nullptr);
  uint8_t cert_contents[DEVICE_CERT_SIZE];
  ASSERT_EQ(fread(&cert_contents, 1, sizeof(cert_contents), fp_cert),
            sizeof(cert_contents));
  EXPECT_EQ(memcmp(&cert_contents, &expected_cert, sizeof(expected_cert)), 0);
  fclose(fp_cert);

  // Verify endorsement output file
  FILE* fp_endorsement = fopen(endorsement_output_file.c_str(), "rb");
  ASSERT_NE(fp_endorsement, nullptr);
  uint8_t endorsement_contents[DEVICE_ENDORSEMENT_CERT_SIZE];
  ASSERT_EQ(fread(&endorsement_contents, 1, sizeof(endorsement_contents),
                  fp_endorsement),
            sizeof(endorsement_contents));
  EXPECT_EQ(memcmp(&endorsement_contents, &expected_endorsement,
                   sizeof(expected_endorsement)),
            0);
  fclose(fp_endorsement);
}

TEST_F(HtoolSecurityCertificatesTest,
       GetDeviceIdCertOnlyCertOutputProvidedSuccess) {
  struct htool_invocation inv{};
  std::string cert_output_file = tmp_dir_path_ + "/device_id_cert.bin";

  EXPECT_CALL(invocation_mock_, GetParamString("endorsement_cert_output", _))
      .WillOnce(DoAll(SetArgPointee<1>(""), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("cert_output", _))
      .WillOnce(DoAll(SetArgPointee<1>(cert_output_file.c_str()), Return(0)));

  uint8_t expected_cert[DEVICE_CERT_SIZE] = {};
  for (size_t i = 0; i < sizeof(expected_cert); ++i) {
    ((uint8_t*)&expected_cert)[i] = i;
  }

  uint8_t expected_endorsement[DEVICE_ENDORSEMENT_CERT_SIZE] = {};
  for (size_t i = 0; i < sizeof(expected_endorsement); ++i) {
    ((uint8_t*)&expected_endorsement)[i] = i;
  }

  EXPECT_CALL(security_v2_mock_, htool_exec_security_v2_cmd)
      .With(IsSecurityV2Command(
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_DEVICE_ID_MINOR_COMMAND,
          HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          HOTH_SECURITY_V2_REQUEST_SIZE(0),
          HOTH_SECURITY_V2_RESPONSE_SIZE(2) + sizeof(expected_cert) +
              sizeof(expected_endorsement)))
      .WillOnce([&](struct libhoth_device* dev, uint8_t major, uint8_t minor,
                    uint16_t base_command,
                    struct security_v2_buffer* request_buffer,
                    const struct security_v2_param* request_params,
                    uint16_t request_param_count,
                    struct security_v2_buffer* response_buffer,
                    struct security_v2_param* response_params,
                    uint16_t response_param_count) {
        EXPECT_EQ(response_param_count, 2);
        EXPECT_EQ(response_params[0].size, sizeof(expected_cert));
        memcpy(response_params[0].data, &expected_cert, sizeof(expected_cert));
        EXPECT_EQ(response_params[1].size, sizeof(expected_endorsement));
        memcpy(response_params[1].data, &expected_endorsement,
               sizeof(expected_endorsement));
        return 0;
      });

  ASSERT_EQ(htool_get_device_id_cert(&inv), 0);
  printf("\nfinished running test!");

  // Verify cert output file
  FILE* fp_cert = fopen(cert_output_file.c_str(), "rb");
  ASSERT_NE(fp_cert, nullptr);
  uint8_t cert_contents[DEVICE_CERT_SIZE];
  ASSERT_EQ(fread(&cert_contents, 1, sizeof(cert_contents), fp_cert),
            sizeof(cert_contents));
  EXPECT_EQ(memcmp(&cert_contents, &expected_cert, sizeof(expected_cert)), 0);
  fclose(fp_cert);
  printf("Assertions complete!");
}

TEST_F(HtoolSecurityCertificatesTest,
       GetDeviceIdCertOnlyEndorsementCertOutputProvidedSuccess) {
  struct htool_invocation inv{};

  std::string endorsement_output_file =
      tmp_dir_path_ + "/device_id_endorsement.bin";

  EXPECT_CALL(invocation_mock_, GetParamString("cert_output", _))
      .WillOnce(DoAll(SetArgPointee<1>(""), Return(0)));

  EXPECT_CALL(invocation_mock_, GetParamString("endorsement_cert_output", _))
      .WillOnce(
          DoAll(SetArgPointee<1>(endorsement_output_file.c_str()), Return(0)));

  uint8_t expected_cert[DEVICE_CERT_SIZE] = {};
  for (size_t i = 0; i < sizeof(expected_cert); ++i) {
    ((uint8_t*)&expected_cert)[i] = i;
  }

  uint8_t expected_endorsement[DEVICE_ENDORSEMENT_CERT_SIZE] = {};
  for (size_t i = 0; i < sizeof(expected_endorsement); ++i) {
    ((uint8_t*)&expected_endorsement)[i] = i;
  }

  EXPECT_CALL(security_v2_mock_, htool_exec_security_v2_cmd)

      .With(IsSecurityV2Command(
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_DEVICE_ID_MINOR_COMMAND,
          HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          HOTH_SECURITY_V2_REQUEST_SIZE(0),
          HOTH_SECURITY_V2_RESPONSE_SIZE(2) + sizeof(expected_cert) +
              sizeof(expected_endorsement)))
      .WillOnce([&](struct libhoth_device* dev, uint8_t major, uint8_t minor,
                    uint16_t base_command,
                    struct security_v2_buffer* request_buffer,
                    const struct security_v2_param* request_params,
                    uint16_t request_param_count,
                    struct security_v2_buffer* response_buffer,
                    struct security_v2_param* response_params,
                    uint16_t response_param_count) {
        EXPECT_EQ(response_param_count, 2);
        EXPECT_EQ(response_params[0].size, sizeof(expected_cert));
        memcpy(response_params[0].data, &expected_cert, sizeof(expected_cert));
        EXPECT_EQ(response_params[1].size, sizeof(expected_endorsement));
        memcpy(response_params[1].data, &expected_endorsement,
               sizeof(expected_endorsement));
        return 0;
      });

  ASSERT_EQ(htool_get_device_id_cert(&inv), 0);

  // Verify endorsement output file
  FILE* fp_endorsement = fopen(endorsement_output_file.c_str(), "rb");
  ASSERT_NE(fp_endorsement, nullptr);
  uint8_t endorsement_contents[DEVICE_ENDORSEMENT_CERT_SIZE];
  ASSERT_EQ(fread(&endorsement_contents, 1, sizeof(endorsement_contents),
                  fp_endorsement),
            sizeof(endorsement_contents));
  EXPECT_EQ(memcmp(&endorsement_contents, &expected_endorsement,
                   sizeof(expected_endorsement)),
            0);
  fclose(fp_endorsement);
}

TEST_F(HtoolSecurityCertificatesTest, GetDeviceIdCertCommandFails) {
  struct htool_invocation inv{};
  std::string cert_output_file = tmp_dir_path_ + "/device_id_cert.bin";
  std::string endorsement_output_file =
      tmp_dir_path_ + "/device_id_endorsement.bin";

  EXPECT_CALL(invocation_mock_, GetParamString("cert_output", _))
      .WillOnce(DoAll(SetArgPointee<1>(cert_output_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("endorsement_cert_output", _))
      .WillOnce(
          DoAll(SetArgPointee<1>(endorsement_output_file.c_str()), Return(0)));
  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(Return(-1));
  EXPECT_EQ(htool_get_device_id_cert(&inv), -1);
}

TEST_F(HtoolSecurityCertificatesTest, GetAttestationPubCertFailGetParam) {
  struct htool_invocation inv{};
  EXPECT_CALL(invocation_mock_, GetParamString("output", _))
      .WillOnce(Return(-1));
  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .Times(0);
  EXPECT_EQ(htool_get_attestation_pub_cert(&inv), -1);
}

TEST_F(HtoolSecurityCertificatesTest, GetAttestationPubCertFailOpenFile) {
  struct htool_invocation inv{};
  EXPECT_CALL(invocation_mock_, GetParamString("output", _))
      .WillOnce(DoAll(SetArgPointee<1>("/dev/null/invalid"), Return(0)));
  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .Times(0);
  EXPECT_EQ(htool_get_attestation_pub_cert(&inv), -1);
}

TEST_F(HtoolSecurityCertificatesTest, GetAttestationPubCertFailCommand) {
  struct htool_invocation inv{};
  std::string tmp_output_file = tmp_dir_path_ + "/attestation_pub_cert.bin";
  EXPECT_CALL(invocation_mock_, GetParamString("output", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_output_file.c_str()), Return(0)));
  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(Return(-1));
  EXPECT_EQ(htool_get_attestation_pub_cert(&inv), -1);
}

TEST_F(HtoolSecurityCertificatesTest, UnloadAttestationKeySuccess) {
  struct htool_invocation inv{};
  EXPECT_CALL(security_v2_mock_, htool_exec_security_v2_cmd)
      .With(IsSecurityV2Command(
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
          HOTH_PRV_CMD_HOTH_SECURITY_V2_UNLOAD_ATTESTATION_KEY_MINOR_COMMAND,
          HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          HOTH_SECURITY_V2_REQUEST_SIZE(0), HOTH_SECURITY_V2_RESPONSE_SIZE(0)))
      .WillOnce(Return(0));

  EXPECT_EQ(htool_unload_attestation_key(&inv), 0);
}

TEST_F(HtoolSecurityCertificatesTest, UnloadAttestationKeyFailure) {
  struct htool_invocation inv{};
  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(Return(-1));

  EXPECT_EQ(htool_unload_attestation_key(&inv), -1);
}

TEST_F(HtoolSecurityCertificatesTest, GenAttestationKeyV1Success) {
  struct htool_invocation inv{};
  std::string csr_output_file = tmp_dir_path_ + "/csr_v1.bin";
  std::string wrapped_key_output_file = tmp_dir_path_ + "/wrapped_key.bin";

  EXPECT_CALL(invocation_mock_, GetParamString("csr_output", _))
      .WillOnce(DoAll(SetArgPointee<1>(csr_output_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("wrapped_key_output", _))
      .WillOnce(
          DoAll(SetArgPointee<1>(wrapped_key_output_file.c_str()), Return(0)));

  uint8_t expected_csr[ATTESTATION_KEY_CSR_V1_SIZE] = {};
  for (size_t i = 0; i < sizeof(expected_csr); ++i) {
    expected_csr[i] = static_cast<uint8_t>(i & 0xff);
  }
  uint8_t expected_wrapped_key[WRAPPED_ATTESTATION_KEY_SIZE] = {};
  for (size_t i = 0; i < sizeof(expected_wrapped_key); ++i) {
    expected_wrapped_key[i] = static_cast<uint8_t>((i + 0x55) & 0xff);
  }

  EXPECT_CALL(security_v2_mock_, htool_exec_security_v2_cmd)
      .With(IsSecurityV2Command(
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GEN_ATTESTATION_KEY_USING_CSR_V1_MINOR_COMMAND,
          HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          HOTH_SECURITY_V2_REQUEST_SIZE(0),
          HOTH_SECURITY_V2_RESPONSE_SIZE(2) + sizeof(expected_csr) +
              sizeof(expected_wrapped_key)))
      .WillOnce([&](struct libhoth_device* dev, uint8_t major, uint8_t minor,
                    uint16_t base_command,
                    struct security_v2_buffer* request_buffer,
                    const struct security_v2_param* request_params,
                    uint16_t request_param_count,
                    struct security_v2_buffer* response_buffer,
                    struct security_v2_param* response_params,
                    uint16_t response_param_count) {
        EXPECT_EQ(response_param_count, 2);
        EXPECT_EQ(response_params[0].size, sizeof(expected_csr));
        EXPECT_EQ(response_params[1].size, sizeof(expected_wrapped_key));
        memcpy(response_params[0].data, expected_csr, sizeof(expected_csr));
        memcpy(response_params[1].data, expected_wrapped_key,
               sizeof(expected_wrapped_key));
        return 0;
      });

  ASSERT_EQ(htool_gen_attestation_key_v1(&inv), 0);

  FILE* fp_csr = fopen(csr_output_file.c_str(), "rb");
  ASSERT_NE(fp_csr, nullptr);
  uint8_t csr_contents[ATTESTATION_KEY_CSR_V1_SIZE];
  ASSERT_EQ(fread(csr_contents, 1, sizeof(csr_contents), fp_csr),
            sizeof(csr_contents));
  EXPECT_EQ(memcmp(csr_contents, expected_csr, sizeof(expected_csr)), 0);
  fclose(fp_csr);

  FILE* fp_key = fopen(wrapped_key_output_file.c_str(), "rb");
  ASSERT_NE(fp_key, nullptr);
  uint8_t key_contents[WRAPPED_ATTESTATION_KEY_SIZE];
  ASSERT_EQ(fread(key_contents, 1, sizeof(key_contents), fp_key),
            sizeof(key_contents));
  EXPECT_EQ(
      memcmp(key_contents, expected_wrapped_key, sizeof(expected_wrapped_key)),
      0);
  fclose(fp_key);
}

TEST_F(HtoolSecurityCertificatesTest, GenAttestationKeyV1NoOutputFails) {
  struct htool_invocation inv{};
  EXPECT_CALL(invocation_mock_, GetParamString("csr_output", _))
      .WillOnce(DoAll(SetArgPointee<1>(""), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("wrapped_key_output", _))
      .WillOnce(DoAll(SetArgPointee<1>(""), Return(0)));
  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .Times(0);

  EXPECT_EQ(htool_gen_attestation_key_v1(&inv), -1);
}

TEST_F(HtoolSecurityCertificatesTest, GenAttestationKeyV2Success) {
  struct htool_invocation inv{};
  std::string csr_output_file = tmp_dir_path_ + "/csr_v2.bin";
  std::string wrapped_key_output_file = tmp_dir_path_ + "/wrapped_key_v2.bin";
  uint32_t expected_fw_major_version = 3;

  EXPECT_CALL(invocation_mock_, GetParamU32("fw_major_version", _))
      .WillOnce(DoAll(SetArgPointee<1>(expected_fw_major_version), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("csr_output", _))
      .WillOnce(DoAll(SetArgPointee<1>(csr_output_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("wrapped_key_output", _))
      .WillOnce(
          DoAll(SetArgPointee<1>(wrapped_key_output_file.c_str()), Return(0)));

  uint8_t expected_csr[ATTESTATION_KEY_CSR_V2_SIZE] = {};
  for (size_t i = 0; i < sizeof(expected_csr); ++i) {
    expected_csr[i] = static_cast<uint8_t>((i + 0x10) & 0xff);
  }
  uint8_t expected_wrapped_key[WRAPPED_ATTESTATION_KEY_SIZE] = {};
  for (size_t i = 0; i < sizeof(expected_wrapped_key); ++i) {
    expected_wrapped_key[i] = static_cast<uint8_t>((i + 0xaa) & 0xff);
  }

  EXPECT_CALL(security_v2_mock_, htool_exec_security_v2_cmd)
      .With(IsSecurityV2Command(
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GEN_VERSIONED_ATTESTATION_KEY_MINOR_COMMAND,
          HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          HOTH_SECURITY_V2_REQUEST_SIZE(2) + sizeof(uint32_t) +
              sizeof(uint32_t),
          HOTH_SECURITY_V2_RESPONSE_SIZE(2) + sizeof(expected_csr) +
              sizeof(expected_wrapped_key)))
      .WillOnce([&](struct libhoth_device* dev, uint8_t major, uint8_t minor,
                    uint16_t base_command,
                    struct security_v2_buffer* request_buffer,
                    const struct security_v2_param* request_params,
                    uint16_t request_param_count,
                    struct security_v2_buffer* response_buffer,
                    struct security_v2_param* response_params,
                    uint16_t response_param_count) {
        EXPECT_EQ(request_param_count, 2);
        EXPECT_EQ(request_params[0].size, sizeof(uint32_t));
        EXPECT_EQ(*static_cast<const uint32_t*>(request_params[0].data), 2u);
        EXPECT_EQ(request_params[1].size, sizeof(uint32_t));
        EXPECT_EQ(*static_cast<const uint32_t*>(request_params[1].data),
                  expected_fw_major_version);

        EXPECT_EQ(response_param_count, 2);
        EXPECT_EQ(response_params[0].size, sizeof(expected_csr));
        EXPECT_EQ(response_params[1].size, sizeof(expected_wrapped_key));
        memcpy(response_params[0].data, expected_csr, sizeof(expected_csr));
        memcpy(response_params[1].data, expected_wrapped_key,
               sizeof(expected_wrapped_key));
        return 0;
      });

  ASSERT_EQ(htool_gen_attestation_key_v2(&inv), 0);

  FILE* fp_csr = fopen(csr_output_file.c_str(), "rb");
  ASSERT_NE(fp_csr, nullptr);
  uint8_t csr_contents[ATTESTATION_KEY_CSR_V2_SIZE];
  ASSERT_EQ(fread(csr_contents, 1, sizeof(csr_contents), fp_csr),
            sizeof(csr_contents));
  EXPECT_EQ(memcmp(csr_contents, expected_csr, sizeof(expected_csr)), 0);
  fclose(fp_csr);

  FILE* fp_key = fopen(wrapped_key_output_file.c_str(), "rb");
  ASSERT_NE(fp_key, nullptr);
  uint8_t key_contents[WRAPPED_ATTESTATION_KEY_SIZE];
  ASSERT_EQ(fread(key_contents, 1, sizeof(key_contents), fp_key),
            sizeof(key_contents));
  EXPECT_EQ(
      memcmp(key_contents, expected_wrapped_key, sizeof(expected_wrapped_key)),
      0);
  fclose(fp_key);
}

TEST_F(HtoolSecurityCertificatesTest, LoadAttestationKeyFromCsrV1Success) {
  struct htool_invocation inv{};
  std::string wrapped_key_file = tmp_dir_path_ + "/input_wrapped_key.bin";
  std::string csr_file = tmp_dir_path_ + "/input_csr_v1.bin";

  uint8_t expected_wrapped_key[WRAPPED_ATTESTATION_KEY_SIZE] = {};
  for (size_t i = 0; i < sizeof(expected_wrapped_key); ++i) {
    expected_wrapped_key[i] = static_cast<uint8_t>(i + 1);
  }
  uint8_t expected_csr[ATTESTATION_KEY_CSR_V1_SIZE] = {};
  for (size_t i = 0; i < sizeof(expected_csr); ++i) {
    expected_csr[i] = static_cast<uint8_t>(255 - (i & 0xff));
  }

  FILE* fp_key = fopen(wrapped_key_file.c_str(), "wb");
  ASSERT_NE(fp_key, nullptr);
  ASSERT_EQ(
      fwrite(expected_wrapped_key, 1, sizeof(expected_wrapped_key), fp_key),
      sizeof(expected_wrapped_key));
  fclose(fp_key);

  FILE* fp_csr = fopen(csr_file.c_str(), "wb");
  ASSERT_NE(fp_csr, nullptr);
  ASSERT_EQ(fwrite(expected_csr, 1, sizeof(expected_csr), fp_csr),
            sizeof(expected_csr));
  fclose(fp_csr);

  EXPECT_CALL(invocation_mock_, GetParamString("wrapped_key", _))
      .WillOnce(DoAll(SetArgPointee<1>(wrapped_key_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("csr", _))
      .WillOnce(DoAll(SetArgPointee<1>(csr_file.c_str()), Return(0)));

  EXPECT_CALL(security_v2_mock_, htool_exec_security_v2_cmd)
      .With(IsSecurityV2Command(
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
          HOTH_PRV_CMD_HOTH_SECURITY_V2_LOAD_ATTESTATION_KEY_FROM_CSR_V1_MINOR_COMMAND,
          HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          HOTH_SECURITY_V2_REQUEST_SIZE(2) + sizeof(expected_wrapped_key) +
              sizeof(expected_csr),
          HOTH_SECURITY_V2_RESPONSE_SIZE(0)))
      .WillOnce([&](struct libhoth_device* dev, uint8_t major, uint8_t minor,
                    uint16_t base_command,
                    struct security_v2_buffer* request_buffer,
                    const struct security_v2_param* request_params,
                    uint16_t request_param_count,
                    struct security_v2_buffer* response_buffer,
                    struct security_v2_param* response_params,
                    uint16_t response_param_count) {
        EXPECT_EQ(request_param_count, 2);
        EXPECT_EQ(request_params[0].size, sizeof(expected_wrapped_key));
        EXPECT_EQ(memcmp(request_params[0].data, expected_wrapped_key,
                         sizeof(expected_wrapped_key)),
                  0);
        EXPECT_EQ(request_params[1].size, sizeof(expected_csr));
        EXPECT_EQ(
            memcmp(request_params[1].data, expected_csr, sizeof(expected_csr)),
            0);
        return 0;
      });

  EXPECT_EQ(htool_load_attestation_key_from_csr_v1(&inv), 0);
}

TEST_F(HtoolSecurityCertificatesTest,
       LoadAttestationKeyFromCsrV1WrongSizeFails) {
  struct htool_invocation inv{};
  std::string wrapped_key_file = tmp_dir_path_ + "/short_wrapped_key.bin";
  std::string csr_file = tmp_dir_path_ + "/input_csr_v1.bin";

  uint8_t short_key[10] = {0};
  FILE* fp_key = fopen(wrapped_key_file.c_str(), "wb");
  ASSERT_NE(fp_key, nullptr);
  ASSERT_EQ(fwrite(short_key, 1, sizeof(short_key), fp_key), sizeof(short_key));
  fclose(fp_key);

  EXPECT_CALL(invocation_mock_, GetParamString("wrapped_key", _))
      .WillOnce(DoAll(SetArgPointee<1>(wrapped_key_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("csr", _))
      .WillOnce(DoAll(SetArgPointee<1>(csr_file.c_str()), Return(0)));
  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .Times(0);

  EXPECT_EQ(htool_load_attestation_key_from_csr_v1(&inv), -1);
}

TEST_F(HtoolSecurityCertificatesTest, ProvisionAttestationKeySuccess) {
  struct htool_invocation inv{};
  uint8_t generated_csr[ATTESTATION_KEY_CSR_V1_SIZE] = {};
  for (size_t i = 0; i < sizeof(generated_csr); ++i) {
    generated_csr[i] = static_cast<uint8_t>((i * 3) & 0xff);
  }
  uint8_t generated_wrapped_key[WRAPPED_ATTESTATION_KEY_SIZE] = {};
  for (size_t i = 0; i < sizeof(generated_wrapped_key); ++i) {
    generated_wrapped_key[i] = static_cast<uint8_t>((i * 7 + 1) & 0xff);
  }

  ::testing::InSequence seq;

  // 1. Unload existing attestation key
  EXPECT_CALL(security_v2_mock_, htool_exec_security_v2_cmd)
      .With(IsSecurityV2Command(
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
          HOTH_PRV_CMD_HOTH_SECURITY_V2_UNLOAD_ATTESTATION_KEY_MINOR_COMMAND,
          HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          HOTH_SECURITY_V2_REQUEST_SIZE(0), HOTH_SECURITY_V2_RESPONSE_SIZE(0)))
      .WillOnce(Return(0));

  // 2. Generate attestation key v1
  EXPECT_CALL(security_v2_mock_, htool_exec_security_v2_cmd)
      .With(IsSecurityV2Command(
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GEN_ATTESTATION_KEY_USING_CSR_V1_MINOR_COMMAND,
          HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          HOTH_SECURITY_V2_REQUEST_SIZE(0),
          HOTH_SECURITY_V2_RESPONSE_SIZE(2) + sizeof(generated_csr) +
              sizeof(generated_wrapped_key)))
      .WillOnce([&](struct libhoth_device* dev, uint8_t major, uint8_t minor,
                    uint16_t base_command,
                    struct security_v2_buffer* request_buffer,
                    const struct security_v2_param* request_params,
                    uint16_t request_param_count,
                    struct security_v2_buffer* response_buffer,
                    struct security_v2_param* response_params,
                    uint16_t response_param_count) {
        EXPECT_EQ(response_param_count, 2);
        memcpy(response_params[0].data, generated_csr, sizeof(generated_csr));
        memcpy(response_params[1].data, generated_wrapped_key,
               sizeof(generated_wrapped_key));
        return 0;
      });

  // 3. Load attestation key from CSR v1 with the generated bytes
  EXPECT_CALL(security_v2_mock_, htool_exec_security_v2_cmd)
      .With(IsSecurityV2Command(
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
          HOTH_PRV_CMD_HOTH_SECURITY_V2_LOAD_ATTESTATION_KEY_FROM_CSR_V1_MINOR_COMMAND,
          HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          HOTH_SECURITY_V2_REQUEST_SIZE(2) + sizeof(generated_wrapped_key) +
              sizeof(generated_csr),
          HOTH_SECURITY_V2_RESPONSE_SIZE(0)))
      .WillOnce([&](struct libhoth_device* dev, uint8_t major, uint8_t minor,
                    uint16_t base_command,
                    struct security_v2_buffer* request_buffer,
                    const struct security_v2_param* request_params,
                    uint16_t request_param_count,
                    struct security_v2_buffer* response_buffer,
                    struct security_v2_param* response_params,
                    uint16_t response_param_count) {
        EXPECT_EQ(request_param_count, 2);
        EXPECT_EQ(memcmp(request_params[0].data, generated_wrapped_key,
                         sizeof(generated_wrapped_key)),
                  0);
        EXPECT_EQ(memcmp(request_params[1].data, generated_csr,
                         sizeof(generated_csr)),
                  0);
        return 0;
      });

  EXPECT_EQ(htool_provision_attestation_key(&inv), 0);
}

TEST_F(HtoolSecurityCertificatesTest,
       GenAttestationKeyV1DeviceFailDoesNotCreateFiles) {
  struct htool_invocation inv{};
  std::string csr_output_file = tmp_dir_path_ + "/should_not_exist_csr.bin";
  std::string wrapped_key_output_file =
      tmp_dir_path_ + "/should_not_exist_key.bin";

  EXPECT_CALL(invocation_mock_, GetParamString("csr_output", _))
      .WillOnce(DoAll(SetArgPointee<1>(csr_output_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("wrapped_key_output", _))
      .WillOnce(
          DoAll(SetArgPointee<1>(wrapped_key_output_file.c_str()), Return(0)));

  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(Return(-1));

  EXPECT_EQ(htool_gen_attestation_key_v1(&inv), -1);
  EXPECT_FALSE(std::filesystem::exists(csr_output_file));
  EXPECT_FALSE(std::filesystem::exists(wrapped_key_output_file));
}

TEST_F(HtoolSecurityCertificatesTest, LoadAttestationKeySuccess) {
  struct htool_invocation inv{};
  std::string wrapped_key_file = tmp_dir_path_ + "/input_wrapped_key_ca.bin";
  std::string cert_file = tmp_dir_path_ + "/input_cert.bin";

  uint8_t expected_wrapped_key[WRAPPED_ATTESTATION_KEY_SIZE] = {};
  for (size_t i = 0; i < sizeof(expected_wrapped_key); ++i) {
    expected_wrapped_key[i] = static_cast<uint8_t>(i + 0x20);
  }
  uint8_t expected_cert[ATTESTATION_CERT_SIZE] = {};
  for (size_t i = 0; i < sizeof(expected_cert); ++i) {
    expected_cert[i] = static_cast<uint8_t>(255 - (i & 0xff));
  }

  FILE* fp_key = fopen(wrapped_key_file.c_str(), "wb");
  ASSERT_NE(fp_key, nullptr);
  ASSERT_EQ(
      fwrite(expected_wrapped_key, 1, sizeof(expected_wrapped_key), fp_key),
      sizeof(expected_wrapped_key));
  fclose(fp_key);

  FILE* fp_cert = fopen(cert_file.c_str(), "wb");
  ASSERT_NE(fp_cert, nullptr);
  ASSERT_EQ(fwrite(expected_cert, 1, sizeof(expected_cert), fp_cert),
            sizeof(expected_cert));
  fclose(fp_cert);

  EXPECT_CALL(invocation_mock_, GetParamString("wrapped_key", _))
      .WillOnce(DoAll(SetArgPointee<1>(wrapped_key_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("cert", _))
      .WillOnce(DoAll(SetArgPointee<1>(cert_file.c_str()), Return(0)));

  EXPECT_CALL(security_v2_mock_, htool_exec_security_v2_cmd)
      .With(IsSecurityV2Command(
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
          HOTH_PRV_CMD_HOTH_SECURITY_V2_LOAD_ATTESTATION_KEY_MINOR_COMMAND,
          HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          HOTH_SECURITY_V2_REQUEST_SIZE(2) + sizeof(expected_wrapped_key) +
              sizeof(expected_cert),
          HOTH_SECURITY_V2_RESPONSE_SIZE(0)))
      .WillOnce([&](struct libhoth_device* dev, uint8_t major, uint8_t minor,
                    uint16_t base_command,
                    struct security_v2_buffer* request_buffer,
                    const struct security_v2_param* request_params,
                    uint16_t request_param_count,
                    struct security_v2_buffer* response_buffer,
                    struct security_v2_param* response_params,
                    uint16_t response_param_count) {
        EXPECT_EQ(request_param_count, 2);
        EXPECT_EQ(request_params[0].size, sizeof(expected_wrapped_key));
        EXPECT_EQ(memcmp(request_params[0].data, expected_wrapped_key,
                         sizeof(expected_wrapped_key)),
                  0);
        EXPECT_EQ(request_params[1].size, sizeof(expected_cert));
        EXPECT_EQ(memcmp(request_params[1].data, expected_cert,
                         sizeof(expected_cert)),
                  0);
        return 0;
      });

  EXPECT_EQ(htool_load_attestation_key(&inv), 0);
}

TEST_F(HtoolSecurityCertificatesTest, LoadAttestationKeyWrongSizeFails) {
  struct htool_invocation inv{};
  std::string wrapped_key_file = tmp_dir_path_ + "/short_wrapped_key_ca.bin";
  std::string cert_file = tmp_dir_path_ + "/input_cert.bin";

  uint8_t short_key[10] = {0};
  FILE* fp_key = fopen(wrapped_key_file.c_str(), "wb");
  ASSERT_NE(fp_key, nullptr);
  ASSERT_EQ(fwrite(short_key, 1, sizeof(short_key), fp_key), sizeof(short_key));
  fclose(fp_key);

  EXPECT_CALL(invocation_mock_, GetParamString("wrapped_key", _))
      .WillOnce(DoAll(SetArgPointee<1>(wrapped_key_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("cert", _))
      .WillOnce(DoAll(SetArgPointee<1>(cert_file.c_str()), Return(0)));
  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .Times(0);

  EXPECT_EQ(htool_load_attestation_key(&inv), -1);
}
