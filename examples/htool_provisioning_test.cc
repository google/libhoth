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

#include "htool_provisioning.h"

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
#include "host_commands.h"
#include "htool_security_version.h"
#include "protocol/host_cmd.h"
#include "protocol/test/libhoth_device_mock.h"
#include "transports/libhoth_device.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;

static HtoolInvocationMock* g_htool_invocation_mock = nullptr;

extern "C" int htool_get_param_string(const struct htool_invocation* inv,
                                      const char* name, const char** value) {
  if (g_htool_invocation_mock) {
    return g_htool_invocation_mock->GetParamString(name, value);
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

class HtoolProvisioningTest : public LibHothTest {
 protected:
  void SetUp() override {
    tmp_dir_path_.clear();
    mock_dev = &hoth_dev_;
    g_htool_invocation_mock = &invocation_mock_;
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
    std::string tmpl = build_root + "/htool_provisioning_test_dir.XXXXXX";
    ASSERT_NE(mkdtemp(&tmpl[0]), nullptr)
        << "mkdtemp failed: " << strerror(errno);
    tmp_dir_path_ = tmpl;
  }

  void TearDown() override {
    g_htool_invocation_mock = nullptr;
    mock_dev = nullptr;
    if (!tmp_dir_path_.empty()) {
      std::filesystem::remove_all(tmp_dir_path_);
    }
  }

  HtoolInvocationMock invocation_mock_;
  std::string tmp_dir_path_;
};

TEST_F(HtoolProvisioningTest, GetProvisioningLogSuccess) {
  struct htool_invocation inv{};
  std::string tmp_output_file =
      tmp_dir_path_ + "/provisioning_log.GetProvisioningLogSuccess.bin";
  EXPECT_CALL(invocation_mock_, GetParamString("output", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_output_file.c_str()), Return(0)));

  struct hoth_provisioning_log_header header = {
      .version = 1,
      .reserved = 0,
      .size = 10,
      .checksum = 0x12345678,
  };

  std::vector<uint8_t> log_data(header.size);
  for (size_t i = 0; i < log_data.size(); ++i) {
    log_data[i] = i;
  }

  struct hoth_provisioning_log response{};
  response.hdr = header;
  memcpy(response.data, log_data.data(), log_data.size());

  // Expected request payload for the first send (getting header)
  struct hoth_provisioning_log_request expected_provisioning_req_hdr_only = {
      .version = 1,
      .operation = PROVISIONING_LOG_READ,
      .reserved = 0,
      .offset = 0,
      .size = 0,
      .checksum = 0,
  };

  // Expected request header for the first send
  struct hoth_host_request expected_req_hdr_only_hdr = {
      .struct_version = HOTH_HOST_REQUEST_VERSION,
      .checksum = 0,
      .command = HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_PROVISIONING_LOG),
      .command_version = 0,
      .reserved = 0,
      .data_len = (uint16_t)sizeof(expected_provisioning_req_hdr_only),
  };
  expected_req_hdr_only_hdr.checksum = libhoth_calculate_checksum(
      &expected_req_hdr_only_hdr, sizeof(expected_req_hdr_only_hdr),
      &expected_provisioning_req_hdr_only,
      sizeof(expected_provisioning_req_hdr_only));

  std::vector<uint8_t> expected_request_buffer_hdr_only(
      sizeof(expected_req_hdr_only_hdr) +
      sizeof(expected_provisioning_req_hdr_only));
  memcpy(expected_request_buffer_hdr_only.data(), &expected_req_hdr_only_hdr,
         sizeof(expected_req_hdr_only_hdr));
  memcpy(expected_request_buffer_hdr_only.data() +
             sizeof(expected_req_hdr_only_hdr),
         &expected_provisioning_req_hdr_only,
         sizeof(expected_provisioning_req_hdr_only));

  // Expected request payload for the second send (getting data)
  struct hoth_provisioning_log_request expected_provisioning_req_data_only = {
      .version = 1,
      .operation = PROVISIONING_LOG_READ,
      .reserved = 0,
      .offset = 0,
      .size = (uint16_t)log_data.size(),
      .checksum = 0,
  };

  // Expected request header for the second send
  struct hoth_host_request expected_req_data_only_hdr = {
      .struct_version = HOTH_HOST_REQUEST_VERSION,
      .checksum = 0,
      .command = HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_PROVISIONING_LOG),
      .command_version = 0,
      .reserved = 0,
      .data_len = (uint16_t)sizeof(expected_provisioning_req_data_only),
  };
  expected_req_data_only_hdr.checksum = libhoth_calculate_checksum(
      &expected_req_data_only_hdr, sizeof(expected_req_data_only_hdr),
      &expected_provisioning_req_data_only,
      sizeof(expected_provisioning_req_data_only));

  std::vector<uint8_t> expected_request_buffer_data_only(
      sizeof(expected_req_data_only_hdr) +
      sizeof(expected_provisioning_req_data_only));
  memcpy(expected_request_buffer_data_only.data(), &expected_req_data_only_hdr,
         sizeof(expected_req_data_only_hdr));
  memcpy(expected_request_buffer_data_only.data() +
             sizeof(expected_req_data_only_hdr),
         &expected_provisioning_req_data_only,
         sizeof(expected_provisioning_req_data_only));

  EXPECT_CALL(mock_,
              send(_,
                   MatchesSentData(expected_request_buffer_hdr_only,
                                   expected_request_buffer_hdr_only.size()),
                   expected_request_buffer_hdr_only.size()))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_,
              send(_,
                   MatchesSentData(expected_request_buffer_data_only,
                                   expected_request_buffer_data_only.size()),
                   expected_request_buffer_data_only.size()))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive(_, _, _, _, _))
      .WillOnce(DoAll(CopyResp(&header, sizeof(header)), Return(LIBHOTH_OK)))
      .WillOnce(DoAll(CopyResp(&response, sizeof(header) + header.size),
                      Return(LIBHOTH_OK)));

  ASSERT_EQ(htool_get_provisioning_log(&inv), 0);

  // Verify output file
  FILE* fp = fopen(tmp_output_file.c_str(), "rb");
  ASSERT_NE(fp, nullptr);
  std::vector<uint8_t> file_contents(header.size);
  ASSERT_EQ(fread(file_contents.data(), 1, header.size, fp), header.size);
  EXPECT_EQ(memcmp(file_contents.data(), log_data.data(), header.size), 0);
  fclose(fp);
  remove(tmp_output_file.c_str());
}

TEST_F(HtoolProvisioningTest, GetProvisioningLogUnexpectedResponseSize) {
  struct htool_invocation inv{};
  std::string tmp_output_file =
      tmp_dir_path_ +
      "/provisioning_log.GetProvisioningLogUnexpectedResponseSize.bin";
  EXPECT_CALL(invocation_mock_, GetParamString("output", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_output_file.c_str()), Return(0)));

  struct hoth_provisioning_log_header header = {
      .version = 1,
      .reserved = 0,
      .size = 10,
      .checksum = 0x12345678,
  };

  std::vector<uint8_t> log_data(header.size);
  for (size_t i = 0; i < log_data.size(); ++i) {
    log_data[i] = i;
  }

  struct hoth_provisioning_log response{};
  response.hdr = header;
  memcpy(response.data, log_data.data(), log_data.size());

  // The first call to libhoth_hostcmd_exec gets the header.
  // The second call gets the data.
  EXPECT_CALL(mock_, send(_, _, _)).WillRepeatedly(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive(_, _, _, _, _))
      .WillOnce(DoAll(CopyResp(&header, sizeof(header)), Return(LIBHOTH_OK)))
      // Return the incorrect response_size
      .WillOnce(DoAll(CopyResp(&response, sizeof(header) + header.size - 1),
                      Return(LIBHOTH_OK)));

  ASSERT_EQ(htool_get_provisioning_log(&inv), 1);

  // Verify output file is empty
  FILE* fp = fopen(tmp_output_file.c_str(), "rb");
  ASSERT_NE(fp, nullptr);
  fseek(fp, 0, SEEK_END);
  uint32_t file_size = ftell(fp);
  rewind(fp);
  ASSERT_EQ(file_size, 0);
  fclose(fp);
  remove(tmp_output_file.c_str());
}

TEST_F(HtoolProvisioningTest, GetProvisioningLogUnexpectedErrorFromDevice) {
  struct htool_invocation inv{};
  std::string tmp_output_file =
      tmp_dir_path_ +
      "/provisioning_log.GetProvisioningLogUnexpectedErrorFromDevice.bin";
  EXPECT_CALL(invocation_mock_, GetParamString("output", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_output_file.c_str()), Return(0)));

  struct hoth_provisioning_log_header header = {
      .version = 1,
      .reserved = 0,
      .size = 10,
      .checksum = 0x12345678,
  };

  std::vector<uint8_t> log_data(header.size);
  for (size_t i = 0; i < log_data.size(); ++i) {
    log_data[i] = i;
  }

  struct hoth_provisioning_log response{};
  response.hdr = header;
  memcpy(response.data, log_data.data(), log_data.size());

  // The first call to libhoth_hostcmd_exec gets the header.
  // The second call gets the data.
  EXPECT_CALL(mock_, send(_, _, _)).WillRepeatedly(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive(_, _, _, _, _))
      .WillOnce(DoAll(CopyResp(&header, sizeof(header)), Return(LIBHOTH_OK)))
      // Return the incorrect response status
      .WillOnce(DoAll(CopyResp(&response, sizeof(header) + header.size),
                      Return(LIBHOTH_ERR_INTERFACE_NOT_FOUND)));

  ASSERT_EQ(htool_get_provisioning_log(&inv), -1);

  // Verify output file is empty
  FILE* fp = fopen(tmp_output_file.c_str(), "rb");
  ASSERT_NE(fp, nullptr);
  fseek(fp, 0, SEEK_END);
  uint32_t file_size = ftell(fp);
  rewind(fp);
  ASSERT_EQ(file_size, 0);
  fclose(fp);
  remove(tmp_output_file.c_str());
}

TEST_F(HtoolProvisioningTest, GetProvisioningLogNoOutputFile) {
  struct htool_invocation inv{};
  EXPECT_CALL(invocation_mock_, GetParamString("output", _))
      .WillOnce(Return(-1));

  struct hoth_provisioning_log_header header = {
      .version = 1,
      .reserved = 0,
      .size = 10,
      .checksum = 0x12345678,
  };

  std::vector<uint8_t> log_data(header.size);
  for (size_t i = 0; i < log_data.size(); ++i) {
    log_data[i] = i;
  }

  struct hoth_provisioning_log response{};
  response.hdr = header;
  memcpy(response.data, log_data.data(), log_data.size());

  // The first call to libhoth_hostcmd_exec would get the header.
  // The second call would get the data.
  // Neither of these calls should happen when there is no output file.
  EXPECT_CALL(mock_, send(_, _, _)).Times(0);
  EXPECT_CALL(mock_, receive(_, _, _, _, _)).Times(0);

  ASSERT_EQ(htool_get_provisioning_log(&inv), -1);
}

TEST_F(HtoolProvisioningTest, GetProvisioningLogOutputFileNotAbleToBeOpened) {
  struct htool_invocation inv{};
  // Add an invalid ouptut file name
  std::string tmp_output_file = "/path/to/nonexistant/file";
  EXPECT_CALL(invocation_mock_, GetParamString("output", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_output_file.c_str()), Return(0)));

  struct hoth_provisioning_log_header header = {
      .version = 1,
      .reserved = 0,
      .size = 10,
      .checksum = 0x12345678,
  };

  std::vector<uint8_t> log_data(header.size);
  for (size_t i = 0; i < log_data.size(); ++i) {
    log_data[i] = i;
  }

  struct hoth_provisioning_log response{};
  response.hdr = header;
  memcpy(response.data, log_data.data(), log_data.size());

  // The first call to libhoth_hostcmd_exec would get the header.
  // The second call would get the data.
  // Neither of these calls should happen when the output file can't be opened
  EXPECT_CALL(mock_, send(_, _, _)).Times(0);
  EXPECT_CALL(mock_, receive(_, _, _, _, _)).Times(0);

  ASSERT_EQ(htool_get_provisioning_log(&inv), -1);

  // Verify output file doesn't exist
  FILE* fp = fopen(tmp_output_file.c_str(), "rb");
  ASSERT_EQ(fp, nullptr);
  remove(tmp_output_file.c_str());
}

TEST_F(HtoolProvisioningTest, GetProvisioningLogResponseTooLarge) {
  struct htool_invocation inv{};
  std::string tmp_output_file =
      tmp_dir_path_ +
      "/provisioning_log.GetProvisioningLogResponseTooLarge.bin";
  EXPECT_CALL(invocation_mock_, GetParamString("output", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_output_file.c_str()), Return(0)));

  struct hoth_provisioning_log_header header = {
      .version = 1,
      .reserved = 0,
      .size = PROVISIONING_LOG_MAX_SIZE + 1,
      .checksum = 0x12345678,
  };

  std::vector<struct hoth_provisioning_log> responses;
  uint16_t bytes_simulated = 0;
  while (bytes_simulated < header.size) {
    uint16_t chunk_size =
        std::min(static_cast<uint16_t>(header.size - bytes_simulated),
                 static_cast<uint16_t>(PROVISIONING_LOG_CHUNK_MAX_SIZE));
    struct hoth_provisioning_log resp{};
    resp.hdr = header;
    resp.hdr.size = chunk_size;
    memset(resp.data, 0xAA, chunk_size);
    responses.push_back(resp);
    bytes_simulated += chunk_size;
  }

  EXPECT_CALL(mock_, send(_, _, _)).WillRepeatedly(Return(LIBHOTH_OK));
  auto& receive_call = EXPECT_CALL(mock_, receive(_, _, _, _, _))
                           .WillOnce(DoAll(CopyResp(&header, sizeof(header)),
                                           Return(LIBHOTH_OK)));
  for (size_t i = 0; i < responses.size(); ++i) {
    uint16_t chunk_size = responses[i].hdr.size;
    receive_call.WillOnce(
        DoAll(CopyResp(&responses[i], sizeof(header) + chunk_size),
              Return(LIBHOTH_OK)));
  }

  ASSERT_EQ(htool_get_provisioning_log(&inv), -1);

  // Verify output file size is 0
  FILE* fp = fopen(tmp_output_file.c_str(), "rb");
  ASSERT_NE(fp, nullptr);
  fseek(fp, 0, SEEK_END);
  uint32_t file_size = ftell(fp);
  rewind(fp);
  ASSERT_EQ(file_size, 0);
  fclose(fp);
  remove(tmp_output_file.c_str());
}

TEST_F(HtoolProvisioningTest, ValidateAndSignSuccess) {
  struct htool_invocation inv{};
  std::string tmp_perso_blob_file =
      tmp_dir_path_ + "/perso_blob.ValidateAndSignSuccess.bin";
  std::string tmp_output_file =
      tmp_dir_path_ + "/signed_log.ValidateAndSignSuccess.bin";
  EXPECT_CALL(invocation_mock_, GetParamString("perso_blob", _))
      .WillOnce(
          DoAll(SetArgPointee<1>(tmp_perso_blob_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("output", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_output_file.c_str()), Return(0)));

  std::vector<uint8_t> perso_blob_data = {0x01, 0x02, 0x03, 0x04, 0x05};
  FILE* fp_in = fopen(tmp_perso_blob_file.c_str(), "wb");
  ASSERT_NE(fp_in, nullptr);
  ASSERT_EQ(fwrite(perso_blob_data.data(), 1, perso_blob_data.size(), fp_in),
            perso_blob_data.size());
  fclose(fp_in);

  std::vector<uint8_t> signed_log_data = {0xDE, 0xAD, 0xBE, 0xEF};

  // Expected request payload for ValidateAndSign
  uint32_t prov_checksum = libhoth_provisioning_crc32(0, perso_blob_data.data(),
                                                      perso_blob_data.size());
  struct hoth_provisioning_log_request expected_provisioning_req = {
      .version = 1,
      .operation = PROVISIONING_LOG_VALIDATE_AND_SIGN,
      .reserved = 0,
      .offset = 0,
      .size = (uint16_t)perso_blob_data.size(),
      .checksum = prov_checksum,
  };

  // Expected request header
  struct hoth_host_request expected_req_hdr = {
      .struct_version = HOTH_HOST_REQUEST_VERSION,
      .checksum = 0,
      .command = HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_PROVISIONING_LOG),
      .command_version = 0,
      .reserved = 0,
      .data_len = (uint16_t)sizeof(expected_provisioning_req),
  };
  expected_req_hdr.checksum = libhoth_calculate_checksum(
      &expected_req_hdr, sizeof(expected_req_hdr), &expected_provisioning_req,
      sizeof(expected_provisioning_req));
  std::vector<uint8_t> expected_request_buffer(
      sizeof(expected_req_hdr) + sizeof(expected_provisioning_req));
  memcpy(expected_request_buffer.data(), &expected_req_hdr,
         sizeof(expected_req_hdr));
  memcpy(expected_request_buffer.data() + sizeof(expected_req_hdr),
         &expected_provisioning_req, sizeof(expected_provisioning_req));

  EXPECT_CALL(mock_, send(_,
                          MatchesSentData(expected_request_buffer,
                                          expected_request_buffer.size()),
                          expected_request_buffer.size()))
      .WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive(_, _, _, _, _))
      .WillOnce(DoAll(CopyResp(signed_log_data.data(), signed_log_data.size()),
                      Return(LIBHOTH_OK)));

  ASSERT_EQ(htool_validate_and_sign(&inv), 0);

  // Verify output file
  FILE* fp_out = fopen(tmp_output_file.c_str(), "rb");
  ASSERT_NE(fp_out, nullptr);
  std::vector<uint8_t> file_contents(signed_log_data.size());
  ASSERT_EQ(fread(file_contents.data(), 1, signed_log_data.size(), fp_out),
            signed_log_data.size());
  EXPECT_EQ(memcmp(file_contents.data(), signed_log_data.data(),
                   signed_log_data.size()),
            0);
  fclose(fp_out);

  remove(tmp_perso_blob_file.c_str());
  remove(tmp_output_file.c_str());
}

TEST_F(HtoolProvisioningTest, ValidateAndSignSuccessWithoutOutput) {
  struct htool_invocation inv{};
  std::string tmp_perso_blob_file =
      tmp_dir_path_ + "/perso_blob.ValidateAndSignSuccessWithoutOutput.bin";
  EXPECT_CALL(invocation_mock_, GetParamString("perso_blob", _))
      .WillOnce(
          DoAll(SetArgPointee<1>(tmp_perso_blob_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("output", _))
      .WillOnce(DoAll(SetArgPointee<1>(""), Return(0)));

  std::vector<uint8_t> perso_blob_data = {0x01, 0x02, 0x03, 0x04, 0x05};
  FILE* fp_in = fopen(tmp_perso_blob_file.c_str(), "wb");
  ASSERT_NE(fp_in, nullptr);
  ASSERT_EQ(fwrite(perso_blob_data.data(), 1, perso_blob_data.size(), fp_in),
            perso_blob_data.size());
  fclose(fp_in);

  std::vector<uint8_t> signed_log_data = {0xDE, 0xAD, 0xBE, 0xEF};

  EXPECT_CALL(mock_, send(_, _, _)).WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive(_, _, _, _, _))
      .WillOnce(DoAll(CopyResp(signed_log_data.data(), signed_log_data.size()),
                      Return(LIBHOTH_OK)));

  ASSERT_EQ(htool_validate_and_sign(&inv), 0);
  remove(tmp_perso_blob_file.c_str());
}

TEST_F(HtoolProvisioningTest, ValidateAndSignUnexpectedErrorFromDevice) {
  struct htool_invocation inv{};
  std::string tmp_perso_blob_file =
      tmp_dir_path_ +
      "/perso_blob.ValidateAndSignUnexpectedErrorFromDevice.bin";
  std::string tmp_output_file =
      tmp_dir_path_ +
      "/signed_log.ValidateAndSignUnexpectedErrorFromDevice.bin";
  EXPECT_CALL(invocation_mock_, GetParamString("perso_blob", _))
      .WillOnce(
          DoAll(SetArgPointee<1>(tmp_perso_blob_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("output", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_output_file.c_str()), Return(0)));

  std::vector<uint8_t> perso_blob_data = {0x01, 0x02, 0x03, 0x04, 0x05};
  FILE* fp_in = fopen(tmp_perso_blob_file.c_str(), "wb");
  ASSERT_NE(fp_in, nullptr);
  ASSERT_EQ(fwrite(perso_blob_data.data(), 1, perso_blob_data.size(), fp_in),
            perso_blob_data.size());
  fclose(fp_in);

  std::vector<uint8_t> signed_log_data = {0xDE, 0xAD, 0xBE, 0xEF};

  EXPECT_CALL(mock_, send(_, _, _)).WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive(_, _, _, _, _))
      .WillOnce(DoAll(CopyResp(signed_log_data.data(), signed_log_data.size()),
                      Return(LIBHOTH_ERR_INTERFACE_NOT_FOUND)));

  ASSERT_EQ(htool_validate_and_sign(&inv), -1);

  // Verify output file is empty
  FILE* fp = fopen(tmp_output_file.c_str(), "rb");
  ASSERT_NE(fp, nullptr);
  fseek(fp, 0, SEEK_END);
  uint32_t file_size = ftell(fp);
  rewind(fp);
  ASSERT_EQ(file_size, 0);
  fclose(fp);

  remove(tmp_perso_blob_file.c_str());
  remove(tmp_output_file.c_str());
}

TEST_F(HtoolProvisioningTest, ValidateAndSignNoOutputFile) {
  struct htool_invocation inv{};
  std::string tmp_perso_blob_file =
      tmp_dir_path_ + "/perso_blob.ValidateAndSignNoOutputFile.bin";
  std::string tmp_output_file = "signed_log.ValidateAndSignNoOutputFile.bin";
  EXPECT_CALL(invocation_mock_, GetParamString("perso_blob", _))
      .WillOnce(
          DoAll(SetArgPointee<1>(tmp_perso_blob_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("output", _))
      .WillOnce(Return(-1));

  std::vector<uint8_t> perso_blob_data = {0x01, 0x02, 0x03, 0x04, 0x05};
  FILE* fp_in = fopen(tmp_perso_blob_file.c_str(), "wb");
  ASSERT_NE(fp_in, nullptr);
  ASSERT_EQ(fwrite(perso_blob_data.data(), 1, perso_blob_data.size(), fp_in),
            perso_blob_data.size());
  fclose(fp_in);

  std::vector<uint8_t> signed_log_data = {0xDE, 0xAD, 0xBE, 0xEF};

  EXPECT_CALL(mock_, send(_, _, _)).Times(0);
  EXPECT_CALL(mock_, receive(_, _, _, _, _)).Times(0);

  ASSERT_EQ(htool_validate_and_sign(&inv), -1);

  // Verify output file
  FILE* fp = fopen(tmp_output_file.c_str(), "rb");
  ASSERT_EQ(fp, nullptr);
  remove(tmp_perso_blob_file.c_str());
  remove(tmp_output_file.c_str());
}

TEST_F(HtoolProvisioningTest, ValidateAndSignOutputFileNotAbleToBeOpened) {
  struct htool_invocation inv{};
  std::string tmp_perso_blob_file =
      tmp_dir_path_ +
      "/perso_blob.ValidateAndSignOutputFileNotAbleToBeOpened.bin";
  std::string tmp_output_file = "/path/to/nonexistant/file";
  EXPECT_CALL(invocation_mock_, GetParamString("perso_blob", _))
      .WillOnce(
          DoAll(SetArgPointee<1>(tmp_perso_blob_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("output", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_output_file.c_str()), Return(0)));

  std::vector<uint8_t> perso_blob_data = {0x01, 0x02, 0x03, 0x04, 0x05};
  FILE* fp_in = fopen(tmp_perso_blob_file.c_str(), "wb");
  ASSERT_NE(fp_in, nullptr);
  ASSERT_EQ(fwrite(perso_blob_data.data(), 1, perso_blob_data.size(), fp_in),
            perso_blob_data.size());
  fclose(fp_in);

  std::vector<uint8_t> signed_log_data = {0xDE, 0xAD, 0xBE, 0xEF};

  EXPECT_CALL(mock_, send(_, _, _)).Times(0);
  EXPECT_CALL(mock_, receive(_, _, _, _, _)).Times(0);

  ASSERT_EQ(htool_validate_and_sign(&inv), -1);

  // Verify output file doesn't exist
  FILE* fp = fopen(tmp_output_file.c_str(), "rb");
  ASSERT_EQ(fp, nullptr);
  remove(tmp_output_file.c_str());
  remove(tmp_perso_blob_file.c_str());
}

TEST_F(HtoolProvisioningTest, ValidateAndSignPersoBlobFileEmpty) {
  struct htool_invocation inv{};
  std::string tmp_perso_blob_file =
      tmp_dir_path_ + "/perso_blob.ValidateAndSignPersoBlobFileEmpty.bin";
  std::string tmp_output_file =
      tmp_dir_path_ + "/signed_log.ValidateAndSignPersoBlobFileEmpty.bin";
  EXPECT_CALL(invocation_mock_, GetParamString("perso_blob", _))
      .WillOnce(
          DoAll(SetArgPointee<1>(tmp_perso_blob_file.c_str()), Return(0)));
  // There should be no call to get the output param
  EXPECT_CALL(invocation_mock_, GetParamString("output", _)).Times(0);

  // Write empty data to the perso_blob file
  std::vector<uint8_t> perso_blob_data = {};
  FILE* fp_in = fopen(tmp_perso_blob_file.c_str(), "wb");
  ASSERT_NE(fp_in, nullptr);
  ASSERT_EQ(fwrite(perso_blob_data.data(), 1, perso_blob_data.size(), fp_in),
            perso_blob_data.size());
  fclose(fp_in);

  EXPECT_CALL(mock_, send(_, _, _)).Times(0);
  EXPECT_CALL(mock_, receive(_, _, _, _, _)).Times(0);

  ASSERT_EQ(htool_validate_and_sign(&inv), -1);

  // Verify output file doesn't exist
  FILE* fp = fopen(tmp_output_file.c_str(), "rb");
  ASSERT_EQ(fp, nullptr);
  remove(tmp_output_file.c_str());
  remove(tmp_perso_blob_file.c_str());
}

TEST_F(HtoolProvisioningTest, ValidateAndSignPersoBlobFileDoesNotExist) {
  struct htool_invocation inv{};
  std::string tmp_perso_blob_file =
      tmp_dir_path_ +
      "/perso_blob.ValidateAndSignPersoBlobFileDoesNotExist.bin";
  std::string tmp_output_file =
      tmp_dir_path_ +
      "/signed_log.ValidateAndSignPersoBlobFileDoesNotExist.bin";
  EXPECT_CALL(invocation_mock_, GetParamString("perso_blob", _))
      .WillOnce(
          DoAll(SetArgPointee<1>(tmp_perso_blob_file.c_str()), Return(0)));
  // There should be no call to get the output param
  EXPECT_CALL(invocation_mock_, GetParamString("output", _)).Times(0);

  EXPECT_CALL(mock_, send(_, _, _)).Times(0);
  EXPECT_CALL(mock_, receive(_, _, _, _, _)).Times(0);

  ASSERT_EQ(htool_validate_and_sign(&inv), -1);

  // Verify output file doesn't exist
  FILE* fp = fopen(tmp_output_file.c_str(), "rb");
  ASSERT_EQ(fp, nullptr);
  remove(tmp_output_file.c_str());
  remove(tmp_perso_blob_file.c_str());
}

TEST_F(HtoolProvisioningTest, ValidateAndSignTooLargeResponse) {
  struct htool_invocation inv{};
  std::string tmp_perso_blob_file =
      tmp_dir_path_ + "/perso_blob.ValidateAndSignTooLargeResponse.bin";
  std::string tmp_output_file =
      tmp_dir_path_ + "/signed_log.ValidateAndSignTooLargeResponse.bin";
  EXPECT_CALL(invocation_mock_, GetParamString("perso_blob", _))
      .WillOnce(
          DoAll(SetArgPointee<1>(tmp_perso_blob_file.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("output", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_output_file.c_str()), Return(0)));

  std::vector<uint8_t> perso_blob_data = {0x01, 0x02, 0x03, 0x04, 0x05};
  FILE* fp_in = fopen(tmp_perso_blob_file.c_str(), "wb");
  ASSERT_NE(fp_in, nullptr);
  ASSERT_EQ(fwrite(perso_blob_data.data(), 1, perso_blob_data.size(), fp_in),
            perso_blob_data.size());
  fclose(fp_in);

  std::vector<uint8_t> signed_log_data(PROVISIONING_CERT_MAX_SIZE + 1, 0xFF);

  EXPECT_CALL(mock_, send(_, _, _)).WillOnce(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive(_, _, _, _, _))
      .WillOnce(DoAll(CopyResp(signed_log_data.data(), signed_log_data.size()),
                      Return(LIBHOTH_OK)));

  ASSERT_EQ(htool_validate_and_sign(&inv), -1);

  // Verify output file size is 0
  FILE* fp = fopen(tmp_output_file.c_str(), "rb");
  ASSERT_NE(fp, nullptr);
  fseek(fp, 0, SEEK_END);
  uint32_t file_size = ftell(fp);
  rewind(fp);
  ASSERT_EQ(file_size, 0);
  fclose(fp);
  remove(tmp_perso_blob_file.c_str());
  remove(tmp_output_file.c_str());
}

TEST_F(HtoolProvisioningTest, StoreSecretsFileSuccess) {
  struct htool_invocation inv{};
  std::string tmp_secrets_file = tmp_dir_path_ + "/secrets.bin";
  FILE* fp = fopen(tmp_secrets_file.c_str(), "wb");
  ASSERT_NE(fp, nullptr);
  uint8_t secret_bytes[] = {0xaa, 0xbb, 0xcc, 0xdd};
  ASSERT_EQ(fwrite(secret_bytes, 1, sizeof(secret_bytes), fp),
            sizeof(secret_bytes));
  fclose(fp);

  EXPECT_CALL(invocation_mock_, GetParamString("secrets", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_secrets_file.c_str()), Return(0)));

  EXPECT_CALL(mock_, send(_, _, _))
      .WillOnce([&](struct libhoth_device*, const void* req, size_t size) {
        const auto* hoth_req =
            static_cast<const struct hoth_host_request*>(req);
        EXPECT_EQ(hoth_req->command,
                  HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_KEY_PROVISIONING));
        const auto* store_req = reinterpret_cast<
            const struct hoth_key_provisioning_store_secrets_request*>(
            static_cast<const uint8_t*>(req) +
            sizeof(struct hoth_host_request));
        EXPECT_EQ(store_req->hdr.version,
                  HOTH_KEY_PROVISIONING_REQUEST_VERSION);
        EXPECT_EQ(store_req->hdr.command, HOTH_KEY_PROVISIONING_STORE_SECRETS);
        EXPECT_EQ(store_req->hdr.size,
                  sizeof(struct hoth_key_provisioning_request_header) +
                      sizeof(secret_bytes));
        EXPECT_EQ(
            memcmp(store_req->secrets, secret_bytes, sizeof(secret_bytes)), 0);
        return LIBHOTH_OK;
      });

  uint8_t dummy_resp = 0;
  EXPECT_CALL(mock_, receive(_, _, _, _, _))
      .WillOnce(DoAll(CopyResp(&dummy_resp, 0), Return(LIBHOTH_OK)));

  ASSERT_EQ(htool_provisioning_store_secrets(&inv), 0);
  remove(tmp_secrets_file.c_str());
}

TEST_F(HtoolProvisioningTest, StoreSecretsTooLargeFile) {
  struct htool_invocation inv{};
  std::string tmp_secrets_file = tmp_dir_path_ + "/secrets_too_large.bin";
  std::vector<uint8_t> data(HOTH_KEY_PROVISIONING_MAX_SECRETS_SIZE + 1, 0x11);
  FILE* fp = fopen(tmp_secrets_file.c_str(), "wb");
  ASSERT_NE(fp, nullptr);
  ASSERT_EQ(fwrite(data.data(), 1, data.size(), fp), data.size());
  fclose(fp);

  EXPECT_CALL(invocation_mock_, GetParamString("secrets", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_secrets_file.c_str()), Return(0)));

  ASSERT_EQ(htool_provisioning_store_secrets(&inv), -1);
  remove(tmp_secrets_file.c_str());
}

TEST_F(HtoolProvisioningTest, StoreSecretsMissingSecrets) {
  struct htool_invocation inv{};
  EXPECT_CALL(invocation_mock_, GetParamString("secrets", _))
      .WillOnce(DoAll(SetArgPointee<1>(""), Return(0)));

  ASSERT_EQ(htool_provisioning_store_secrets(&inv), -1);
}

TEST_F(HtoolProvisioningTest, WriteSuccess) {
  struct htool_invocation inv{};
  std::string tmp_input_file = tmp_dir_path_ + "/prov_log_to_write.bin";
  std::vector<uint8_t> data(1500, 0x5a);
  FILE* fp = fopen(tmp_input_file.c_str(), "wb");
  ASSERT_NE(fp, nullptr);
  ASSERT_EQ(fwrite(data.data(), 1, data.size(), fp), data.size());
  fclose(fp);

  EXPECT_CALL(invocation_mock_, GetParamString("input", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_input_file.c_str()), Return(0)));

  // 1500 bytes: chunk 0 = 1004, chunk 1 = 496, then commit
  int call_count = 0;
  EXPECT_CALL(mock_, send(_, _, _))
      .Times(3)
      .WillRepeatedly([&](struct libhoth_device*, const void* req,
                          size_t size) {
        const auto* hoth_req =
            static_cast<const struct hoth_host_request*>(req);
        EXPECT_EQ(hoth_req->command,
                  HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_PROVISIONING_LOG));
        const auto* write_req =
            reinterpret_cast<const struct hoth_provisioning_log_write_request*>(
                static_cast<const uint8_t*>(req) +
                sizeof(struct hoth_host_request));
        if (call_count == 0) {
          EXPECT_EQ(write_req->req.operation, PROVISIONING_LOG_WRITE);
          EXPECT_EQ(write_req->req.offset, 0);
          EXPECT_EQ(write_req->req.size, 1004);
          EXPECT_EQ(memcmp(write_req->data, data.data(), 1004), 0);
        } else if (call_count == 1) {
          EXPECT_EQ(write_req->req.operation, PROVISIONING_LOG_WRITE);
          EXPECT_EQ(write_req->req.offset, 1004);
          EXPECT_EQ(write_req->req.size, 496);
          EXPECT_EQ(memcmp(write_req->data, data.data() + 1004, 496), 0);
        } else if (call_count == 2) {
          EXPECT_EQ(write_req->req.operation, PROVISIONING_LOG_COMMIT);
          EXPECT_EQ(write_req->req.size, 1500);
          EXPECT_EQ(write_req->req.checksum,
                    libhoth_provisioning_crc32(0, data.data(), data.size()));
        }
        call_count++;
        return LIBHOTH_OK;
      });

  uint8_t dummy_resp = 0;
  EXPECT_CALL(mock_, receive(_, _, _, _, _))
      .Times(3)
      .WillRepeatedly(DoAll(CopyResp(&dummy_resp, 0), Return(LIBHOTH_OK)));

  ASSERT_EQ(htool_provisioning_write(&inv), 0);
  remove(tmp_input_file.c_str());
}

TEST_F(HtoolProvisioningTest, WriteTooLargeFile) {
  struct htool_invocation inv{};
  std::string tmp_input_file = tmp_dir_path_ + "/prov_log_too_large.bin";
  std::vector<uint8_t> data(PROVISIONING_LOG_MAX_SIZE + 1, 0x5a);
  FILE* fp = fopen(tmp_input_file.c_str(), "wb");
  ASSERT_NE(fp, nullptr);
  ASSERT_EQ(fwrite(data.data(), 1, data.size(), fp), data.size());
  fclose(fp);

  EXPECT_CALL(invocation_mock_, GetParamString("input", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_input_file.c_str()), Return(0)));

  ASSERT_EQ(htool_provisioning_write(&inv), -1);
  remove(tmp_input_file.c_str());
}

TEST_F(HtoolProvisioningTest, WriteMissingInput) {
  struct htool_invocation inv{};
  EXPECT_CALL(invocation_mock_, GetParamString("input", _))
      .WillOnce(DoAll(SetArgPointee<1>(""), Return(0)));

  ASSERT_EQ(htool_provisioning_write(&inv), -1);
}

TEST_F(HtoolProvisioningTest, LoadMldsaKeyFileSuccess) {
  struct htool_invocation inv{};
  std::string tmp_key_file = tmp_dir_path_ + "/mldsa.bin";
  std::vector<uint8_t> key_data(HOTH_KEY_PROVISIONING_MLDSA44_PUBLIC_KEY_BYTES,
                                0x44);
  FILE* fp = fopen(tmp_key_file.c_str(), "wb");
  ASSERT_NE(fp, nullptr);
  ASSERT_EQ(fwrite(key_data.data(), 1, key_data.size(), fp), key_data.size());
  fclose(fp);

  EXPECT_CALL(invocation_mock_, GetParamString("key", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_key_file.c_str()), Return(0)));

  int call_count = 0;
  EXPECT_CALL(mock_, send(_, _, _))
      .Times(2)
      .WillRepeatedly([&](struct libhoth_device*, const void* req,
                          size_t size) {
        const auto* hoth_req =
            static_cast<const struct hoth_host_request*>(req);
        EXPECT_EQ(hoth_req->command,
                  HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_KEY_PROVISIONING));
        const auto* load_req = reinterpret_cast<
            const struct hoth_key_provisioning_load_key_request*>(
            static_cast<const uint8_t*>(req) +
            sizeof(struct hoth_host_request));
        EXPECT_EQ(load_req->hdr.version, HOTH_KEY_PROVISIONING_REQUEST_VERSION);
        EXPECT_EQ(load_req->hdr.command,
                  HOTH_KEY_PROVISIONING_LOAD_MLDSA_PUBLIC_KEY);
        if (call_count == 0) {
          EXPECT_EQ(load_req->args.offset, 0);
          EXPECT_EQ(load_req->args.size, 1008);
          EXPECT_EQ(load_req->hdr.size,
                    sizeof(load_req->hdr) + sizeof(load_req->args) + 1008);
          EXPECT_EQ(memcmp(load_req->data, key_data.data(), 1008), 0);
        } else if (call_count == 1) {
          EXPECT_EQ(load_req->args.offset, 1008);
          EXPECT_EQ(load_req->args.size, 304);
          EXPECT_EQ(load_req->hdr.size,
                    sizeof(load_req->hdr) + sizeof(load_req->args) + 304);
          EXPECT_EQ(memcmp(load_req->data, key_data.data() + 1008, 304), 0);
        }
        call_count++;
        return LIBHOTH_OK;
      });
  uint8_t dummy_resp = 0;
  EXPECT_CALL(mock_, receive(_, _, _, _, _))
      .Times(2)
      .WillRepeatedly(DoAll(CopyResp(&dummy_resp, 0), Return(LIBHOTH_OK)));

  ASSERT_EQ(htool_provisioning_load_mldsa_key(&inv), 0);
  remove(tmp_key_file.c_str());
}

TEST_F(HtoolProvisioningTest, LoadMldsaKeyTooLargeFile) {
  struct htool_invocation inv{};
  std::string tmp_key_file = tmp_dir_path_ + "/mldsa_too_large.bin";
  std::vector<uint8_t> key_data(
      HOTH_KEY_PROVISIONING_MLDSA44_PUBLIC_KEY_BYTES + 1, 0x44);
  FILE* fp = fopen(tmp_key_file.c_str(), "wb");
  ASSERT_NE(fp, nullptr);
  ASSERT_EQ(fwrite(key_data.data(), 1, key_data.size(), fp), key_data.size());
  fclose(fp);

  EXPECT_CALL(invocation_mock_, GetParamString("key", _))
      .WillOnce(DoAll(SetArgPointee<1>(tmp_key_file.c_str()), Return(0)));

  ASSERT_EQ(htool_provisioning_load_mldsa_key(&inv), -1);
  remove(tmp_key_file.c_str());
}

TEST_F(HtoolProvisioningTest, LoadMldsaKeyMissingKey) {
  struct htool_invocation inv{};
  EXPECT_CALL(invocation_mock_, GetParamString("key", _))
      .WillOnce(DoAll(SetArgPointee<1>(""), Return(0)));

  ASSERT_EQ(htool_provisioning_load_mldsa_key(&inv), -1);
}
