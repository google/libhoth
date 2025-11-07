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
#include "protocol/host_cmd.h"
#include "host_commands.h"
#include "htool_security_version.h"
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

  // First chunk
  struct hoth_provisioning_log response1{};
  response1.hdr = header;
  response1.hdr.size = PROVISIONING_LOG_CHUNK_MAX_SIZE;
  std::vector<uint8_t> data1(PROVISIONING_LOG_CHUNK_MAX_SIZE, 0xAA);
  memcpy(response1.data, data1.data(), data1.size());

  // Second chunk
  struct hoth_provisioning_log response2{};
  response2.hdr = header;
  response2.hdr.size = PROVISIONING_LOG_CHUNK_MAX_SIZE;
  std::vector<uint8_t> data2(PROVISIONING_LOG_CHUNK_MAX_SIZE, 0xBB);
  memcpy(response2.data, data2.data(), data2.size());

  // Third chunk (the one that will overflow)
  struct hoth_provisioning_log response3{};
  response3.hdr = header;
  uint16_t last_chunk_size = (header.size % PROVISIONING_LOG_CHUNK_MAX_SIZE);
  if (last_chunk_size == 0) {
    last_chunk_size = PROVISIONING_LOG_CHUNK_MAX_SIZE;
  }
  response3.hdr.size = last_chunk_size;
  std::vector<uint8_t> data3(last_chunk_size, 0xCC);
  memcpy(response3.data, data3.data(), data3.size());

  EXPECT_CALL(mock_, send(_, _, _)).WillRepeatedly(Return(LIBHOTH_OK));
  EXPECT_CALL(mock_, receive(_, _, _, _, _))
      .WillOnce(DoAll(CopyResp(&header, sizeof(header)), Return(LIBHOTH_OK)))
      .WillOnce(DoAll(CopyResp(&response1, sizeof(header) +
                                               PROVISIONING_LOG_CHUNK_MAX_SIZE),
                      Return(LIBHOTH_OK)))
      .WillOnce(DoAll(CopyResp(&response2, sizeof(header) +
                                               PROVISIONING_LOG_CHUNK_MAX_SIZE),
                      Return(LIBHOTH_OK)))
      .WillOnce(DoAll(CopyResp(&response3, sizeof(header) + last_chunk_size),
                      Return(LIBHOTH_OK)));

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
  uint32_t prov_checksum =
      crc32(0, perso_blob_data.data(), perso_blob_data.size());
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
      tmp_dir_path_ +
      "/perso_blob.ValidateAndSignPersoBlobFileEmpty.bin";
  std::string tmp_output_file =
      tmp_dir_path_ +
      "/signed_log.ValidateAndSignPersoBlobFileEmpty.bin";
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
