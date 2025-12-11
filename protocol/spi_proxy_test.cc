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

#include "spi_proxy.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstring>
#include <vector>

#include "test/libhoth_device_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

const uint8_t SPI_OP_READ = 0x03;

// Test for spi_proxy_init for basic spi proxy initialization and communication
#define SPI_TEST_DEFAULT_ADDR 0x1000
// Default size for read/write operations in tests
#define SPI_TEST_DEFAULT_SIZE 5
// Default length for read/write operations in tests
#define SPI_TEST_DEFAULT_LEN 0x1024
// Size of MOSI data in test operations
#define SPI_TEST_MOSI_LEN 4

// Defines tailored to test the 64k erase boundary
// The data length is exactly 64k, and the address is aligned to 64k boundary
#define SPI_TEST_DATA_LEN_64K (65536)
#define SPI_TEST_ADDR_ALIGNED (0x20000)

// The SPI response payload length calculation
#define SPI_TEST_RESP_PAYLOAD_LEN (LIBHOTH_MAILBOX_SIZE - sizeof(struct hoth_host_response))
// Replicating the offset calculation for spi operation request MISO data offset
#define SPI_TEST_OP_REQ_MISO_OFFSET (sizeof(struct hoth_spi_operation_request)) + sizeof(SPI_OP_READ)

// Test for spi_proxy_init for basic spi proxy initialization and communication

TEST_F(LibHothTest, spi_proxy_init) {
  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_SPI_OPERATION),
                          _))
      .WillOnce(Return(LIBHOTH_OK));
  uint32_t dummy;
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&dummy, 0), Return(LIBHOTH_OK)));

  struct libhoth_spi_proxy spi;

  EXPECT_EQ(libhoth_spi_proxy_init(&spi, &hoth_dev_, false, false), LIBHOTH_OK);
}



TEST_F(LibHothTest, spi_proxy_verify) {
  //Create a buffer that matches a mock location that lives within
  //the external SPI flash and set to all zeros.
  std::vector<uint8_t> buffer(SPI_TEST_RESP_PAYLOAD_LEN, 0);

  std::vector<uint8_t> mock_resp_buffer(SPI_TEST_RESP_PAYLOAD_LEN, 0);

  // Populate the mock response buffer with expected data
  for(unsigned int i = 0; i < SPI_TEST_MOSI_LEN; i++) {
    mock_resp_buffer[SPI_TEST_OP_REQ_MISO_OFFSET + i] = (7 + i) % 256;
    buffer[SPI_TEST_OP_REQ_MISO_OFFSET + i] = mock_resp_buffer[SPI_TEST_OP_REQ_MISO_OFFSET + i];
  }

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_SPI_OPERATION),
                          _))
      .WillRepeatedly(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillRepeatedly(DoAll(CopyResp(&buffer[0], SPI_TEST_RESP_PAYLOAD_LEN), Return(LIBHOTH_OK)));

  struct libhoth_spi_proxy spi = {};
  spi.dev = &hoth_dev_;
  spi.is_4_byte = true;

  struct libhoth_progress_stderr progress = {};
  libhoth_progress_stderr_init(&progress, "Verifying SPI flash");

  EXPECT_EQ(libhoth_spi_proxy_verify(&spi, SPI_TEST_DEFAULT_ADDR, &mock_resp_buffer[SPI_TEST_OP_REQ_MISO_OFFSET], SPI_TEST_DEFAULT_SIZE, &progress.progress), LIBHOTH_OK);
}

// Test for spi_proxy_verify failure case
TEST_F(LibHothTest, spi_proxy_fail_verify) {
  //Create a buffer that matches a mock location that lives within
  //the external SPI flash and set to all zeros.
  std::vector<uint8_t> buffer(SPI_TEST_RESP_PAYLOAD_LEN, 0);

  std::vector<uint8_t> mock_resp_buffer(SPI_TEST_RESP_PAYLOAD_LEN, 0);

  // Populate the mock response buffer with expected data
  for(unsigned int i = 0; i < SPI_TEST_MOSI_LEN; i++) {
    mock_resp_buffer[SPI_TEST_OP_REQ_MISO_OFFSET + i] = (7 + i) % 256;
  }

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_SPI_OPERATION),
                          _))
      .WillRepeatedly(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillRepeatedly(DoAll(CopyResp(&buffer[0], SPI_TEST_RESP_PAYLOAD_LEN), Return(LIBHOTH_OK)));

  struct libhoth_spi_proxy spi = {};
  spi.dev = &hoth_dev_;
  spi.is_4_byte = true;

  struct libhoth_progress_stderr progress = {};
  libhoth_progress_stderr_init(&progress, "Verifying SPI flash");

  EXPECT_EQ(libhoth_spi_proxy_verify(&spi, SPI_TEST_DEFAULT_ADDR, &mock_resp_buffer[SPI_TEST_OP_REQ_MISO_OFFSET], SPI_TEST_DEFAULT_SIZE, &progress.progress), -1);
}

// Test for spi_proxy_update with progress callback enabled
TEST_F(LibHothTest, spi_proxy_update) {
  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_SPI_OPERATION),
                          _))
      .WillRepeatedly(Return(LIBHOTH_OK));

  uint32_t dummy;
  EXPECT_CALL(mock_, receive)
      .WillRepeatedly(DoAll(CopyResp(&dummy, 0), Return(LIBHOTH_OK)));


  struct libhoth_spi_proxy spi = {};
  spi.dev = &hoth_dev_;

  struct libhoth_progress_stderr progress = {};
  libhoth_progress_stderr_init(&progress, "Updating SPI flash");

  std::vector<uint8_t> buffer(SPI_TEST_DEFAULT_LEN);
  EXPECT_EQ(libhoth_spi_proxy_update(&spi, SPI_TEST_DEFAULT_ADDR, buffer.data(), SPI_TEST_DEFAULT_LEN, &progress.progress),
            LIBHOTH_OK);
}

// Testing to see if the 64k erase boundary is handled correctly
TEST_F(LibHothTest, spi_proxy_update_64k_erase) {
  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_SPI_OPERATION),
                          _))
      .WillRepeatedly(Return(LIBHOTH_OK));
      
  uint32_t dummy;
  EXPECT_CALL(mock_, receive)
      .WillRepeatedly(DoAll(CopyResp(&dummy, 0), Return(LIBHOTH_OK)));


  struct libhoth_spi_proxy spi = {};
  spi.dev = &hoth_dev_;

  std::vector<uint8_t> buffer(SPI_TEST_DATA_LEN_64K);
  EXPECT_EQ(libhoth_spi_proxy_update(&spi, SPI_TEST_ADDR_ALIGNED, buffer.data(), SPI_TEST_DATA_LEN_64K, nullptr),
            LIBHOTH_OK);
}
