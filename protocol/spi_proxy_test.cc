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

#define SPI_TEST_DEFAULT_ADDR 0x1000
#define SPI_TEST_DEFAULT_SIZE 5
// The chunk size includes the hoth_spi_operation_request header to represent the full SPI operation payload
#define SPI_TEST_DEFAULT_CHUNK_SIZE (sizeof(struct hoth_spi_operation_request) + SPI_TEST_DEFAULT_SIZE)
// Replicating the offset calculation for spi operation request MISO data offset
#define SPI_TEST_OP_REQ_MISO_OFFSET (sizeof(struct hoth_spi_operation_request)) + 1 // sizeof(SPI_OP_READ) = 1

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
  std::vector<uint8_t> buffer(SPI_TEST_DEFAULT_CHUNK_SIZE, 0);

  std::vector<uint8_t> mock_resp_buffer(SPI_TEST_DEFAULT_CHUNK_SIZE, 0);

  uint32_t prng_seed = 0xA5A5A5A5;

  for(int i = 0; i < 4; i++) {
    mock_resp_buffer[SPI_TEST_OP_REQ_MISO_OFFSET + i] = ((uint8_t)libhoth_generate_pseudorandom_u32(&prng_seed));
    buffer[SPI_TEST_OP_REQ_MISO_OFFSET + i] = mock_resp_buffer[SPI_TEST_OP_REQ_MISO_OFFSET + i];
  }

  EXPECT_CALL(mock_, send(_,
                          UsesCommand(HOTH_CMD_BOARD_SPECIFIC_BASE +
                                      HOTH_PRV_CMD_HOTH_SPI_OPERATION),
                          _))
      .WillRepeatedly(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillRepeatedly(DoAll(CopyResp(&buffer[0], SPI_TEST_DEFAULT_CHUNK_SIZE + 1), Return(LIBHOTH_OK)));

  struct libhoth_spi_proxy spi = {};
  spi.dev = &hoth_dev_;
  spi.is_4_byte = true;

  struct libhoth_progress_stderr progress = {};
  libhoth_progress_stderr_init(&progress, "Verifying SPI flash");

  EXPECT_EQ(libhoth_spi_proxy_verify(&spi, SPI_TEST_DEFAULT_ADDR, &mock_resp_buffer[SPI_TEST_OP_REQ_MISO_OFFSET], SPI_TEST_DEFAULT_SIZE, &progress.progress), LIBHOTH_OK);
}
