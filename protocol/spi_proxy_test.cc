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

#define SPI_PROXY_TEST_ADDR 0x1000
#define SPI_PROXY_TEST_DEFAULT_LEN 0x1024

// Defines tailored to test the 64k erase boundary
// The data length is exactly 64k, and the address is aligned to 64k boundary
#define SPI_PROXY_TEST_DATA_LEN_64K (65536)
#define SPI_PROXY_TEST_ADDR_ALIGNED (0x20000)

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

  std::vector<uint8_t> buffer(SPI_PROXY_TEST_DEFAULT_LEN);
  EXPECT_EQ(libhoth_spi_proxy_update(&spi, SPI_PROXY_TEST_ADDR, buffer.data(), SPI_PROXY_TEST_DEFAULT_LEN, &progress.progress),
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

  std::vector<uint8_t> buffer(SPI_PROXY_TEST_DATA_LEN_64K);
  EXPECT_EQ(libhoth_spi_proxy_update(&spi, SPI_PROXY_TEST_ADDR_ALIGNED, buffer.data(), SPI_PROXY_TEST_DATA_LEN_64K, nullptr),
            LIBHOTH_OK);
}