// Copyright 2026 Google LLC
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

#include "protocol/status.h"

#include <errno.h>
#include <gtest/gtest.h>
#include <stdio.h>
#include <string.h>

#include <string>

namespace {

// Helper to read entire file into string
std::string ReadFileToString(FILE* file) {
  std::string result;
  char buf[256];
  rewind(file);
  while (fgets(buf, sizeof(buf), file)) {
    result += buf;
  }
  return result;
}

class LibhothStatusTest : public ::testing::Test {
 protected:
  FILE* temp_file_ = nullptr;

  void SetUp() override {
    temp_file_ = tmpfile();
    ASSERT_NE(temp_file_, nullptr);
  }

  void TearDown() override {
    if (temp_file_) {
      fclose(temp_file_);
    }
  }

  std::string GetOutput() { return ReadFileToString(temp_file_); }
};

TEST_F(LibhothStatusTest, SuccessDoesNotLog) {
  libhoth_log_err(temp_file_, HOTH_SUCCESS);
  EXPECT_EQ(GetOutput(), "");
}

TEST_F(LibhothStatusTest, LogEcError) {
  // Context: USB, Space: EC, Code: HOTH_RES_TIMEOUT
  libhoth_error err =
      LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_USB, HOTH_HOST_SPACE_EC, HOTH_RES_TIMEOUT);
  libhoth_log_err(temp_file_, err);
  EXPECT_EQ(GetOutput(), "[USB][EC_RES][TIMEOUT]\n");
}

TEST_F(LibhothStatusTest, LogRawUint64) {
  // 0x000a00010000000aULL -> CTX: 10 (USB), Space: 1 (EC), Code: 10 (TIMEOUT)
  libhoth_error err = 0x000a00010000000aULL;
  libhoth_log_err(temp_file_, err);
  EXPECT_EQ(GetOutput(), "[USB][EC_RES][TIMEOUT]\n");
}

TEST_F(LibhothStatusTest, LogLibusbError) {
  // Context: USB, Space: LIBUSB, Code: -1 (LIBUSB_ERROR_IO)
  libhoth_error err = LIBHOTH_ERR_CONSTRUCT(
      HOTH_CTX_USB, HOTH_HOST_SPACE_LIBUSB, static_cast<uint32_t>(-1));
  libhoth_log_err(temp_file_, err);

  std::string expected = "[USB][LIBUSB][Input/Output Error]\n";
  EXPECT_EQ(GetOutput(), expected);
}

TEST_F(LibhothStatusTest, LogErrnoError) {
  // Context: SPI, Space: SPIDEV, Code: EINVAL
  libhoth_error err =
      LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_SPI, HOTH_HOST_SPACE_SPIDEV, EINVAL);
  libhoth_log_err(temp_file_, err);

  std::string expected =
      std::string("[SPI][SPIDEV][") + strerror(EINVAL) + "]\n";
  EXPECT_EQ(GetOutput(), expected);
}

TEST_F(LibhothStatusTest, LogUnhandledSpaceHex) {
  // Context: CMD_EXEC, Space: LIBHOTH, Code: 4 (LIBHOTH_ERR_TIMEOUT)
  libhoth_error err =
      LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH, 4);
  libhoth_log_err(temp_file_, err);
  EXPECT_EQ(GetOutput(), "[CMD_EXEC][LIBHOTH][0x00000004]\n");
}

TEST_F(LibhothStatusTest, LogUnknownContextAndSpace) {
  // Context: 99 (Unknown), Space: 99 (Unknown), Code: 0x1234
  libhoth_error err = LIBHOTH_ERR_CONSTRUCT(99, 99, 0x1234);
  libhoth_log_err(temp_file_, err);
  EXPECT_EQ(GetOutput(), "[UNKNOWN][UNKNOWN][0x00001234]\n");
}

TEST(LibhothStatusMacroTest, ConstructAndGetValid) {
  uint16_t ctx = 0x1234;
  uint16_t space = 0x5678;
  uint32_t code = 0x9ABCDEF0;

  libhoth_error err = LIBHOTH_ERR_CONSTRUCT(ctx, space, code);

  EXPECT_EQ(LIBHOTH_ERR_GET_CTX(err), ctx);
  EXPECT_EQ(LIBHOTH_ERR_GET_SPACE(err), space);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), code);
}

TEST(LibhothStatusMacroTest, ConstructAndGetZero) {
  libhoth_error err = LIBHOTH_ERR_CONSTRUCT(0, 0, 0);

  EXPECT_EQ(LIBHOTH_ERR_GET_CTX(err), 0);
  EXPECT_EQ(LIBHOTH_ERR_GET_SPACE(err), 0);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), 0);
  EXPECT_EQ(err, 0x0ULL);
}

TEST(LibhothStatusMacroTest, ConstructAndGetMax) {
  uint16_t ctx = 0xFFFF;
  uint16_t space = 0xFFFF;
  uint32_t code = 0xFFFFFFFF;

  libhoth_error err = LIBHOTH_ERR_CONSTRUCT(ctx, space, code);

  EXPECT_EQ(LIBHOTH_ERR_GET_CTX(err), ctx);
  EXPECT_EQ(LIBHOTH_ERR_GET_SPACE(err), space);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), code);
  EXPECT_EQ(err, 0xFFFFFFFFFFFFFFFFULL);
}

TEST(LibhothStatusMacroTest, ConstructTruncatesOverflow) {
  // Pass values that exceed the expected bit widths
  uint32_t oversized_ctx = 0x12345;    // 17 bits, should mask to 0x2345
  uint32_t oversized_space = 0x56789;  // 17 bits, should mask to 0x6789
  uint64_t oversized_code =
      0x9ABCDEF01ULL;  // 33 bits, should mask to 0xABCDEF01

  libhoth_error err =
      LIBHOTH_ERR_CONSTRUCT(oversized_ctx, oversized_space, oversized_code);

  EXPECT_EQ(LIBHOTH_ERR_GET_CTX(err), 0x2345);
  EXPECT_EQ(LIBHOTH_ERR_GET_SPACE(err), 0x6789);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(err), 0xABCDEF01);
}

}  // namespace
