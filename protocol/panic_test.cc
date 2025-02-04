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

#include "protocol/panic.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstring>
#include <fstream>

#include "test/libhoth_device_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::StrEq;

constexpr char kTestData[] = "protocol/test/panic_record.bin";

struct panic_data GetPanicData() {
  struct panic_data ret;
  std::ifstream test_record(kTestData);
  EXPECT_TRUE(test_record.is_open());

  for (std::size_t i = 0; i < sizeof(ret); i++) {
    reinterpret_cast<int8_t*>(&ret)[i] = test_record.get();
  }

  return ret;
}
TEST_F(LibHothTest, panic_data_test) {
  auto panic_data = GetPanicData();

  EXPECT_EQ(panic_data.struct_version, 2);
  EXPECT_EQ(panic_data.arch, PANIC_ARCH_RISCV_RV32I);
  EXPECT_EQ(panic_data.magic, PANIC_DATA_MAGIC);
  EXPECT_EQ(panic_data.struct_size, sizeof(panic_data));
}

TEST_F(LibHothTest, panic_test) {
  EXPECT_CALL(mock_, send(_,
                          UsesCommand(EC_CMD_BOARD_SPECIFIC_BASE +
                                      EC_PRV_CMD_HOTH_PERSISTENT_PANIC_INFO),
                          _))
      .WillRepeatedly(Return(LIBHOTH_OK));

  struct ec_response_persistent_panic_info exp_panic_record = {
      .uart_head = 0xFFFFFFFF,
      .uart_tail = 0xFFFFFFFF,
      .persistent_panic_record_version = 0,
  };

  exp_panic_record.rw_version.epoch = 6;
  exp_panic_record.rw_version.major = 5;
  exp_panic_record.rw_version.minor = 4;

  auto panic_data = GetPanicData();
  EXPECT_EQ(sizeof(panic_data), sizeof(exp_panic_record.panic_record));
  std::memcpy(&exp_panic_record.panic_record, &panic_data,
              sizeof(exp_panic_record.panic_record));
  auto n_chunks =
      sizeof(exp_panic_record) / HOTH_PERSISTENT_PANIC_INFO_CHUNK_SIZE;
  auto chunk_size = HOTH_PERSISTENT_PANIC_INFO_CHUNK_SIZE;

  uint8_t* resp_buf = reinterpret_cast<uint8_t*>(&exp_panic_record);
  std::size_t chunk_offset = 0;

  auto& exp_call = EXPECT_CALL(mock_, receive);
  for (std::size_t i = 0; i < n_chunks; i++) {
    exp_call.WillOnce(DoAll(CopyResp(resp_buf + chunk_offset, chunk_size),
                            Return(LIBHOTH_OK)));
    chunk_offset += HOTH_PERSISTENT_PANIC_INFO_CHUNK_SIZE;
  }

  struct ec_response_persistent_panic_info panic_record;
  EXPECT_EQ(libhoth_get_panic(&hoth_dev_, &panic_record), LIBHOTH_OK);

  EXPECT_EQ(exp_panic_record.rw_version.epoch, panic_record.rw_version.epoch);
  EXPECT_EQ(exp_panic_record.rw_version.major, panic_record.rw_version.major);
  EXPECT_EQ(exp_panic_record.rw_version.minor, panic_record.rw_version.minor);
}

TEST_F(LibHothTest, clear_panic_test) {
  EXPECT_CALL(mock_, send(_,
                          UsesCommand(EC_CMD_BOARD_SPECIFIC_BASE +
                                      EC_PRV_CMD_HOTH_PERSISTENT_PANIC_INFO),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  uint32_t dummy;

  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&dummy, 0), Return(LIBHOTH_OK)));

  EXPECT_EQ(libhoth_clear_persistent_panic_info(&hoth_dev_), LIBHOTH_OK);
}
