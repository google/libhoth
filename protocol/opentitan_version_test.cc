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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>

#include "test/libhoth_device_mock.h"
#include "opentitan_version.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::ElementsAreArray;
using ::testing::Return;

TEST_F(LibHothTest, opentitan_version_test) {

  struct opentitan_get_version_resp mock_response = {};
  struct opentitan_get_version_resp response = {};

  mock_response.rom_ext.slots[0].major = 0;
  mock_response.rom_ext.slots[0].minor = 123;
  mock_response.rom_ext.slots[1].major = 0;
  mock_response.rom_ext.slots[1].minor = 124;

  mock_response.app.slots[0].major = 0;
  mock_response.app.slots[0].minor = 123;
  mock_response.app.slots[1].major = 0;
  mock_response.app.slots[1].minor = 124;


  EXPECT_CALL(mock_, send(_, UsesCommand(HOTH_OPENTITAN_GET_VERSION), _))
    .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
    .WillOnce(
        DoAll(CopyResp(&mock_response, sizeof(mock_response)), Return(LIBHOTH_OK)));
  
  EXPECT_EQ(libhoth_opentitan_version(&hoth_dev_, &response), LIBHOTH_OK);

  EXPECT_EQ(response.rom_ext.slots[0].major, mock_response.rom_ext.slots[0].major);
  EXPECT_EQ(response.rom_ext.slots[0].minor, mock_response.rom_ext.slots[0].minor);
  EXPECT_EQ(response.rom_ext.slots[1].major, mock_response.rom_ext.slots[1].major);
  EXPECT_EQ(response.rom_ext.slots[1].minor, mock_response.rom_ext.slots[1].minor);
  EXPECT_EQ(response.app.slots[0].major, mock_response.app.slots[0].major);
  EXPECT_EQ(response.app.slots[0].minor, mock_response.app.slots[0].minor);
  EXPECT_EQ(response.app.slots[1].major, mock_response.app.slots[1].major);
  EXPECT_EQ(response.app.slots[1].minor, mock_response.app.slots[1].minor);


}
