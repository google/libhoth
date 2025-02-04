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

#include "protocol/payload_status.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstring>

#include "test/libhoth_device_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::StrEq;

const struct payload_status kDefaultPayloadStatus = {
    .resp_hdr =
        {
            .version = 0,
            .lockdown_state = 0,
            .active_half = 0,
            .region_count = 2,
        },
    .region_state = {{
                         .validation_state = PAYLOAD_IMAGE_INVALID,
                         .failure_reason = 1,
                         .image_type = 0,
                         .key_index = 0,
                         .image_family = 0,
                         .version_major = 0,
                         .version_minor = 0,
                         .version_point = 0,
                         .version_subpoint = 0,
                         .descriptor_offset = 0,
                     },
                     {
                         .validation_state = PAYLOAD_IMAGE_INVALID,
                         .failure_reason = 1,
                         .image_type = 0,
                         .key_index = 0,
                         .image_family = 0,
                         .version_major = 0,
                         .version_minor = 0,
                         .version_point = 0,
                         .version_subpoint = 0,
                         .descriptor_offset = 0,
                     }},

};

TEST_F(LibHothTest, payload_status_test) {
  EXPECT_CALL(mock_, send(_,
                          UsesCommand(EC_CMD_BOARD_SPECIFIC_BASE +
                                      EC_PRV_CMD_HOTH_PAYLOAD_STATUS),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(&kDefaultPayloadStatus, sizeof(kDefaultPayloadStatus)),
                Return(LIBHOTH_OK)));

  struct payload_status status;
  EXPECT_EQ(libhoth_payload_status(&hoth_dev_, &status), LIBHOTH_OK);

  EXPECT_TRUE(std::memcmp(&kDefaultPayloadStatus, &status, sizeof(status)) ==
              0);
}

TEST_F(LibHothTest, payload_status_bad_region_count) {
  EXPECT_CALL(mock_, send(_,
                          UsesCommand(EC_CMD_BOARD_SPECIFIC_BASE +
                                      EC_PRV_CMD_HOTH_PAYLOAD_STATUS),
                          _))
      .WillOnce(Return(LIBHOTH_OK));

  auto bad_status = kDefaultPayloadStatus;
  bad_status.resp_hdr.region_count = 3;

  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(&bad_status, sizeof(bad_status)), Return(LIBHOTH_OK)));

  struct payload_status status;
  EXPECT_EQ(libhoth_payload_status(&hoth_dev_, &status), -1);
}

TEST_F(LibHothTest, lockdown_status_string) {
  EXPECT_THAT(libhoth_sps_eeprom_lockdown_status_string(0), StrEq("Failsafe"));
  EXPECT_THAT(libhoth_sps_eeprom_lockdown_status_string(1), StrEq("Ready"));
  EXPECT_THAT(libhoth_sps_eeprom_lockdown_status_string(2), StrEq("Immutable"));
  EXPECT_THAT(libhoth_sps_eeprom_lockdown_status_string(3), StrEq("Enabled"));
  EXPECT_THAT(libhoth_sps_eeprom_lockdown_status_string(4),
              StrEq("(unknown sps_eeprom_lockdown_status)"));
}

TEST_F(LibHothTest, payload_validation_state_string) {
  EXPECT_THAT(libhoth_payload_validation_state_string(0), StrEq("Invalid"));
  EXPECT_THAT(libhoth_payload_validation_state_string(1), StrEq("Unverified"));
  EXPECT_THAT(libhoth_payload_validation_state_string(2), StrEq("Valid"));
  EXPECT_THAT(libhoth_payload_validation_state_string(3),
              StrEq("Descriptor Valid"));
  EXPECT_THAT(libhoth_payload_validation_state_string(4),
              StrEq("(unknown payload_validation_state)"));
}

TEST_F(LibHothTest, image_type_string) {
  EXPECT_THAT(libhoth_image_type_string(0), StrEq("Dev"));
  EXPECT_THAT(libhoth_image_type_string(1), StrEq("Prod"));
  EXPECT_THAT(libhoth_image_type_string(3), StrEq("Test"));
  EXPECT_THAT(libhoth_image_type_string(125), StrEq("(unknown image_type)"));
}
