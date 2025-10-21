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

#ifndef _LIBHOTH_PROTOCOL_TEST_LIBHOTH_DEVICE_MOCK_H_
#define _LIBHOTH_PROTOCOL_TEST_LIBHOTH_DEVICE_MOCK_H_

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstring>

#include "protocol/host_cmd.h"
#include "transports/libhoth_device.h"

class LibHothDeviceMock {
 public:
  MOCK_METHOD(int, send,
              (struct libhoth_device * dev, const void* request,
               size_t request_size),
              ());
  MOCK_METHOD(int, receive,
              (struct libhoth_device * dev, void* response,
               size_t max_response_size, size_t* actual_size, int timeout_ms),
              ());
};

class LibHothTest : public testing::Test {
 protected:
  LibHothTest();
  struct libhoth_device hoth_dev_;
  LibHothDeviceMock mock_;
};

MATCHER_P(UsesCommand, command, "") {
  struct hoth_host_request* req = (struct hoth_host_request*)arg;
  return req->command == command;
}

MATCHER_P2(UsesCommandWithVersion, command, version, "") {
  struct hoth_host_request* req = (struct hoth_host_request*)arg;
  return req->command == command && req->command_version == version;
}

ACTION_P(CopyResp, response, resp_size) {
  auto full_resp_size = sizeof(struct hoth_host_response) + resp_size;

  struct {
    struct hoth_host_response hdr;
    uint8_t payload_buf[LIBHOTH_MAILBOX_SIZE - sizeof(struct hoth_host_response)];
  } resp;

  ASSERT_LE(full_resp_size, sizeof(resp));

  resp.hdr.struct_version = HOTH_HOST_RESPONSE_VERSION;
  resp.hdr.result = HOTH_RES_SUCCESS;
  resp.hdr.data_len = resp_size;
  resp.hdr.reserved = 0;
  resp.hdr.checksum = 0;

  std::memcpy(resp.payload_buf, response, resp_size);

  resp.hdr.checksum = libhoth_calculate_checksum(
      &resp.hdr, sizeof(resp.hdr), &resp.payload_buf, resp_size);

  std::memcpy(arg1, &resp, full_resp_size);
  *arg3 = full_resp_size;
}

ACTION_P(CopyRespRaw, response, resp_size) {
  ASSERT_LE(resp_size, arg2);
  std::memcpy(arg1, response, resp_size);
  *arg3 = resp_size;
}

#endif  // _LIBHOTH_PROTOCOL_TEST_LIBHOTH_DEVICE_MOCK_H_
