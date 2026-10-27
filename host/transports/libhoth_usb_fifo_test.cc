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

#include <gtest/gtest.h>
#include <libusb.h>

#include <cstdlib>
#include <cstring>
#include <vector>

#include "protocol/status.h"
#include "transports/libhoth_device.h"
#include "transports/libhoth_usb_device.h"

namespace {

constexpr size_t kRequestIdSize = 16;
constexpr size_t kFifoMtu = kRequestIdSize + LIBHOTH_MAX_MAILBOX_SIZE;

class LibHothUsbFifoTest : public ::testing::Test {
 protected:
  void SetUp() override {
    endpoints_[0].bEndpointAddress = LIBUSB_ENDPOINT_IN | 0x01;
    endpoints_[0].bmAttributes = LIBUSB_TRANSFER_TYPE_BULK;
    endpoints_[0].wMaxPacketSize = 64;
    endpoints_[1].bEndpointAddress = LIBUSB_ENDPOINT_OUT | 0x02;
    endpoints_[1].bmAttributes = LIBUSB_TRANSFER_TYPE_BULK;
    endpoints_[1].wMaxPacketSize = 64;

    altsetting_.bNumEndpoints = 2;
    altsetting_.endpoint = endpoints_;

    iface_.altsetting = &altsetting_;
    iface_.num_altsetting = 1;

    config_.bNumInterfaces = 1;
    config_.interface = &iface_;

    dev_.info.type = LIBHOTH_USB_INTERFACE_TYPE_FIFO;
    dev_.info.interface_id = 0;
    dev_.info.interface_altsetting = 0;

    ASSERT_EQ(libhoth_usb_fifo_open(&dev_, &config_, /*prng_seed=*/0x12345678),
              LIBHOTH_OK);
  }

  void TearDown() override {
    EXPECT_EQ(libhoth_usb_fifo_close(&dev_), LIBHOTH_OK);
  }

  struct libusb_endpoint_descriptor endpoints_[2]{};
  struct libusb_interface_descriptor altsetting_{};
  struct libusb_interface iface_{};
  struct libusb_config_descriptor config_{};
  struct libhoth_usb_device dev_{};
};

TEST_F(LibHothUsbFifoTest, AcceptsKrrSizedRequestUpToMaxMailbox) {
  std::vector<uint8_t> req(4096);
  for (size_t i = 0; i < req.size(); ++i) {
    req[i] = static_cast<uint8_t>(i * 3 + 1);
  }

  EXPECT_EQ(libhoth_usb_fifo_send_request(&dev_, req.data(), req.size()),
            LIBHOTH_OK);
  EXPECT_EQ(static_cast<size_t>(dev_.driver_data.fifo.out_transfer->length),
            kRequestIdSize + req.size());
  EXPECT_NE(dev_.driver_data.fifo.out_transfer->flags &
                LIBUSB_TRANSFER_ADD_ZERO_PACKET,
            0);
  EXPECT_EQ(std::memcmp(dev_.driver_data.fifo.out_buffer + kRequestIdSize,
                        req.data(), req.size()),
            0);

  std::vector<uint8_t> max_req(LIBHOTH_MAX_MAILBOX_SIZE, 0x5a);
  EXPECT_EQ(
      libhoth_usb_fifo_send_request(&dev_, max_req.data(), max_req.size()),
      LIBHOTH_OK);
  EXPECT_EQ(static_cast<size_t>(dev_.driver_data.fifo.out_transfer->length),
            kFifoMtu);
}

TEST_F(LibHothUsbFifoTest, RejectsOversizedRequestAboveMaxMailbox) {
  std::vector<uint8_t> oversized(LIBHOTH_MAX_MAILBOX_SIZE + 1, 0);
  EXPECT_EQ(
      libhoth_usb_fifo_send_request(&dev_, oversized.data(), oversized.size()),
      LIBUSB_ERROR_INVALID_PARAM);
}

}  // namespace
