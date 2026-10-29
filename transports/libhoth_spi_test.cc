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

#include "transports/libhoth_spi.h"

#include <gtest/gtest.h>
#include <linux/spi/spidev.h>
#include <sys/ioctl.h>

#include <cstdarg>
#include <cstdint>
#include <cstring>
#include <vector>

#include "protocol/status.h"
#include "transports/libhoth_device.h"
#include "transports/libhoth_ec.h"

namespace {

struct CapturedSpiIoctl {
  int call_count = 0;
  unsigned long last_request = 0;
  std::vector<spi_ioc_transfer> xfers;
  std::vector<std::vector<uint8_t>> tx_payloads;
  struct hoth_host_response canned_response = {
      .struct_version = 3,
      .checksum = 0xfd,
      .result = 0,
      .data_len = 0,
      .reserved = 0,
  };
};

CapturedSpiIoctl* g_captured = nullptr;

extern "C" int __wrap_ioctl(int fd, unsigned long request, ...) {
  (void)fd;
  va_list ap;
  va_start(ap, request);
  auto* xfers = va_arg(ap, struct spi_ioc_transfer*);
  va_end(ap);

  if (!g_captured) {
    return -1;
  }
  g_captured->call_count++;
  g_captured->last_request = request;

  const size_t msg_bytes = _IOC_SIZE(request);
  const size_t num_xfers = msg_bytes / sizeof(struct spi_ioc_transfer);
  g_captured->xfers.assign(xfers, xfers + num_xfers);
  g_captured->tx_payloads.clear();
  for (size_t i = 0; i < num_xfers; ++i) {
    if (xfers[i].tx_buf != 0) {
      const auto* ptr = reinterpret_cast<const uint8_t*>(xfers[i].tx_buf);
      g_captured->tx_payloads.emplace_back(ptr, ptr + xfers[i].len);
    } else {
      g_captured->tx_payloads.emplace_back();
    }
    if (xfers[i].rx_buf != 0) {
      if (xfers[i].len >= sizeof(struct hoth_host_response)) {
        std::memcpy(reinterpret_cast<void*>(xfers[i].rx_buf),
                    &g_captured->canned_response,
                    sizeof(g_captured->canned_response));
      } else {
        std::memset(reinterpret_cast<void*>(xfers[i].rx_buf), 0, xfers[i].len);
      }
    }
  }
  return 0;
}

class LibHothSpiAtomicTest : public ::testing::Test {
 protected:
  void SetUp() override {
    g_captured = &captured_;
    spi_dev_.fd = 42;
    spi_dev_.mailbox_address = 0x00800000;
    spi_dev_.address_mode_4b = true;
    dev_.user_ctx = &spi_dev_;
  }

  void TearDown() override { g_captured = nullptr; }

  CapturedSpiIoctl captured_;
  struct libhoth_spi_device spi_dev_{};
  struct libhoth_device dev_{};
};

TEST_F(LibHothSpiAtomicTest,
       NonAtomicSendRequestSplitsMultiPageAndPollsBusyWait) {
  spi_dev_.device_busy_wait_timeout = 10000;
  spi_dev_.device_busy_wait_check_interval = 10;

  // 4,072 bytes spans 15 full 256B pages + 1 partial 232B page = 16 pages.
  std::vector<uint8_t> req(4072, 0x5a);
  ASSERT_EQ(libhoth_spi_send_request(&dev_, req.data(), req.size()),
            HOTH_SUCCESS);
  // 16 pages * (1 WRITE_ENABLE + 1 PAGE_PROGRAM + 1 READ_STATUS) = 48 ioctls.
  EXPECT_EQ(captured_.call_count, 48);

  std::vector<uint8_t> oversized(LIBHOTH_MAX_MAILBOX_SIZE + 1, 0x5a);
  EXPECT_EQ(libhoth_spi_send_request(&dev_, oversized.data(), oversized.size()),
            LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_SPI, HOTH_HOST_SPACE_LIBHOTH,
                                  LIBHOTH_ERR_INVALID_PARAMETER));
}

TEST_F(LibHothSpiAtomicTest, NonAtomicReceiveRejectsResponseAbove1KiBMailbox) {
  captured_.canned_response.data_len =
      LIBHOTH_MAILBOX_SIZE - sizeof(struct hoth_host_response) + 1;

  std::vector<uint8_t> resp_buf(LIBHOTH_MAX_MAILBOX_SIZE, 0);
  size_t actual_size = 0;
  EXPECT_EQ(libhoth_spi_receive_response(&dev_, resp_buf.data(),
                                         resp_buf.size(), &actual_size, 1000),
            LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_SPI, HOTH_HOST_SPACE_LIBHOTH,
                                  LIBHOTH_ERR_RESPONSE_BUFFER_OVERFLOW));
}

TEST_F(LibHothSpiAtomicTest, AtomicSinglePageSendAndReceiveClampsRxTo1KiB) {
  std::vector<uint8_t> req(SPI_NOR_FLASH_PAGE_SIZE, 0x3c);
  ASSERT_EQ(libhoth_spi_buffer_request(&dev_, req.data(), req.size()),
            HOTH_SUCCESS);

  std::vector<uint8_t> resp_buf(LIBHOTH_MAX_MAILBOX_SIZE, 0);
  size_t actual_size = 0;
  ASSERT_EQ(libhoth_spi_send_and_receive_response(
                &dev_, resp_buf.data(), resp_buf.size(), &actual_size, 1000),
            HOTH_SUCCESS);
  EXPECT_EQ(actual_size, sizeof(struct hoth_host_response));
  EXPECT_EQ(captured_.call_count, 1);
  ASSERT_EQ(captured_.xfers.size(), 5u);
  EXPECT_EQ(captured_.xfers[4].len, static_cast<size_t>(LIBHOTH_MAILBOX_SIZE));
  EXPECT_EQ(spi_dev_.buffered_request, nullptr);
}

TEST_F(LibHothSpiAtomicTest,
       AtomicBufferRequestRejectsMultiPageAndFreesOnInvalidReceive) {
  std::vector<uint8_t> multi_page(SPI_NOR_FLASH_PAGE_SIZE + 1, 0xaa);
  EXPECT_EQ(
      libhoth_spi_buffer_request(&dev_, multi_page.data(), multi_page.size()),
      LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_SPI, HOTH_HOST_SPACE_LIBHOTH,
                            LIBHOTH_ERR_INVALID_PARAMETER));
  EXPECT_EQ(spi_dev_.buffered_request, nullptr);

  uint8_t small_req[8] = {0};
  ASSERT_EQ(libhoth_spi_buffer_request(&dev_, small_req, sizeof(small_req)),
            HOTH_SUCCESS);
  uint8_t tiny_resp[4] = {0};
  size_t actual_size = 0;
  EXPECT_EQ(libhoth_spi_send_and_receive_response(
                &dev_, tiny_resp, sizeof(tiny_resp), &actual_size, 1000),
            LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_SPI, HOTH_HOST_SPACE_LIBHOTH,
                                  LIBHOTH_ERR_INVALID_PARAMETER));
  EXPECT_EQ(spi_dev_.buffered_request, nullptr);
}

}  // namespace
