#include "libhoth_device_mock.h"

static int send(struct libhoth_device* dev, const void* request,
                size_t request_size) {
  LibHothDeviceMock* mock = (LibHothDeviceMock*)dev->user_ctx;
  return mock->send(dev, request, request_size);
}

static int receive(struct libhoth_device* dev, void* response,
                   size_t max_response_size, size_t* actual_size,
                   int timeout_ms) {
  LibHothDeviceMock* mock = (LibHothDeviceMock*)dev->user_ctx;
  return mock->receive(dev, response, max_response_size, actual_size,
                       timeout_ms);
}

LibHothTest::LibHothTest() {
  hoth_dev_.user_ctx = &mock_;
  hoth_dev_.send = send;
  hoth_dev_.receive = receive;

  // protocol operations should never touch these
  hoth_dev_.close = nullptr;
  hoth_dev_.claim = nullptr;
  hoth_dev_.release = nullptr;
}
