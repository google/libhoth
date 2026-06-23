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

#include <chrono>
#include <cstring>
#include <expected>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "hoth_device.h"
#include "usb_hoth_device.h"
#include "mtd_hoth_device.h"
#include "spi_hoth_device.h"
#include "transports/libhoth_device.h"
#include "transports/libhoth_usb.h"
#include "transports/libhoth_mtd.h"
#include "transports/libhoth_spi.h"
#include "protocol/hello.h"
#include <libusb.h>


bool TestHello(HothDevice& device, int iteration) {
  uint32_t input = 0x12345678 + iteration;
  uint32_t output = 0;
  libhoth_error err = libhoth_hello(device.Dev(), input, &output);
  if (err != HOTH_SUCCESS) {
    std::cerr << "\n  Hello request failed with error: " << err << std::endl;
    return false;
  }

  uint32_t expected_output = input + 0x01020304;
  if (output != expected_output) {
    std::cerr << "\n  ERROR: Unexpected output! Expected: 0x" << std::hex << expected_output 
              << ", Got: 0x" << std::hex << output << std::endl;
    return false;
  }
  return true;
}

bool TestClaimRelease(HothDevice& device) {
  // 1. Claim the device
  int status = libhoth_claim_device(device.Dev(), 1000000); // 1s timeout
  if (status != LIBHOTH_OK) {
    std::cerr << "\n  Failed to claim device: " << status << std::endl;
    return false;
  }

  // 2. Release the device
  status = libhoth_release_device(device.Dev());
  if (status != LIBHOTH_OK) {
    std::cerr << "\n  Failed to release device: " << status << std::endl;
    return false;
  }

  // 3. Claim it again and leave it claimed.
  // The caller (RunTransportTest) will drop the HothDevice while it is in this claimed state,
  // verifying that the RAII destructor correctly handles dropping a claimed device.
  status = libhoth_claim_device(device.Dev(), 1000000);
  if (status != LIBHOTH_OK) {
    std::cerr << "\n  Failed to claim device for drop test: " << status << std::endl;
    return false;
  }

  return true;
}

bool TestReconnect(HothDevice& device) {
  // 1. Attempt to reconnect
  int status = libhoth_device_reconnect(device.Dev());
  if (status != LIBHOTH_OK) {
    std::cerr << "\n  Reconnect failed: " << status << std::endl;
    return false;
  }

  // 2. Verify connection is still active by sending a hello request
  uint32_t output = 0;
  libhoth_error err = libhoth_hello(device.Dev(), 0x87654321, &output);
  if (err != HOTH_SUCCESS) {
    std::cerr << "\n  Hello request after reconnect failed: " << err << std::endl;
    return false;
  }

  uint32_t expected_output = 0x87654321 + 0x01020304;
  if (output != expected_output) {
    std::cerr << "\n  ERROR after reconnect: Unexpected output! Expected: 0x" << std::hex << expected_output 
              << ", Got: 0x" << std::hex << output << std::endl;
    return false;
  }

  return true;
}

// Generic test runner
bool RunTransportTest(
    const std::string& transport_name,
    std::function<std::expected<HothDevice, libhoth_status>()> factory,
    int iterations) {
  
  std::cout << "Starting transport test for: " << transport_name 
            << " (" << iterations << " iterations)... " << std::flush;

  for (int i = 0; i < iterations; ++i) {
    // 1. Construct
    auto device_or_err = factory();
    if (!device_or_err.has_value()) {
      std::cerr << "\nFailed to construct HothDevice on iteration " << (i + 1) 
                << ". Error code: " << device_or_err.error() << std::endl;
      return false;
    }

    {
      HothDevice device = std::move(device_or_err.value());

      // 2. Run tests
      if (!TestHello(device, i)) {
        std::cerr << "\nHello test failed on iteration " << (i + 1) << std::endl;
        return false;
      }

      if (!TestReconnect(device)) {
        std::cerr << "\nReconnect test failed on iteration " << (i + 1) << std::endl;
        return false;
      }

      if (!TestClaimRelease(device)) {
        std::cerr << "\nClaim/Release test failed on iteration " << (i + 1) << std::endl;
        return false;
      }
    } // Destruct (RAII close) - device is dropped here while claimed!
    
    std::cout << "." << std::flush;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  std::cout << " PASSED." << std::endl;
  return true;
}

void PrintUsage(const char* prog) {
  std::cerr << "Usage: " << prog << " --transport <usb|mtd|spi> [options]" << std::endl;
  std::cerr << "Common options:" << std::endl;
  std::cerr << "  --iterations <N>      Number of construct/destruct iterations (default: 5)" << std::endl;
  std::cerr << "USB options:" << std::endl;
  std::cerr << "  --usb_timeout <ms>    USB connection timeout in ms (default: 10000)" << std::endl;
  std::cerr << "MTD options:" << std::endl;
  std::cerr << "  --mtd_path <path>     MTD device path (e.g., /dev/mtd0)" << std::endl;
  std::cerr << "  --mtd_name <name>     MTD device name" << std::endl;
  std::cerr << "  --mailbox <addr>      Mailbox address (default: 0)" << std::endl;
  std::cerr << "SPI options:" << std::endl;
  std::cerr << "  --spi_path <path>     SPI device path (e.g., /dev/spidev0.0)" << std::endl;
  std::cerr << "  --spi_mailbox <addr>  SPI mailbox address (default: 0)" << std::endl;
  std::cerr << "  --spi_speed <hz>      SPI speed in Hz (default: 0, meaning driver default)" << std::endl;
}

int main(int argc, char* argv[]) {
  std::string transport = "";
  int iterations = 5;
  uint32_t usb_timeout_ms = 10000;
  std::string mtd_path = "";
  std::string mtd_name = "";
  uint32_t mailbox = 0;
  std::string spi_path = "";
  uint32_t spi_mailbox = 0;
  int spi_speed = 0;

  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--transport") == 0 && i + 1 < argc) {
      transport = argv[++i];
    } else if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
      iterations = std::stoi(argv[++i]);
    } else if (strcmp(argv[i], "--usb_timeout") == 0 && i + 1 < argc) {
      usb_timeout_ms = std::stoul(argv[++i]);
    } else if (strcmp(argv[i], "--mtd_path") == 0 && i + 1 < argc) {
      mtd_path = argv[++i];
    } else if (strcmp(argv[i], "--mtd_name") == 0 && i + 1 < argc) {
      mtd_name = argv[++i];
    } else if (strcmp(argv[i], "--mailbox") == 0 && i + 1 < argc) {
      mailbox = std::stoul(argv[++i], nullptr, 0);
    } else if (strcmp(argv[i], "--spi_path") == 0 && i + 1 < argc) {
      spi_path = argv[++i];
    } else if (strcmp(argv[i], "--spi_mailbox") == 0 && i + 1 < argc) {
      spi_mailbox = std::stoul(argv[++i], nullptr, 0);
    } else if (strcmp(argv[i], "--spi_speed") == 0 && i + 1 < argc) {
      spi_speed = std::stoi(argv[++i]);
    } else {
      PrintUsage(argv[0]);
      return 1;
    }
  }

  if (transport.empty()) {
    std::cerr << "ERROR: --transport is required." << std::endl;
    PrintUsage(argv[0]);
    return 1;
  }

  bool success = false;

  if (transport == "usb") {
    libusb_context* ctx = nullptr;
    int rv = libusb_init(&ctx);
    if (rv != LIBUSB_SUCCESS) {
      std::cerr << "libusb_init() failed: " << libusb_strerror(rv) << std::endl;
      return 1;
    }

    auto usb_factory = [&]() -> std::expected<HothDevice, libhoth_status> {
      return MakeUsbHothDevice(ctx, usb_timeout_ms * 1000);
    };

    success = RunTransportTest("USB", usb_factory, iterations);
    libusb_exit(ctx);

  } else if (transport == "mtd") {
    if (mtd_path.empty() && mtd_name.empty()) {
      std::cerr << "ERROR: MTD transport requires either --mtd_path or --mtd_name" << std::endl;
      return 1;
    }
    auto mtd_factory = [&]() -> std::expected<HothDevice, libhoth_status> {
      libhoth_mtd_device_init_options opts = {};
      opts.path = mtd_path.empty() ? nullptr : mtd_path.c_str();
      opts.name = mtd_name.empty() ? nullptr : mtd_name.c_str();
      opts.mailbox = mailbox;
      return MakeMtdHothDevice(opts);
    };
    success = RunTransportTest("MTD", mtd_factory, iterations);

  } else if (transport == "spi") {
    if (spi_path.empty()) {
      std::cerr << "ERROR: SPI transport requires --spi_path" << std::endl;
      return 1;
    }
    auto spi_factory = [&]() -> std::expected<HothDevice, libhoth_status> {
      libhoth_spi_device_init_options opts = {};
      opts.path = spi_path.c_str();
      opts.mailbox = spi_mailbox;
      opts.speed = spi_speed;
      opts.bits = 0;
      opts.mode = 0;
      opts.atomic = 0;
      opts.device_busy_wait_timeout = 180000000;
      opts.device_busy_wait_check_interval = 100;
      opts.timeout_us = 10000000;
      return MakeSpiHothDevice(opts);
    };
    success = RunTransportTest("SPI", spi_factory, iterations);
  } else {
    std::cerr << "ERROR: Unknown transport: " << transport << std::endl;
    return 1;
  }

  return success ? 0 : 1;
}
