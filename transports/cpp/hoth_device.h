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


#ifndef _LIBHOTH_HOTH_DEVICE_H_
#define _LIBHOTH_HOTH_DEVICE_H_

#include <utility>

#include "transports/libhoth_device.h"

// HothDevice is an RAII wrapper around a raw `libhoth_device` pointer.
// It assumes exclusive ownership of the pointer and will automatically
// close and free the device using `libhoth_device_close` when it goes
// out of scope.
//
// This class is non-copyable but movable, ensuring that there is always
// a single owner of the underlying device.
class HothDevice {
  public:
    explicit HothDevice(struct libhoth_device* dev);
    ~HothDevice();

    // Returns a raw pointer to the underlying libhoth_device.
    // The returned pointer is owned by this HothDevice instance and is
    // intended for temporary observation or passing to C API functions
    // (e.g., libhoth_hello, libhoth_claim_device).
    //
    // WARNING: Do NOT manually close the returned pointer using
    // `libhoth_device_close` or wrap it in another owning object,
    // as this will cause a double-free/crash when this HothDevice is dropped.
    struct libhoth_device* Dev() const noexcept;
    HothDevice(const HothDevice&) = delete;
    HothDevice& operator=(const HothDevice&) = delete;
    HothDevice(HothDevice&&) noexcept;
    HothDevice& operator=(HothDevice&&) noexcept;
    HothDevice& swap(HothDevice& other)
    {
        std::swap(this->dev_, other.dev_);
        return *this;
    }

  private:
    struct libhoth_device* dev_;
};


#endif // _LIBHOTH_HOTH_DEVICE_H_
