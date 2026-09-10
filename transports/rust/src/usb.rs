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

//! Opens a [`HothDevice`] over USB.
//!
//! This is the only Rust crate that links against libusb.

use core::ffi::c_void;
use hoth_device::{Error, HothDevice, LibhothDevice, check};
use std::os::raw::c_int;

/// Maximum number of USB ports in a [`Location`] chain.
pub const MAX_PORTS: usize = 8;

#[repr(C)]
struct UsbLoc {
    bus: u8,
    ports: [u8; MAX_PORTS],
    num_ports: usize,
}

#[repr(C)]
struct UsbDeviceInitOptions {
    usb_device: *mut c_void,
    usb_ctx: *mut c_void,
    prng_seed: u32,
    timeout_us: u32,
}

unsafe extern "C" {
    fn libusb_init(ctx: *mut *mut c_void) -> c_int;
    fn libusb_exit(ctx: *mut c_void);
    fn libusb_unref_device(dev: *mut c_void);

    fn libhoth_usb_get_device(
        ctx: *mut c_void,
        usb_loc: *const UsbLoc,
        out: *mut *mut c_void,
    ) -> c_int;

    fn libhoth_usb_open(
        options: *const UsbDeviceInitOptions,
        out: *mut *mut LibhothDevice,
    ) -> c_int;
}

/// Where a device sits on the USB bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Location {
    /// The USB bus number.
    pub bus: u8,
    /// The chain of port numbers from the root hub, at most [`MAX_PORTS`] long.
    pub ports: [u8; MAX_PORTS],
    /// How many entries of `ports` are meaningful.
    pub num_ports: usize,
}

impl Location {
    /// Builds a `Location` from a bus and a port chain.
    ///
    /// Returns an error if `ports` is longer than [`MAX_PORTS`].
    pub fn new(bus: u8, ports: &[u8]) -> Result<Self, Error> {
        if ports.len() > MAX_PORTS {
            return Err(Error::InvalidArgument("too many USB ports"));
        }
        let mut location = Self {
            bus,
            ports: [0; MAX_PORTS],
            num_ports: ports.len(),
        };
        location.ports[..ports.len()].copy_from_slice(ports);
        Ok(location)
    }
}

/// How long to wait for the USB bus when opening a device, in microseconds.
pub const DEFAULT_TIMEOUT_US: u32 = 5_000_000;

/// Opens the only Hoth USB device on the bus.
///
/// Fails if there is more than one, in which case use [`open_at`].
pub fn open() -> Result<HothDevice, Error> {
    open_impl(None, DEFAULT_TIMEOUT_US)
}

/// Opens the Hoth USB device at `location`.
pub fn open_at(location: &Location) -> Result<HothDevice, Error> {
    open_impl(Some(location), DEFAULT_TIMEOUT_US)
}

/// Opens the Hoth USB device at `location`, waiting up to `timeout_us` for the
/// USB bus. Pass `None` to open the only device on the bus.
pub fn open_with_timeout(
    location: Option<&Location>,
    timeout_us: u32,
) -> Result<HothDevice, Error> {
    open_impl(location, timeout_us)
}

fn open_impl(location: Option<&Location>, timeout_us: u32) -> Result<HothDevice, Error> {
    let loc = location.map(|l| UsbLoc {
        bus: l.bus,
        ports: l.ports,
        num_ports: l.num_ports,
    });

    // SAFETY: every pointer below is either null or points at a live local, and
    // the libusb context is freed on every error path.
    unsafe {
        let mut ctx: *mut c_void = std::ptr::null_mut();
        check(libusb_init(&mut ctx))?;

        let loc_ptr = loc
            .as_ref()
            .map_or(std::ptr::null(), |l| l as *const UsbLoc);
        let mut usb_dev: *mut c_void = std::ptr::null_mut();
        if let Err(err) = check(libhoth_usb_get_device(ctx, loc_ptr, &mut usb_dev)) {
            libusb_exit(ctx);
            return Err(err);
        }

        let options = UsbDeviceInitOptions {
            usb_device: usb_dev,
            usb_ctx: ctx,
            prng_seed: 1,
            timeout_us,
        };
        let mut dev: *mut LibhothDevice = std::ptr::null_mut();
        let result = check(libhoth_usb_open(&options, &mut dev));
        libusb_unref_device(usb_dev);
        if let Err(err) = result {
            libusb_exit(ctx);
            return Err(err);
        }

        // The context has to outlive the device, so it is torn down by the
        // cleanup callback rather than here.
        HothDevice::from_raw_with_cleanup(dev, libusb_exit, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn location_rejects_too_many_ports() {
        assert_eq!(
            Location::new(1, &[0; MAX_PORTS + 1]),
            Err(Error::InvalidArgument("too many USB ports"))
        );
    }

    #[test]
    fn location_records_port_chain() {
        let location = Location::new(3, &[1, 2]).unwrap();
        assert_eq!(location.bus, 3);
        assert_eq!(location.num_ports, 2);
        assert_eq!(location.ports[..2], [1, 2]);
    }
}
