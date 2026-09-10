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

//! Opens a [`HothDevice`] over spidev.
//!
//! This crate does not link against libusb.

use hoth_device::{Error, HothDevice, LibhothDevice, check};
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_uint};

#[repr(C)]
struct SpiDeviceInitOptions {
    path: *const c_char,
    mailbox: c_uint,
    bits: c_int,
    mode: c_int,
    speed: c_int,
    atomic: c_int,
    device_busy_wait_timeout: u32,
    device_busy_wait_check_interval: u32,
    timeout_us: u32,
}

unsafe extern "C" {
    fn libhoth_spi_open(
        options: *const SpiDeviceInitOptions,
        out: *mut *mut LibhothDevice,
    ) -> c_int;
}

/// The spidev used when [`Options::path`] is left at its default.
pub const DEFAULT_PATH: &str = "/dev/spidev0.0";

/// The mailbox address used when [`Options::mailbox`] is left at its default.
pub const DEFAULT_MAILBOX: u32 = 0x7FF_0000;

/// Settings for [`open`].
///
/// The defaults target a RoT at [`DEFAULT_PATH`] with its mailbox at
/// [`DEFAULT_MAILBOX`]; everything else matches htool's defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options<'a> {
    /// The spidev to open. Defaults to [`DEFAULT_PATH`].
    pub path: &'a str,
    /// Address of the mailbox on the RoT. Defaults to [`DEFAULT_MAILBOX`].
    pub mailbox: u32,
    /// Bits per word, or 0 to leave the spidev setting alone.
    pub bits: i32,
    /// SPI mode, or 0 to leave the spidev setting alone.
    pub mode: i32,
    /// Clock speed in Hz, or 0 to leave the spidev setting alone.
    pub speed: i32,
    /// Send the request and receive the response in a single ioctl. Required
    /// for correctness on some systems.
    pub atomic: bool,
    /// How long to wait, in microseconds, while the device reports being busy.
    pub busy_wait_timeout_us: u32,
    /// How long to wait, in microseconds, between busy checks.
    pub busy_wait_check_interval_us: u32,
    /// How long to wait, in microseconds, for the device when opening it.
    pub timeout_us: u32,
}

impl Default for Options<'_> {
    fn default() -> Self {
        Self {
            path: DEFAULT_PATH,
            mailbox: DEFAULT_MAILBOX,
            bits: 0,
            mode: 0,
            speed: 0,
            atomic: false,
            busy_wait_timeout_us: 180_000_000,
            busy_wait_check_interval_us: 100,
            timeout_us: 5_000_000,
        }
    }
}

/// Opens the Hoth device on the spidev described by `options`.
pub fn open(options: &Options) -> Result<HothDevice, Error> {
    let path = CString::new(options.path)
        .map_err(|_| Error::InvalidArgument("spidev path contains a NUL byte"))?;
    let c_options = SpiDeviceInitOptions {
        path: path.as_ptr(),
        mailbox: options.mailbox as c_uint,
        bits: options.bits,
        mode: options.mode,
        speed: options.speed,
        atomic: options.atomic as c_int,
        device_busy_wait_timeout: options.busy_wait_timeout_us,
        device_busy_wait_check_interval: options.busy_wait_check_interval_us,
        timeout_us: options.timeout_us,
    };

    let mut dev: *mut LibhothDevice = std::ptr::null_mut();
    // SAFETY: `path` and `c_options` outlive the call, which is all
    // libhoth_spi_open requires of the options struct.
    unsafe {
        check(libhoth_spi_open(&c_options, &mut dev))?;
        HothDevice::from_raw(dev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interior_nul_in_path_is_rejected() {
        let options = Options {
            path: "/dev/spi\0dev0.0",
            ..Default::default()
        };
        match open(&options) {
            Err(err) => assert_eq!(
                err,
                Error::InvalidArgument("spidev path contains a NUL byte")
            ),
            Ok(_) => panic!("expected an error"),
        }
    }
}
