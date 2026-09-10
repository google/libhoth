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

//! A thin Rust wrapper around `libhoth_device`.
//!
//! This crate is transport-agnostic: it knows how to talk to an already-open
//! `libhoth_device` and nothing else. Use one of the transport crates
//! (`hoth_usb`, `hoth_spi`) to obtain a [`HothDevice`].
//!
//! There are no dependencies beyond `std`. Host command framing, checksums and
//! response validation are all done by the C library; requests and responses
//! are plain byte buffers here.

use core::ffi::c_void;
use std::fmt;
use std::os::raw::c_int;

/// Largest host command payload that fits in the mailbox, in bytes.
///
/// Mirrors `LIBHOTH_MAILBOX_SIZE` minus the size of `struct hoth_host_response`.
pub const MAX_PAYLOAD_SIZE: usize = 1024 - 8;

/// Opaque handle to the C `struct libhoth_device`.
#[repr(C)]
pub struct LibhothDevice {
    _unused: [u8; 0],
}

unsafe extern "C" {
    fn libhoth_send_request(
        dev: *mut LibhothDevice,
        request: *const c_void,
        request_size: usize,
    ) -> c_int;

    fn libhoth_receive_response(
        dev: *mut LibhothDevice,
        response: *mut c_void,
        max_response_size: usize,
        actual_size: *mut usize,
        timeout_ms: c_int,
    ) -> c_int;

    fn libhoth_device_close(dev: *mut LibhothDevice) -> c_int;

    fn libhoth_hostcmd_exec_v2(
        dev: *mut LibhothDevice,
        command: u16,
        version: u8,
        req_payload: *const c_void,
        req_payload_size: usize,
        resp_buf: *mut c_void,
        resp_buf_size: usize,
        out_resp_size: *mut usize,
    ) -> u64;
}

/// An error reported by the C library.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The device handle was null.
    NullDevice,
    /// An argument could not be passed to the C library.
    InvalidArgument(&'static str),
    /// A `libhoth_status` code, as returned by the transport functions.
    Status(c_int),
    /// A 64-bit `libhoth_error`, as returned by `libhoth_hostcmd_exec_v2`.
    ///
    /// Use [`Error::context`], [`Error::space`] and [`Error::code`] to decode it.
    HostCommand(u64),
}

impl Error {
    /// The `hoth_context_id` of a [`Error::HostCommand`], otherwise `None`.
    pub fn context(&self) -> Option<u16> {
        match self {
            Self::HostCommand(err) => Some((err >> 48) as u16),
            _ => None,
        }
    }

    /// The `hoth_host_space` of a [`Error::HostCommand`], otherwise `None`.
    pub fn space(&self) -> Option<u16> {
        match self {
            Self::HostCommand(err) => Some((err >> 32) as u16),
            _ => None,
        }
    }

    /// The error code of a [`Error::HostCommand`], otherwise `None`.
    pub fn code(&self) -> Option<u32> {
        match self {
            Self::HostCommand(err) => Some(*err as u32),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NullDevice => write!(f, "null libhoth_device"),
            Self::InvalidArgument(what) => write!(f, "invalid argument: {what}"),
            Self::Status(status) => write!(f, "libhoth_status {status}"),
            Self::HostCommand(err) => write!(
                f,
                "libhoth_error {err:#018x} (ctx {:#x}, space {:#x}, code {:#x})",
                err >> 48,
                (err >> 32) as u16,
                *err as u32,
            ),
        }
    }
}

impl std::error::Error for Error {}

/// Converts a `libhoth_status` return value into a `Result`.
///
/// Transport crates use this to report failures from their `_open` functions.
pub fn check(status: c_int) -> Result<(), Error> {
    if status == 0 {
        Ok(())
    } else {
        Err(Error::Status(status))
    }
}

/// An owned `libhoth_device`, closed on drop.
pub struct HothDevice {
    dev: *mut LibhothDevice,
    cleanup: Option<(unsafe extern "C" fn(*mut c_void), *mut c_void)>,
}

unsafe impl Send for HothDevice {}

impl HothDevice {
    /// Takes ownership of an existing raw `libhoth_device` pointer.
    ///
    /// The device is closed when the returned `HothDevice` is dropped.
    ///
    /// # Safety
    /// `dev` must be a valid, uniquely owned pointer to a `libhoth_device`.
    pub unsafe fn from_raw(dev: *mut LibhothDevice) -> Result<Self, Error> {
        if dev.is_null() {
            return Err(Error::NullDevice);
        }
        Ok(Self { dev, cleanup: None })
    }

    /// Takes ownership of a raw `libhoth_device` that needs transport-specific
    /// teardown, such as a libusb context.
    ///
    /// `cleanup(cleanup_arg)` is called once, immediately after the device is
    /// closed.
    ///
    /// # Safety
    /// `dev` must be a valid, uniquely owned pointer to a `libhoth_device`, and
    /// `cleanup_arg` must remain valid until `cleanup` is called.
    pub unsafe fn from_raw_with_cleanup(
        dev: *mut LibhothDevice,
        cleanup: unsafe extern "C" fn(*mut c_void),
        cleanup_arg: *mut c_void,
    ) -> Result<Self, Error> {
        // SAFETY: forwarded to the caller of this function.
        let mut device = unsafe { Self::from_raw(dev) }?;
        device.cleanup = Some((cleanup, cleanup_arg));
        Ok(device)
    }

    /// Returns the underlying raw `libhoth_device` pointer, still owned by `self`.
    pub fn as_raw(&self) -> *mut LibhothDevice {
        self.dev
    }

    /// Executes a host command, returning the response payload.
    ///
    /// `request` is the request payload; the C library adds the host command
    /// header, checksum, and validates the response.
    pub fn exec(&mut self, command: u16, version: u8, request: &[u8]) -> Result<Vec<u8>, Error> {
        let mut response = vec![0u8; MAX_PAYLOAD_SIZE];
        let mut response_size = 0usize;
        // SAFETY: the buffers outlive the call and their lengths are passed
        // alongside their pointers.
        let err = unsafe {
            libhoth_hostcmd_exec_v2(
                self.dev,
                command,
                version,
                request.as_ptr() as *const c_void,
                request.len(),
                response.as_mut_ptr() as *mut c_void,
                response.len(),
                &mut response_size,
            )
        };
        if err != 0 {
            return Err(Error::HostCommand(err));
        }
        response.truncate(response_size);
        Ok(response)
    }

    /// Sends a raw, fully framed request buffer.
    pub fn send(&mut self, request: &[u8]) -> Result<(), Error> {
        // SAFETY: `request` outlives the call and its length is passed along.
        check(unsafe {
            libhoth_send_request(self.dev, request.as_ptr() as *const c_void, request.len())
        })
    }

    /// Receives a raw response into `response`, returning the bytes written.
    pub fn receive(&mut self, response: &mut [u8], timeout_ms: i32) -> Result<usize, Error> {
        let mut actual_size = 0usize;
        // SAFETY: `response` outlives the call and its length is passed along.
        check(unsafe {
            libhoth_receive_response(
                self.dev,
                response.as_mut_ptr() as *mut c_void,
                response.len(),
                &mut actual_size,
                timeout_ms,
            )
        })?;
        Ok(actual_size)
    }
}

impl Drop for HothDevice {
    fn drop(&mut self) {
        // SAFETY: `dev` is owned by `self` and is only closed here. The cleanup
        // callback was supplied by the transport that opened the device, and
        // runs after the device is closed.
        unsafe {
            libhoth_device_close(self.dev);
            if let Some((cleanup, arg)) = self.cleanup.take() {
                cleanup(arg);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_command_error_is_decoded() {
        // LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_EC, 3)
        let err = Error::HostCommand(0x001e_0001_0000_0003);
        assert_eq!(err.context(), Some(30));
        assert_eq!(err.space(), Some(1));
        assert_eq!(err.code(), Some(3));
    }

    #[test]
    fn status_error_has_no_host_command_fields() {
        let err = Error::Status(4);
        assert_eq!(err.context(), None);
        assert_eq!(err.space(), None);
        assert_eq!(err.code(), None);
    }
}
