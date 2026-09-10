//! Rust bindings for `libhoth_device`.

use aligned::{A4, Aligned};
use core::ffi::c_void;
use core::fmt;
use libhoth_protocol::{ProtocolError, Request, Response};
use std::os::raw::c_int;

#[repr(C)]
pub struct libhoth_device {
    _unused: [u8; 0],
}

#[repr(C)]
pub struct libhoth_usb_loc {
    pub bus: u8,
    pub ports: [u8; 8],
    pub num_ports: usize,
}

#[repr(C)]
pub struct libhoth_usb_device_init_options {
    pub usb_device: *mut c_void,
    pub usb_ctx: *mut c_void,
    pub prng_seed: u32,
    pub timeout_us: u32,
}

unsafe extern "C" {
    pub fn libhoth_send_request(
        dev: *mut libhoth_device,
        request: *const c_void,
        request_size: usize,
    ) -> c_int;

    pub fn libhoth_receive_response(
        dev: *mut libhoth_device,
        response: *mut c_void,
        max_response_size: usize,
        actual_size: *mut usize,
        timeout_ms: c_int,
    ) -> c_int;

    pub fn libhoth_device_close(dev: *mut libhoth_device) -> c_int;

    pub fn libusb_init(ctx: *mut *mut c_void) -> c_int;
    pub fn libusb_exit(ctx: *mut c_void);
    pub fn libusb_unref_device(dev: *mut c_void);

    pub fn libhoth_usb_get_device(
        ctx: *mut c_void,
        usb_loc: *const libhoth_usb_loc,
        out: *mut *mut c_void,
    ) -> c_int;

    pub fn libhoth_usb_open(
        options: *const libhoth_usb_device_init_options,
        out: *mut *mut libhoth_device,
    ) -> c_int;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HothError {
    Timeout,
    InterfaceNotFound,
    MallocFailed,
    OutUnderflow,
    InOverflow,
    UnsupportedVersion,
    InvalidParameter,
    Fail,
    NullDevice,
    Protocol(ProtocolError),
    Other(i32),
}

impl fmt::Display for HothError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => write!(f, "Hoth error: timeout"),
            Self::InterfaceNotFound => write!(f, "Hoth error: interface not found"),
            Self::MallocFailed => write!(f, "Hoth error: malloc failed"),
            Self::OutUnderflow => write!(f, "Hoth error: out underflow"),
            Self::InOverflow => write!(f, "Hoth error: in overflow"),
            Self::UnsupportedVersion => write!(f, "Hoth error: unsupported version"),
            Self::InvalidParameter => write!(f, "Hoth error: invalid parameter"),
            Self::Fail => write!(f, "Hoth error: generic failure"),
            Self::NullDevice => write!(f, "Hoth error: null device"),
            Self::Protocol(e) => write!(f, "Hoth protocol error: {e:?}"),
            Self::Other(c) => write!(f, "Hoth error code: {c}"),
        }
    }
}

impl std::error::Error for HothError {}

impl From<ProtocolError> for HothError {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}

impl HothError {
    pub fn from_c_int(code: c_int) -> Self {
        match code {
            4 => Self::Timeout,
            2 => Self::InterfaceNotFound,
            3 => Self::MallocFailed,
            5 => Self::OutUnderflow,
            6 => Self::InOverflow,
            7 => Self::UnsupportedVersion,
            8 => Self::InvalidParameter,
            9 => Self::Fail,
            other => Self::Other(other),
        }
    }
}

pub struct HothDevice {
    dev: *mut libhoth_device,
    usb_ctx: *mut c_void,
}

unsafe impl Send for HothDevice {}

impl HothDevice {
    /// Wrap an existing raw `libhoth_device` pointer.
    ///
    /// # Safety
    /// `dev` must be a valid, uniquely owned pointer to a `libhoth_device` or null.
    pub unsafe fn from_raw(dev: *mut libhoth_device) -> Result<Self, HothError> {
        if dev.is_null() {
            return Err(HothError::NullDevice);
        }
        Ok(Self {
            dev,
            usb_ctx: core::ptr::null_mut(),
        })
    }

    /// Open the first available Hoth USB device.
    pub fn open_usb() -> Result<Self, HothError> {
        Self::open_usb_loc_internal(None)
    }

    /// Open a Hoth USB device matching the given bus and port chain.
    pub fn open_usb_loc(bus: u8, ports: &[u8]) -> Result<Self, HothError> {
        let mut loc = libhoth_usb_loc {
            bus,
            ports: [0; 8],
            num_ports: ports.len(),
        };
        let copy_len = ports.len().min(8);
        loc.ports[..copy_len].copy_from_slice(&ports[..copy_len]);
        Self::open_usb_loc_internal(Some(loc))
    }

    fn open_usb_loc_internal(loc: Option<libhoth_usb_loc>) -> Result<Self, HothError> {
        unsafe {
            let mut ctx: *mut c_void = core::ptr::null_mut();
            let rc = libusb_init(&mut ctx);
            if rc != 0 {
                return Err(HothError::from_c_int(rc));
            }

            let mut usb_dev: *mut c_void = core::ptr::null_mut();
            let loc_ptr = match &loc {
                Some(l) => l as *const libhoth_usb_loc,
                None => core::ptr::null(),
            };
            let rc = libhoth_usb_get_device(ctx, loc_ptr, &mut usb_dev);
            if rc != 0 {
                libusb_exit(ctx);
                return Err(HothError::from_c_int(rc));
            }

            let opts = libhoth_usb_device_init_options {
                usb_device: usb_dev,
                usb_ctx: ctx,
                prng_seed: 1,
                timeout_us: 5_000_000,
            };
            let mut dev: *mut libhoth_device = core::ptr::null_mut();
            let rc = libhoth_usb_open(&opts, &mut dev);
            libusb_unref_device(usb_dev);

            if rc != 0 {
                libusb_exit(ctx);
                return Err(HothError::from_c_int(rc));
            }

            Ok(Self { dev, usb_ctx: ctx })
        }
    }

    /// Return the underlying raw `libhoth_device` pointer.
    pub fn as_raw(&self) -> *mut libhoth_device {
        self.dev
    }

    /// Consume `self` and return the raw `libhoth_device` pointer without closing it.
    pub fn into_raw(mut self) -> *mut libhoth_device {
        let dev = self.dev;
        self.dev = core::ptr::null_mut();
        self.usb_ctx = core::ptr::null_mut();
        dev
    }

    /// Send a raw request buffer.
    pub fn send(&mut self, request: &[u8]) -> Result<(), HothError> {
        if self.dev.is_null() {
            return Err(HothError::NullDevice);
        }
        let rc = unsafe {
            libhoth_send_request(
                self.dev,
                request.as_ptr() as *const c_void,
                request.len(),
            )
        };
        if rc != 0 {
            return Err(HothError::from_c_int(rc));
        }
        Ok(())
    }

    /// Receive a response into a buffer, returning the number of bytes read.
    pub fn receive(&mut self, response: &mut [u8], timeout_ms: i32) -> Result<usize, HothError> {
        if self.dev.is_null() {
            return Err(HothError::NullDevice);
        }
        let mut actual_size: usize = 0;
        let rc = unsafe {
            libhoth_receive_response(
                self.dev,
                response.as_mut_ptr() as *mut c_void,
                response.len(),
                &mut actual_size,
                timeout_ms,
            )
        };
        if rc != 0 {
            return Err(HothError::from_c_int(rc));
        }
        Ok(actual_size)
    }

    /// Send a raw request and receive the response.
    pub fn send_and_receive(
        &mut self,
        request: &[u8],
        response: &mut [u8],
        timeout_ms: i32,
    ) -> Result<usize, HothError> {
        self.send(request)?;
        self.receive(response, timeout_ms)
    }

    /// Send a typed `Request` and receive into an aligned response buffer, returning a `Response`.
    pub fn call<'a>(
        &mut self,
        req: &Request,
        resp_buf: &'a mut Aligned<A4, [u8]>,
        timeout_ms: i32,
    ) -> Result<&'a mut Response, HothError> {
        let actual_size = self.send_and_receive(req.as_bytes(), &mut resp_buf[..], timeout_ms)?;
        let resp = Response::mut_from_bytes(&mut resp_buf[..actual_size])?;
        Ok(resp)
    }
}

impl Drop for HothDevice {
    fn drop(&mut self) {
        if !self.dev.is_null() {
            unsafe {
                libhoth_device_close(self.dev);
            }
            self.dev = core::ptr::null_mut();
        }
        if !self.usb_ctx.is_null() {
            unsafe {
                libusb_exit(self.usb_ctx);
            }
            self.usb_ctx = core::ptr::null_mut();
        }
    }
}
