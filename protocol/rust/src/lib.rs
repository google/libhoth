#![cfg_attr(not(test), no_std)]
// TODO(kor): Get rid of these once zerocopy can compute num_elements from the
// (un-padded) len
#![feature(ptr_metadata)]
#![feature(layout_for_ptr)]

use aligned::{A4, Aligned};
use core::cmp::min;
use core::fmt::Debug;
use core::mem::align_of_val_raw;
use core::mem::offset_of;
use core::mem::size_of;
use core::mem::size_of_val_raw;
use core::ptr;
use core::ptr::Pointee;
use core::slice;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const MIN_HOST_COMMAND_BUFFER_SIZE: usize = 6144;
pub const HOST_COMMAND_VERSION: u8 = 3;

use zerocopy::ConvertError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolSizeError {
    BufferOverflow,
    InvalidSize,
    DataLenOverflow,
}

impl core::fmt::Display for ProtocolSizeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferOverflow => write!(f, "buffer overflow"),
            Self::InvalidSize => write!(f, "invalid size"),
            Self::DataLenOverflow => write!(f, "data length overflow"),
        }
    }
}

pub type ProtocolError = zerocopy::ConvertError<(), ProtocolSizeError, ()>;

pub const PROTOCOL_ERROR_BUFFER_OVERFLOW: ProtocolError =
    ConvertError::Size(ProtocolSizeError::BufferOverflow);
pub const PROTOCOL_ERROR_INVALID_SIZE: ProtocolError =
    ConvertError::Size(ProtocolSizeError::InvalidSize);
pub const PROTOCOL_ERROR_DATA_LEN_OVERFLOW: ProtocolError =
    ConvertError::Size(ProtocolSizeError::DataLenOverflow);
pub const PROTOCOL_ERROR_INVALID_ALIGNMENT: ProtocolError =
    ConvertError::Alignment(());

impl ProtocolSizeError {
    pub const BUFFER_OVERFLOW: ProtocolError = PROTOCOL_ERROR_BUFFER_OVERFLOW;
    pub const INVALID_SIZE: ProtocolError = PROTOCOL_ERROR_INVALID_SIZE;
    pub const DATA_LEN_OVERFLOW: ProtocolError = PROTOCOL_ERROR_DATA_LEN_OVERFLOW;
    pub const INVALID_ALIGNMENT: ProtocolError = PROTOCOL_ERROR_INVALID_ALIGNMENT;
}

#[derive(Debug, FromBytes, Immutable, KnownLayout, IntoBytes, PartialEq, Eq)]
#[repr(C)]
pub struct RequestHeader {
    pub version: u8,
    pub checksum: u8,
    pub command: HostCommand,
    pub command_version: u8,
    pub reserved: u8,
    pub data_len: u16,
}
const _: () = {
    assert!(offset_of!(RequestHeader, version) == 0);
    assert!(offset_of!(RequestHeader, checksum) == 1);
    assert!(offset_of!(RequestHeader, command) == 2);
    assert!(offset_of!(RequestHeader, command_version) == 4);
    assert!(offset_of!(RequestHeader, data_len) == 6);
    assert!(size_of::<RequestHeader>() == 8);
};

const _: () = assert!(size_of::<RequestHeader>() == 8);

impl RequestHeader {
    pub const REQ_VERSION: u8 = 3;

    pub fn req_len(&self) -> Option<usize> {
        if self.version != Self::REQ_VERSION {
            return None;
        }

        if self.reserved != 0 {
            return None;
        }

        Some(size_of::<Self>() + usize::from(self.data_len))
    }
}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct HostCommand(pub u16);

// Update entries in
// `lib/host_command/is_host_command_supported.rs:IMPLEMENTED_HOST_COMMAND_CONSTANTS` as well when
// updating the entries here
impl HostCommand {
    pub const HELLO: Self = Self(1);
    pub const GET_VERSION: Self = Self(2);

    pub const REBOOT: Self = Self(0x00D2);

    pub const CHIP_INFO: Self = Self(0x3e10);
    pub const TARGET_CONTROL: Self = Self(0x3e47); // TODO Properly handle the 0x3e__ offset
    pub const CHANNEL_READ: Self = Self(0x3e36);
    pub const CHANNEL_STATUS: Self = Self(0x3e37);
    pub const TPM: Self = Self(0x3e33);
    pub const DFU_WRITE: Self = Self(0x3e4f);
    pub const DFU_COMPLETE: Self = Self(0x3e50);
    pub const SET_TPM_MODE: Self = Self(0x3e51);
    pub const GET_TPM_MODE: Self = Self(0x3e52);
    pub const _GET_AUTHZ_STATE: Self = Self(0x3e53);
    pub const _GET_TPM_RTM_DATA: Self = Self(0x3e54);
    pub const _TPM_CONTROL: Self = Self(0x3e55);
    pub const SET_GPIO_DRIVE_STRENGTH: Self = Self(0x3e56);
    pub const _UPDATE_MAUV: Self = Self(0x3e57);
    pub const _UNIQUE_CHIP_ID: Self = Self(0x3e58);
    pub const GET_GPIO_DRIVE_STRENGTH: Self = Self(0x3e59);

    pub const OPENTITAN_GET_VERSION: Self = Self(0x3300);
    pub const OPENTITAN_GET_BOOT_LOG: Self = Self(0x3301);
    pub const OPENTITAN_SET_BOOT_SVC_MSG: Self = Self(0x3302);
    pub const OPENTITAN_GET_BOOT_SVC_MSG: Self = Self(0x3303);
    pub const OPENTITAN_READ_ACTIVE_OWNER_RECORD: Self = Self(0x3304);
    pub const OPENTITAN_WRITE_STAGING_OWNER_RECORD: Self = Self(0x3305);

    pub const TEST_ECHO_NOT: Self = Self(0x3201);
    pub const TEST_ECHO_REPEAT: Self = Self(0x3202);
    pub const TEST_ECHO_CHECKSUM: Self = Self(0x3203);
    pub const TEST_ECHO_SHA256: Self = Self(0x3204);

    pub const PAYLOAD_UPDATE: Self = Self(0x3e05);
    pub const PAYLOAD_STATUS: Self = Self(0x3e06);

    pub const TARGET_RESET: Self = Self(0x3e12); // refer to pie-rot/libhoth/examples/htool.c

    // commands prefixed with UNSAFE_ are only enabled if pie_rot is built with
    // --@mutask//:feature_unsafe_commands=true
    pub const UNSAFE_SYSCALL: Self = Self(0x3100);
    pub const UNSAFE_MEM_WRITE: Self = Self(0x3101);
    pub const UNSAFE_HANG: Self = Self(0x3102);

    pub const GET_STATISTICS: Self = Self(0x3e0f);
    pub const IS_HOST_COMMAND_SUPPORTED: Self = Self(0x3e11);
    pub const PERSISTENT_PANIC_INFO: Self = Self(0x3e14);
}

impl core::fmt::Display for HostCommand {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x{:04x}", self.0)
    }
}

struct DstMeta {
    align: usize,
    fixed_size: usize,
    elem_size: usize,
}
impl DstMeta {
    const fn get<T: ?Sized + Pointee<Metadata = usize>>() -> &'static Self {
        const {
            let ptr_0 = ptr::from_raw_parts::<T>(ptr::null::<()>(), 0);
            let align = unsafe { align_of_val_raw(ptr_0) };

            // Use align instead of 1 because size_of_val_raw() includes the
            // padding bytes, messing up the elem_size calculation when
            // elem_size < align.
            let ptr_1 = ptr::from_raw_parts::<T>(ptr::null::<()>(), align);

            let fixed_size = unsafe { size_of_val_raw(ptr_0) };
            let elem_size = (unsafe { size_of_val_raw(ptr_1) } - fixed_size) / align;

            &Self {
                align,
                fixed_size,
                elem_size,
            }
        }
    }
}

pub trait HostCmdReq: FromBytes + IntoBytes + Immutable + KnownLayout {
    const COMMAND: HostCommand;
    const VERSION: u8;
    type Response: HostCmdResp;

    /// Returns a `RequestHeader` with the correct version, command, and
    /// command_version for this request. `data_len` specifies the total length
    /// of the data.
    ///
    /// If Self is fixed-size, prefer [`HostCmdReq::header_template_fixed()`]
    #[inline(always)]
    fn header_template(data_len: usize) -> Result<RequestHeader, ProtocolError> {
        Ok(RequestHeader {
            version: RequestHeader::REQ_VERSION,
            checksum: 0, // Filled in by ReqBuilder::finalize()
            command: Self::COMMAND,
            reserved: 0,
            command_version: Self::VERSION,
            data_len: u16::try_from(data_len).map_err(|_| ProtocolSizeError::DATA_LEN_OVERFLOW)?,
        })
    }

    /// Returns a `RequestHeader` with the correct version, command,
    /// command_version, and length for this request.
    ///
    /// If Self is dynamically-sized, use [`HostCmdReq::header_template`].
    #[inline(always)]
    fn header_template_fixed() -> Result<RequestHeader, ProtocolError>
    where
        Self: Sized,
    {
        Self::header_template(core::mem::size_of::<Self>())
    }

    /// Helper for building a dynamically-sized request.
    ///
    /// `buf` is the buffer that will contain the request.
    /// `num_elems` is the number of elements in the dynamically-sized tail of
    /// the request.
    ///
    /// Returns a mutable reference to a `ReqBuilder` that can be used to
    /// populate the request and then finalize it. Upon finalization, all the
    /// header fields (including checksum) will be set.
    ///
    /// # Compile-time error
    ///
    /// Causes a compile-time error if `Self` is greater than 4-byte aligned.
    #[inline(always)]
    fn build_dynamic(
        buf: &mut Aligned<A4, [u8]>,
        num_elems: usize,
    ) -> Result<&mut ReqBuilder<Self>, ProtocolError>
    where
        Self: Pointee<Metadata = usize>,
    {
        // TODO(kor): Reimplement this once we update zerocopy with a version
        // that has KnownLayout::size_for_metadata(), and supports generics.
        let meta = const {
            let meta = DstMeta::get::<Self>();
            assert!(meta.align <= 4);
            meta
        };

        // We can't use
        // `size_of_val_raw(ptr::from_raw_parts_mut::<ReqBuilder<Self>>(buf.as_mut_ptr(), num_elems))`
        // because that has undefined behavior when the size overflows `isize`,
        // so compute the size manually...

        // Calculate the size of the data part
        let data_size = num_elems
            .checked_mul(meta.elem_size)
            .ok_or(ProtocolSizeError::BUFFER_OVERFLOW)?
            .checked_add(meta.fixed_size)
            .ok_or(ProtocolSizeError::BUFFER_OVERFLOW)?;

        // Calculate the total size of the RequestHeader, add to data
        let total_size = size_of::<RequestHeader>()
            .checked_add(data_size)
            .ok_or(ProtocolSizeError::BUFFER_OVERFLOW)?;

        // Account for 4 byte alignment
        let total_size_aligned = total_size
            .checked_next_multiple_of(4)
            .ok_or(ProtocolSizeError::BUFFER_OVERFLOW)?;

        if total_size_aligned > buf.len() {
            return Err(ProtocolSizeError::BUFFER_OVERFLOW);
        }

        let builder = unsafe {
            &mut *ptr::from_raw_parts_mut::<ReqBuilder<Self>>(buf.as_mut_ptr(), num_elems)
        };

        // Make sure the size-calculations above match the compiler (we can't
        // just use this because we need to check the size BEFORE we construct a
        // potentially-unsound rust reference.
        // TODO(kor): optimization: Use debug_assert_eq!() once we have more confidence in this code.
        assert_eq!(size_of_val(builder), total_size_aligned);

        builder.header = Self::header_template(data_size)?;
        // TODO(kor): Are we sure we want to do this?
        builder.data.as_mut_bytes().fill(0);
        Ok(builder)
    }

    #[inline(always)]
    fn build_fixed(buf: &mut Aligned<A4, [u8]>) -> Result<&mut ReqBuilder<Self>, ProtocolError>
    where
        Self: Sized,
    {
        let builder = unsafe { &mut *(buf.as_mut_ptr() as *mut ReqBuilder<Self>) };
        builder.header = Self::header_template_fixed()?;
        Ok(builder)
    }
}

/// A helper for building a host command request.
///
/// Construct it with [`HostCmdReq::build_fixed`] or
/// [`HostCmdReq::build_dynamic`], populate [`Self::data`], then call
/// [`Self::finalize()`].
#[derive(Eq, PartialEq)]
#[repr(C, align(4))]
pub struct ReqBuilder<R: HostCmdReq + ?Sized> {
    pub header: RequestHeader,
    pub data: R,
}
impl<R: HostCmdReq + ?Sized> ReqBuilder<R> {
    /// Finalizes the request by setting the checksum and returning a
    /// type-erased reference to the underlying request.
    pub fn finalize(&mut self) -> &mut Request {
        let len = core::mem::size_of::<RequestHeader>() + core::mem::size_of_val(&self.data);
        let slf: *mut Self = self;

        let bytes = unsafe {
            &mut *(ptr::slice_from_raw_parts(slf.cast::<u8>(), len) as *mut Aligned<A4, [u8]>)
        };
        let req = Request::mut_from_bytes(bytes).unwrap();
        req.set_checksum();
        req
    }
}

pub trait HostCmdResp: FromBytes + IntoBytes + Immutable + KnownLayout {}

impl HostCmdResp for () {}

mod request {

    use super::*;

    #[derive(Eq, PartialEq, FromBytes, Immutable, KnownLayout)]
    #[repr(C, align(4))]
    pub struct Request {
        pub header: RequestHeader,

        /// data_bytes is at least `self.len` bytes, with some space for padding
        pub data_bytes: [u8],
    }

    impl Request {
        const DATA_OFFSET: usize = size_of::<RequestHeader>();

        pub fn ref_from_bytes(r: &Aligned<A4, [u8]>) -> Result<&Self, ProtocolError> {
            let data_len = r
                .len()
                .checked_sub(Self::DATA_OFFSET)
                .ok_or(ProtocolSizeError::INVALID_SIZE)?;
            Ok(unsafe {
                // The metadata for a custom DST is the size of the
                // dynamically-sized field (data_len).
                &*(ptr::slice_from_raw_parts(r.as_ptr(), data_len) as *const Self)
            })
        }
        #[inline(always)]
        pub fn as_bytes(&self) -> &[u8] {
            unsafe {
                slice::from_raw_parts(
                    (self as *const Self).cast::<u8>(),
                    Self::DATA_OFFSET + self.data_bytes.len(),
                )
            }
        }

        /// Returns a reference to the data section of the request, interpreted
        /// as type `T`.
        ///
        /// If `T` is dynamically-sized, use [`Request::data_dynamic()`].
        pub fn data<T>(&self) -> Result<&T, ProtocolError>
        where
            T: FromBytes + KnownLayout + Immutable,
        {
            T::ref_from_bytes(&self.data_bytes).map_err(|_| ProtocolSizeError::INVALID_SIZE)
        }

        /// Returns a reference to the data section of the request, interpreted
        /// as dynamically sized type `T`.
        ///
        /// If `T` is fixed-sized, use [`Request::data()`].
        pub fn data_dynamic<T>(&self) -> Result<&T, ProtocolError>
        where
            T: ?Sized
                + Pointee<Metadata = usize>
                + FromBytes
                + KnownLayout<PointerMetadata = usize>
                + Immutable,
        {
            let meta = DstMeta::get::<T>();
            let elems_len = usize::from(self.header.data_len) - meta.fixed_size;
            let num_elems = elems_len / meta.elem_size;
            Ok(T::ref_from_prefix_with_elems(&self.data_bytes, num_elems).map_err(|_| ProtocolSizeError::INVALID_SIZE)?.0)
        }

        pub fn is_checksum_valid(&self) -> bool {
            let max_len = min(
                size_of::<RequestHeader>() + usize::from(self.header.data_len),
                self.as_bytes().len(),
            );
            self.as_bytes()[..max_len]
                .iter()
                .fold(0u8, |acc, &b| acc.wrapping_add(b))
                == 0
        }
    }

    impl Request {
        pub fn mut_from_bytes(r: &mut Aligned<A4, [u8]>) -> Result<&mut Self, ProtocolError> {
            let data_len = r
                .len()
                .checked_sub(Self::DATA_OFFSET)
                .ok_or(ProtocolSizeError::INVALID_SIZE)?;
            Ok(unsafe {
                // The metadata for a custom DST is the size of the
                // dynamically-sized field (data_bytes).
                &mut *(ptr::slice_from_raw_parts_mut(r.as_mut_ptr(), data_len) as *mut Self)
            })
        }

        pub fn set_checksum(&mut self) {
            self.header.checksum = 0;
            let max_len = min(
                size_of::<RequestHeader>() + usize::from(self.header.data_len),
                self.as_bytes().len(),
            );
            let complement = self.as_bytes()[..max_len]
                .iter()
                .fold(0u8, |acc, &b| acc.wrapping_sub(b));
            self.header.checksum = complement;
        }
    }

    impl Debug for Request {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("Request")
                .field("version", &self.header.version)
                .field("checksum", &self.header.checksum)
                .field("command", &self.header.command)
                .field("command_version", &self.header.command_version)
                .field("reserved", &self.header.reserved)
                .field("data_len", &self.header.data_len)
                .field("data", &&self.data_bytes)
                .finish()
        }
    }

    #[cfg(test)]
    mod test_request {
        use super::*;

        use std::format;

        #[test]
        fn test_checksum() {
            let mut bytes = Aligned([1u8, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
            let req = Request::ref_from_bytes(&bytes).unwrap();
            assert!(!req.is_checksum_valid());
            bytes[0] = 255 - 9 + 1; //10 bytes - 1byte of checksum, sum to 0
            let req = Request::ref_from_bytes(&bytes).unwrap();
            assert!(req.is_checksum_valid());
        }

        #[test]
        fn test_ref_from_bytes_invalid_input() {
            assert_eq!(
                Request::ref_from_bytes(&Aligned([])),
                Err(ProtocolSizeError::INVALID_SIZE)
            );
            assert_eq!(
                Request::ref_from_bytes(&Aligned([0x5e, 0x8c, 0x49, 0x89, 0xf8, 0x1d, 0x45])),
                Err(ProtocolSizeError::INVALID_SIZE)
            );
        }

        #[test]
        fn test_ref_from_bytes_and_as_slice() {
            let bytes = Aligned([
                0xf1, 0x4a, 0x97, 0xad, 0x1a, 0xf6, 0xc7, 0xbd, 0xe2, 0x0c, 0x79, 0x36, 0xe6,
            ]);
            let req = Request::ref_from_bytes(&bytes).unwrap();
            assert_eq!(
                req.header,
                RequestHeader {
                    version: 0xf1,
                    checksum: 0x4a,
                    command: HostCommand(0xad97),
                    command_version: 0x1a,
                    reserved: 0xf6,
                    data_len: 0xbdc7,
                }
            );
            assert_eq!(req.data_bytes, [0xe2, 0x0c, 0x79, 0x36, 0xe6]);

            assert_eq!(req.as_bytes(), bytes.as_slice(),);
        }

        #[test]
        fn test_mut_from_bytes_invalid_input() {
            assert_eq!(
                Request::mut_from_bytes(&mut Aligned([])),
                Err(ProtocolSizeError::INVALID_SIZE)
            );
            assert_eq!(
                Request::mut_from_bytes(&mut Aligned([0x5e, 0x8c, 0x49, 0x89, 0xf8, 0x1d, 0x45])),
                Err(ProtocolSizeError::INVALID_SIZE)
            );
        }

        #[test]
        fn test_mut_from_bytes() {
            let mut bytes = Aligned([
                0xf1, 0x4a, 0x97, 0xad, 0x1a, 0xf6, 0xc7, 0xbd, 0xe2, 0x0c, 0x79, 0x36, 0xe6,
            ]);
            let req = Request::mut_from_bytes(&mut bytes).unwrap();
            assert_eq!(
                req.header,
                RequestHeader {
                    version: 0xf1,
                    checksum: 0x4a,
                    command: HostCommand(0xad97),
                    command_version: 0x1a,
                    reserved: 0xf6,
                    data_len: 0xbdc7,
                }
            );
            assert_eq!(req.data_bytes, [0xe2, 0x0c, 0x79, 0x36, 0xe6]);

            req.header.version = 0x42;
            req.header.command_version = 0xee;
            req.data_bytes[0] = 0x33;
            assert_eq!(
                bytes.as_slice(),
                [
                    0x42, 0x4a, 0x97, 0xad, 0xee, 0xf6, 0xc7, 0xbd, 0x33, 0x0c, 0x79, 0x36, 0xe6,
                ]
            );
        }

        #[test]
        fn debug() {
            let bytes = Aligned([1u8, 2, 3, 0, 4, 5, 6, 0, 7, 8]);
            let req = Request::ref_from_bytes(&bytes).unwrap();
            assert_eq!(
                format!("{req:?}"),
                "Request { version: 1, checksum: 2, command: HostCommand(3), command_version: 4, reserved: 5, data_len: 6, data: [7, 8] }"
            );
        }
    }
}

pub use request::Request;
pub use response::Response;
pub use response::ResponseFinalized;

#[derive(Debug, FromBytes, Immutable, KnownLayout, IntoBytes, Eq, PartialEq)]
#[repr(C)]
pub struct ResponseHeader {
    pub version: u8,
    pub checksum: u8,
    pub result: Status,
    pub data_len: u16,
    pub extra: u16,
}
const _: () = assert!(size_of::<ResponseHeader>() == 8);

impl ResponseHeader {
    pub const RESP_VERSION: u8 = 3;

    pub fn is_version_valid(&self) -> bool {
        self.version == ResponseHeader::RESP_VERSION
    }
}

mod response {

    use super::*;

    #[derive(Eq, PartialEq, FromBytes, Immutable, KnownLayout)]
    #[repr(C, align(4))]
    pub struct Response {
        pub header: ResponseHeader,
        pub data_bytes: [u8],
    }

    impl Response {
        const DATA_OFFSET: usize = size_of::<ResponseHeader>();

        /// Returns a mut ref to a Response, sized to ResponseHeader + data_len bytes
        #[inline(always)]
        pub fn mut_from_prefix_with_elems(
            bytes: &mut Aligned<A4, [u8]>,
            data_len: usize,
        ) -> Result<&mut Self, ProtocolError> {
            if data_len > u16::MAX.into() {
                return Err(ProtocolSizeError::DATA_LEN_OVERFLOW);
            }
            let total_size = size_of::<ResponseHeader>()
                .checked_add(data_len)
                .ok_or(ProtocolSizeError::INVALID_SIZE)?;
            if bytes.len() < total_size {
                return Err(ProtocolSizeError::INVALID_SIZE);
            }
            Ok(unsafe {
                // The metadata for a custom DST is the size of the
                // dynamically-sized field (data_len).
                &mut *(ptr::slice_from_raw_parts_mut(bytes.as_mut_ptr(), data_len) as *mut Self)
            })
        }
        #[inline(always)]
        pub fn as_bytes(&self) -> &[u8] {
            unsafe {
                slice::from_raw_parts(
                    (self as *const Self).cast::<u8>(),
                    Self::DATA_OFFSET + self.data_bytes.len(),
                )
            }
        }

        #[inline(always)]
        pub fn as_bytes_mut(&mut self) -> &mut [u8] {
            unsafe {
                slice::from_raw_parts_mut(
                    (self as *mut Self).cast::<u8>(),
                    Self::DATA_OFFSET + self.data_bytes.len(),
                )
            }
        }

        pub fn set_checksum(&mut self) {
            self.header.checksum = 0;
            let complement = self
                .as_bytes()
                .iter()
                .fold(0u8, |acc, &b| acc.wrapping_sub(b));
            self.header.checksum = complement;
        }

        pub fn is_checksum_valid(&self) -> bool {
            self.as_bytes()
                .iter()
                .fold(0u8, |acc, &b| acc.wrapping_add(b))
                == 0
        }

        pub fn finalize(&mut self, status: Status) -> &ResponseFinalized {
            self.header.version = ResponseHeader::RESP_VERSION;
            self.header.extra = 0;
            self.header.result = status;
            // The constructor ensures data_bytes is <= u16::MAX.
            self.header.data_len = self.data_bytes.len() as u16;
            self.set_checksum();
            unsafe { core::mem::transmute::<&Response, &ResponseFinalized>(self) }
        }

        pub fn respond_ok<'res, T: HostCmdResp>(
            response_buf: &'res mut Aligned<A4, [u8]>,
            data: &T,
        ) -> Result<&'res ResponseFinalized, ProtocolError> {
            let resp = Self::mut_from_prefix_with_elems(response_buf, size_of::<T>())?;
            resp.data_bytes.copy_from_slice(data.as_bytes());
            Ok(resp.finalize(Status::OK))
        }

        pub fn ref_from_bytes(bytes: &Aligned<A4, [u8]>) -> Result<&Self, ProtocolError> {
            let data_len = bytes
                .len()
                .checked_sub(Self::DATA_OFFSET)
                .ok_or(ProtocolSizeError::INVALID_SIZE)?;
            Ok(unsafe { &*(ptr::slice_from_raw_parts(bytes.as_ptr(), data_len) as *const Self) })
        }
        pub fn mut_from_bytes(bytes: &mut Aligned<A4, [u8]>) -> Result<&mut Self, ProtocolError> {
            let data_len = bytes
                .len()
                .checked_sub(Self::DATA_OFFSET)
                .ok_or(ProtocolSizeError::INVALID_SIZE)?;
            Ok(unsafe {
                &mut *(ptr::slice_from_raw_parts_mut(bytes.as_mut_ptr(), data_len) as *mut Self)
            })
        }
    }

    #[repr(transparent)]
    pub struct ResponseFinalized(Response);

    impl ResponseFinalized {
        #[inline(always)]
        pub fn data_bytes(&self) -> &[u8] {
            &self.0.data_bytes
        }
        #[inline(always)]
        pub fn header(&self) -> &ResponseHeader {
            &self.0.header
        }
        #[inline(always)]
        pub fn as_bytes(&self) -> &[u8] {
            self.0.as_bytes()
        }
        pub fn is_checksum_valid(&self) -> bool {
            self.0.is_checksum_valid()
        }

        #[inline(always)]
        pub fn as_aligned_bytes(&self) -> &Aligned<A4, [u8]> {
            // Safe because self.0 is align(4)
            unsafe { &*(self.0.as_bytes() as *const [u8] as *const Aligned<A4, [u8]>) }
        }

        #[inline(always)]
        pub fn from_error<E: Into<u32> + Copy>(
            err: E,
            response_buf: &mut Aligned<A4, [u8]>,
        ) -> Result<&ResponseFinalized, E> {
            let resp = match Response::mut_from_prefix_with_elems(response_buf, 4) {
                Ok(r) => r,
                Err(_) => return Err(err),
            };
            let val: u32 = err.into();
            resp.data_bytes.copy_from_slice(val.as_bytes());
            Ok(resp.finalize(Status::ERROR))
        }
    }

    impl Debug for ResponseFinalized {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            Debug::fmt(&self.0, f)
        }
    }

    impl Debug for Response {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("Response")
                .field("version", &self.header.version)
                .field("checksum", &self.header.checksum)
                .field("result", &self.header.result)
                .field("data_len", &self.header.data_len)
                .field("extra", &self.header.extra)
                .field("data", &&self.data_bytes)
                .finish()
        }
    }

    #[cfg(test)]
    mod test_response {
        use super::*;

        use aligned::{A4, Aligned};
        use std::format;

        #[test]
        fn test_ref_from_bytes_invalid_input() {
            assert_eq!(
                Response::ref_from_bytes(&Aligned([])),
                Err(ProtocolSizeError::INVALID_SIZE)
            );
            assert_eq!(
                Response::ref_from_bytes(&Aligned([0x5e, 0x8c, 0x49, 0x89, 0xf8, 0x1d, 0x45])),
                Err(ProtocolSizeError::INVALID_SIZE)
            );
        }

        #[test]
        fn test_ref_from_bytes_and_as_slice() {
            let bytes = Aligned([
                0xc1, 0x3f, 0x99, 0xe4, 0xfd, 0xea, 0xce, 0xbc, 0x5f, 0xc4, 0xa3, 0xac, 0xad,
            ]);
            let resp = Response::ref_from_bytes(&bytes).unwrap();
            assert_eq!(
                resp.header,
                ResponseHeader {
                    version: 0xc1,
                    checksum: 0x3f,
                    result: Status(0xe499),
                    data_len: 0xeafd,
                    extra: 0xbcce,
                }
            );
            assert_eq!(resp.data_bytes, [0x5f, 0xc4, 0xa3, 0xac, 0xad]);

            assert_eq!(resp.as_bytes(), bytes.as_slice(),);
        }

        #[test]
        fn test_mut_from_bytes_invalid_input() {
            assert_eq!(
                Response::mut_from_bytes(&mut Aligned([])),
                Err(ProtocolSizeError::INVALID_SIZE)
            );
            assert_eq!(
                Response::mut_from_bytes(&mut Aligned([0x5e, 0x8c, 0x49, 0x89, 0xf8, 0x1d, 0x45])),
                Err(ProtocolSizeError::INVALID_SIZE)
            );
        }

        #[test]
        fn test_mut_from_bytes() {
            let mut bytes = Aligned([
                0xc1, 0x3f, 0x99, 0xe4, 0xfd, 0xea, 0xce, 0xbc, 0x5f, 0xc4, 0xa3, 0xac, 0xad,
            ]);
            let resp = Response::mut_from_bytes(&mut bytes).unwrap();
            assert_eq!(
                resp.header,
                ResponseHeader {
                    version: 0xc1,
                    checksum: 0x3f,
                    result: Status(0xe499),
                    data_len: 0xeafd,
                    extra: 0xbcce,
                }
            );
            assert_eq!(resp.data_bytes, [0x5f, 0xc4, 0xa3, 0xac, 0xad]);

            resp.header.version = 0x42;
            resp.header.extra = 0x96a2;
            resp.data_bytes[0] = 0x33;
            assert_eq!(
                bytes.as_slice(),
                [
                    0x42, 0x3f, 0x99, 0xe4, 0xfd, 0xea, 0xa2, 0x96, 0x33, 0xc4, 0xa3, 0xac, 0xad,
                ]
            );
        }

        #[test]
        fn test_checksum() {
            let mut bytes = Aligned::<A4, _>([1u8, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
            let res = Response::mut_from_bytes(&mut bytes).unwrap();
            res.set_checksum();
            assert_eq!(res.header.checksum, 255 - 9 + 1); //10 bytes - 1byte of checksum, sum to 0
        }

        #[test]
        fn debug() {
            let bytes = Aligned::<A4, _>([1u8, 2, 3, 0, 4, 5, 6, 0, 7, 8]);
            let res = Response::ref_from_bytes(&bytes).unwrap();
            assert_eq!(
                format!("{res:?}"),
                "Response { version: 1, checksum: 2, result: Status(3), data_len: 1284, extra: 6, data: [7, 8] }"
            );
        }
    }
}

#[derive(
    FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq,
)]
#[repr(transparent)]
pub struct Status(u16);
#[allow(dead_code)]
impl Status {
    pub const OK: Self = Self(0);
    pub const INVALID_CMD: Self = Self(1);
    pub const ERROR: Self = Self(2);
    pub const INVALID_CHECKSUM: Self = Self(7);
}

impl From<Status> for u16 {
    fn from(value: Status) -> Self {
        value.0
    }
}

impl core::fmt::Display for Status {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[derive(FromBytes, Immutable, IntoBytes, KnownLayout, Debug, PartialEq, Eq)]
    #[repr(C)]
    struct TestDynamicReq {
        a: u32,
        b: u32,
        c: [u32],
    }
    impl HostCmdReq for TestDynamicReq {
        const COMMAND: HostCommand = HostCommand(0x1234);
        const VERSION: u8 = 7;
        type Response = ();
    }

    #[derive(FromBytes, Immutable, IntoBytes, KnownLayout, Debug, PartialEq, Eq)]
    #[repr(C)]
    struct TestUnalignedDynamicReq {
        a: u8,
        b: u8,
        c: [u8],
    }
    impl HostCmdReq for TestUnalignedDynamicReq {
        const COMMAND: HostCommand = HostCommand(0x1234);
        const VERSION: u8 = 3;
        type Response = ();
    }

    #[derive(FromBytes, Immutable, IntoBytes, KnownLayout, Debug, PartialEq, Eq)]
    #[repr(C)]
    struct TestByteReq([u8]);

    impl HostCmdReq for TestByteReq {
        const COMMAND: HostCommand = HostCommand(0x2345);
        const VERSION: u8 = 0;
        type Response = ();
    }

    #[derive(FromBytes, Immutable, IntoBytes, KnownLayout, Debug, PartialEq, Eq)]
    struct TestFixedReq {
        a: u32,
        b: u16,
        c: u16,
    }

    impl HostCmdReq for TestFixedReq {
        const COMMAND: HostCommand = HostCommand(0x4567);
        const VERSION: u8 = 0;
        type Response = ();
    }

    #[derive(FromBytes, Immutable, IntoBytes, KnownLayout, Debug, PartialEq, Eq)]
    struct TestFixedReq3 {
        a: u8,
        b: u8,
        c: u8,
    }

    impl HostCmdReq for TestFixedReq3 {
        const COMMAND: HostCommand = HostCommand(0x4568);
        const VERSION: u8 = 0;
        type Response = ();
    }

    #[test]
    fn test_hostcmd_req_build_dynamic() {
        let mut buf = Aligned::<A4, _>([0x55_u8; 1024]);
        let req = TestDynamicReq::build_dynamic(&mut buf, 5).unwrap();
        req.data.a = 0xba5e_ba11;
        req.data.b = 0x1234_5678;
        req.data.c[1] = 0x2222_2222;
        assert_eq!(req.data.c.len(), 5);
        let req = req.finalize();
        assert_eq!(
            req.header,
            RequestHeader {
                version: 3,
                checksum: 21,
                command: HostCommand(0x1234),
                reserved: 0,
                command_version: 7,
                data_len: 28,
            }
        );
        assert_eq!(req.data_bytes.len(), 28);
        assert!(req.is_checksum_valid());
        let data = req.data_dynamic::<TestDynamicReq>().unwrap();
        assert_eq!(data.a, 0xba5e_ba11);
        assert_eq!(data.b, 0x1234_5678);
        assert_eq!(data.c, [0, 0x2222_2222, 0, 0, 0]);
    }

    #[test]
    fn test_hostcmd_req_build_dynamic_unaligned_data() {
        let mut buf = Aligned::<A4, _>([0x55_u8; 1024]);
        let req = TestByteReq::build_dynamic(&mut buf, 3).unwrap();
        assert_eq!(req.data.0.len(), 3);
        req.data.0.copy_from_slice(&[0xdd, 0xee, 0xff]);
        let req = req.finalize();

        assert_eq!(
            req.header,
            RequestHeader {
                version: 3,
                checksum: 0xc8,
                command: HostCommand(0x2345),
                reserved: 0,
                command_version: 0,
                data_len: 3,
            }
        );
        assert_eq!(req.data_bytes.len(), 3);
        assert_eq!(req.as_bytes().len(), 11);
        assert!(req.is_checksum_valid());
        let data = req.data_dynamic::<TestByteReq>().unwrap();
        assert_eq!(data.0, [0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_hostcmd_req_build_dynamic_unaligned_slice() {
        let mut req_buf = Aligned::<A4, _>([0x55_u8; 1024]);
        let req = TestUnalignedDynamicReq::build_dynamic(&mut req_buf, 2).unwrap();
        req.data.a = 0xaa;
        req.data.b = 0xbb;
        req.data.c.copy_from_slice(&[0x11, 0x22]);
        let req = req.finalize();

        assert_eq!(
            req.header,
            RequestHeader {
                version: 3,
                checksum: 24,
                command: HostCommand(0x1234),
                reserved: 0,
                command_version: 3,
                data_len: 4,
            }
        );
        assert_eq!(req.data_bytes.len(), 4);
        let data = req.data_dynamic::<TestUnalignedDynamicReq>().unwrap();
        assert_eq!(data.a, 0xaa);
        assert_eq!(data.b, 0xbb);
        assert_eq!(data.c, [0x11, 0x22]);
    }

    #[test]
    fn test_hostcmd_req_build_fixed() {
        let mut buf = Aligned::<A4, _>([0x55_u8; 1024]);
        let req = TestFixedReq::build_fixed(&mut buf).unwrap();
        req.data.a = 0x1122_3344;
        req.data.b = 0xaabb;
        req.data.c = 0xccdd;
        let req = req.finalize();
        assert_eq!(
            req.header,
            RequestHeader {
                version: 3,
                checksum: 145,
                command: HostCommand(0x4567),
                reserved: 0,
                command_version: 0,
                data_len: 8,
            }
        );
        assert_eq!(req.data_bytes.len(), 8);
        assert!(req.is_checksum_valid());
        let data = req.data::<TestFixedReq>().unwrap();
        assert_eq!(data.a, 0x1122_3344);
        assert_eq!(data.b, 0xaabb);
        assert_eq!(data.c, 0xccdd);
    }

    #[test]
    fn test_hostcmd_req_build_fixed_3byte() {
        let mut buf = Aligned::<A4, _>([0x55_u8; 1024]);
        let req = TestFixedReq3::build_fixed(&mut buf).unwrap();
        req.data.a = 0x11;
        req.data.b = 0x22;
        req.data.c = 0x33;
        let req = req.finalize();
        assert_eq!(
            req.header,
            RequestHeader {
                version: 3,
                checksum: 231,
                command: HostCommand(0x4568),
                reserved: 0,
                command_version: 0,
                data_len: 3,
            }
        );
        assert_eq!(req.data_bytes.len(), 3);
        assert!(req.is_checksum_valid());
        let data = req.data::<TestFixedReq3>().unwrap();
        assert_eq!(data.a, 0x11);
        assert_eq!(data.b, 0x22);
        assert_eq!(data.c, 0x33);
    }

    #[test]
    fn test_response_from_error() {
        let mut response_buf = Aligned::<A4, _>([0u8; 1024]);
        let response = ResponseFinalized::from_error(
            0x3326_0404u32,
            &mut response_buf,
        )
        .unwrap();
        assert!(response.is_checksum_valid());
        assert_eq!(response.header().version, 3);
        assert_eq!(response.header().result, Status::ERROR);
        assert_eq!(response.header().extra, 0);
        assert_eq!(response.header().data_len, 4);
        assert_eq!(response.data_bytes(), [0x04, 0x04, 0x26, 0x33]);
    }

    #[test]
    fn test_response_respond_ok() {
        #[derive(FromBytes, Immutable, IntoBytes, KnownLayout, Debug, PartialEq, Eq)]
        #[repr(C)]
        struct TestRespData {
            value_a: u32,
            value_b: u32,
        }
        impl HostCmdResp for TestRespData {}
        const _: () = assert!(core::mem::size_of::<TestRespData>() == 8);

        let data = TestRespData {
            value_a: 0x1234_5678,
            value_b: 0x9abc_def0,
        };

        let mut response_buf = Aligned::<A4, _>([0u8; 1024]);
        let response = Response::respond_ok(&mut response_buf, &data).unwrap();

        assert!(response.is_checksum_valid());
        assert_eq!(response.header().version, 3);
        assert_eq!(response.header().result, Status::OK);
        assert_eq!(response.header().extra, 0);
        assert_eq!(
            response.header().data_len as usize,
            core::mem::size_of::<TestRespData>()
        );
        assert_eq!(response.data_bytes(), data.as_bytes());

        // Test error when response buffer is too small
        let mut small_buf = Aligned::<A4, _>([0u8; 2]);
        assert_eq!(
            Response::respond_ok(&mut small_buf, &data).err(),
            Some(ProtocolSizeError::INVALID_SIZE)
        );
    }

    #[test]
    fn test_response_respond_ok_non_multiple_of_4() {
        #[derive(FromBytes, Immutable, IntoBytes, KnownLayout, Debug, PartialEq, Eq)]
        #[repr(C)]
        struct TestRespData3 {
            val_a: u8,
            val_b: u8,
            val_c: u8,
        }
        impl HostCmdResp for TestRespData3 {}
        const _: () = assert!(core::mem::size_of::<TestRespData3>() == 3);

        let data = TestRespData3 {
            val_a: 0x11,
            val_b: 0x22,
            val_c: 0x33,
        };

        let mut response_buf = Aligned::<A4, _>([0u8; 1024]);
        let response = Response::respond_ok(&mut response_buf, &data).unwrap();

        assert!(response.is_checksum_valid());
        assert_eq!(response.header().version, 3);
        assert_eq!(response.header().result, Status::OK);
        assert_eq!(response.header().extra, 0);
        assert_eq!(response.header().data_len, 3);
        assert_eq!(response.data_bytes(), [0x11, 0x22, 0x33]);
    }
}

pub mod channel;
pub mod chipinfo;
pub mod dfu;
pub mod get_version;
pub mod gpio_drive_strength;
pub mod hello;
pub mod is_host_command_supported;
pub mod opentitan_version;
pub mod payload_update;
pub mod reboot;
pub mod target_control;
pub mod target_reset;
pub mod test_commands;
pub mod tpm_mode;
pub mod unsafe_commands;
