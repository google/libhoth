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

//! Host command wire types, shared by RoT firmware and host tooling.
//!
//! This crate is the Rust counterpart to the C definitions in `protocol/`, and is
//! meant to be the single place a host command is declared: adding one means
//! adding a struct here, after which both the firmware that implements it and the
//! host tooling that calls it pick it up from the same definition.
//!
//! # Scope
//!
//! Types and header arithmetic only -- no transport, no allocation, no I/O. Two
//! things build on it:
//!
//! - RoT firmware, which assembles requests in place inside a pre-allocated,
//!   4-byte-aligned mailbox buffer;
//! - `hoth_hostcmd`, the host-side allocating builder, for tooling that would
//!   rather be handed a `Vec<u8>`.
//!
//! Both emit identical bytes, and `hoth_hostcmd` has a test that pins that.
//!
//! # `no_std`
//!
//! This crate is linked into firmware, so it is `no_std`, depends only on
//! `zerocopy`, and must not depend on any of libhoth's C targets.
//!
//! In particular, do not add `ufmt`. A formatting trait implemented here could
//! not then be implemented by a consumer for these types (orphan rule), and two
//! `ufmt` instances in one build would make the impls invisible to each other.
//!
//! # Alignment
//!
//! The multi-byte fields below are plain `u16`/`u32`, deliberately, rather than
//! `zerocopy::byteorder::little_endian::U16`.
//!
//! `U16` would give the headers alignment 1, which is convenient on the host
//! because they would then parse straight out of an arbitrary `&[u8]`. It would
//! also make every access to, say, `RequestHeader::data_len` an unaligned load,
//! which on `riscv32imc` is a pair of byte loads plus a shift and an or -- on the
//! hot path of every host command, for no firmware benefit.
//!
//! So the headers keep their natural alignment, and host-side callers that need
//! to parse from an arbitrary offset use [`zerocopy::FromBytes::read_from_prefix`],
//! which copies and therefore has no alignment requirement at all.
//!
//! Little-endian is the wire contract rather than a choice: nothing in the C
//! library byte-swaps, and every device speaking this protocol is little-endian.

#![cfg_attr(not(test), no_std)]

use core::mem::offset_of;
use core::mem::size_of;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub mod channel;
pub mod chipinfo;
pub mod dfu;
pub mod get_version;
pub mod hello;
pub mod is_host_command_supported;
pub mod reboot;
pub mod target_control;
pub mod target_reset;
pub mod tpm_mode;
pub mod unsafe_commands;

pub const MIN_HOST_COMMAND_BUFFER_SIZE: usize = 6144;
pub const HOST_COMMAND_VERSION: u8 = 3;

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
    pub const CHANNEL_WRITE: Self = Self(0x3e38);
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

    // Commands prefixed with UNSAFE_ are only enabled in builds that explicitly
    // opt in. They exist to test fault handling and MUST NOT ship in production.
    pub const UNSAFE_SYSCALL: Self = Self(0x3100);
    pub const UNSAFE_MEM_WRITE: Self = Self(0x3101);
    pub const UNSAFE_HANG: Self = Self(0x3102);

    pub const GET_STATISTICS: Self = Self(0x3e0f);
    pub const IS_HOST_COMMAND_SUPPORTED: Self = Self(0x3e11);
    pub const PERSISTENT_PANIC_INFO: Self = Self(0x3e14);
}

pub trait HostCmdReq: FromBytes + IntoBytes + Immutable + KnownLayout {
    const COMMAND: HostCommand;
    const VERSION: u8;
    type Response: HostCmdResp;

    /// Returns a `RequestHeader` with the correct version, command, and
    /// command_version for this request. `data_len` specifies the total length
    /// of the data.
    ///
    /// The checksum is left zero; it can only be computed once the payload is
    /// in place, so whichever builder assembles the frame fills it in.
    ///
    /// Returns `None` if `data_len` does not fit the 16-bit length field. That
    /// is the only way this can fail, which is why it is an `Option` rather
    /// than a bespoke error type -- every caller already has an error enum of
    /// its own to map it into.
    ///
    /// If Self is fixed-size, prefer [`HostCmdReq::header_template_fixed()`]
    #[inline(always)]
    fn header_template(data_len: usize) -> Option<RequestHeader> {
        Some(RequestHeader {
            version: RequestHeader::REQ_VERSION,
            checksum: 0,
            command: Self::COMMAND,
            reserved: 0,
            command_version: Self::VERSION,
            data_len: u16::try_from(data_len).ok()?,
        })
    }

    /// Returns a `RequestHeader` with the correct version, command,
    /// command_version, and length for this request.
    ///
    /// If Self is dynamically-sized, use [`HostCmdReq::header_template`].
    #[inline(always)]
    fn header_template_fixed() -> Option<RequestHeader>
    where
        Self: Sized,
    {
        Self::header_template(core::mem::size_of::<Self>())
    }
}
pub trait HostCmdResp: FromBytes + IntoBytes + Immutable + KnownLayout {}

impl HostCmdResp for () {}

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

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Status(u16);
#[allow(dead_code)]
impl Status {
    pub const OK: Self = Self(0);
    pub const INVALID_CMD: Self = Self(1);
    pub const ERROR: Self = Self(2);
    pub const INVALID_CHECKSUM: Self = Self(7);

    /// The raw wire value.
    ///
    /// The field itself stays private so that the named constants remain the
    /// obvious way to spell a status; these two exist because callers in other
    /// crates still need to round-trip an unrecognised value off the wire.
    pub const fn get(self) -> u16 {
        self.0
    }

    pub const fn new(value: u16) -> Self {
        Self(value)
    }
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

/// Length of both the request and response headers.
pub const HEADER_LEN: usize = size_of::<RequestHeader>();
const _: () = assert!(HEADER_LEN == size_of::<ResponseHeader>());

/// The value the checksum byte must hold for `bytes` to sum to zero.
///
/// `bytes` must be the complete frame, with its checksum byte already zeroed.
#[inline]
pub fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |acc, &b| acc.wrapping_sub(b))
}

/// Whether a complete frame, checksum byte included, sums to zero.
#[inline]
pub fn checksum_valid(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b)) == 0
}

/// A 64-bit integer stored as two 32-bit words.
///
/// Useful on 32-bit microcontrollers that cannot efficiently load an 8-byte
/// value, and it keeps the wire layout independent of the target's `u64`
/// alignment.
#[derive(Clone, Copy, Default, Eq, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct U64Align4 {
    pub low: u32,
    pub high: u32,
}

impl U64Align4 {
    pub const fn new(val: u64) -> Self {
        Self {
            low: val as u32,
            high: (val >> 32) as u32,
        }
    }

    pub const fn get(self) -> u64 {
        self.low as u64 | ((self.high as u64) << 32)
    }
}

impl From<U64Align4> for u64 {
    fn from(value: U64Align4) -> Self {
        value.get()
    }
}

impl From<u64> for U64Align4 {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl core::fmt::Display for U64Align4 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&u64::from(*self), f)
    }
}

impl core::fmt::LowerHex for U64Align4 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::LowerHex::fmt(&u64::from(*self), f)
    }
}

impl core::fmt::Debug for U64Align4 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&u64::from(*self), f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_keep_their_natural_alignment() {
        assert_eq!(size_of::<RequestHeader>(), 8);
        assert_eq!(size_of::<ResponseHeader>(), 8);
        // Not 1. See the module docs: alignment 1 would make every `data_len`
        // access an unaligned load in firmware.
        assert_eq!(core::mem::align_of::<RequestHeader>(), 2);
        assert_eq!(core::mem::align_of::<ResponseHeader>(), 2);
    }

    #[test]
    fn checksum_makes_a_frame_sum_to_zero() {
        let mut frame = [3u8, 0, 2, 0, 0, 0, 0, 0];
        frame[1] = checksum(&frame);
        assert!(checksum_valid(&frame));
        assert_eq!(frame[1], 0xfb);
    }

    #[test]
    fn checksum_valid_rejects_a_corrupted_frame() {
        let mut frame = [3u8, 0, 2, 0, 0, 0, 0, 0];
        frame[1] = checksum(&frame);
        frame[4] ^= 0xff;
        assert!(!checksum_valid(&frame));
    }

    #[test]
    fn header_template_fills_in_the_command() {
        let header = hello::HelloRequestData::header_template_fixed().unwrap();
        assert_eq!(header.version, RequestHeader::REQ_VERSION);
        assert_eq!(header.command, HostCommand::HELLO);
        assert_eq!(header.command_version, 0);
        assert_eq!(header.reserved, 0);
        assert_eq!(header.checksum, 0);
        assert_eq!(
            usize::from(header.data_len),
            size_of::<hello::HelloRequestData>()
        );
    }

    #[test]
    fn header_template_rejects_a_payload_too_big_for_the_length_field() {
        assert!(hello::HelloRequestData::header_template(usize::from(u16::MAX)).is_some());
        assert!(hello::HelloRequestData::header_template(usize::from(u16::MAX) + 1).is_none());
    }

    #[test]
    fn req_len_rejects_a_bad_version_or_a_dirty_reserved_byte() {
        let mut header = hello::HelloRequestData::header_template_fixed().unwrap();
        assert_eq!(header.req_len(), Some(HEADER_LEN + 4));

        header.version = 2;
        assert_eq!(header.req_len(), None);

        header.version = RequestHeader::REQ_VERSION;
        header.reserved = 1;
        assert_eq!(header.req_len(), None);
    }

    #[test]
    fn u64_align4_round_trips() {
        let v = U64Align4::new(0x1234_5678_9abc_def0);
        assert_eq!(v.low, 0x9abc_def0);
        assert_eq!(v.high, 0x1234_5678);
        assert_eq!(v.get(), 0x1234_5678_9abc_def0);
        assert_eq!(u64::from(v), 0x1234_5678_9abc_def0);
    }
}
