use core::mem::{offset_of, size_of};
use crate::{HostCmdReq, HostCmdResp, HostCommand};
use zerocopy::byteorder::little_endian::{U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct ImageVersion {
    pub major: u32,
    pub minor: u32,
    pub point: u32,
    pub subpoint: u32,
}

const _: () = {
    assert!(offset_of!(ImageVersion, major) == 0);
    assert!(offset_of!(ImageVersion, minor) == 4);
    assert!(offset_of!(ImageVersion, point) == 8);
    assert!(offset_of!(ImageVersion, subpoint) == 12);
    assert!(size_of::<ImageVersion>() == 16);
};

impl core::fmt::Debug for ImageVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "({}.{}.{}.{})",
            self.major, self.minor, self.point, self.subpoint
        )
    }
}

#[derive(Copy, Clone, Eq, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(transparent)]
pub struct ImageType(pub u8);

impl ImageType {
    pub const DEV: Self = Self(0);
    pub const PROD: Self = Self(1);
    pub const BREAKOUT: Self = Self(2);
    pub const TEST: Self = Self(3);
    pub const UNSIGNED_INTEGRITY: Self = Self(4);
}

impl ImageType {
    pub fn is_recognized(&self) -> bool {
        matches!(
            *self,
            Self::DEV | Self::PROD | Self::BREAKOUT | Self::TEST | Self::UNSIGNED_INTEGRITY
        )
    }
}

impl core::fmt::Debug for ImageType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::DEV => write!(f, "DEV"),
            Self::PROD => write!(f, "PROD"),
            Self::BREAKOUT => write!(f, "BREAKOUT"),
            Self::TEST => write!(f, "TEST"),
            Self::UNSIGNED_INTEGRITY => write!(f, "UNSIGNED_INTEGRITY"),
            _ => write!(f, "Unknown (0x{:x})", self.0),
        }
    }
}

#[derive(Copy, Clone, FromBytes, IntoBytes, KnownLayout, Immutable, PartialEq, Eq)]
#[repr(transparent)]
pub struct Op(pub u8);

impl Op {
    /// Erase the entire staging area.
    pub const INITIATE: Self = Self(0);

    /// Program `Request::data` to `Request::offset` on the staging area.
    pub const CONTINUE: Self = Self(1);

    /// Validate the staging area. If validation is successful, mark the staging area as the new
    /// active area.
    pub const FINALIZE: Self = Self(2);

    /// Validate the staging area. Doesn't activate.
    pub const VERIFY: Self = Self(4);

    /// Mark a previously-validated staging area as the new active area.
    ///
    /// Errors when the staging area is unvalidated.
    pub const ACTIVATE: Self = Self(5);

    /// Read `Request::len` bytes stating at `Request::offset` from the staging area.
    pub const READ: Self = Self(6);

    /// Return payload validation states and information about the current and next active sides.
    pub const GET_STATUS: Self = Self(7);

    /// Erase `Request::len` bytes starting at `Request::offset` on the staging area.
    pub const ERASE: Self = Self(8);

    /// Subcommands that allow a host to explicitly confirm a new payload is functional.
    ///
    /// See [`ConfirmOp`].
    ///
    /// Process:
    ///  1. The host stages a new payload via payload update.
    ///
    ///  2. The host sets a confirm timeout with ENABLE or ENABLE_WITH_TIMEOUT.
    ///
    ///  3. The chip resets the host into the new payload.
    ///
    ///  4. The host must CONFIRM the new payload is functional within the timeout set in (2).
    ///
    ///  5. If the host does not confirm the payload, the chip will reset the host into the old
    ///     payload.
    pub const CONFIRM: Self = Self(10);

    /// Validate the staging area. Doesn't activate.
    ///
    /// As an optimization, this command historically only verified the payload's image_descriptor
    /// and relied on boot-time validation to perform the full validation, hence the name "verify
    /// descriptor".
    ///
    /// Today, this command is equivalent to VERIFY, i.e., performs full validation of the staging
    /// area.
    pub const VERIFY_DESCRIPTOR: Self = Self(11);

    /// Return `true` if this operation mutates the staged payload in any way.
    pub fn is_mutating(self) -> bool {
        matches!(self, Self::CONTINUE | Self::ERASE | Self::INITIATE)
    }
}

#[derive(FromBytes, KnownLayout, IntoBytes, Immutable)]
#[repr(C)]
pub struct PayloadUpdateRequest {
    pub offset: U32,
    pub len: U32,
    pub op: Op,
    pub data: [u8],
}
const _: () = {
    assert!(offset_of!(PayloadUpdateRequest, offset) == 0);
    assert!(offset_of!(PayloadUpdateRequest, len) == 4);
    assert!(offset_of!(PayloadUpdateRequest, op) == 8);
};

impl HostCmdReq for PayloadUpdateRequest {
    const COMMAND: HostCommand = HostCommand::PAYLOAD_UPDATE;
    const VERSION: u8 = 0;
    // TODO(roycerajan): Different payload update operations can return different data shapes.
    type Response = ();
}

#[derive(FromBytes, KnownLayout, IntoBytes, Immutable)]
#[repr(C)]
pub struct ConfirmRequest {
    pub op: ConfirmOp,
    pub padding: [u8; 3],
    pub timeout: ConfirmSeconds,
    pub cookie: U64,
}
const _: () = {
    assert!(size_of::<ConfirmRequest>() == 16);
    assert!(offset_of!(ConfirmRequest, op) == 0);
    assert!(offset_of!(ConfirmRequest, timeout) == 4);
    assert!(offset_of!(ConfirmRequest, cookie) == 8);
};

#[derive(Copy, Clone, FromBytes, IntoBytes, KnownLayout, Immutable, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct ConfirmOp(pub u8);

impl ConfirmOp {
    /// Enable the confirm feature and set a default timeout.
    pub const ENABLE: Self = Self(0);

    /// Enable the confirm feature and set a custom timeout.
    pub const ENABLE_WITH_TIMEOUT: Self = Self(1);

    /// Disable the confirm feature and clear the timeout.
    pub const DISABLE: Self = Self(2);

    /// Confirm the payload is functional. Disarm the payload confirmation timer.
    pub const CONFIRM: Self = Self(3);

    /// Return the current timeout and timeout settings (min, max, default).
    pub const GET_TIMEOUT_VALUES: Self = Self(4);
}

#[derive(
    FromBytes, KnownLayout, IntoBytes, Immutable, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug,
)]
#[repr(transparent)]
pub struct ConfirmSeconds(pub U32);

impl ConfirmSeconds {
    pub const ZERO: Self = Self::new(0);
    // TODO(roycerajan): These are integration-specific?
    pub const MIN: Self = Self::new(5 * 60);
    pub const MAX: Self = Self::new(60 * 60);
    pub const DEFAULT: Self = Self::new(15 * 60);

    pub const fn new(seconds: u32) -> Self {
        Self(U32::new(seconds))
    }
}

impl From<ConfirmSeconds> for u32 {
    fn from(value: ConfirmSeconds) -> Self {
        value.0.get()
    }
}

impl From<u32> for ConfirmSeconds {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

/// The result of an attempt to disarm the payload confirmation timer.
#[derive(FromBytes, KnownLayout, IntoBytes, Immutable, Copy, Clone, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct ConfirmDisarm(pub u8);
impl ConfirmDisarm {
    /// No confirmation timer was armed.
    pub const INACTIVE: Self = Self(0);
    /// A confirmation timer was armed and has been successfully disarmed.
    pub const DISARMED: Self = Self(1);
}

#[derive(FromBytes, KnownLayout, IntoBytes, Immutable)]
#[repr(C)]
pub struct ConfirmResponse {
    pub timeouts: ConfirmTimeouts,
}
const _: () = {
    assert!(size_of::<ConfirmResponse>() == 16);
    assert!(offset_of!(ConfirmResponse, timeouts) == 0);
};

#[derive(FromBytes, KnownLayout, IntoBytes, Immutable)]
#[repr(C)]
pub struct ConfirmTimeouts {
    pub min: ConfirmSeconds,
    pub max: ConfirmSeconds,
    pub default: ConfirmSeconds,
    pub current: ConfirmSeconds,
}
const _: () = {
    assert!(size_of::<ConfirmTimeouts>() == 16);
    assert!(offset_of!(ConfirmTimeouts, min) == 0);
    assert!(offset_of!(ConfirmTimeouts, max) == 4);
    assert!(offset_of!(ConfirmTimeouts, default) == 8);
    assert!(offset_of!(ConfirmTimeouts, current) == 12);
};

#[derive(FromBytes, KnownLayout, IntoBytes, Immutable)]
#[repr(C)]
pub struct ActivateRequest {
    pub side: u8,
    pub make_persistent: u8,
}
const _: () = {
    assert!(size_of::<ActivateRequest>() == 2);
    assert!(offset_of!(ActivateRequest, side) == 0);
    assert!(offset_of!(ActivateRequest, make_persistent) == 1);
};

#[derive(FromBytes, KnownLayout, IntoBytes, Immutable, PartialEq, Debug)]
#[repr(C)]
pub struct GetStatusResponse {
    pub a_validation: PayloadValidationState,
    pub b_validation: PayloadValidationState,
    pub active_side: u8,
    pub next_side: u8,
    pub persistent_side: u8,
}
const _: () = {
    assert!(size_of::<GetStatusResponse>() == 5);
    assert!(offset_of!(GetStatusResponse, a_validation) == 0);
    assert!(offset_of!(GetStatusResponse, b_validation) == 1);
    assert!(offset_of!(GetStatusResponse, active_side) == 2);
    assert!(offset_of!(GetStatusResponse, next_side) == 3);
    assert!(offset_of!(GetStatusResponse, persistent_side) == 4);
};

#[derive(Copy, Clone, FromBytes, IntoBytes, KnownLayout, Immutable, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct PayloadValidationState(pub u8);

impl PayloadValidationState {
    pub const IMAGE_INVALID: Self = Self(0);
    pub const IMAGE_UNVERIFIED: Self = Self(1);
    pub const IMAGE_VALID: Self = Self(2);
    pub const DESCRIPTOR_VALID: Self = Self(3);
}

#[derive(FromBytes, KnownLayout, IntoBytes, Immutable)]
#[repr(C)]
pub struct PayloadStatusRequest;
const _: () = {
    assert!(size_of::<PayloadStatusRequest>() == 0);
};

impl HostCmdReq for PayloadStatusRequest {
    const COMMAND: HostCommand = HostCommand::PAYLOAD_STATUS;
    const VERSION: u8 = 0;
    type Response = PayloadStatusResponse;
}

#[derive(FromBytes, KnownLayout, IntoBytes, Immutable)]
#[repr(C)]
pub struct PayloadStatusResponse {
    pub header: PayloadStatusResponseHeader,
    pub region_states: [PayloadRegionState; Self::REGION_COUNT as usize],
}
const _: () = {
    assert!(size_of::<PayloadStatusResponse>() == 68);
    assert!(offset_of!(PayloadStatusResponse, header) == 0);
    assert!(offset_of!(PayloadStatusResponse, region_states) == 4);
};
impl PayloadStatusResponse {
    pub const REGION_COUNT: u8 = 2;
}
impl HostCmdResp for PayloadStatusResponse {}

#[derive(FromBytes, KnownLayout, IntoBytes, Immutable)]
#[repr(C)]
pub struct PayloadStatusResponseHeader {
    pub version: u8,
    pub lockdown_state: LockdownState,
    pub active_side: u8,
    pub region_count: u8,
}
const _: () = {
    assert!(size_of::<PayloadStatusResponseHeader>() == 4);
    assert!(offset_of!(PayloadStatusResponseHeader, version) == 0);
    assert!(offset_of!(PayloadStatusResponseHeader, lockdown_state) == 1);
    assert!(offset_of!(PayloadStatusResponseHeader, active_side) == 2);
    assert!(offset_of!(PayloadStatusResponseHeader, region_count) == 3);
};

#[derive(Copy, Clone, FromBytes, IntoBytes, KnownLayout, Immutable, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct LockdownState(pub u8);

impl LockdownState {
    /// All regions are mutable.
    pub const FAILSAFE: Self = Self(0);

    /// STATIC regions are immutable.
    pub const READY: Self = Self(1);

    /// Only the mailbox is mutable.
    pub const IMMUTABLE: Self = Self(2);

    /// STATIC and WRITE_PROTECTED regions are immutable.
    pub const ENABLED: Self = Self(3);
}

#[derive(FromBytes, KnownLayout, IntoBytes, Immutable, Copy, Clone, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct PayloadRegionState {
    pub validation_state: PayloadValidationState,
    pub failure_reason: PayloadValidationFailureReason,
    pub reserved_0: u8,
    pub image_type: ImageType,
    pub key_index: u16,
    pub reserved_1: u16,
    pub image_family: u32,
    pub version: ImageVersion,
    pub descriptor_offset: u32,
}
const _: () = {
    assert!(size_of::<PayloadRegionState>() == 32);
    assert!(offset_of!(PayloadRegionState, validation_state) == 0);
    assert!(offset_of!(PayloadRegionState, failure_reason) == 1);
    assert!(offset_of!(PayloadRegionState, reserved_0) == 2);
    assert!(offset_of!(PayloadRegionState, image_type) == 3);
    assert!(offset_of!(PayloadRegionState, key_index) == 4);
    assert!(offset_of!(PayloadRegionState, reserved_1) == 6);
    assert!(offset_of!(PayloadRegionState, image_family) == 8);
    assert!(offset_of!(PayloadRegionState, version) == 12);
    assert!(offset_of!(PayloadRegionState, descriptor_offset) == 28);
};

impl PayloadRegionState {
    pub const UNVERIFIED: Self = Self {
        validation_state: PayloadValidationState::IMAGE_UNVERIFIED,
        failure_reason: PayloadValidationFailureReason::RUNTIME_FAILURE,
        reserved_0: 0,
        image_type: ImageType::DEV,
        key_index: 0,
        reserved_1: 0,
        image_family: 0,
        version: ImageVersion {
            major: 0,
            minor: 0,
            point: 0,
            subpoint: 0,
        },
        descriptor_offset: 0,
    };
}

#[derive(Copy, Clone, FromBytes, IntoBytes, KnownLayout, Immutable, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct PayloadValidationFailureReason(pub u8);

impl PayloadValidationFailureReason {
    pub const SUCCESS: Self = Self(0);
    pub const RUNTIME_FAILURE: Self = Self(1);
    pub const UNSUPPORTED_DESCRIPTOR: Self = Self(2);
    pub const INVALID_DESCRIPTOR: Self = Self(3);
    pub const INVALID_IMAGE_FAMILY: Self = Self(4);
    pub const IMAGE_TYPE_DISALLOWED: Self = Self(5);
    pub const DENYLISTED_VERSION: Self = Self(6);
    pub const UNTRUSTED_KEY: Self = Self(7);
    pub const INVALID_SIGNATURE: Self = Self(8);
    pub const INVALID_HASH: Self = Self(9);
    pub const PENDING: Self = Self(10);
    pub const INVALID_SESSION_ID: Self = Self(11);
    pub const FINGERPRINT_NOT_FOUND: Self = Self(12);
    pub const UNSUPPORTED_FINGERPRINT_HASH_TYPE: Self = Self(13);
    pub const MISSING_BOOT_HASH: Self = Self(14);
    pub const UNEXPECTED_SKIP_BOOT_VALIDATION_REGION: Self = Self(15);
    pub const MULTIPLE_DESCRIPTORS_FOUND: Self = Self(16);
    pub const UNSIGNED_INTEGRITY_NOT_SUPPORTED: Self = Self(17);
    pub const KEY_ROT_NO_MATCHING_KEY_OR_HASH_FOUND: Self = Self(18);
}

