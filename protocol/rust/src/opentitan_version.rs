use core::mem::offset_of;
use crate::{HostCmdReq, HostCmdResp, HostCommand};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenTitanGetVersion;
impl HostCmdReq for OpenTitanGetVersion {
    const COMMAND: HostCommand = HostCommand::OPENTITAN_GET_VERSION;
    const VERSION: u8 = 0;
    type Response = OpenTitanGetVersionResp;
}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct BootSlot(pub u32);
impl BootSlot {
    pub const SLOT_A: Self = Self(0x5f5f_4141);
    pub const SLOT_B: Self = Self(0x4242_5f5f);
}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ImageVersion {
    pub major: u32,
    pub minor: u32,
    pub security_version: u32,
    pub reserved: [u32; 3],
    pub timestamp: u64,
    pub measurement: [u32; 8],
}
const _: () = {
    assert!(offset_of!(ImageVersion, major) == 0);
    assert!(offset_of!(ImageVersion, minor) == 4);
    assert!(offset_of!(ImageVersion, security_version) == 8);
    assert!(offset_of!(ImageVersion, reserved) == 12);
    assert!(offset_of!(ImageVersion, timestamp) == 24);
    assert!(offset_of!(ImageVersion, measurement) == 32);
    assert!(size_of::<ImageVersion>() == 64);
};

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ImageBootInfo {
    /// slots[0] describes Slot A, and slots[1] describes Slot B.
    pub slots: [ImageVersion; 2],

    /// Which slot booted after the most recent reset.
    pub booted_slot: BootSlot,

    pub reserved: [u32; 3],
}
const _: () = {
    assert!(offset_of!(ImageBootInfo, slots) == 0);
    assert!(offset_of!(ImageBootInfo, booted_slot) == 128);
    assert!(size_of::<ImageBootInfo>() == 144);
};

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct OwnerConfigVersion {
    /// Same as `OwnershipBlock::config_version`.
    config_version: u32,

    reserved: [u32; 3],

    /// The hash of all the bytes in `OwnershipBlock`. Can be 0 if this data is unavailable.
    sha256: [u32; 8],
}
const _: () = {
    assert!(offset_of!(OwnerConfigVersion, config_version) == 0);
    assert!(offset_of!(OwnerConfigVersion, sha256) == 16);
    assert!(size_of::<OwnerConfigVersion>() == 48);
};

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct OpenTitanGetVersionResp {
    pub rom_ext: ImageBootInfo,
    pub app: ImageBootInfo,
    pub primary_bl0_slot: BootSlot,
    pub bl0_min_sec_ver: u32,
    pub owner_config: OwnerConfigVersion,
}
impl HostCmdResp for OpenTitanGetVersionResp {}
