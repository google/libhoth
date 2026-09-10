use crate::HostCmdReq;
use crate::HostCmdResp;
use crate::HostCommand;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct GpioDriveStrength {
    pub pad: u8,
    pub strength: u8,
}

impl HostCmdReq for GpioDriveStrength {
    const COMMAND: HostCommand = HostCommand::SET_GPIO_DRIVE_STRENGTH;
    const VERSION: u8 = 0;
    type Response = ();
}

impl GpioDriveStrength {
    /// Offset added to dedicated/direct IO pad indices to distinguish them
    /// from muxed IO pads.
    pub const DIO_PAD_OFFSET: u8 = 128;
}

#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct GetGpioDriveStrengthReq {
    pub pad: u8,
}

impl HostCmdReq for GetGpioDriveStrengthReq {
    const COMMAND: HostCommand = HostCommand::GET_GPIO_DRIVE_STRENGTH;
    const VERSION: u8 = 0;
    type Response = GetGpioDriveStrengthResp;
}

#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct GetGpioDriveStrengthResp {
    pub strength: u8,
}

impl HostCmdResp for GetGpioDriveStrengthResp {}

