use crate::HostCmdReq;
use crate::HostCmdResp;
use crate::HostCommand;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct GetVersionRequestData;
impl HostCmdReq for GetVersionRequestData {
    const COMMAND: HostCommand = HostCommand::GET_VERSION;
    const VERSION: u8 = 0;
    type Response = GetVersionResponseData;
}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct GetVersionResponseData {
    // Reusing version_string_ro field for ROM_EXT
    pub version_string_ro: [u8; 32],
    pub version_string_rw: [u8; 32],
    pub reserved: [u8; 32],
    pub current_image: u32,
}
impl HostCmdResp for GetVersionResponseData {}
