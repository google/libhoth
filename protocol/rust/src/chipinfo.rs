use crate::HostCmdReq;
use crate::HostCmdResp;
use crate::HostCommand;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ChipInfoRequestData;
impl HostCmdReq for ChipInfoRequestData {
    const COMMAND: HostCommand = HostCommand::CHIP_INFO;
    const VERSION: u8 = 0;
    type Response = ChipInfoResponseData;
}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ChipInfoResponseData {
    pub response: [u8; 32],
}
impl HostCmdResp for ChipInfoResponseData {}
