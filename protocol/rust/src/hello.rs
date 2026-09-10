use crate::HostCmdReq;
use crate::HostCmdResp;
use crate::HostCommand;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct HelloRequestData {
    pub challenge: u32,
}
impl HostCmdReq for HelloRequestData {
    const COMMAND: HostCommand = HostCommand::HELLO;
    const VERSION: u8 = 0;
    type Response = HelloResponseData;
}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct HelloResponseData {
    pub response: u32,
}
impl HostCmdResp for HelloResponseData {}
