use crate::HostCmdReq;
use crate::HostCmdResp;
use crate::HostCommand;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes)]
#[repr(C)]
pub struct IsHostCommandSupportedRequestData {
    pub cmd_code: u16,
}

impl HostCmdReq for IsHostCommandSupportedRequestData {
    const COMMAND: HostCommand = HostCommand::IS_HOST_COMMAND_SUPPORTED;
    const VERSION: u8 = 0;
    type Response = IsHostCommandSupportedResponseData;
}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes)]
#[repr(C)]
pub struct IsHostCommandSupportedResponseData {
    pub is_supported: u8,
}

impl HostCmdResp for IsHostCommandSupportedResponseData {}
