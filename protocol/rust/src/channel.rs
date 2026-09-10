use crate::HostCmdReq;
use crate::HostCmdResp;
use crate::HostCommand;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const LOG_CHANNEL_EROT: u32 = u32::from_be_bytes(*b"EROT");
pub const LOG_CHANNEL_URT1: u32 = u32::from_be_bytes(*b"URT1");

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ChannelReadRequest {
    pub channel_id: u32,
    pub offset: u32,
    pub size: u32,
    pub timeout_us: u32,
}
impl HostCmdReq for ChannelReadRequest {
    const COMMAND: HostCommand = HostCommand::CHANNEL_READ;
    const VERSION: u8 = 0;
    type Response = ChannelReadResponse;
}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ChannelReadResponse {
    pub offset: u32,
}
impl HostCmdResp for ChannelReadResponse {}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ChannelStatusRequest {
    pub channel_id: u32,
}
impl HostCmdReq for ChannelStatusRequest {
    const COMMAND: HostCommand = HostCommand::CHANNEL_STATUS;
    const VERSION: u8 = 0;
    type Response = ChannelStatusResponse;
}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ChannelStatusResponse {
    pub write_offset: u32,
}
impl HostCmdResp for ChannelStatusResponse {}
