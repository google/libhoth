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

use zerocopy::little_endian::U32;

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ChannelWriteRequestHeader {
    pub channel_id: U32,
    pub flags: U32,
}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ChannelWriteRequest {
    pub header: ChannelWriteRequestHeader,
    pub data: [u8],
}

impl HostCmdReq for ChannelWriteRequest {
    const COMMAND: HostCommand = HostCommand::CHANNEL_WRITE;
    const VERSION: u8 = 1;
    type Response = ();
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn test_channel_write_request_layout() {
        assert_eq!(size_of::<ChannelWriteRequestHeader>(), 8);
    }

    // The other half of this test -- building a ChannelWriteRequest with
    // `build_dynamic` and checking the framed bytes -- lives with the in-place
    // builder in pie-rot, since that builder needs a 4-byte-aligned buffer and
    // therefore cannot live in this crate.
}
