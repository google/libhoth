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

#![no_std]

use pie_rot_hostcmd_types::HostCmdReq;
use pie_rot_hostcmd_types::HostCmdResp;
use pie_rot_hostcmd_types::HostCommand;
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
    use aligned::{A4, Aligned};
    use core::mem::size_of;

    #[test]
    fn test_channel_write_request_layout() {
        assert_eq!(size_of::<ChannelWriteRequestHeader>(), 8);

        let mut buf = Aligned::<A4, _>([0u8; 64]);
        let builder = ChannelWriteRequest::build_dynamic(&mut buf, 5).unwrap();
        builder.data.header = ChannelWriteRequestHeader {
            channel_id: U32::new(LOG_CHANNEL_URT1),
            flags: U32::new(0),
        };
        builder.data.data.copy_from_slice(b"hello");
        let req = builder.finalize();

        assert_eq!(req.header.command, HostCommand::CHANNEL_WRITE);
        assert_eq!(req.header.command_version, 1);
        assert_eq!(req.header.data_len, 13);
        assert!(req.is_checksum_valid());

        let parsed_req: &ChannelWriteRequest = req.data_dynamic().unwrap();
        assert_eq!(parsed_req.header.channel_id.get(), LOG_CHANNEL_URT1);
        assert_eq!(parsed_req.header.flags.get(), 0);
        assert_eq!(&parsed_req.data, b"hello");
    }
}
