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
use ufmt::derive::uDebug;
use zerocopy_derive::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(
    FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq, uDebug,
)]
#[repr(transparent)]
pub struct TpmMode(pub u8);

impl TpmMode {
    pub const DISABLED: Self = Self(0);
    pub const TPM_SPI: Self = Self(1);
    pub const SPI_NOR_MAILBOX: Self = Self(2);
}

impl TpmMode {
    pub fn is_valid(self) -> bool {
        matches!(self, Self::DISABLED | Self::TPM_SPI | Self::SPI_NOR_MAILBOX)
    }
}

impl TryFrom<u8> for TpmMode {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::DISABLED),
            1 => Ok(Self::TPM_SPI),
            2 => Ok(Self::SPI_NOR_MAILBOX),
            _ => Err(()),
        }
    }
}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct SetTpmModeReq {
    pub mode: u8,
    pub reserved: [u8; 3],
}

impl HostCmdReq for SetTpmModeReq {
    const COMMAND: HostCommand = HostCommand::SET_TPM_MODE;
    const VERSION: u8 = 0;
    type Response = ();
}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct GetTpmModeReq {}

impl HostCmdReq for GetTpmModeReq {
    const COMMAND: HostCommand = HostCommand::GET_TPM_MODE;
    const VERSION: u8 = 0;
    type Response = GetTpmModeResp;
}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct GetTpmModeResp {
    pub mode: u8,
    pub reserved: [u8; 3],
}
impl HostCmdResp for GetTpmModeResp {}
