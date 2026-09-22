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
use pie_rot_hostcmd_types::HostCommand;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// refer to pie-rot/libhoth/examples/host_commands.h
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
#[repr(u8)]
pub enum TargetResetOption {
    /// Release the target from reset (de-assert reset).
    Release = 0,
    /// Put the target into reset (assert reset).
    Set = 1,
    /// short pulse of reset
    Pulse = 2,
}

impl TryFrom<u8> for TargetResetOption {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Release),
            1 => Ok(Self::Set),
            2 => Ok(Self::Pulse),
            _ => Err(()),
        }
    }
}

impl From<TargetResetOption> for u8 {
    fn from(opt: TargetResetOption) -> u8 {
        opt as u8
    }
}

// refer to pie-rot/libhoth/examples/host_commands.h
#[derive(
    FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq, Default,
)]
#[repr(C)]
pub struct TargetResetRequestData {
    pub target_id: u32, // unused for now
    pub reset_option: u8,
    pub reserved: [u8; 11],
}

impl HostCmdReq for TargetResetRequestData {
    const COMMAND: HostCommand = HostCommand::TARGET_RESET;
    const VERSION: u8 = 0;
    type Response = ();
}
