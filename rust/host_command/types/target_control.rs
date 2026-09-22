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
use ufmt::uDebug;
use ufmt::uwrite;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Debug, PartialEq, Eq)]
pub struct Action(u16);
#[allow(dead_code)]
impl Action {
    pub const GET_STATUS: Self = Self(0);
    pub const DISABLE: Self = Self(1);
    pub const ENABLE: Self = Self(2);
    pub const I2C_MUX_SELECT_HOST_AS_CONTROLLER: Self = Self::DISABLE;
    pub const I2C_MUX_SELECT_ROT_AS_CONTROLLER: Self = Self::ENABLE;
    pub const USB_MUX_CONNECT_ROT_TO_EXTERNAL_PORT: Self = Self::DISABLE;
    pub const USB_MUX_CONNECT_ROT_TO_INTERNAL_HOST: Self = Self::ENABLE;
    pub const SBS_MUX_SINGLE_CONNECT_FLASH_TO_ROT: Self = Self::DISABLE;
    pub const SBS_MUX_SINGLE_CONNECT_FLASH_TO_TARGET: Self = Self::ENABLE;
    pub const SBS_MUX_DUAL_CONNECT_TARGET_TO_EXT_FLASH_0: Self = Self::DISABLE;
    pub const SBS_MUX_DUAL_CONNECT_TARGET_TO_EXT_FLASH_1: Self = Self::ENABLE;
}

impl uDebug for Action {
    fn fmt<W>(&self, f: &mut ufmt::Formatter<'_, W>) -> Result<(), W::Error>
    where
        W: ufmt::uWrite + ?Sized,
    {
        uwrite!(f, "{}", self.0)
    }
}

#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Debug, PartialEq, Eq)]
pub struct Function(u16);
#[allow(dead_code)]
impl Function {
    pub const DEBUG_MODE: Self = Self(0);
    pub const TEST_MODE: Self = Self(1);
    pub const I2C_MUX: Self = Self(2);
    pub const USB_MUX: Self = Self(3);
    pub const EXTERNAL_USB_HOST_PRESENCE: Self = Self(4);
    pub const SBS_MUX_SINGLE: Self = Self(5);
    pub const SBS_MUX_DUAL: Self = Self(6);
}

impl uDebug for Function {
    fn fmt<W>(&self, f: &mut ufmt::Formatter<'_, W>) -> Result<(), W::Error>
    where
        W: ufmt::uWrite + ?Sized,
    {
        uwrite!(f, "{}", self.0)
    }
}

#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Debug, PartialEq, Eq)]
pub struct TargetControlStatus(u16);
#[allow(dead_code)]
impl TargetControlStatus {
    pub const UNKNOWN: Self = Self(0);
    pub const DISABLED: Self = Self(1);
    pub const ENABLED: Self = Self(2);
    pub const I2C_MUX_HOST_SELECTED_AS_CONTROLLER: Self = Self::DISABLED;
    pub const I2C_MUX_ROT_SELECTED_AS_CONTROLLER: Self = Self::ENABLED;
    pub const USB_MUX_ROT_CONNECTED_TO_EXTERNAL_PORT: Self = Self::DISABLED;
    pub const USB_MUX_ROT_CONNECTED_TO_INTERNAL_HOST: Self = Self::ENABLED;
    pub const EXTERNAL_USB_HOST_NOT_PRESENT: Self = Self::DISABLED;
    pub const EXTERNAL_USB_HOST_PRESENT: Self = Self::ENABLED;
    pub const SBS_MUX_SINGLE_FLASH_CONNECTED_TO_ROT: Self = Self::DISABLED;
    pub const SBS_MUX_SINGLE_FLASH_CONNECTED_TO_TARGET: Self = Self::ENABLED;
    pub const SBS_MUX_DUAL_TARGET_CONNECTED_TO_SPI_FLASH_0: Self = Self::DISABLED;
    pub const SBS_MUX_DUAL_TARGET_CONNECTED_TO_SPI_FLASH_1: Self = Self::ENABLED;
}

impl Default for TargetControlStatus {
    fn default() -> Self {
        Self::UNKNOWN
    }
}

#[derive(Clone, Copy, Immutable, KnownLayout, Debug, PartialEq, Eq, FromBytes, IntoBytes)]
#[repr(C)]
pub struct TargetControlRequestData {
    pub function: Function,
    pub action: Action,
    // pub args: [u8], // Not used, ignoring to avoid DST issues
}
impl HostCmdReq for TargetControlRequestData {
    const COMMAND: HostCommand = HostCommand::TARGET_CONTROL;
    const VERSION: u8 = 0;
    type Response = TargetControlResponseData;
}

#[derive(
    FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq, Default,
)]
#[repr(C)]
pub struct TargetControlResponseData {
    pub status: TargetControlStatus,
    _padding: u16, // TODO: needed for haventool to decode the response, but not in the original code?
}
impl TargetControlResponseData {
    pub fn new_with_status(status: TargetControlStatus) -> Self {
        Self {
            status,
            ..Default::default()
        }
    }
}
impl HostCmdResp for TargetControlResponseData {}
