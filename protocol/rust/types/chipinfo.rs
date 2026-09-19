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
