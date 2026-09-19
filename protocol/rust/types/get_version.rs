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
pub struct GetVersionRequestData;
impl HostCmdReq for GetVersionRequestData {
    const COMMAND: HostCommand = HostCommand::GET_VERSION;
    const VERSION: u8 = 0;
    type Response = GetVersionResponseData;
}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct GetVersionResponseData {
    // Reusing version_string_ro field for ROM_EXT
    pub version_string_ro: [u8; 32],
    pub version_string_rw: [u8; 32],
    pub reserved: [u8; 32],
    pub current_image: u32,
}
impl HostCmdResp for GetVersionResponseData {}
