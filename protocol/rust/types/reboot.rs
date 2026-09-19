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

use crate::{HostCmdReq, HostCommand};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(Debug, Copy, Clone, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RebootReq {
    pub reset_type: ResetType,
    pub reserved: u8,
}
impl HostCmdReq for RebootReq {
    const COMMAND: HostCommand = HostCommand::REBOOT;
    const VERSION: u8 = 0;
    type Response = ();
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(transparent)]
pub struct ResetType(pub u8);

impl ResetType {
    pub const COLD: Self = Self(4);
    pub const WARM: Self = Self(8);
}
