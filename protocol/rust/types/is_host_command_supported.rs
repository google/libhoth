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
