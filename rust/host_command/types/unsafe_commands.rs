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

//! These commands are only enabled if pie_rot is built with
//! `--@mutask//:feature_unsafe_commands=true`.
//!
//! They are only intended to test fault handling, and MUST not be enabled in
//! production builds.

use pie_rot_hostcmd_types::HostCmdReq;
use pie_rot_hostcmd_types::HostCmdResp;
use pie_rot_hostcmd_types::HostCommand;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// The fields are the CPU register arguments to the syscall. See `@mutask//userlib` for more information.
#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct UnsafeSyscall {
    pub a0: u32,
    pub a1: u32,
    pub a2: u32,
    pub a3: u32,
    pub a4: u32,
    pub a5: u32,
    pub a6: u32,
    pub a7: u32,
}
impl HostCmdReq for UnsafeSyscall {
    const COMMAND: HostCommand = HostCommand::UNSAFE_SYSCALL;
    const VERSION: u8 = 0;
    type Response = UnsafeSyscall;
}
impl HostCmdResp for UnsafeSyscall {}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct UnsafeMemWrite {
    pub address: u32,
    pub value: u32,
}
impl HostCmdReq for UnsafeMemWrite {
    const COMMAND: HostCommand = HostCommand::UNSAFE_MEM_WRITE;
    const VERSION: u8 = 0;
    type Response = ();
}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct UnsafeHang;
impl HostCmdReq for UnsafeHang {
    const COMMAND: HostCommand = HostCommand::UNSAFE_HANG;
    const VERSION: u8 = 0;
    type Response = ();
}
