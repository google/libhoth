//! These commands are only enabled if pie_rot is built with
//! `--@mutask//:feature_unsafe_commands=true`.
//!
//! They are only intended to test fault handling, and MUST not be enabled in
//! production builds.

use crate::HostCmdReq;
use crate::HostCmdResp;
use crate::HostCommand;
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
