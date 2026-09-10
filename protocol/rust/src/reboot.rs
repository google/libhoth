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
