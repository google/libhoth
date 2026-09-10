use crate::HostCmdReq;
use crate::HostCommand;
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
