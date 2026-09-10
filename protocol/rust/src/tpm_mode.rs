use crate::HostCmdReq;
use crate::HostCmdResp;
use crate::HostCommand;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(
    FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq,
)]
#[repr(transparent)]
pub struct TpmMode(pub u8);

impl TpmMode {
    pub const DISABLED: Self = Self(0);
    pub const TPM_SPI: Self = Self(1);
    pub const SPI_NOR_MAILBOX: Self = Self(2);
}

impl TpmMode {
    pub fn is_valid(self) -> bool {
        matches!(self, Self::DISABLED | Self::TPM_SPI | Self::SPI_NOR_MAILBOX)
    }
}

impl TryFrom<u8> for TpmMode {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::DISABLED),
            1 => Ok(Self::TPM_SPI),
            2 => Ok(Self::SPI_NOR_MAILBOX),
            _ => Err(()),
        }
    }
}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct SetTpmModeReq {
    pub mode: u8,
    pub reserved: [u8; 3],
}

impl HostCmdReq for SetTpmModeReq {
    const COMMAND: HostCommand = HostCommand::SET_TPM_MODE;
    const VERSION: u8 = 0;
    type Response = ();
}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct GetTpmModeReq {}

impl HostCmdReq for GetTpmModeReq {
    const COMMAND: HostCommand = HostCommand::GET_TPM_MODE;
    const VERSION: u8 = 0;
    type Response = GetTpmModeResp;
}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct GetTpmModeResp {
    pub mode: u8,
    pub reserved: [u8; 3],
}
impl HostCmdResp for GetTpmModeResp {}
