use crate::HostCmdReq;
use crate::HostCmdResp;
use crate::HostCommand;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// the exact challenge/response may vary in size, so they are not included in
// these types when they are dynamic and are to be placed immediately following
// the request/response data struct where it exists, or header struct otherwise

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct TestEchoNotRequestData {
    /// data to bitwise NOT in response
    pub challenge: [u8],
}

impl HostCmdReq for TestEchoNotRequestData {
    const COMMAND: HostCommand = HostCommand::TEST_ECHO_NOT;
    const VERSION: u8 = 0;
    // TODO(amitkh) - use a DST Response type when infrastructure supports this
    type Response = ();
}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct TestEchoRepeatRequestData {
    /// Number of times to repeat the payload in the response
    pub repeat_count: u8,

    /// Optionally busy wait before replying (ms)
    pub busy_wait_ms: u8,

    /// data to repeat in response
    pub challenge: [u8],
}

impl TestEchoRepeatRequestData {
    /// Fixed byte length of the fields (`repeat_count` and `busy_wait_ms`)
    /// at the start of the struct before `challenge`.
    pub const FIXED_LEN: usize = 2;
}

impl HostCmdReq for TestEchoRepeatRequestData {
    const COMMAND: HostCommand = HostCommand::TEST_ECHO_REPEAT;
    const VERSION: u8 = 0;
    // TODO(amitkh) - use a DST Response type when infrastructure supports this
    type Response = ();
}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct TestEchoChecksumRequestData {
    /// data to calculate checksum for in response
    pub challenge: [u8],
}

impl HostCmdReq for TestEchoChecksumRequestData {
    const COMMAND: HostCommand = HostCommand::TEST_ECHO_CHECKSUM;
    const VERSION: u8 = 0;
    type Response = TestEchoChecksumResponseData;
}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct TestEchoChecksumResponseData {
    pub checksum: u8,
}
impl HostCmdResp for TestEchoChecksumResponseData {}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct TestEchoSha256RequestData {
    /// data to calculate SHA256 for in response
    pub challenge: [u8],
}

impl HostCmdReq for TestEchoSha256RequestData {
    const COMMAND: HostCommand = HostCommand::TEST_ECHO_SHA256;
    const VERSION: u8 = 0;
    type Response = TestEchoSha256ResponseData;
}

#[derive(FromBytes, Immutable, KnownLayout, IntoBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct TestEchoSha256ResponseData {
    pub sha256: [u8; 32],
}
impl HostCmdResp for TestEchoSha256ResponseData {}
