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

use aligned::{A4, Aligned};
use libhoth_block_on::block_on;
use libhoth_error::ErrorCode;
use pie_rot_hostcmd_types::{HostCmdReq, Request, Response, Status};
use zerocopy::FromBytes;

use std::future::Future;

/// A trait for sending host commands over a generic transport
pub trait HostCmdClient: Sized {
    /// Send a generic host command request and return a Response. This function
    /// should only encompass transport logic; host-command specific logic
    /// should be implemented at the trait level.
    fn call_raw<'a>(
        &mut self,
        req: &Request,
        resp_buf: &'a mut Aligned<A4, [u8]>,
    ) -> impl Future<Output = Result<&'a mut Response, HostCmdError>>;

    /// Send a generic host command request and return a Response. Unlike
    /// [`Self::call_raw()`], [`Self::call()`] will check the response code and
    /// return a [`HostCmdError::FwErr`] or [`HostCmdError::BadStatus`] if the
    /// firmware returns an error response.
    fn call<'a>(
        &mut self,
        req: &Request,
        resp_buf: &'a mut Aligned<A4, [u8]>,
    ) -> impl Future<Output = Result<&'a mut Response, HostCmdError>> {
        async {
            let resp = self.call_raw(req, resp_buf).await?;
            response_extract_error(resp)?;
            Ok(resp)
        }
    }

    /// Given a non-DST host command's request data, build a generic host
    /// command request, send it, and receive the response data as the command's
    /// Response type
    ///
    /// If sending a DST, we should use the HostCmdReq::build_dynamic and
    /// ReqBuilder::finalize functions, then call [`Self::call()`].
    #[inline(always)]
    fn call_fixed<TReq: HostCmdReq>(
        &mut self,
        req: TReq,
    ) -> impl std::future::Future<Output = Result<TReq::Response, HostCmdError>> {
        async {
            let mut buf = Aligned::<A4, _>([0x55_u8; 1024]);
            let builder = TReq::build_fixed(&mut buf).map_err(HostCmdError::Command)?;
            builder.data = req;
            let req = builder.finalize();

            let resp_buf: &mut Aligned<A4, [u8]> = &mut Aligned::<A4, _>([0u8; 1024]);
            let resp = self.call(req, resp_buf).await?;

            TReq::Response::read_from_bytes(&resp.data_bytes)
                .map_err(|_| HostCmdError::TruncatedResponse)
        }
    }

    fn call_fixed_sync<TReq: HostCmdReq>(
        &mut self,
        req: TReq,
    ) -> Result<TReq::Response, HostCmdError> {
        block_on(self.call_fixed(req))
    }

    fn call_sync<'a>(
        &mut self,
        req: &Request,
        resp_buf: &'a mut Aligned<A4, [u8]>,
    ) -> Result<&'a mut Response, HostCmdError> {
        block_on(self.call(req, resp_buf))
    }
}

fn response_extract_error(resp: &Response) -> Result<(), HostCmdError> {
    if resp.header.result == Status::OK {
        return Ok(());
    }
    if let Ok((err_code, _)) = u32::read_from_prefix(&resp.data_bytes)
        && let Err(err) = ErrorCode::u32_as_result(err_code)
    {
        return Err(HostCmdError::FwErr(err));
    }
    Err(HostCmdError::BadStatus(resp.header.result))
}

#[derive(thiserror::Error, Debug)]
pub enum HostCmdError {
    #[error("Transport error: {0}")]
    Transport(Box<dyn std::error::Error + Send + Sync>),

    #[error("Command error: {0}")]
    Command(#[from] ErrorCode),

    #[error("Request buffer too large (actual: {actual}, max: {max})")]
    RequestTooLarge { actual: usize, max: usize },

    #[error("HostCmd returned bad status ({0})")]
    BadStatus(Status),

    #[error("HostCmd returned extended error code ({0})")]
    FwErr(ErrorCode),

    #[error("Invalid response header")]
    InvalidResponseHeader,

    #[error("Invalid response checksum")]
    InvalidResponseChecksum,

    #[error("Response data truncated")]
    TruncatedResponse,

    #[error("Data length overflow")]
    DataLenOverflow,

    #[error("Test timed out")]
    Timeout,
}

impl HostCmdError {
    /// Helper to convert transport errors into Boxed HostCmdError::Transport
    pub fn transport<E: std::error::Error + Send + Sync + 'static>(error: E) -> Self {
        Self::Transport(Box::new(error))
    }

    /// Assert the error matches a specific firmware ErrorCode.
    /// Panics if the error is not a firmware error or does not match the expected
    pub fn assert_is_fw_err(&self, expected: ErrorCode) {
        match self {
            Self::FwErr(actual) if *actual == expected => {}
            _ => panic!("Expected {:?}, got {self:?}", Self::FwErr(expected)),
        }
    }

    /// Assert the error matches a specific Status value.
    /// Panics if the error is not a HostCmdError::BadStatus or does not match
    /// the expected value.
    pub fn assert_is_bad_status(&self, expected: Status) {
        match self {
            Self::BadStatus(actual) if *actual == expected => {}
            _ => panic!("Expected {:?}, got {self:?}", Self::BadStatus(expected)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aligned::{A4, Aligned};
    use libhoth_error::{
        KERNEL_FAULT_EXCEPTION_ILLEGAL_INSTRUCTION, KERNEL_FAULT_EXCEPTION_INSTRUCTION_PAGE_FAULT,
    };
    use pie_rot_hostcmd_types::{ResponseFinalized, Status};

    #[test]
    fn test_response_extract_error_ok() {
        let mut buf = Aligned::<A4, _>([0u8; 8]);
        let resp = Response::mut_from_bytes(&mut buf).unwrap();
        resp.finalize(Status::OK);
        assert!(response_extract_error(resp).is_ok());
    }

    #[test]
    fn test_response_extract_error_fw_err() {
        let mut buf = Aligned::<A4, _>([0u8; 12]);
        ResponseFinalized::from_error(KERNEL_FAULT_EXCEPTION_ILLEGAL_INSTRUCTION, &mut buf)
            .unwrap();
        let resp = Response::ref_from_bytes(&buf).unwrap();
        response_extract_error(resp)
            .unwrap_err()
            .assert_is_fw_err(KERNEL_FAULT_EXCEPTION_ILLEGAL_INSTRUCTION);
    }

    #[test]
    fn test_response_extract_error_bad_status() {
        let mut buf = Aligned::<A4, _>([0u8; 8]);
        let resp = Response::mut_from_bytes(&mut buf).unwrap();
        resp.finalize(Status::INVALID_CMD);
        response_extract_error(resp)
            .unwrap_err()
            .assert_is_bad_status(Status::INVALID_CMD);
    }

    #[test]
    fn test_response_extract_error_not_large_enough_for_fw_err() {
        let mut buf = Aligned::<A4, _>([0x55_u8; 11]);
        let resp = Response::mut_from_bytes(&mut buf).unwrap();
        resp.finalize(Status::INVALID_CHECKSUM);
        response_extract_error(resp)
            .unwrap_err()
            .assert_is_bad_status(Status::INVALID_CHECKSUM);
    }

    #[test]
    fn test_response_extract_error_all_zeroes() {
        let mut buf = Aligned::<A4, _>([0_u8; 12]);
        let resp = Response::mut_from_bytes(&mut buf).unwrap();
        resp.finalize(Status::INVALID_CMD);
        response_extract_error(resp)
            .unwrap_err()
            .assert_is_bad_status(Status::INVALID_CMD);
    }
    #[test]
    fn test_assert_is_fw_err_passes() {
        let err = HostCmdError::FwErr(KERNEL_FAULT_EXCEPTION_ILLEGAL_INSTRUCTION);
        err.assert_is_fw_err(KERNEL_FAULT_EXCEPTION_ILLEGAL_INSTRUCTION);
    }

    #[test]
    #[should_panic(expected = "Expected FwErr(0x78b30002), got FwErr(0x78b3000c)")]
    fn test_assert_is_fw_err_panics_on_wrong_error() {
        let err = HostCmdError::FwErr(KERNEL_FAULT_EXCEPTION_INSTRUCTION_PAGE_FAULT);
        err.assert_is_fw_err(KERNEL_FAULT_EXCEPTION_ILLEGAL_INSTRUCTION);
    }

    #[test]
    #[should_panic(expected = "Expected FwErr(0x78b30002), got BadStatus(Status(0))")]
    fn test_assert_is_fw_err_panics_on_wrong_type() {
        let err = HostCmdError::BadStatus(Status::OK);
        err.assert_is_fw_err(KERNEL_FAULT_EXCEPTION_ILLEGAL_INSTRUCTION);
    }

    #[test]
    fn test_assert_is_bad_status_passes() {
        let err = HostCmdError::BadStatus(Status::INVALID_CMD);
        err.assert_is_bad_status(Status::INVALID_CMD);
    }

    #[test]
    #[should_panic(expected = "Expected BadStatus(Status(7)), got BadStatus(Status(1))")]
    fn test_assert_is_bad_status_panics_on_wrong_status() {
        let err = HostCmdError::BadStatus(Status::INVALID_CMD);
        err.assert_is_bad_status(Status::INVALID_CHECKSUM);
    }

    #[test]
    #[should_panic(expected = "Expected BadStatus(Status(1)), got FwErr(0x78b30002)")]
    fn test_assert_is_bad_status_panics_on_wrong_type() {
        let err = HostCmdError::FwErr(KERNEL_FAULT_EXCEPTION_ILLEGAL_INSTRUCTION);
        err.assert_is_bad_status(Status::INVALID_CMD);
    }
}
