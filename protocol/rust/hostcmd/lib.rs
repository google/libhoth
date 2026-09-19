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

//! Host-side host command framing.
//!
//! An allocating counterpart to the in-place builder that RoT firmware uses. The
//! types come from [`hoth_hostcmd_types`]; this crate only knows how to lay them
//! out into a `Vec<u8>` and how to check one coming back.
//!
//! Firmware cannot use this -- it is `std` and it allocates -- and this crate
//! cannot use firmware's builder, which needs a 4-byte-aligned caller-supplied
//! buffer. They are two assemblers over one set of definitions, and
//! `builders_agree_byte_for_byte` in the tests below is what keeps them honest.
//!
//! # Relationship to the C API
//!
//! `libhoth_hostcmd_exec_v2` does its own framing and folds a non-OK device
//! status into an error. This crate exists for callers that need the frame
//! itself -- a passthrough that must return a device's error response verbatim,
//! or a test that wants to send a deliberately corrupt checksum.

use hoth_hostcmd_types::{
    checksum, checksum_valid, HostCmdReq, HostCommand, RequestHeader, ResponseHeader, HEADER_LEN,
    MIN_HOST_COMMAND_BUFFER_SIZE,
};
use zerocopy::{FromBytes, IntoBytes};

/// Largest frame this crate will build or accept, header included.
///
/// A transport may well be smaller than this -- the mailbox transport in
/// `transports/` certainly is -- and is expected to reject anything it cannot
/// carry. This is the protocol ceiling, not a promise.
pub const MAX_FRAME_LEN: usize = MIN_HOST_COMMAND_BUFFER_SIZE;

/// Why a frame was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// Shorter than the 8-byte header.
    TooShort,
    /// Longer than [`MAX_FRAME_LEN`].
    TooLong,
    /// Header version is not the expected protocol version.
    BadVersion,
    /// The bytes do not sum to zero.
    BadChecksum,
    /// `data_len` disagrees with the number of bytes present.
    LengthMismatch,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "frame is shorter than the {HEADER_LEN}-byte header"),
            Self::TooLong => write!(f, "frame is longer than {MAX_FRAME_LEN} bytes"),
            Self::BadVersion => write!(f, "header version is not supported"),
            Self::BadChecksum => write!(f, "checksum does not sum to zero"),
            Self::LengthMismatch => write!(f, "data_len disagrees with the frame length"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Builds a complete request frame: the 8-byte header followed by `payload`.
pub fn build_request(
    command: HostCommand,
    command_version: u8,
    payload: &[u8],
) -> Result<Vec<u8>, FrameError> {
    if HEADER_LEN + payload.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLong);
    }
    let header = RequestHeader {
        version: RequestHeader::REQ_VERSION,
        checksum: 0, // filled in below, once the whole frame exists
        command,
        command_version,
        reserved: 0,
        // Bounded by the MAX_FRAME_LEN check above.
        data_len: payload.len() as u16,
    };
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.extend_from_slice(header.as_bytes());
    frame.extend_from_slice(payload);
    frame[1] = checksum(&frame);
    Ok(frame)
}

/// Builds the frame for a fixed-size request, taking the command code and
/// version from the type.
pub fn build<R: HostCmdReq + Sized>(request: &R) -> Result<Vec<u8>, FrameError> {
    build_request(R::COMMAND, R::VERSION, request.as_bytes())
}

/// Checks that a caller-supplied request frame is well formed enough to send.
///
/// The checksum is deliberately *not* verified. A passthrough exists so callers
/// can drive a device directly, including with a deliberately corrupt checksum
/// to exercise the device's own validation.
pub fn validate_request(frame: &[u8]) -> Result<(), FrameError> {
    if frame.len() < HEADER_LEN {
        return Err(FrameError::TooShort);
    }
    if frame.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLong);
    }
    // `read_from_prefix` copies, so this works at any alignment. `ref_from_prefix`
    // would not: RequestHeader is 2-byte aligned. See hoth_hostcmd_types' docs.
    let (header, rest) =
        RequestHeader::read_from_prefix(frame).map_err(|_| FrameError::TooShort)?;
    if header.version != RequestHeader::REQ_VERSION {
        return Err(FrameError::BadVersion);
    }
    if usize::from(header.data_len) != rest.len() {
        return Err(FrameError::LengthMismatch);
    }
    Ok(())
}

/// Validates a response frame and returns its header and payload.
pub fn validate_response(frame: &[u8]) -> Result<(ResponseHeader, &[u8]), FrameError> {
    if frame.len() < HEADER_LEN {
        return Err(FrameError::TooShort);
    }
    let (header, rest) =
        ResponseHeader::read_from_prefix(frame).map_err(|_| FrameError::TooShort)?;
    if !header.is_version_valid() {
        return Err(FrameError::BadVersion);
    }
    if !checksum_valid(frame) {
        return Err(FrameError::BadChecksum);
    }
    let data_len = usize::from(header.data_len);
    if data_len > rest.len() {
        return Err(FrameError::LengthMismatch);
    }
    Ok((header, &rest[..data_len]))
}

/// Parses a response payload as a command's response type.
///
/// Returns `None` if the payload is too short. Trailing bytes are ignored: a
/// device running newer firmware may append fields we do not know about.
pub fn parse<R: HostCmdReq>(payload: &[u8]) -> Option<R::Response>
where
    R::Response: Sized,
{
    R::Response::read_from_prefix(payload).ok().map(|(r, _)| r)
}

/// Turns a NUL-terminated or NUL-padded byte field into a clean `String`.
pub fn cstr_to_string(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hoth_hostcmd_types::get_version::GetVersionRequestData;
    use hoth_hostcmd_types::hello::HelloRequestData;
    use hoth_hostcmd_types::Status;

    /// The wire format must not move. Independently derived: version 3, command
    /// 0x0002 little-endian, no payload, and a checksum making the frame sum to
    /// zero (0x100 - 3 - 2 = 0xfb).
    #[test]
    fn get_version_frame_is_byte_for_byte_what_the_protocol_says() {
        let frame = build(&GetVersionRequestData).unwrap();
        assert_eq!(frame, vec![0x03, 0xfb, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    /// The whole point of sharing `hoth_hostcmd_types`: this crate's allocating
    /// builder and firmware's in-place builder must lay out the same bytes. Both
    /// start from `header_template`, so pinning that against the frame we emit
    /// catches any drift between them.
    #[test]
    fn builders_agree_byte_for_byte() {
        let payload = HelloRequestData { challenge: 0xdead_beef };
        let frame = build(&payload).unwrap();

        let mut expected = HelloRequestData::header_template_fixed().unwrap();
        expected.checksum = 0;
        let mut by_hand = expected.as_bytes().to_vec();
        by_hand.extend_from_slice(payload.as_bytes());
        by_hand[1] = checksum(&by_hand);

        assert_eq!(frame, by_hand);
        assert!(checksum_valid(&frame));
    }

    #[test]
    fn built_frames_sum_to_zero() {
        let frame = build_request(HostCommand(0x1234), 7, &[1, 2, 3, 4, 5]).unwrap();
        assert!(checksum_valid(&frame));
    }

    #[test]
    fn build_request_lays_out_the_header() {
        let frame = build_request(HostCommand(0x1234), 7, &[9, 9]).unwrap();
        let (header, payload) = RequestHeader::read_from_prefix(&frame).unwrap();
        assert_eq!(header.version, RequestHeader::REQ_VERSION);
        assert_eq!(header.command, HostCommand(0x1234));
        assert_eq!(header.command_version, 7);
        assert_eq!(header.reserved, 0);
        assert_eq!(header.data_len, 2);
        assert_eq!(payload, &[9, 9]);
    }

    #[test]
    fn build_request_rejects_an_oversized_payload() {
        let payload = vec![0u8; MAX_FRAME_LEN];
        assert_eq!(
            build_request(HostCommand(0x1234), 0, &payload),
            Err(FrameError::TooLong)
        );
    }

    /// Headers must parse at any offset. This is what `read_from_prefix` buys us
    /// and the reason the types crate can keep 2-byte-aligned fields.
    #[test]
    fn headers_parse_from_an_unaligned_slice() {
        let frame = build_request(HostCommand(0x1234), 0, &[]).unwrap();
        let mut offset = vec![0u8; 1];
        offset.extend_from_slice(&frame);
        let header = RequestHeader::read_from_prefix(&offset[1..]).unwrap().0;
        assert_eq!(header.command, HostCommand(0x1234));
    }

    fn response_frame(version: u8, result: u16, payload: &[u8]) -> Vec<u8> {
        let header = ResponseHeader {
            version,
            checksum: 0,
            result: Status::new(result),
            data_len: payload.len() as u16,
            extra: 0,
        };
        let mut frame = header.as_bytes().to_vec();
        frame.extend_from_slice(payload);
        frame[1] = checksum(&frame);
        frame
    }

    #[test]
    fn validate_response_accepts_a_good_frame() {
        let frame = response_frame(ResponseHeader::RESP_VERSION, 0, &[1, 2, 3]);
        let (header, payload) = validate_response(&frame).unwrap();
        assert_eq!(header.result, Status::OK);
        assert_eq!(payload, &[1, 2, 3]);
    }

    #[test]
    fn validate_response_rejects_a_short_frame() {
        assert_eq!(validate_response(&[3, 0, 0]), Err(FrameError::TooShort));
    }

    #[test]
    fn validate_response_rejects_a_bad_version() {
        let frame = response_frame(2, 0, &[]);
        assert_eq!(validate_response(&frame), Err(FrameError::BadVersion));
    }

    #[test]
    fn validate_response_rejects_a_corrupted_frame() {
        let mut frame = response_frame(ResponseHeader::RESP_VERSION, 0, &[1, 2, 3]);
        frame[9] ^= 0xff;
        assert_eq!(validate_response(&frame), Err(FrameError::BadChecksum));
    }

    #[test]
    fn validate_request_accepts_what_build_request_produces() {
        let frame = build_request(HostCommand(0x1234), 0, &[7; 16]).unwrap();
        assert_eq!(validate_request(&frame), Ok(()));
    }

    #[test]
    fn validate_request_rejects_a_length_mismatch() {
        let mut frame = build_request(HostCommand(0x1234), 0, &[7; 16]).unwrap();
        frame[6] = 15;
        assert_eq!(validate_request(&frame), Err(FrameError::LengthMismatch));
    }

    /// A deliberately corrupt checksum must still be transmittable -- that is how
    /// a caller tests the device's own validation.
    #[test]
    fn validate_request_ignores_the_checksum() {
        let mut frame = build_request(HostCommand(0x1234), 0, &[]).unwrap();
        frame[1] ^= 0xff;
        assert_eq!(validate_request(&frame), Ok(()));
    }

    #[test]
    fn parse_reads_a_get_version_response() {
        let mut payload = vec![0u8; 100];
        payload[..4].copy_from_slice(b"ro-1");
        payload[32..36].copy_from_slice(b"rw-2");
        let parsed = parse::<GetVersionRequestData>(&payload).unwrap();
        assert_eq!(cstr_to_string(&parsed.version_string_ro), "ro-1");
        assert_eq!(cstr_to_string(&parsed.version_string_rw), "rw-2");
    }

    #[test]
    fn parse_rejects_a_short_payload() {
        assert!(parse::<GetVersionRequestData>(&[0u8; 99]).is_none());
    }

    #[test]
    fn cstr_to_string_handles_termination_padding_and_full_fields() {
        assert_eq!(cstr_to_string(b"abc\0\0\0"), "abc");
        assert_eq!(cstr_to_string(b"abc"), "abc");
        assert_eq!(cstr_to_string(b"  abc  \0"), "abc");
        assert_eq!(cstr_to_string(b"\0"), "");
        assert_eq!(cstr_to_string(b""), "");
    }
}
