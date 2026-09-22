// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Cryptographic primitives, key coordinate parsing, and signature verification.

use alloc::string::String;
use alloc::vec::Vec;
use anyhow::Result;
use anyhow::anyhow;
use base64::Engine as _;

// -----------------------------------------------------------------------------
// FIPS 180-4 SHA2-256 (via mutask)
// -----------------------------------------------------------------------------

pub use mutask_sha256_sw::Sha256;
pub use mutask_sha256_sw::sha256;

/// Length of an ML-DSA-44 public key, in bytes.
pub const MLDSA44_PUBLIC_KEY_LEN: usize = 1312;

/// Length of an ML-DSA-44 signature, in bytes.
pub const MLDSA44_SIGNATURE_LEN: usize = 2420;

/// Length of a raw P-256 public key (`x || y`), in bytes.
pub const P256_PUBLIC_KEY_LEN: usize = 64;

/// Length of a raw P-256 signature (`r || s`), in bytes.
pub const P256_SIGNATURE_LEN: usize = 64;

// -----------------------------------------------------------------------------
// Encoding Utilities
// -----------------------------------------------------------------------------

pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    let clean = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    Ok(hex::decode(clean)?)
}

/// Decodes `s` as either hex or standard base64.
pub fn decode_hex_or_base64(s: &str) -> Option<Vec<u8>> {
    let clean = s.trim();
    from_hex(clean)
        .ok()
        .or_else(|| base64::engine::general_purpose::STANDARD.decode(clean).ok())
}

/// Strips PEM armour from `data` and decodes the body as hex or base64.
///
/// Returns `None` if `data` is not UTF-8 text or the body does not decode.
fn decode_pem(data: &[u8]) -> Option<Vec<u8>> {
    let text = core::str::from_utf8(data).ok()?;
    let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    decode_hex_or_base64(&body)
}

// -----------------------------------------------------------------------------
// Fingerprints
// -----------------------------------------------------------------------------

/// SHA2-256 over the concatenation of `parts`.
fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize()
}

/// Fingerprints a P-256 public key as `SHA2-256(x || y)` over the coordinates
/// exactly as they appear in the parsed key.
pub fn p256_fingerprint_sha256(x: &[u8; 32], y: &[u8; 32]) -> [u8; 32] {
    sha256_parts(&[x, y])
}

/// Fingerprints a hybrid signing authority as `SHA2-256(x || y || mldsa)`.
///
/// This is the value provisioned into RoT OTP to pin the key rotation authority.
pub fn compute_hybrid_otp_fingerprint(
    x: &[u8; 32],
    y: &[u8; 32],
    mldsa: &[u8; MLDSA44_PUBLIC_KEY_LEN],
) -> [u8; 32] {
    sha256_parts(&[x, y, mldsa])
}

// -----------------------------------------------------------------------------
// P-256 Public Key & Signature Parsing
// -----------------------------------------------------------------------------

/// Splits a 64-byte `a || b` buffer into its two 32-byte halves.
fn split_halves(data: &[u8; 64]) -> ([u8; 32], [u8; 32]) {
    let (a, b) = data.split_at(32);
    (a.try_into().unwrap(), b.try_into().unwrap())
}

/// Locates an uncompressed SEC1 point (`0x04 || X || Y`) inside `data`, which may
/// be the bare point or a DER/SPKI structure wrapping it.
fn uncompressed_point(data: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let pos = data.windows(65).position(|w| w[0] == 0x04)?;
    let point: &[u8; 64] = data[pos + 1..pos + 65].try_into().ok()?;
    Some(split_halves(point))
}

pub fn parse_p256_public_key(data: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    // Bare `X || Y`, with no SEC1 point prefix.
    if let Ok(xy) = <&[u8; P256_PUBLIC_KEY_LEN]>::try_from(data) {
        return Ok(split_halves(xy));
    }
    // A bare SEC1 point, or binary DER/SPKI wrapping one.
    if let Some(point) = uncompressed_point(data) {
        return Ok(point);
    }
    // PEM-armoured hex or base64 SPKI.
    if let Some(point) = decode_pem(data).as_deref().and_then(uncompressed_point) {
        return Ok(point);
    }
    Err(anyhow!("Unrecognized P-256 public key encoding"))
}

pub fn parse_p256_signature(data: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    if let Ok(rs) = <&[u8; P256_SIGNATURE_LEN]>::try_from(data) {
        return Ok(split_halves(rs));
    }
    if let Some(rs) = parse_der_signature(data) {
        return Ok(rs);
    }
    Err(anyhow!("Expected 64-byte raw or DER P-256 signature"))
}

/// Reads the DER `INTEGER` at `*idx`, advancing `idx` past it.
///
/// Every access is bounds checked, so a truncated or malformed encoding yields
/// `None` rather than panicking on untrusted input.
fn der_integer(data: &[u8], idx: &mut usize) -> Option<[u8; 32]> {
    if *data.get(*idx)? != 0x02 {
        return None;
    }
    let len = *data.get(*idx + 1)? as usize;
    let value = data.get(*idx + 2..*idx + 2 + len)?;
    *idx += 2 + len;
    pad_or_trim_32(value)
}

/// Parses a DER `SEQUENCE { INTEGER r, INTEGER s }` ECDSA signature.
fn parse_der_signature(data: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if *data.first()? != 0x30 {
        return None;
    }
    // Skip the outer SEQUENCE tag and length.
    let mut idx = 2;
    Some((der_integer(data, &mut idx)?, der_integer(data, &mut idx)?))
}

fn pad_or_trim_32(bytes: &[u8]) -> Option<[u8; 32]> {
    let trimmed = if bytes.len() > 32 && bytes[0] == 0x00 {
        &bytes[1..]
    } else {
        bytes
    };
    if trimmed.len() > 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out[32 - trimmed.len()..].copy_from_slice(trimmed);
    Some(out)
}

// -----------------------------------------------------------------------------
// ML-DSA-44 Public Key & Signature Parsing
// -----------------------------------------------------------------------------

/// Extracts an ML-DSA-44 public key from the bare key, or from a DER/SPKI blob
/// whose trailing `MLDSA44_PUBLIC_KEY_LEN` bytes are preceded by the BIT STRING
/// unused-bits octet.
fn mldsa44_key_bytes(data: &[u8]) -> Option<[u8; MLDSA44_PUBLIC_KEY_LEN]> {
    if let Ok(pk) = <[u8; MLDSA44_PUBLIC_KEY_LEN]>::try_from(data) {
        return Some(pk);
    }
    let start = data.len().checked_sub(MLDSA44_PUBLIC_KEY_LEN)?;
    if start > 0 && data[start - 1] == 0x00 {
        return data[start..].try_into().ok();
    }
    None
}

pub fn parse_mldsa44_public_key(data: &[u8]) -> Result<[u8; MLDSA44_PUBLIC_KEY_LEN]> {
    if let Some(pk) = mldsa44_key_bytes(data) {
        return Ok(pk);
    }
    if let Some(pk) = decode_pem(data).as_deref().and_then(mldsa44_key_bytes) {
        return Ok(pk);
    }
    Err(anyhow!(
        "Expected 1312-byte raw or SPKI PEM ML-DSA-44 public key"
    ))
}

pub fn parse_mldsa44_signature(data: &[u8]) -> Result<[u8; MLDSA44_SIGNATURE_LEN]> {
    if let Ok(sig) = <[u8; MLDSA44_SIGNATURE_LEN]>::try_from(data) {
        return Ok(sig);
    }
    if let Some(sig) = decode_pem(data)
        .as_deref()
        .and_then(|b| <[u8; MLDSA44_SIGNATURE_LEN]>::try_from(b).ok())
    {
        return Ok(sig);
    }
    Err(anyhow!(
        "Expected 2420-byte raw, hex, or base64 ML-DSA-44 signature"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_conversion() {
        let data = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let hex_str = to_hex(&data);
        assert_eq!(hex_str, "0123456789abcdef");
        let decoded = from_hex(&hex_str).unwrap();
        assert_eq!(decoded, data);

        let prefixed = from_hex("0x0123456789abcdef").unwrap();
        assert_eq!(prefixed, data);
    }

    #[test]
    fn test_decode_hex_or_base64() {
        assert_eq!(
            decode_hex_or_base64("AQIDBAU=").unwrap(),
            vec![1, 2, 3, 4, 5]
        );
        assert_eq!(
            decode_hex_or_base64("0102030405").unwrap(),
            vec![1, 2, 3, 4, 5]
        );
        assert!(decode_hex_or_base64("not valid!!").is_none());
    }

    #[test]
    fn test_p256_key_parsing() {
        let mut raw_64 = vec![0x11u8; 32];
        raw_64.extend_from_slice(&[0x22u8; 32]);
        let (x, y) = parse_p256_public_key(&raw_64).unwrap();
        assert_eq!(x, [0x11u8; 32]);
        assert_eq!(y, [0x22u8; 32]);

        let mut raw_65 = vec![0x04u8];
        raw_65.extend_from_slice(&raw_64);
        let (x2, y2) = parse_p256_public_key(&raw_65).unwrap();
        assert_eq!(x, x2);
        assert_eq!(y, y2);

        assert!(parse_p256_public_key(&[0u8; 8]).is_err());
    }

    #[test]
    fn test_mldsa44_key_parsing() {
        let raw_pk = vec![0x55u8; MLDSA44_PUBLIC_KEY_LEN];
        assert_eq!(parse_mldsa44_public_key(&raw_pk).unwrap()[0], 0x55);

        // SPKI-shaped: header, BIT STRING unused-bits octet, then the key.
        let mut spki = vec![0x30, 0x82, 0x05, 0x26, 0x03, 0x82, 0x05, 0x21, 0x00];
        spki.extend_from_slice(&raw_pk);
        assert_eq!(parse_mldsa44_public_key(&spki).unwrap(), raw_pk[..]);

        assert!(parse_mldsa44_public_key(&[0u8; 16]).is_err());
    }

    #[test]
    fn test_p256_signature_parsing() {
        let mut raw_sig = vec![0x33u8; 32];
        raw_sig.extend_from_slice(&[0x44u8; 32]);
        let (r, s) = parse_p256_signature(&raw_sig).unwrap();
        assert_eq!(r, [0x33u8; 32]);
        assert_eq!(s, [0x44u8; 32]);
    }

    #[test]
    fn test_der_signature_parsing() {
        // SEQUENCE { INTEGER 0x01, INTEGER 0x02 }, left-padded to 32 bytes each.
        let der = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let (r, s) = parse_p256_signature(&der).unwrap();
        assert_eq!(r[31], 0x01);
        assert_eq!(s[31], 0x02);
        assert_eq!(r[..31], [0u8; 31]);
    }

    #[test]
    fn test_malformed_der_signature_is_rejected_not_panic() {
        // An INTEGER whose declared length runs off the end of the buffer.
        assert!(parse_p256_signature(&[0x30, 0x06, 0x02, 0x7f, 0, 0, 0, 0]).is_err());
        // A second INTEGER whose length octet is missing entirely.
        assert!(parse_p256_signature(&[0x30, 0x04, 0x02, 0x01, 0x01, 0x02]).is_err());
        // Not a SEQUENCE at all.
        assert!(parse_p256_signature(&[0x02, 0x01, 0x01]).is_err());
    }

    #[test]
    fn test_mldsa44_signature_parsing() {
        let raw_sig = vec![0x66u8; MLDSA44_SIGNATURE_LEN];
        assert_eq!(parse_mldsa44_signature(&raw_sig).unwrap()[0], 0x66);

        assert!(parse_mldsa44_signature(&[0u8; 16]).is_err());
    }

    #[test]
    fn test_hybrid_otp_fingerprint() {
        let x = [0x12u8; 32];
        let y = [0x34u8; 32];
        let mldsa = [0x77u8; MLDSA44_PUBLIC_KEY_LEN];
        let fp = compute_hybrid_otp_fingerprint(&x, &y, &mldsa);
        assert_ne!(fp, [0u8; 32]);

        // The hybrid fingerprint is the streaming hash of the same concatenation.
        let mut material = Vec::new();
        material.extend_from_slice(&x);
        material.extend_from_slice(&y);
        material.extend_from_slice(&mldsa);
        assert_eq!(fp, sha256(&material));
    }
}
