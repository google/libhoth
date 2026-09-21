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

//! Cryptographic primitives and public key coordinate parsing.

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
// P-256 Curve & Utilities
// -----------------------------------------------------------------------------

pub fn p256_public_key_to_words(x_bytes: &[u8; 32], y_bytes: &[u8; 32]) -> ([u32; 8], [u32; 8]) {
    let mut x_words = [0u32; 8];
    let mut y_words = [0u32; 8];
    for i in 0..8 {
        x_words[i] = u32::from_le_bytes(x_bytes[i * 4..(i + 1) * 4].try_into().unwrap());
        y_words[i] = u32::from_le_bytes(y_bytes[i * 4..(i + 1) * 4].try_into().unwrap());
    }
    (x_words, y_words)
}

pub fn p256_fingerprint_sha256(x_le: &[u32; 8], y_le: &[u32; 8]) -> [u8; 32] {
    let mut raw_le = [0u8; 64];
    for (i, word) in x_le.iter().enumerate() {
        raw_le[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    for (i, word) in y_le.iter().enumerate() {
        raw_le[32 + i * 4..32 + (i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    sha256(&raw_le)
}

/// Locates an uncompressed SEC1 point (`0x04 || X || Y`) inside `data`, which may
/// be the bare point or a DER/SPKI structure wrapping it.
fn uncompressed_point(data: &[u8]) -> Option<([u32; 8], [u32; 8])> {
    let pos = data.windows(65).position(|w| w[0] == 0x04)?;
    let point = &data[pos..pos + 65];
    let x: [u8; 32] = point[1..33].try_into().ok()?;
    let y: [u8; 32] = point[33..65].try_into().ok()?;
    Some(p256_public_key_to_words(&x, &y))
}

pub fn parse_p256_public_key(data: &[u8]) -> Result<([u32; 8], [u32; 8])> {
    // Bare `X || Y`, with no SEC1 point prefix.
    if let Ok(xy) = <[u8; 64]>::try_from(data) {
        let x: [u8; 32] = xy[0..32].try_into().unwrap();
        let y: [u8; 32] = xy[32..64].try_into().unwrap();
        return Ok(p256_public_key_to_words(&x, &y));
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

// -----------------------------------------------------------------------------
// ML-DSA-44 Public Key Parsing
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
        assert_eq!(x[0], 0x11111111);
        assert_eq!(y[0], 0x22222222);

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
}
