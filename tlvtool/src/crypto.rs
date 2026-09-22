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

//! Cryptographic primitives, public key parsing, and key fingerprints.
//!
//! Every parser accepts the encodings that real signing services hand out
//! (raw, DER/SPKI, PEM) and normalises them into the `crypto_tlv` public
//! material structs the firmware uses. Fingerprints are then computed by the
//! firmware's own [`FingerprintableKey`] implementation, so the tool cannot
//! disagree with the device about what a fingerprint covers.
//!
//! # Byte order
//!
//! Big integers are stored **little-endian** on the wire: `crypto.proto` says
//! so for P-256 coordinates and scalars, and RSA moduli follow the OpenPRoT
//! manifest convention the firmware verifier uses (the proto is silent on
//! them). Parsers return the big-endian bytes found in DER; the conversion
//! happens exactly once, in [`le_bytes`] / [`le_words`] / [`rsa_modulus_le`],
//! when the TLV material is built.

use alloc::string::String;
use alloc::vec::Vec;
use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::ensure;
use base64::Engine as _;
use crypto_tlv::HybridP256MlDsa44PublicMaterial;
use crypto_tlv::HybridP256SlhDsaPublicMaterial;
use crypto_tlv::MlDsa44PublicMaterial;
use crypto_tlv::P256PublicMaterial;
use crypto_tlv::Rsa2048PublicMaterial;
use crypto_tlv::Rsa3072PublicMaterial;
use crypto_tlv::Rsa4096PublicMaterial;
use crypto_tlv::SlhDsaPublicMaterial;
use mutask_fingerprints::FingerprintableKey;
use serde::Deserialize;
use serde::Serialize;

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

/// Length of an SLH-DSA-SHA2-128s public key (`PK.seed || PK.root`), in bytes.
pub const SLHDSA128S_PUBLIC_KEY_LEN: usize = 32;

/// The only RSA public exponent the firmware supports (F4); it is not carried
/// on the wire, so any other exponent must be rejected at build time.
const RSA_PUBLIC_EXPONENT_F4: [u8; 3] = [0x01, 0x00, 0x01];

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

/// Tries `parse` on `data` as given, then on its PEM-decoded body.
fn raw_or_pem<T>(data: &[u8], parse: impl Fn(&[u8]) -> Option<T>) -> Option<T> {
    parse(data).or_else(|| decode_pem(data).as_deref().and_then(parse))
}

/// Reverses a big-endian 256-bit integer into the little-endian byte order
/// `crypto.proto` mandates for P-256 coordinates and scalars.
pub fn le_bytes(be: &[u8; 32]) -> [u8; 32] {
    let mut le = *be;
    le.reverse();
    le
}

/// Packs a big-endian 256-bit integer into little-endian `[u32; 8]`
/// (`word[0]` holds the least significant 32 bits).
pub fn le_words(be: &[u8; 32]) -> [u32; 8] {
    words_of(&le_bytes(be))
}

/// Views 32 bytes as the eight native TLV words they occupy, in memory order.
fn words_of(bytes: &[u8; 32]) -> [u32; 8] {
    core::array::from_fn(|i| u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap()))
}

// -----------------------------------------------------------------------------
// Minimal DER reader
// -----------------------------------------------------------------------------

const DER_INTEGER: u8 = 0x02;
const DER_BIT_STRING: u8 = 0x03;
const DER_SEQUENCE: u8 = 0x30;

/// Reads the next DER `(tag, value)` from `data`, advancing `pos` past it.
///
/// Handles short- and long-form lengths. Every access is bounds checked, so a
/// truncated or malformed encoding yields `None` rather than panicking on
/// untrusted input.
fn der_next<'a>(data: &'a [u8], pos: &mut usize) -> Option<(u8, &'a [u8])> {
    let tag = *data.get(*pos)?;
    let first = *data.get(*pos + 1)? as usize;
    let (len, hdr) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let len_bytes = data.get(*pos + 2..*pos + 2 + n)?;
        (
            len_bytes
                .iter()
                .fold(0usize, |acc, b| acc << 8 | *b as usize),
            2 + n,
        )
    };
    let value = data.get(*pos + hdr..*pos + hdr + len)?;
    *pos += hdr + len;
    Some((tag, value))
}

/// Reads the next DER element, requiring it to carry `tag`.
fn der_expect<'a>(data: &'a [u8], pos: &mut usize, tag: u8) -> Option<&'a [u8]> {
    match der_next(data, pos)? {
        (t, value) if t == tag => Some(value),
        _ => None,
    }
}

/// Strips the sign-padding octet DER adds to non-negative INTEGERs whose top
/// bit is set.
fn der_unsigned(value: &[u8]) -> &[u8] {
    match value {
        [0x00, rest @ ..] if !rest.is_empty() => rest,
        _ => value,
    }
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

/// Parses a P-256 public key into its big-endian `(x, y)` coordinates.
pub fn parse_p256_public_key(data: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    // Bare `X || Y`, with no SEC1 point prefix.
    if let Ok(xy) = <&[u8; P256_PUBLIC_KEY_LEN]>::try_from(data) {
        return Ok(split_halves(xy));
    }
    // A bare SEC1 point, binary DER/SPKI wrapping one, or PEM of either.
    raw_or_pem(data, uncompressed_point).context("Unrecognized P-256 public key encoding")
}

/// Parses a P-256 signature into its big-endian `(r, s)` scalars.
pub fn parse_p256_signature(data: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    if let Ok(rs) = <&[u8; P256_SIGNATURE_LEN]>::try_from(data) {
        return Ok(split_halves(rs));
    }
    parse_der_signature(data).context("Expected 64-byte raw or DER P-256 signature")
}

/// Parses a DER `SEQUENCE { INTEGER r, INTEGER s }` ECDSA signature.
fn parse_der_signature(data: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let seq = der_expect(data, &mut 0, DER_SEQUENCE)?;
    let mut pos = 0;
    let r = pad_to_32(der_unsigned(der_expect(seq, &mut pos, DER_INTEGER)?))?;
    let s = pad_to_32(der_unsigned(der_expect(seq, &mut pos, DER_INTEGER)?))?;
    Some((r, s))
}

/// Left-pads a big-endian integer of at most 32 bytes to exactly 32.
fn pad_to_32(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() > 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Some(out)
}

// -----------------------------------------------------------------------------
// ML-DSA-44 / SLH-DSA Public Key & Signature Parsing
// -----------------------------------------------------------------------------

/// The `subjectPublicKey` payload of an X.509 `SubjectPublicKeyInfo`
/// (`SEQUENCE { AlgorithmIdentifier, BIT STRING { 0x00, key } }`).
fn spki_key(data: &[u8]) -> Option<&[u8]> {
    let spki = der_expect(data, &mut 0, DER_SEQUENCE)?;
    let mut pos = 0;
    der_expect(spki, &mut pos, DER_SEQUENCE)?;
    match der_expect(spki, &mut pos, DER_BIT_STRING)? {
        [0x00, key @ ..] => Some(key),
        _ => None,
    }
}

/// An `N`-byte opaque public key, either bare or wrapped in DER SPKI.
fn raw_or_spki<const N: usize>(data: &[u8]) -> Option<[u8; N]> {
    data.try_into()
        .ok()
        .or_else(|| spki_key(data)?.try_into().ok())
}

pub fn parse_mldsa44_public_key(data: &[u8]) -> Result<[u8; MLDSA44_PUBLIC_KEY_LEN]> {
    raw_or_pem(data, raw_or_spki).context("Expected 1312-byte raw or SPKI PEM ML-DSA-44 public key")
}

/// Parses an SLH-DSA-SHA2-128s public key from raw bytes, `RAW:SPHINCS+` PEM,
/// or DER/PEM SPKI.
pub fn parse_slhdsa128s_public_key(data: &[u8]) -> Result<[u8; SLHDSA128S_PUBLIC_KEY_LEN]> {
    raw_or_pem(data, raw_or_spki)
        .context("Expected 32-byte raw, RAW PEM, or SPKI SLH-DSA-SHA2-128s public key")
}

pub fn parse_mldsa44_signature(data: &[u8]) -> Result<[u8; MLDSA44_SIGNATURE_LEN]> {
    raw_or_pem(data, |b| <[u8; MLDSA44_SIGNATURE_LEN]>::try_from(b).ok())
        .context("Expected 2420-byte raw, hex, or base64 ML-DSA-44 signature")
}

// -----------------------------------------------------------------------------
// RSA Public Key Parsing
// -----------------------------------------------------------------------------

/// Parses a PKCS#1 `RSAPublicKey ::= SEQUENCE { modulus, publicExponent }`
/// into big-endian `(n, e)` with DER sign padding removed.
fn rsa_pkcs1(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let seq = der_expect(data, &mut 0, DER_SEQUENCE)?;
    let mut pos = 0;
    let n = der_unsigned(der_expect(seq, &mut pos, DER_INTEGER)?);
    let e = der_unsigned(der_expect(seq, &mut pos, DER_INTEGER)?);
    Some((n, e))
}

/// Parses either a PKCS#1 `RSAPublicKey` or an X.509 `SubjectPublicKeyInfo`
/// wrapping one, returning big-endian `(n, e)`.
fn rsa_der(data: &[u8]) -> Option<(&[u8], &[u8])> {
    rsa_pkcs1(data).or_else(|| rsa_pkcs1(spki_key(data)?))
}

/// Parses an RSA public key (DER/PEM, PKCS#1 or SPKI) whose modulus is exactly
/// `N` bytes and whose exponent is 65537, returning the big-endian modulus.
pub fn parse_rsa_public_key<const N: usize>(data: &[u8]) -> Result<[u8; N]> {
    let (n, e) = raw_or_pem(data, |b| rsa_der(b).map(|(n, e)| (n.to_vec(), e.to_vec())))
        .context("Unrecognized RSA public key encoding")?;
    ensure!(
        e == RSA_PUBLIC_EXPONENT_F4,
        "RSA public exponent must be 65537 (got 0x{})",
        to_hex(&e)
    );
    <[u8; N]>::try_from(n.as_slice())
        .map_err(|_| anyhow!("RSA modulus must be {} bits (got {})", N * 8, n.len() * 8))
}

// -----------------------------------------------------------------------------
// Key Material & Fingerprints
// -----------------------------------------------------------------------------

/// Signature algorithm selecting which `KeyFingerprint` arm a key populates.
///
/// Variant names and their `snake_case` JSON spellings track the `key_type`
/// oneof in `crypto.proto` one-to-one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Algorithm {
    P256,
    Slhdsa,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    HybridP256Slhdsa,
    Mldsa,
    HybridP256Mldsa,
}

impl Algorithm {
    /// Whether keys of this algorithm are supplied as an EC part and a PQ part.
    pub fn is_hybrid(self) -> bool {
        matches!(self, Self::HybridP256Slhdsa | Self::HybridP256Mldsa)
    }
}

/// Encoded public key input, shaped by whether the algorithm is hybrid.
#[derive(Debug, Clone, Copy)]
pub enum KeyBytes<'a> {
    Single(&'a [u8]),
    Hybrid { ec: &'a [u8], pq: &'a [u8] },
}

/// A public key in the exact form the firmware fingerprints it.
#[derive(Debug, Clone, PartialEq)]
pub enum KeyMaterial {
    P256(P256PublicMaterial),
    Slhdsa(SlhDsaPublicMaterial),
    Rsa2048(Rsa2048PublicMaterial),
    Rsa3072(Rsa3072PublicMaterial),
    Rsa4096(Rsa4096PublicMaterial),
    HybridP256Slhdsa(HybridP256SlhDsaPublicMaterial),
    Mldsa(MlDsa44PublicMaterial),
    HybridP256Mldsa(HybridP256MlDsa44PublicMaterial),
}

/// Builds the little-endian P-256 coordinates of `key`.
fn p256_words(key: &[u8]) -> Result<([u32; 8], [u32; 8])> {
    let (x, y) = parse_p256_public_key(key)?;
    Ok((le_words(&x), le_words(&y)))
}

fn slhdsa_words(key: &[u8]) -> Result<[u32; 8]> {
    // Opaque hash bytes, not an integer: kept in memory order.
    Ok(words_of(&parse_slhdsa128s_public_key(key)?))
}

/// The OpenPRoT manifest stores RSA moduli little-endian.
fn rsa_modulus_le<const N: usize>(key: &[u8]) -> Result<[u8; N]> {
    let mut modulus = parse_rsa_public_key::<N>(key)?;
    modulus.reverse();
    Ok(modulus)
}

impl KeyMaterial {
    /// Parses `bytes` as an `algorithm` public key.
    pub fn parse(algorithm: Algorithm, bytes: KeyBytes<'_>) -> Result<Self> {
        let (key, pq) = match (algorithm.is_hybrid(), bytes) {
            (false, KeyBytes::Single(key)) => (key, None),
            (true, KeyBytes::Hybrid { ec, pq }) => (ec, Some(pq)),
            (true, KeyBytes::Single(_)) => {
                bail!("{algorithm:?} is a hybrid algorithm and needs both an EC and a PQ key")
            }
            (false, KeyBytes::Hybrid { .. }) => {
                bail!("{algorithm:?} takes a single key, not an EC + PQ pair")
            }
        };
        Ok(match algorithm {
            Algorithm::P256 => {
                let (x, y) = p256_words(key)?;
                Self::P256(P256PublicMaterial { x, y })
            }
            Algorithm::Slhdsa => Self::Slhdsa(SlhDsaPublicMaterial {
                slhdsa: slhdsa_words(key)?,
            }),
            Algorithm::Mldsa => Self::Mldsa(MlDsa44PublicMaterial {
                mldsa: parse_mldsa44_public_key(key)?,
            }),
            Algorithm::Rsa2048 => Self::Rsa2048(Rsa2048PublicMaterial {
                modulus: rsa_modulus_le(key)?,
            }),
            Algorithm::Rsa3072 => Self::Rsa3072(Rsa3072PublicMaterial {
                modulus: rsa_modulus_le(key)?,
            }),
            Algorithm::Rsa4096 => Self::Rsa4096(Rsa4096PublicMaterial {
                modulus: rsa_modulus_le(key)?,
            }),
            Algorithm::HybridP256Slhdsa => {
                let (x, y) = p256_words(key)?;
                Self::HybridP256Slhdsa(HybridP256SlhDsaPublicMaterial {
                    x,
                    y,
                    slhdsa: slhdsa_words(pq.unwrap())?,
                })
            }
            Algorithm::HybridP256Mldsa => {
                let (x, y) = p256_words(key)?;
                Self::HybridP256Mldsa(HybridP256MlDsa44PublicMaterial {
                    x,
                    y,
                    mldsa: parse_mldsa44_public_key(pq.unwrap())?,
                })
            }
        })
    }

    /// The firmware's SHA2-256 fingerprint of this key.
    pub fn fingerprint_sha256(&self) -> [u8; 32] {
        match self {
            Self::P256(m) => m.fingerprint_sha256(),
            Self::Slhdsa(m) => m.fingerprint_sha256(),
            Self::Rsa2048(m) => m.fingerprint_sha256(),
            Self::Rsa3072(m) => m.fingerprint_sha256(),
            Self::Rsa4096(m) => m.fingerprint_sha256(),
            Self::HybridP256Slhdsa(m) => m.fingerprint_sha256(),
            Self::Mldsa(m) => m.fingerprint_sha256(),
            Self::HybridP256Mldsa(m) => m.fingerprint_sha256(),
        }
    }
}

/// A synthetic PKCS#1 `RSAPublicKey` with an `N`-byte modulus whose top bit
/// is set (so DER sign-pads it) and public exponent `e`. Test fixture only.
#[cfg(test)]
pub(crate) fn rsa_pkcs1_der<const N: usize>(e: &[u8]) -> Vec<u8> {
    let modulus: Vec<u8> = (0..N).map(|i| 0x80 | i as u8).collect();
    let mut n_int = alloc::vec![DER_INTEGER, 0x82, ((N + 1) >> 8) as u8, (N + 1) as u8, 0x00];
    n_int.extend_from_slice(&modulus);
    let mut e_int = alloc::vec![DER_INTEGER, e.len() as u8];
    e_int.extend_from_slice(e);
    let body_len = n_int.len() + e_int.len();
    let mut der = alloc::vec![DER_SEQUENCE, 0x82, (body_len >> 8) as u8, body_len as u8];
    der.extend(n_int);
    der.extend(e_int);
    der
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test P-256 public key (SPKI PEM).
    const P256_SPKI_PEM: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBYAk4OZX3K0yh4j6950NlUpCQlwZ
M97unt4Q7HG36ecljO7J3mFVWaraKzXTjM7oGqPNkKpVQg7CIcHZ6MRsaA==
-----END PUBLIC KEY-----
";

    /// Test SLH-DSA-SHA2-128s public key, as raw PEM and
    /// as SPKI PEM (the same key).
    const SLHDSA_RAW_PEM: &str = "-----BEGIN RAW:SPHINCS+_SHA2_128s_simple PUBLIC KEY-----
szRCBKbhiZP2Hu/mtVAvQTdyraaLL9+cqDB6gKhS88M=
-----END RAW:SPHINCS+_SHA2_128s_simple PUBLIC KEY-----
";
    const SLHDSA_SPKI_PEM: &str = "-----BEGIN PUBLIC KEY-----
MDAwCwYJYIZIAWUDBAMjAyEAszRCBKbhiZP2Hu/mtVAvQTdyraaLL9+cqDB6gKhS
88M=
-----END PUBLIC KEY-----
";

    /// Wraps a PKCS#1 key in an SPKI envelope with a dummy AlgorithmIdentifier.
    fn rsa_spki_der(pkcs1: &[u8]) -> Vec<u8> {
        let alg = [DER_SEQUENCE, 0x02, 0x05, 0x00];
        let bits_len = pkcs1.len() + 1;
        let mut bits = vec![
            DER_BIT_STRING,
            0x82,
            (bits_len >> 8) as u8,
            bits_len as u8,
            0x00,
        ];
        bits.extend_from_slice(pkcs1);
        let body_len = alg.len() + bits.len();
        let mut der = vec![DER_SEQUENCE, 0x82, (body_len >> 8) as u8, body_len as u8];
        der.extend_from_slice(&alg);
        der.extend(bits);
        der
    }

    #[test]
    fn test_hex_conversion() {
        let data = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let hex_str = to_hex(&data);
        assert_eq!(hex_str, "0123456789abcdef");
        assert_eq!(from_hex(&hex_str).unwrap(), data);
        assert_eq!(from_hex("0x0123456789abcdef").unwrap(), data);
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
    fn test_le_words_packs_least_significant_word_first() {
        let be: [u8; 32] = core::array::from_fn(|i| i as u8);
        let words = le_words(&be);
        // The least significant 32 bits of the integer are its last four BE bytes.
        assert_eq!(words[0], 0x1c1d_1e1f);
        assert_eq!(words[7], 0x0001_0203);
        // Round-trips through the byte form used on the SIGC wire.
        assert_eq!(words_of(&le_bytes(&be)), words);
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
        assert_eq!(parse_p256_public_key(&raw_65).unwrap(), (x, y));

        // A real SPKI PEM: x starts 0x0580 24e0 (see the DER dump of the same key).
        let (x, _) = parse_p256_public_key(P256_SPKI_PEM.as_bytes()).unwrap();
        assert_eq!(x[..4], [0x05, 0x80, 0x24, 0xe0]);

        assert!(parse_p256_public_key(&[0u8; 8]).is_err());
    }

    #[test]
    fn test_mldsa44_key_parsing() {
        let raw_pk = vec![0x55u8; MLDSA44_PUBLIC_KEY_LEN];
        assert_eq!(parse_mldsa44_public_key(&raw_pk).unwrap()[0], 0x55);

        // Real SPKI shape: SEQUENCE { SEQUENCE { OID id-ml-dsa-44 }, BIT STRING { 0x00, key } }.
        let mut spki = vec![0x30, 0x82, 0x05, 0x32];
        spki.extend_from_slice(&[
            0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11,
        ]);
        spki.extend_from_slice(&[0x03, 0x82, 0x05, 0x21, 0x00]);
        spki.extend_from_slice(&raw_pk);
        assert_eq!(parse_mldsa44_public_key(&spki).unwrap(), raw_pk[..]);

        assert!(parse_mldsa44_public_key(&[0u8; 16]).is_err());
    }

    #[test]
    fn test_slhdsa_key_parsing_accepts_every_shipped_shape() {
        let from_raw_pem = parse_slhdsa128s_public_key(SLHDSA_RAW_PEM.as_bytes()).unwrap();
        let from_spki_pem = parse_slhdsa128s_public_key(SLHDSA_SPKI_PEM.as_bytes()).unwrap();
        assert_eq!(from_raw_pem, from_spki_pem);
        assert_eq!(from_raw_pem[..3], [0xb3, 0x34, 0x42]);
        assert_eq!(
            parse_slhdsa128s_public_key(&from_raw_pem).unwrap(),
            from_raw_pem
        );

        assert!(parse_slhdsa128s_public_key(&[0u8; 16]).is_err());
    }

    #[test]
    fn test_rsa_key_parsing() {
        let pkcs1 = rsa_pkcs1_der::<384>(&RSA_PUBLIC_EXPONENT_F4);
        let n = parse_rsa_public_key::<384>(&pkcs1).unwrap();
        assert_eq!(n[0], 0x80);
        assert_eq!(n[383], 0x80 | 0x7f);

        // The same key wrapped in SPKI, and as PEM, parses identically.
        let spki = rsa_spki_der(&pkcs1);
        assert_eq!(parse_rsa_public_key::<384>(&spki).unwrap(), n);
        let pem = alloc::format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(&spki)
        );
        assert_eq!(parse_rsa_public_key::<384>(pem.as_bytes()).unwrap(), n);

        // Wrong size for the requested arm, and an exponent the firmware cannot use.
        assert!(parse_rsa_public_key::<256>(&pkcs1).is_err());
        let e3 = rsa_pkcs1_der::<384>(&[0x03]);
        let err = parse_rsa_public_key::<384>(&e3).unwrap_err().to_string();
        assert!(err.contains("65537"), "{err}");
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

        // A 33-byte sign-padded INTEGER is accepted and the pad dropped.
        let mut padded = vec![0x30, 0x26, 0x02, 0x21, 0x00];
        padded.extend_from_slice(&[0xff; 32]);
        padded.extend_from_slice(&[0x02, 0x01, 0x02]);
        assert_eq!(parse_p256_signature(&padded).unwrap().0, [0xff; 32]);
    }

    #[test]
    fn test_malformed_der_signature_is_rejected_not_panic() {
        // An INTEGER whose declared length runs off the end of the buffer.
        assert!(parse_p256_signature(&[0x30, 0x06, 0x02, 0x7f, 0, 0, 0, 0]).is_err());
        // A second INTEGER whose length octet is missing entirely.
        assert!(parse_p256_signature(&[0x30, 0x04, 0x02, 0x01, 0x01, 0x02]).is_err());
        // Not a SEQUENCE at all.
        assert!(parse_p256_signature(&[0x02, 0x01, 0x01]).is_err());
        // A long-form length with an absurd octet count.
        assert!(parse_p256_signature(&[0x30, 0x85, 1, 1, 1, 1, 1]).is_err());
    }

    #[test]
    fn test_mldsa44_signature_parsing() {
        let raw_sig = vec![0x66u8; MLDSA44_SIGNATURE_LEN];
        assert_eq!(parse_mldsa44_signature(&raw_sig).unwrap()[0], 0x66);
        assert!(parse_mldsa44_signature(&[0u8; 16]).is_err());
    }

    #[test]
    fn test_key_material_matches_firmware_fingerprint() {
        // P-256: the fingerprint covers the little-endian words the device sees.
        let x: [u8; 32] = core::array::from_fn(|i| i as u8);
        let y: [u8; 32] = core::array::from_fn(|i| 0x40 + i as u8);
        let mut raw = x.to_vec();
        raw.extend_from_slice(&y);
        let km = KeyMaterial::parse(Algorithm::P256, KeyBytes::Single(&raw)).unwrap();
        let expected = P256PublicMaterial {
            x: le_words(&x),
            y: le_words(&y),
        };
        assert_eq!(km, KeyMaterial::P256(expected));

        // RSA: modulus reversed into little-endian, then hashed as the device would.
        let pkcs1 = rsa_pkcs1_der::<256>(&RSA_PUBLIC_EXPONENT_F4);
        let km = KeyMaterial::parse(Algorithm::Rsa2048, KeyBytes::Single(&pkcs1)).unwrap();
        let mut modulus = parse_rsa_public_key::<256>(&pkcs1).unwrap();
        modulus.reverse();
        assert_eq!(
            km.fingerprint_sha256(),
            Rsa2048PublicMaterial { modulus }.fingerprint_sha256()
        );

        // Hybrid: EC + PQ parts feed one digest.
        let pq = [0x33u8; MLDSA44_PUBLIC_KEY_LEN];
        let km = KeyMaterial::parse(
            Algorithm::HybridP256Mldsa,
            KeyBytes::Hybrid { ec: &raw, pq: &pq },
        )
        .unwrap();
        assert_eq!(
            km.fingerprint_sha256(),
            HybridP256MlDsa44PublicMaterial {
                x: le_words(&x),
                y: le_words(&y),
                mldsa: pq,
            }
            .fingerprint_sha256()
        );
    }

    #[test]
    fn test_key_material_rejects_wrong_arity() {
        let raw = [0x11u8; P256_PUBLIC_KEY_LEN];
        assert!(KeyMaterial::parse(Algorithm::HybridP256Mldsa, KeyBytes::Single(&raw)).is_err());
        assert!(
            KeyMaterial::parse(Algorithm::P256, KeyBytes::Hybrid { ec: &raw, pq: &raw }).is_err()
        );
    }
}
