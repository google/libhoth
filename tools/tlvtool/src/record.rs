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

//! Record types and the frozen unsigned wire image shared by `build` and `sign`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::ensure;
use core::marker::PhantomData;
use openprot_tlv::TlvData;
use openprot_tlv::TlvObject;
use std::path::Path;

/// Longest image vendor or family name, in bytes, as stored on the wire.
pub const MAX_IDENTITY_STRING_LEN: usize = 8;
/// Image vendor a record names when its config does not say.
pub const DEFAULT_IMAGE_VENDOR: &str = "GOOGLE";
/// Image family a record names when its config does not say.
pub const DEFAULT_IMAGE_FAMILY: &str = "EARLGREY";

/// Describes one kind of signed record that `tlvtool` can build and sign.
pub trait RecordKind: core::fmt::Debug + Clone {
    /// Root TLV of the unsigned record
    type Descriptor: TlvObject + 'static;
    /// Root TLV of the signed record
    type SignedDescriptor: TlvObject + 'static;
    /// Largest unsigned record accepted, in bytes.
    const MAX_UNSIGNED_BYTES: usize;
    /// Largest signed record accepted, in bytes.
    const MAX_SIGNED_BYTES: usize;
}

/// Renders a TLV tag as its four ASCII characters.
pub(crate) fn fourcc(tag: u32) -> String {
    String::from_utf8_lossy(&tag.to_le_bytes()).into_owned()
}

/// Decodes a hex string that must denote exactly one SHA2-256 digest.
pub(crate) fn parse_digest32(label: &str, hex_str: &str) -> Result<[u8; 32]> {
    let raw = crate::crypto::from_hex(hex_str).with_context(|| format!("Invalid {label} hex"))?;
    raw.try_into()
        .map_err(|_| anyhow!("{label} '{hex_str}' must be 32 bytes (64 hex chars)"))
}

/// Validates an identity string and NUL-pads it to [`MAX_IDENTITY_STRING_LEN`].
pub(crate) fn identity_name(field: &str, s: &str) -> Result<String> {
    ensure!(s.is_ascii(), "{field} string must be ASCII (got '{s}')");
    ensure!(
        s.len() <= MAX_IDENTITY_STRING_LEN,
        "{} string exceeds maximum limit of {} bytes (got {} bytes)",
        field,
        MAX_IDENTITY_STRING_LEN,
        s.len()
    );
    let mut padded = String::from(s);
    padded.push_str(&"\0".repeat(MAX_IDENTITY_STRING_LEN - s.len()));
    Ok(padded)
}

/// Rejects an unsigned record image that would not fit its limit.
fn check_unsigned_size<K: RecordKind>(size: usize) -> Result<()> {
    ensure!(
        size <= K::MAX_UNSIGNED_BYTES,
        "Unsigned '{}' record size ({size} bytes) exceeds limit ({} bytes)",
        fourcc(K::Descriptor::TAG),
        K::MAX_UNSIGNED_BYTES
    );
    Ok(())
}

/// A validated unsigned record wire image holding a `K::Descriptor`.
#[derive(Debug, Clone)]
pub struct Unsigned<K> {
    bytes: Vec<u8>,
    kind: PhantomData<K>,
}

impl<K: RecordKind> Unsigned<K> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        check_unsigned_size::<K>(bytes.len())?;
        let tlv_data = TlvData::overlay_bytes(bytes)
            .map_err(|_| anyhow!("Unsigned record length must be 4-byte aligned"))?;
        let has_desc = tlv_data.iter::<K::Descriptor>().next().is_some();
        ensure!(
            has_desc,
            "No '{}' descriptor found in binary record",
            fourcc(K::Descriptor::TAG)
        );
        Ok(Self {
            bytes: bytes.to_vec(),
            kind: PhantomData,
        })
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let p = path.as_ref();
        let bytes = std::fs::read(p).with_context(|| format!("Failed to read {}", p.display()))?;
        Self::from_bytes(&bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::krr::Krr;

    /// The generic messages name the record by its descriptor tag.
    #[test]
    fn test_messages_name_the_descriptor_tag() {
        let err = check_unsigned_size::<Krr>(2020).unwrap_err().to_string();
        assert_eq!(
            err,
            "Unsigned 'KROT' record size (2020 bytes) exceeds limit (2016 bytes)"
        );

        let err = Unsigned::<Krr>::from_bytes(&vec![0u8; 16])
            .unwrap_err()
            .to_string();
        assert_eq!(err, "No 'KROT' descriptor found in binary record");
    }
}
