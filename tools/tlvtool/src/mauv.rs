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

//! Minimum acceptable update version (MAUV) record compilation.

use crate::record::DEFAULT_IMAGE_FAMILY;
use crate::record::DEFAULT_IMAGE_VENDOR;
use crate::record::RecordKind;
use crate::record::Unsigned;
use crate::record::identity_name;
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use openprot_tlv::TlvHeader;
use serde::Deserialize;
use serde::Serialize;
use std::path::Path;
use zerocopy::IntoBytes;

/// Largest signed MAUV record the device mailbox accepts.
pub const MAX_MAUV_SIGNED_RECORD_SIZE_BYTES: usize = 6144;

/// The MAUV record: a `MAUV` descriptor, signed as a `MVSD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mauv;

impl RecordKind for Mauv {
    type Descriptor = proto::mauv::Descriptor;
    type SignedDescriptor = proto::mauv::SignedDescriptor;
    // The record is not stored on the device, so the only bound on the
    // unsigned descriptor is that it fits in the signed one.
    const MAX_UNSIGNED_BYTES: usize = MAX_MAUV_SIGNED_RECORD_SIZE_BYTES - size_of::<TlvHeader>();
    const MAX_SIGNED_BYTES: usize = MAX_MAUV_SIGNED_RECORD_SIZE_BYTES;
}

/// A validated unsigned MAUV record wire image (`MAUV`).
pub type UnsignedMauvRecord = Unsigned<Mauv>;

fn default_image_vendor() -> String {
    DEFAULT_IMAGE_VENDOR.to_string()
}

fn default_image_family() -> String {
    DEFAULT_IMAGE_FAMILY.to_string()
}

/// JSON configuration for `mauv build`.
///
/// Unknown keys are rejected: a misspelled key would otherwise silently fall
/// back to its default, and the floor a MAUV record sets is permanent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MauvBuildConfig {
    /// The new minimum acceptable BL0 `security_version`. Required.
    pub min_security_version_bl0: u32,
    #[serde(default = "default_image_vendor")]
    pub image_vendor: String,
    #[serde(default = "default_image_family")]
    pub image_family: String,
}

/// Fluent builder for an unsigned MAUV record.
#[derive(Debug, Clone)]
pub struct MauvRecordBuilder {
    min_security_version_bl0: u32,
    image_vendor: String,
    image_family: String,
}

impl Default for MauvRecordBuilder {
    fn default() -> Self {
        Self {
            // Deliberately invalid: the floor has no sensible default and
            // `build_unsigned` rejects 0 until the caller sets one.
            min_security_version_bl0: 0,
            image_vendor: default_image_vendor(),
            image_family: default_image_family(),
        }
    }
}

impl MauvRecordBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_config(config: &MauvBuildConfig) -> Self {
        Self::new()
            .min_security_version_bl0(config.min_security_version_bl0)
            .image_vendor(&config.image_vendor)
            .image_family(&config.image_family)
    }

    pub fn from_json(json_str: &str) -> Result<Self> {
        let config: MauvBuildConfig =
            serde_json::from_str(json_str).context("Failed to parse JSON config")?;
        Ok(Self::from_config(&config))
    }

    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self> {
        let p = path.as_ref();
        let content = std::fs::read_to_string(p)
            .with_context(|| format!("Failed to read {}", p.display()))?;
        Self::from_json(&content)
    }

    pub fn min_security_version_bl0(mut self, version: u32) -> Self {
        self.min_security_version_bl0 = version;
        self
    }

    pub fn image_vendor(mut self, vendor: impl Into<String>) -> Self {
        self.image_vendor = vendor.into();
        self
    }

    pub fn image_family(mut self, family: impl Into<String>) -> Self {
        self.image_family = family.into();
        self
    }

    pub fn build_unsigned(self) -> Result<UnsignedMauvRecord> {
        ensure!(
            self.min_security_version_bl0 != 0,
            "min_security_version_bl0 must be > 0 (every image already satisfies a floor of 0)"
        );
        let vendor_name = identity_name("Image Vendor", &self.image_vendor)?;
        let family_name = identity_name("Image Family", &self.image_family)?;

        let desc = protobuf::proto!(mauv_rust_proto::Descriptor {
            min_security_version_bl0: self.min_security_version_bl0,
            image_vendor: identity_rust_proto::ImageVendor { name: vendor_name },
            image_family: identity_rust_proto::ImageFamily { name: family_name },
        });

        let tlv_words = openprot_tlv_proto_conv::message_to_tlv(
            &mauv_rust_proto::__unstable::SHARED_OPENPROT_PROTO_MAUV_DESCRIPTOR_INFO,
            &desc,
        )
        .context("Failed to convert protobuf record to TLV wire format")?;

        UnsignedMauvRecord::from_bytes(tlv_words.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Algorithm;
    use crate::inspect::inspect_file;
    use crate::krr::KrrRecordBuilder;
    use openprot_tlv::TlvData;

    /// The complete 28-byte wire image for N = 7, GOOGLE / EARLGREY.
    const GOLDEN_N7: [u8; 28] = [
        b'M', b'A', b'U', b'V', // tag
        0x05, 0x00, // word_len: 5 words = 20 payload bytes
        0x00, // reserved
        0x00, // flags (no padding)
        0x07, 0x00, 0x00, 0x00, // min_security_version_bl0 = 7 (little-endian)
        b'G', b'O', b'O', b'G', b'L', b'E', 0, 0, // image_vendor
        b'E', b'A', b'R', b'L', b'G', b'R', b'E', b'Y', // image_family
    ];

    /// Parses `bytes` as TLV and returns the `MAUV` descriptor's fixed fields.
    fn descriptor(bytes: &[u8]) -> proto::mauv::Descriptor {
        *TlvData::overlay_bytes(bytes)
            .expect("Invalid alignment")
            .iter::<proto::mauv::Descriptor>()
            .next()
            .expect("No MAUV descriptor")
            .data
    }

    fn assert_err_contains<T: core::fmt::Debug>(result: Result<T>, needle: &str) {
        let err = format!("{:#}", result.expect_err("expected an error"));
        assert!(err.contains(needle), "'{needle}' not in: {err}");
    }

    #[test]
    fn test_build_matches_golden_bytes() {
        let unsigned = MauvRecordBuilder::new()
            .min_security_version_bl0(7)
            .build_unsigned()
            .unwrap();
        assert_eq!(unsigned.as_bytes(), GOLDEN_N7);
    }

    #[test]
    fn test_fluent_build_round_trips() {
        let unsigned = MauvRecordBuilder::new()
            .min_security_version_bl0(0x1234_5678)
            .image_vendor("VNDR")
            .image_family("FAM")
            .build_unsigned()
            .unwrap();

        let desc = descriptor(unsigned.as_bytes());
        assert_eq!(desc.min_security_version_bl0, 0x1234_5678);
        assert_eq!(&desc.image_vendor.name, b"VNDR\0\0\0\0");
        assert_eq!(&desc.image_family.name, b"FAM\0\0\0\0\0");

        let report = inspect_file(unsigned.as_bytes()).unwrap();
        assert!(report.contains("Tag: 'MAUV'"), "{report}");
    }

    #[test]
    fn test_build_unsigned_validation() {
        let base = || MauvRecordBuilder::new().min_security_version_bl0(1);
        assert!(base().build_unsigned().is_ok());

        // The floor must be set, and 0 raises nothing.
        assert_err_contains(MauvRecordBuilder::new().build_unsigned(), "must be > 0");

        // Identity strings are bounded and must be ASCII.
        assert_err_contains(
            base().image_vendor("TOOLONGVENDOR").build_unsigned(),
            "exceeds maximum limit",
        );
        assert_err_contains(base().image_family("é").build_unsigned(), "must be ASCII");

        // u32::MAX is representable on the wire.
        let max = base()
            .min_security_version_bl0(u32::MAX)
            .build_unsigned()
            .unwrap();
        assert_eq!(
            descriptor(max.as_bytes()).min_security_version_bl0,
            u32::MAX
        );
    }

    #[test]
    fn test_from_json() {
        let json = r#"{
            "min_security_version_bl0": 42,
            "image_vendor": "CUSTOM",
            "image_family": "CHIP"
        }"#;
        let unsigned = MauvRecordBuilder::from_json(json)
            .unwrap()
            .build_unsigned()
            .unwrap();
        let desc = descriptor(unsigned.as_bytes());
        assert_eq!(desc.min_security_version_bl0, 42);
        assert_eq!(&desc.image_vendor.name, b"CUSTOM\0\0");
        assert_eq!(&desc.image_family.name, b"CHIP\0\0\0\0");
    }

    #[test]
    fn test_from_json_defaults() {
        let unsigned = MauvRecordBuilder::from_json(r#"{ "min_security_version_bl0": 7 }"#)
            .unwrap()
            .build_unsigned()
            .unwrap();
        assert_eq!(unsigned.as_bytes(), GOLDEN_N7);
    }

    #[test]
    fn test_from_json_errors() {
        let cases = [
            // Invalid JSON syntax.
            ("{ invalid json }", "Failed to parse JSON config"),
            // The floor is required.
            (r#"{ "image_vendor": "GOOGLE" }"#, "missing field"),
            // A typo must not silently fall back to a default.
            (
                r#"{ "min_security_version_bl0": 3, "image_famliy": "OTHER" }"#,
                "unknown field",
            ),
            // Out of the u32 range, or the wrong type.
            (r#"{ "min_security_version_bl0": -1 }"#, "invalid value"),
            (
                r#"{ "min_security_version_bl0": 4294967296 }"#,
                "invalid value",
            ),
            (r#"{ "min_security_version_bl0": "3" }"#, "invalid type"),
        ];
        for (json, needle) in cases {
            assert_err_contains(MauvRecordBuilder::from_json(json), needle);
        }

        // N = 0 parses, but is rejected when the record is built.
        assert_err_contains(
            MauvRecordBuilder::from_json(r#"{ "min_security_version_bl0": 0 }"#)
                .unwrap()
                .build_unsigned(),
            "must be > 0",
        );
    }

    #[test]
    fn test_from_json_file_missing() {
        assert_err_contains(
            MauvRecordBuilder::from_json_file("/nonexistent/mauv.json"),
            "Failed to read",
        );
    }

    #[test]
    fn test_unsigned_from_bytes() {
        // Round-trips a built record.
        let built = MauvRecordBuilder::new()
            .min_security_version_bl0(9)
            .build_unsigned()
            .unwrap();
        let reparsed = UnsignedMauvRecord::from_bytes(built.as_bytes()).unwrap();
        assert_eq!(reparsed.as_bytes(), built.as_bytes());

        assert_err_contains(
            UnsignedMauvRecord::from_bytes(&vec![0u8; 15]),
            "4-byte aligned",
        );
        assert_err_contains(
            UnsignedMauvRecord::from_bytes(&vec![0u8; Mauv::MAX_UNSIGNED_BYTES + 4]),
            "exceeds limit (6136 bytes)",
        );

        // A key rotation record is not a MAUV record.
        let krot = KrrRecordBuilder::new()
            .add_fingerprint(
                crypto_rust_proto::KeyDomain::PayloadProd,
                Algorithm::P256,
                [0x42u8; 32],
            )
            .build_unsigned()
            .unwrap();
        assert_err_contains(
            UnsignedMauvRecord::from_bytes(krot.as_bytes()),
            "No 'MAUV' descriptor",
        );
    }
}
