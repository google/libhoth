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

//! Record compilation, partition size limit verification, and binary emission.

use crate::crypto::Algorithm;
use crate::crypto::KeyBytes;
use crate::crypto::KeyMaterial;
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::ensure;
use serde::Deserialize;
use serde::Serialize;
use std::path::Path;
use zerocopy::IntoBytes;

pub const MAX_IDENTITY_STRING_LEN: usize = 8;
pub const MAX_UNSIGNED_RECORD_SIZE_BYTES: usize = 2016;
pub const MAX_MAILBOX_RECORD_SIZE_BYTES: usize = 8192;

/// Rejects an unsigned record image that would not fit its flash slot.
fn check_unsigned_size(size: usize) -> Result<()> {
    ensure!(
        size <= MAX_UNSIGNED_RECORD_SIZE_BYTES,
        "Unsigned key rotation record size ({size} bytes) exceeds flash slot payload limit \
         ({MAX_UNSIGNED_RECORD_SIZE_BYTES} bytes)"
    );
    Ok(())
}

fn read_key(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("Failed to read key file {}", path.display()))
}

/// Key domain parsing helper.
pub fn parse_key_domain(s: &str) -> Result<crypto_rust_proto::KeyDomain> {
    Ok(match s {
        "prod" => crypto_rust_proto::KeyDomain::PayloadProd,
        "dev" => crypto_rust_proto::KeyDomain::PayloadDev,
        "test" => crypto_rust_proto::KeyDomain::PayloadTest,
        "bios_prod" => crypto_rust_proto::KeyDomain::BiosProd,
        "bios_dev" => crypto_rust_proto::KeyDomain::BiosDev,
        "rotr" => crypto_rust_proto::KeyDomain::Rotr,
        _ => bail!(
            "Unknown key domain '{s}'. Valid domains: prod, dev, test, bios_prod, bios_dev, rotr"
        ),
    })
}

/// Decodes a hex string that must denote exactly one SHA2-256 digest.
fn parse_digest32(label: &str, hex_str: &str) -> Result<[u8; 32]> {
    let raw = crate::crypto::from_hex(hex_str).with_context(|| format!("Invalid {label} hex"))?;
    raw.try_into()
        .map_err(|_| anyhow!("{label} '{hex_str}' must be 32 bytes (64 hex chars)"))
}

/// Validates an identity string and NUL-pads it to [`MAX_IDENTITY_STRING_LEN`].
fn identity_name(field: &str, s: &str) -> Result<String> {
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

fn default_key_domain() -> String {
    "prod".to_string()
}

/// JSON configuration for building a Key Rotation Record.
///
/// Every field is optional; omitted fields take their [`Default`] value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct KrrBuildConfig {
    pub version: u32,
    pub image_vendor: String,
    pub image_family: String,
    pub legacy_image_family: Option<u32>,
    pub fingerprints: Vec<KeyFingerprintConfig>,
    pub digests: Vec<String>,
}

impl Default for KrrBuildConfig {
    fn default() -> Self {
        Self {
            version: 1,
            image_vendor: "GOOGLE".to_string(),
            image_family: "EARLGREY".to_string(),
            legacy_image_family: None,
            fingerprints: Vec::new(),
            digests: Vec::new(),
        }
    }
}

/// Where the fingerprint bytes for a key come from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FingerprintSource {
    /// Path to a public key file; the fingerprint is derived from its contents.
    KeyFile(String),
    /// Paths to the two halves of a hybrid public key.
    KeyFiles(HybridKeyFiles),
    /// A precomputed SHA2-256 fingerprint, hex encoded.
    Fingerprint(String),
}

/// The EC and post-quantum public key files making up one hybrid key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridKeyFiles {
    pub ec: String,
    pub pq: String,
}

/// Configuration for an individual key fingerprint in JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyFingerprintConfig {
    #[serde(default = "default_key_domain")]
    pub key_domain: String,

    pub algorithm: Algorithm,

    #[serde(flatten)]
    pub source: FingerprintSource,
}

/// Fluent builder for constructing canonical OpenPRoT key rotation records (`KROT`).
#[derive(Debug)]
pub struct RecordBuilder {
    version: u32,
    image_vendor: String,
    image_family: String,
    legacy_image_family: Option<u32>,
    fingerprints: Vec<crypto_rust_proto::KeyFingerprint>,
    img_descriptor_digests: Vec<key_rotation_rust_proto::ImgDescriptorDigest>,
}

impl Default for RecordBuilder {
    fn default() -> Self {
        // Defaults live in exactly one place: `KrrBuildConfig::default()`.
        let config = KrrBuildConfig::default();
        Self {
            version: config.version,
            image_vendor: config.image_vendor,
            image_family: config.image_family,
            legacy_image_family: config.legacy_image_family,
            fingerprints: Vec::new(),
            img_descriptor_digests: Vec::new(),
        }
    }
}

impl RecordBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_config(config: &KrrBuildConfig) -> Result<Self> {
        let mut builder = Self::new()
            .version(config.version)
            .image_vendor(&config.image_vendor)
            .image_family(&config.image_family);

        if let Some(legacy) = config.legacy_image_family {
            builder = builder.legacy_image_family(legacy);
        }

        for fp_cfg in &config.fingerprints {
            let domain = parse_key_domain(&fp_cfg.key_domain)?;
            builder = match &fp_cfg.source {
                FingerprintSource::KeyFile(path) => {
                    builder.add_key_file(domain, fp_cfg.algorithm, path)?
                }
                FingerprintSource::KeyFiles(files) => {
                    builder.add_hybrid_key_files(domain, fp_cfg.algorithm, &files.ec, &files.pq)?
                }
                FingerprintSource::Fingerprint(hex_str) => builder.add_fingerprint(
                    domain,
                    fp_cfg.algorithm,
                    parse_digest32("Fingerprint", hex_str)?,
                ),
            };
        }

        for hex_str in &config.digests {
            builder = builder.add_image_digest(parse_digest32("Image digest", hex_str)?);
        }

        Ok(builder)
    }

    pub fn from_json(json_str: &str) -> Result<Self> {
        let config: KrrBuildConfig =
            serde_json::from_str(json_str).context("Failed to parse JSON config")?;
        Self::from_config(&config)
    }

    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self> {
        let p = path.as_ref();
        let content = std::fs::read_to_string(p)
            .with_context(|| format!("Failed to read {}", p.display()))?;
        Self::from_json(&content)
    }

    pub fn version(mut self, version: u32) -> Self {
        self.version = version;
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

    pub fn legacy_image_family(mut self, family: u32) -> Self {
        self.legacy_image_family = Some(family);
        self
    }

    /// Appends a precomputed SHA2-256 fingerprint for `algorithm` under `domain`.
    pub fn add_fingerprint(
        mut self,
        domain: crypto_rust_proto::KeyDomain,
        algorithm: Algorithm,
        digest: [u8; 32],
    ) -> Self {
        let mut fp = protobuf::proto!(crypto_rust_proto::KeyFingerprint { key_domain: domain });
        let digest = protobuf::proto!(crypto_rust_proto::Sha2_256Digest {
            data: digest.to_vec()
        });
        match algorithm {
            Algorithm::P256 => fp.p256_mut().set_sha2_256(digest),
            Algorithm::Slhdsa => fp.slhdsa_mut().set_sha2_256(digest),
            Algorithm::Rsa2048 => fp.rsa2048_mut().set_sha2_256(digest),
            Algorithm::Rsa3072 => fp.rsa3072_mut().set_sha2_256(digest),
            Algorithm::Rsa4096 => fp.rsa4096_mut().set_sha2_256(digest),
            Algorithm::HybridP256Slhdsa => fp.hybrid_p256_slhdsa_mut().set_sha2_256(digest),
            Algorithm::Mldsa => fp.mldsa_mut().set_sha2_256(digest),
            Algorithm::HybridP256Mldsa => fp.hybrid_p256_mldsa_mut().set_sha2_256(digest),
        }
        self.fingerprints.push(fp);
        self
    }

    /// Fingerprints a public key held in memory and appends it.
    pub fn add_key_bytes(
        self,
        domain: crypto_rust_proto::KeyDomain,
        algorithm: Algorithm,
        key: KeyBytes<'_>,
    ) -> Result<Self> {
        let material = KeyMaterial::parse(algorithm, key)
            .with_context(|| format!("Invalid {algorithm:?} key"))?;
        Ok(self.add_fingerprint(domain, algorithm, material.fingerprint_sha256()))
    }

    /// Reads a public key file and appends its SHA2-256 fingerprint.
    pub fn add_key_file(
        self,
        domain: crypto_rust_proto::KeyDomain,
        algorithm: Algorithm,
        path: impl AsRef<Path>,
    ) -> Result<Self> {
        let content = read_key(path.as_ref())?;
        self.add_key_bytes(domain, algorithm, KeyBytes::Single(&content))
            .with_context(|| format!("Failed to fingerprint key file {}", path.as_ref().display()))
    }

    /// Reads the EC and PQ halves of a hybrid public key and appends its fingerprint.
    pub fn add_hybrid_key_files(
        self,
        domain: crypto_rust_proto::KeyDomain,
        algorithm: Algorithm,
        ec: impl AsRef<Path>,
        pq: impl AsRef<Path>,
    ) -> Result<Self> {
        let (ec_key, pq_key) = (read_key(ec.as_ref())?, read_key(pq.as_ref())?);
        let key = KeyBytes::Hybrid {
            ec: &ec_key,
            pq: &pq_key,
        };
        self.add_key_bytes(domain, algorithm, key).with_context(|| {
            format!(
                "Failed to fingerprint key files {} + {}",
                ec.as_ref().display(),
                pq.as_ref().display()
            )
        })
    }

    pub fn add_image_digest(mut self, digest: [u8; 32]) -> Self {
        let d = protobuf::proto!(key_rotation_rust_proto::ImgDescriptorDigest {
            sha2_256: crypto_rust_proto::Sha2_256Digest {
                data: digest.to_vec()
            }
        });
        self.img_descriptor_digests.push(d);
        self
    }

    pub fn build_unsigned(self) -> Result<UnsignedRecord> {
        ensure!(
            self.version != 0,
            "Record version must be > 0 (v0 rollback records are not supported)"
        );
        ensure!(
            !self.fingerprints.is_empty() || !self.img_descriptor_digests.is_empty(),
            "Key rotation record must contain at least one key fingerprint or image descriptor digest"
        );

        let vendor_name = identity_name("Image Vendor", &self.image_vendor)?;
        let family_name = identity_name("Image Family", &self.image_family)?;
        let mut desc = protobuf::proto!(key_rotation_rust_proto::Descriptor {
            version: self.version,
            image_vendor: identity_rust_proto::ImageVendor { name: vendor_name },
            image_family: identity_rust_proto::ImageFamily { name: family_name },
            fingerprint: self.fingerprints.into_iter(),
            img_descriptor_digest: self.img_descriptor_digests.into_iter(),
        });
        if let Some(family) = self.legacy_image_family {
            desc.set_legacy_image_family(protobuf::proto!(
                key_rotation_rust_proto::LegacyImageFamily { family }
            ));
        }

        let tlv_words = mutask_tlv_proto_conv::message_to_tlv(
            &key_rotation_rust_proto::__unstable::CONTRIB_OPENPROT_PROTO_KEY_ROTATION_DESCRIPTOR_INFO,
            &desc,
        )
        .context("Failed to convert protobuf record to TLV wire format")?;

        let tlv_bytes = tlv_words.as_bytes().to_vec();
        check_unsigned_size(tlv_bytes.len())?;

        Ok(UnsignedRecord(tlv_bytes))
    }
}

/// A validated unsigned key rotation record wire image (`KROT`).
#[derive(Debug, Clone)]
pub struct UnsignedRecord(Vec<u8>);

impl UnsignedRecord {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        check_unsigned_size(bytes.len())?;
        let tlv_data = mutask_tlv::TlvData::overlay_bytes(bytes)
            .map_err(|_| anyhow!("Unsigned record length must be 4-byte aligned"))?;
        let has_desc = tlv_data
            .iter::<proto::key_rotation::Descriptor>()
            .next()
            .is_some();
        ensure!(has_desc, "No 'KROT' descriptor found in binary record");
        Ok(Self(bytes.to_vec()))
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let p = path.as_ref();
        let bytes = std::fs::read(p).with_context(|| format!("Failed to read {}", p.display()))?;
        Self::from_bytes(&bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspect::inspect_file;

    /// Parses `bytes` as TLV and returns the contained `KROT` descriptor version.
    fn descriptor_version(bytes: &[u8]) -> u32 {
        mutask_tlv::TlvData::overlay_bytes(bytes)
            .expect("Invalid alignment")
            .iter::<proto::key_rotation::Descriptor>()
            .next()
            .expect("No descriptor")
            .data
            .version
    }

    #[test]
    fn test_record_builder_fluent_unsigned() {
        let unsigned = RecordBuilder::new()
            .version(2)
            .image_vendor("VNDR")
            .image_family("FAM")
            .add_fingerprint(
                crypto_rust_proto::KeyDomain::PayloadProd,
                Algorithm::P256,
                [0x42u8; 32],
            )
            .add_image_digest([0x99u8; 32])
            .build_unsigned()
            .expect("Failed to build unsigned record with RecordBuilder");

        assert!(unsigned.as_bytes().len() <= MAX_UNSIGNED_RECORD_SIZE_BYTES);
        assert_eq!(descriptor_version(unsigned.as_bytes()), 2);

        let report = inspect_file(unsigned.as_bytes()).unwrap();
        assert!(report.contains("Tag: 'KROT'"));
        assert!(report.contains("TLV Structure Tree:"));
    }

    #[test]
    fn test_record_too_large_rejected() {
        let mut builder = RecordBuilder::new()
            .image_vendor("VNDR")
            .image_family("FAM");
        for i in 0..70u8 {
            let mut d = [0u8; 32];
            d[0] = i;
            builder = builder.add_image_digest(d);
        }
        let err = builder.build_unsigned().unwrap_err().to_string();
        assert!(err.contains("exceeds flash slot payload limit"));
    }

    #[test]
    fn test_build_unsigned_validation() {
        let base = || {
            RecordBuilder::new().add_fingerprint(
                crypto_rust_proto::KeyDomain::PayloadProd,
                Algorithm::P256,
                [0x42u8; 32],
            )
        };

        // v0 rollback records are not representable.
        assert!(base().version(0).build_unsigned().is_err());

        // A record with no fingerprints and no digests carries no information.
        assert!(RecordBuilder::new().build_unsigned().is_err());

        // Identity strings are bounded and must be ASCII, so that the padded
        // proto string is exactly MAX_IDENTITY_STRING_LEN bytes on the wire.
        assert!(
            base()
                .image_vendor("TOOLONGVENDOR")
                .build_unsigned()
                .is_err()
        );
        assert!(base().image_family("é").build_unsigned().is_err());
    }

    #[test]
    fn test_from_bytes_rejects_bad_length_and_missing_descriptor() {
        // Not 4-byte aligned.
        assert!(UnsignedRecord::from_bytes(&[0u8; 15]).is_err());

        // Well-formed length, but contains no 'KROT' descriptor.
        assert!(UnsignedRecord::from_bytes(&[0u8; 16]).is_err());

        // Round-trips a real record.
        let unsigned = RecordBuilder::new()
            .add_fingerprint(
                crypto_rust_proto::KeyDomain::PayloadProd,
                Algorithm::P256,
                [0x42u8; 32],
            )
            .build_unsigned()
            .unwrap();
        let reparsed = UnsignedRecord::from_bytes(unsigned.as_bytes()).unwrap();
        assert_eq!(reparsed.as_bytes(), unsigned.as_bytes());
    }

    /// Every `KeyFingerprint` arm, with filler key bytes its parser accepts.
    fn all_algorithms() -> Vec<(Algorithm, Vec<u8>, Vec<u8>)> {
        let ec: Vec<u8> = (0u8..64).collect();
        let slh = vec![0x11u8; 32];
        let mldsa = vec![0x22u8; 1312];
        let rsa = |n: usize| match n {
            256 => crate::crypto::rsa_pkcs1_der::<256>(&[1, 0, 1]),
            384 => crate::crypto::rsa_pkcs1_der::<384>(&[1, 0, 1]),
            _ => crate::crypto::rsa_pkcs1_der::<512>(&[1, 0, 1]),
        };
        vec![
            (Algorithm::P256, ec.clone(), vec![]),
            (Algorithm::Slhdsa, slh.clone(), vec![]),
            (Algorithm::Rsa2048, rsa(256), vec![]),
            (Algorithm::Rsa3072, rsa(384), vec![]),
            (Algorithm::Rsa4096, rsa(512), vec![]),
            (Algorithm::HybridP256Slhdsa, ec.clone(), slh),
            (Algorithm::Mldsa, mldsa.clone(), vec![]),
            (Algorithm::HybridP256Mldsa, ec, mldsa),
        ]
    }

    /// Reads the single `KeyFingerprint` out of `bytes` the way the firmware
    /// does and reports which `key_type` arm it populates.
    fn fingerprint_arm(bytes: &[u8]) -> Algorithm {
        use proto::crypto::KeyFingerprintExt;
        use proto::crypto::KeyFingerprintKeyType as K;
        use proto::key_rotation::DescriptorExt;
        let desc = mutask_tlv::TlvData::overlay_bytes(bytes)
            .unwrap()
            .iter::<proto::key_rotation::Descriptor>()
            .next()
            .unwrap();
        let fp = desc.fingerprint().next().expect("no KFIP in record");
        match fp.key_type().expect("KFIP has no key_type arm") {
            K::P256(_) => Algorithm::P256,
            K::Slhdsa(_) => Algorithm::Slhdsa,
            K::Rsa2048(_) => Algorithm::Rsa2048,
            K::Rsa3072(_) => Algorithm::Rsa3072,
            K::Rsa4096(_) => Algorithm::Rsa4096,
            K::HybridP256Slhdsa(_) => Algorithm::HybridP256Slhdsa,
            K::Mldsa(_) => Algorithm::Mldsa,
            K::HybridP256Mldsa(_) => Algorithm::HybridP256Mldsa,
        }
    }

    #[test]
    fn test_add_key_bytes_populates_every_fingerprint_arm() {
        for (algorithm, key, pq) in all_algorithms() {
            let bytes = if pq.is_empty() {
                KeyBytes::Single(&key)
            } else {
                KeyBytes::Hybrid { ec: &key, pq: &pq }
            };
            let unsigned = RecordBuilder::new()
                .add_key_bytes(crypto_rust_proto::KeyDomain::PayloadProd, algorithm, bytes)
                .unwrap_or_else(|e| panic!("{algorithm:?}: {e}"))
                .build_unsigned()
                .unwrap();
            assert_eq!(fingerprint_arm(unsigned.as_bytes()), algorithm);
        }
    }

    #[test]
    fn test_add_key_bytes_rejects_a_bad_key() {
        let err = RecordBuilder::new()
            .add_key_bytes(
                crypto_rust_proto::KeyDomain::PayloadProd,
                Algorithm::P256,
                KeyBytes::Single(&[0u8; 8]),
            )
            .unwrap_err();
        assert!(err.to_string().contains("Invalid P256 key"), "{err:#}");
    }

    #[test]
    fn test_record_builder_from_json() {
        let json = r#"{
            "version": 2,
            "image_vendor": "CUSTOM",
            "image_family": "CHIP",
            "legacy_image_family": 42,
            "fingerprints": [
                {
                    "key_domain": "prod",
                    "algorithm": "p256",
                    "fingerprint": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                },
                {
                    "key_domain": "dev",
                    "algorithm": "mldsa",
                    "fingerprint": "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
                }
            ],
            "digests": [
                "6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80"
            ]
        }"#;
        let unsigned = RecordBuilder::from_json(json)
            .expect("Failed to parse JSON")
            .build_unsigned()
            .expect("Failed to build unsigned");

        assert_eq!(descriptor_version(unsigned.as_bytes()), 2);
        assert!(
            inspect_file(unsigned.as_bytes())
                .unwrap()
                .contains("Tag: 'KROT'")
        );
    }

    #[test]
    fn test_record_builder_from_json_defaults() {
        // Every field is optional; a bare fingerprint list is a valid config.
        let json = r#"{
            "fingerprints": [
                { "algorithm": "p256", "fingerprint": "0000000000000000000000000000000000000000000000000000000000000001" }
            ]
        }"#;
        let unsigned = RecordBuilder::from_json(json)
            .unwrap()
            .build_unsigned()
            .unwrap();
        assert_eq!(
            descriptor_version(unsigned.as_bytes()),
            KrrBuildConfig::default().version
        );
    }

    #[test]
    fn test_record_builder_from_json_errors() {
        let cases = [
            // Invalid JSON syntax.
            "{ invalid json }",
            // Unknown key domain.
            r#"{"fingerprints": [{ "key_domain": "nonexistent", "algorithm": "p256",
                "fingerprint": "0000000000000000000000000000000000000000000000000000000000000000" }]}"#,
            // Unknown algorithm.
            r#"{"fingerprints": [{ "algorithm": "rsa",
                "fingerprint": "0000000000000000000000000000000000000000000000000000000000000000" }]}"#,
            // Neither key_file nor fingerprint.
            r#"{"fingerprints": [{ "algorithm": "p256" }]}"#,
            // Invalid hex.
            r#"{"fingerprints": [{ "algorithm": "p256", "fingerprint": "not_hex" }]}"#,
            // Correct hex, wrong length.
            r#"{"fingerprints": [{ "algorithm": "p256", "fingerprint": "0102" }]}"#,
            // Invalid image digest.
            r#"{"digests": ["0102"]}"#,
        ];
        for json in cases {
            assert!(
                RecordBuilder::from_json(json).is_err(),
                "expected rejection of: {json}"
            );
        }
    }
}
