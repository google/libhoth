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

const KEY_DOMAINS: [(&str, crypto_rust_proto::KeyDomain); 6] = [
    ("prod", crypto_rust_proto::KeyDomain::PayloadProd),
    ("dev", crypto_rust_proto::KeyDomain::PayloadDev),
    ("test", crypto_rust_proto::KeyDomain::PayloadTest),
    ("bios_prod", crypto_rust_proto::KeyDomain::BiosProd),
    ("bios_dev", crypto_rust_proto::KeyDomain::BiosDev),
    ("rotr", crypto_rust_proto::KeyDomain::Rotr),
];

const TEST_KEY_DOMAINS: [crypto_rust_proto::KeyDomain; 3] = [
    crypto_rust_proto::KeyDomain::PayloadTest,
    crypto_rust_proto::KeyDomain::PayloadDev,
    crypto_rust_proto::KeyDomain::BiosDev,
];

/// Key domain parsing helper.
pub fn parse_key_domain(s: &str) -> Result<crypto_rust_proto::KeyDomain> {
    KEY_DOMAINS
        .iter()
        .find(|(name, _)| *name == s)
        .map(|(_, domain)| *domain)
        .with_context(|| {
            let valid: Vec<&str> = KEY_DOMAINS.iter().map(|(name, _)| *name).collect();
            format!(
                "Unknown key domain '{}'. Valid domains: {}",
                s,
                valid.join(", ")
            )
        })
}

/// The name an operator would have written for `domain`.
fn key_domain_name(domain: crypto_rust_proto::KeyDomain) -> &'static str {
    KEY_DOMAINS
        .iter()
        .find(|(_, d)| *d == domain)
        .map_or("unknown", |(name, _)| name)
}

/// Decodes a hex string that must denote exactly one SHA2-256 digest.
pub(crate) fn parse_digest32(label: &str, hex_str: &str) -> Result<[u8; 32]> {
    let raw = crate::crypto::from_hex(hex_str).with_context(|| format!("Invalid {label} hex"))?;
    raw.try_into()
        .map_err(|_| anyhow!("{label} '{hex_str}' must be 32 bytes (64 hex chars)"))
}

/// Fingerprints an in-memory public key the way the firmware would.
fn key_digest(algorithm: Algorithm, key: KeyBytes<'_>) -> Result<[u8; 32]> {
    KeyMaterial::parse(algorithm, key).map(|material| material.fingerprint_sha256())
}

fn read_key(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("Failed to read key file {}", path.display()))
}

fn key_file_digest(algorithm: Algorithm, path: &Path) -> Result<[u8; 32]> {
    key_digest(algorithm, KeyBytes::Single(&read_key(path)?))
        .with_context(|| format!("Invalid {algorithm:?} key in {}", path.display()))
}

fn hybrid_key_files_digest(algorithm: Algorithm, ec: &Path, pq: &Path) -> Result<[u8; 32]> {
    let (ec_key, pq_key) = (read_key(ec)?, read_key(pq)?);
    let key = KeyBytes::Hybrid {
        ec: &ec_key,
        pq: &pq_key,
    };
    key_digest(algorithm, key).with_context(|| {
        format!(
            "Invalid {algorithm:?} key in {} + {}",
            ec.display(),
            pq.display()
        )
    })
}

fn check_expected_fingerprint(
    key_domain: &str,
    algorithm: Algorithm,
    expected_hex: &str,
    actual: [u8; 32],
) -> Result<()> {
    let expected = parse_digest32("Expected fingerprint", expected_hex)?;
    ensure!(
        expected == actual,
        "Fingerprint mismatch for the {:?} key in domain '{}': config expects {}, the key hashes to {}",
        algorithm,
        key_domain,
        crate::crypto::to_hex(&expected),
        crate::crypto::to_hex(&actual)
    );
    Ok(())
}

/// The first item that repeats one already seen, if any.
fn first_duplicate<T: PartialEq>(items: &[T]) -> Option<&T> {
    (1..items.len())
        .find(|&i| items[..i].contains(&items[i]))
        .map(|i| &items[i])
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

    // Assumed hex encoding
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fingerprint {
    key_domain: crypto_rust_proto::KeyDomain,
    algorithm: Algorithm,
    digest: [u8; 32],
}

impl Fingerprint {
    fn to_proto(self) -> crypto_rust_proto::KeyFingerprint {
        let mut fp = protobuf::proto!(crypto_rust_proto::KeyFingerprint {
            key_domain: self.key_domain
        });
        let digest = protobuf::proto!(crypto_rust_proto::Sha2_256Digest {
            data: self.digest.to_vec()
        });
        match self.algorithm {
            Algorithm::P256 => fp.p256_mut().set_sha2_256(digest),
            Algorithm::Slhdsa => fp.slhdsa_mut().set_sha2_256(digest),
            Algorithm::Rsa2048 => fp.rsa2048_mut().set_sha2_256(digest),
            Algorithm::Rsa3072 => fp.rsa3072_mut().set_sha2_256(digest),
            Algorithm::Rsa4096 => fp.rsa4096_mut().set_sha2_256(digest),
            Algorithm::HybridP256Slhdsa => fp.hybrid_p256_slhdsa_mut().set_sha2_256(digest),
            Algorithm::Mldsa => fp.mldsa_mut().set_sha2_256(digest),
            Algorithm::HybridP256Mldsa => fp.hybrid_p256_mldsa_mut().set_sha2_256(digest),
        }
        fp
    }
}

#[derive(Debug)]
pub struct RecordBuilder {
    version: u32,
    image_vendor: String,
    image_family: String,
    legacy_image_family: Option<u32>,
    fingerprints: Vec<Fingerprint>,
    img_descriptor_digests: Vec<[u8; 32]>,
    allow_test_keys: bool,
}

impl Default for RecordBuilder {
    fn default() -> Self {
        let config = KrrBuildConfig::default();
        Self {
            version: config.version,
            image_vendor: config.image_vendor,
            image_family: config.image_family,
            legacy_image_family: config.legacy_image_family,
            fingerprints: Vec::new(),
            img_descriptor_digests: Vec::new(),
            allow_test_keys: false,
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
            let algorithm = fp_cfg.algorithm;
            let digest = match &fp_cfg.source {
                FingerprintSource::KeyFile(path) => key_file_digest(algorithm, Path::new(path))?,
                FingerprintSource::KeyFiles(files) => {
                    hybrid_key_files_digest(algorithm, Path::new(&files.ec), Path::new(&files.pq))?
                }
                FingerprintSource::Fingerprint(hex_str) => {
                    ensure!(
                        fp_cfg.expected_fingerprint.is_none(),
                        "'expected_fingerprint' has nothing to check in the '{}' {:?} entry: \
                         it already states the fingerprint instead of naming a key file",
                        fp_cfg.key_domain,
                        algorithm
                    );
                    parse_digest32("Fingerprint", hex_str)?
                }
            };
            if let Some(expected) = &fp_cfg.expected_fingerprint {
                check_expected_fingerprint(&fp_cfg.key_domain, algorithm, expected, digest)?;
            }
            builder = builder.add_fingerprint(domain, algorithm, digest);
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

    pub fn allow_test_keys(mut self, allow: bool) -> Self {
        self.allow_test_keys = allow;
        self
    }

    /// Appends a precomputed SHA2-256 fingerprint for `algorithm` under `domain`.
    pub fn add_fingerprint(
        mut self,
        domain: crypto_rust_proto::KeyDomain,
        algorithm: Algorithm,
        digest: [u8; 32],
    ) -> Self {
        self.fingerprints.push(Fingerprint {
            key_domain: domain,
            algorithm,
            digest,
        });
        self
    }

    /// Fingerprints a public key held in memory and appends it.
    pub fn add_key_bytes(
        self,
        domain: crypto_rust_proto::KeyDomain,
        algorithm: Algorithm,
        key: KeyBytes<'_>,
    ) -> Result<Self> {
        let digest =
            key_digest(algorithm, key).with_context(|| format!("Invalid {algorithm:?} key"))?;
        Ok(self.add_fingerprint(domain, algorithm, digest))
    }

    pub fn add_image_digest(mut self, digest: [u8; 32]) -> Self {
        self.img_descriptor_digests.push(digest);
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

        if !self.allow_test_keys
            && let Some(fp) = self
                .fingerprints
                .iter()
                .find(|fp| TEST_KEY_DOMAINS.contains(&fp.key_domain))
        {
            bail!(
                "Key domain '{}' holds test or development keys; pass --allow-test-keys to rotate to them",
                key_domain_name(fp.key_domain)
            );
        }

        // A repeated entry is always an editing accident: the record would say
        // the same thing twice and waste the flash slot doing it.
        if let Some(fp) = first_duplicate(&self.fingerprints) {
            bail!(
                "Duplicate {:?} key fingerprint in domain '{}': {}",
                fp.algorithm,
                key_domain_name(fp.key_domain),
                crate::crypto::to_hex(&fp.digest)
            );
        }
        if let Some(digest) = first_duplicate(&self.img_descriptor_digests) {
            bail!(
                "Duplicate image descriptor digest: {}",
                crate::crypto::to_hex(digest)
            );
        }

        let vendor_name = identity_name("Image Vendor", &self.image_vendor)?;
        let family_name = identity_name("Image Family", &self.image_family)?;
        let mut desc = protobuf::proto!(key_rotation_rust_proto::Descriptor {
            version: self.version,
            image_vendor: identity_rust_proto::ImageVendor { name: vendor_name },
            image_family: identity_rust_proto::ImageFamily { name: family_name },
            fingerprint: self.fingerprints.iter().map(|fp| fp.to_proto()),
            img_descriptor_digest: self.img_descriptor_digests.iter().map(|digest| {
                protobuf::proto!(key_rotation_rust_proto::ImgDescriptorDigest {
                    sha2_256: crypto_rust_proto::Sha2_256Digest {
                        data: digest.to_vec()
                    }
                })
            }),
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
            // The config names the `dev` domain, so it needs the opt-in.
            .allow_test_keys(true)
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
            // A pinned fingerprint with no key to check it against.
            r#"{"fingerprints": [{ "algorithm": "p256",
                "fingerprint": "0000000000000000000000000000000000000000000000000000000000000000",
                "expected_fingerprint": "0000000000000000000000000000000000000000000000000000000000000000" }]}"#,
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

    #[test]
    fn test_test_key_domains_need_the_flag() {
        use crypto_rust_proto::KeyDomain;
        let record =
            |domain| RecordBuilder::new().add_fingerprint(domain, Algorithm::P256, [0x42u8; 32]);

        for domain in [
            KeyDomain::PayloadTest,
            KeyDomain::PayloadDev,
            KeyDomain::BiosDev,
        ] {
            let err = record(domain)
                .build_unsigned()
                .expect_err("a test domain must not build by default");
            assert!(err.to_string().contains("--allow-test-keys"), "{err:#}");
            assert!(
                record(domain)
                    .allow_test_keys(true)
                    .build_unsigned()
                    .is_ok()
            );
        }

        // Production domains never need the opt-in.
        for domain in [KeyDomain::PayloadProd, KeyDomain::BiosProd, KeyDomain::Rotr] {
            assert!(record(domain).build_unsigned().is_ok());
        }
    }

    #[test]
    fn test_duplicate_entries_rejected() {
        use crypto_rust_proto::KeyDomain;
        let digest = [0x42u8; 32];
        let base = || {
            RecordBuilder::new().add_fingerprint(KeyDomain::PayloadProd, Algorithm::P256, digest)
        };

        let err = base()
            .add_fingerprint(KeyDomain::PayloadProd, Algorithm::P256, digest)
            .build_unsigned()
            .expect_err("the same fingerprint twice says nothing new");
        assert!(
            err.to_string().contains("Duplicate P256 key fingerprint"),
            "{err}"
        );

        // One key can legitimately appear under two domains or two algorithms.
        assert!(
            base()
                .add_fingerprint(KeyDomain::BiosProd, Algorithm::P256, digest)
                .add_fingerprint(KeyDomain::PayloadProd, Algorithm::Mldsa, digest)
                .build_unsigned()
                .is_ok()
        );

        let err = base()
            .add_image_digest(digest)
            .add_image_digest(digest)
            .build_unsigned()
            .expect_err("the same image digest twice says nothing new");
        assert!(
            err.to_string()
                .contains("Duplicate image descriptor digest"),
            "{err}"
        );
    }
}
