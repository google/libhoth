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

//! Offline signature attachment and byte-identical container integration for `krr sign`.

use crate::builder::MAX_MAILBOX_RECORD_SIZE_BYTES;
use crate::builder::UnsignedRecord;
use crate::crypto::le_bytes;
use crate::crypto::le_words;
use crate::crypto::parse_mldsa44_public_key;
use crate::crypto::parse_mldsa44_signature;
use crate::crypto::parse_p256_public_key;
use crate::crypto::parse_p256_signature;
use crate::crypto::to_hex;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::ensure;
use crypto_tlv::HybridP256MlDsa44PublicMaterial;
use mutask_fingerprints::FingerprintableKey;
use mutask_tlv::TlvBuilder;
use mutask_tlv::TlvData;
use mutask_tlv::TlvHeader;
use mutask_tlv::TlvItem;
use mutask_tlv::TlvObject;
use std::path::Path;

/// The four offline artefacts that make up one hybrid P-256 + ML-DSA-44 signature.
///
/// Generic over the representation so that the same field names describe the
/// inputs as paths on the way in and as bytes once loaded. Naming the fields
/// makes the otherwise interchangeable blobs impossible to transpose at a call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HybridMaterial<T> {
    pub ec_public_key: T,
    pub mldsa_public_key: T,
    pub ec_signature: T,
    pub mldsa_signature: T,
}

/// [`HybridMaterial`] as paths on disk.
pub type HybridSignatureFiles<'a> = HybridMaterial<&'a Path>;

impl HybridSignatureFiles<'_> {
    /// Loads the contents of all four files.
    pub fn read(&self) -> Result<HybridMaterial<Vec<u8>>> {
        let read = |label: &str, path: &Path| {
            std::fs::read(path)
                .with_context(|| format!("Failed to read {label} from {}", path.display()))
        };
        Ok(HybridMaterial {
            ec_public_key: read("EC public key", self.ec_public_key)?,
            mldsa_public_key: read("ML-DSA public key", self.mldsa_public_key)?,
            ec_signature: read("EC signature", self.ec_signature)?,
            mldsa_signature: read("ML-DSA signature", self.mldsa_signature)?,
        })
    }
}

/// Builds a `SIGC` container for a hybrid signature, alongside the hex OTP
/// fingerprint of the signing authority it names.
fn build_hybrid_sigc<T: AsRef<[u8]>>(
    key_domain: crypto_rust_proto::KeyDomain,
    material: &HybridMaterial<T>,
) -> Result<(crypto_rust_proto::SignatureContainer, String)> {
    let (x, y) = parse_p256_public_key(material.ec_public_key.as_ref())
        .context("Failed to parse EC public key")?;
    let mldsa_pk = parse_mldsa44_public_key(material.mldsa_public_key.as_ref())
        .context("Failed to parse ML-DSA public key")?;
    let (r, s) = parse_p256_signature(material.ec_signature.as_ref())
        .context("Failed to parse EC signature")?;
    let mldsa_sig = parse_mldsa44_signature(material.mldsa_signature.as_ref())
        .context("Failed to parse ML-DSA signature")?;

    // The OTP value pins exactly the key material the device will see, so it
    // is computed by the firmware's fingerprint over the little-endian words.
    let authority = HybridP256MlDsa44PublicMaterial {
        x: le_words(&x),
        y: le_words(&y),
        mldsa: mldsa_pk,
    };
    let otp_fp_hex = to_hex(&authority.fingerprint_sha256());

    let sigc = protobuf::proto!(crypto_rust_proto::SignatureContainer {
        public_key: crypto_rust_proto::PublicKey {
            key_domain: key_domain,
            hybrid_p256_mldsa: crypto_rust_proto::HybridP256MlDsa44PublicMaterial {
                x: le_bytes(&x).to_vec(),
                y: le_bytes(&y).to_vec(),
                mldsa: mldsa_pk.to_vec(),
            }
        },
        signature: crypto_rust_proto::Signature {
            hybrid_p256_mldsa: crypto_rust_proto::HybridP256MlDsa44Signature {
                r: le_bytes(&r).to_vec(),
                s: le_bytes(&s).to_vec(),
                mldsa: mldsa_sig.to_vec(),
            }
        }
    });

    Ok((sigc, otp_fp_hex))
}

/// Views `data` as the single `T` container it is expected to hold.
fn root_container<T: TlvObject>(data: &TlvData) -> Result<TlvItem<'_, T>> {
    data.iter::<T>().next().with_context(|| {
        format!(
            "TLV image is missing its '{}' root container",
            String::from_utf8_lossy(&T::TAG.to_le_bytes())
        )
    })
}

/// Fluent builder for integrating offline signatures into `SignedDescriptor` (`KRSD`).
#[derive(Debug, Clone)]
pub struct SignedRecordBuilder {
    unsigned: UnsignedRecord,
    signatures: Vec<crypto_rust_proto::SignatureContainer>,
    otp_fingerprint: Option<String>,
}

impl SignedRecordBuilder {
    pub fn new(unsigned: UnsignedRecord) -> Self {
        Self {
            unsigned,
            signatures: Vec::new(),
            otp_fingerprint: None,
        }
    }

    pub fn from_unsigned_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self::new(UnsignedRecord::from_bytes(bytes)?))
    }

    pub fn from_unsigned_file(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self::new(UnsignedRecord::from_file(path)?))
    }

    pub fn add_signature_container(mut self, sigc: crypto_rust_proto::SignatureContainer) -> Self {
        self.signatures.push(sigc);
        self
    }

    pub fn add_hybrid_signature<T: AsRef<[u8]>>(
        mut self,
        key_domain: crypto_rust_proto::KeyDomain,
        material: &HybridMaterial<T>,
    ) -> Result<Self> {
        let (sigc, otp_fp_hex) = build_hybrid_sigc(key_domain, material)?;
        // The first signing authority is the one reported back to the operator.
        self.otp_fingerprint.get_or_insert(otp_fp_hex);
        self.signatures.push(sigc);
        Ok(self)
    }

    pub fn add_hybrid_signature_files(
        self,
        key_domain: crypto_rust_proto::KeyDomain,
        files: HybridSignatureFiles<'_>,
    ) -> Result<Self> {
        let material = files.read()?;
        self.add_hybrid_signature(key_domain, &material)
    }

    /// Wraps the frozen `KROT` record and every encoded `SIGC` in a `KRSD` container.
    ///
    /// Children are copied verbatim by [`TlvBuilder::add_copy`], so unknown sub-TLVs
    /// in the unsigned record survive signing byte-for-byte.
    pub fn build(self) -> Result<SignedRecord> {
        ensure!(
            !self.signatures.is_empty(),
            "At least one signature container must be provided"
        );

        // Encode every `SIGC` up front: the TLV builder copies out of these
        // buffers, so they have to outlive it.
        let sigc_words = self
            .signatures
            .iter()
            .map(|sigc| {
                mutask_tlv_proto_conv::message_to_tlv(
                    &crypto_rust_proto::__unstable::CONTRIB_OPENPROT_PROTO_CRYPTO_DESCRIPTOR_INFO,
                    sigc,
                )
                .context("Failed to convert signature container to TLV wire format")
            })
            .collect::<Result<Vec<_>>>()?;

        let unsigned_bytes = self.unsigned.as_bytes();
        let unsigned_size = unsigned_bytes.len();
        let unsigned_data = TlvData::overlay_bytes(unsigned_bytes)
            .map_err(|_| anyhow!("Unsigned record has invalid alignment or length"))?;
        let krot_item = root_container::<proto::key_rotation::Descriptor>(unsigned_data)?;

        // `add_copy` only reports *that* the destination ran out of room, so work
        // out the size the operator needs to see before handing the buffer over.
        let sigc_size: usize = sigc_words.iter().map(|w| w.len() * size_of::<u32>()).sum();
        let total_size = size_of::<TlvHeader>() + unsigned_size + sigc_size;
        let too_large = || {
            anyhow!(
                "Signed record size ({total_size} bytes) exceeds mailbox capacity \
                 ({MAX_MAILBOX_RECORD_SIZE_BYTES} bytes)"
            )
        };

        let mut buf = vec![0u32; MAX_MAILBOX_RECORD_SIZE_BYTES / 4];
        let (_, mut krsd) = TlvBuilder::new::<proto::key_rotation::SignedDescriptor>(&mut buf)
            .map_err(|_| too_large())?;

        krsd.add_copy(&krot_item).map_err(|_| too_large())?;

        for words in &sigc_words {
            let sigc =
                root_container::<proto::crypto::SignatureContainer>(TlvData::overlay(words))?;
            krsd.add_copy(&sigc).map_err(|_| too_large())?;
        }

        let tlv_bytes = krsd
            .finish()
            .into_bytes(&buf)
            .map_err(|_| too_large())?
            .to_vec();

        // Signing is only meaningful if what we shipped is what was signed.
        let embedded =
            tlv_bytes.get(size_of::<TlvHeader>()..size_of::<TlvHeader>() + unsigned_size);
        ensure!(
            embedded == Some(self.unsigned.as_bytes()),
            "Embedded unsigned record is not byte-identical to the signed input; \
             the attached signatures would not verify"
        );

        Ok(SignedRecord {
            tlv_bytes,
            unsigned_size,
            otp_fingerprint: self.otp_fingerprint,
        })
    }
}

/// A validated signed key rotation record wire image (`KRSD`).
#[derive(Debug, Clone)]
pub struct SignedRecord {
    tlv_bytes: Vec<u8>,
    unsigned_size: usize,
    otp_fingerprint: Option<String>,
}

impl SignedRecord {
    pub fn as_bytes(&self) -> &[u8] {
        &self.tlv_bytes
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.tlv_bytes
    }

    /// Size of the embedded unsigned `KROT` record, in bytes.
    pub fn unsigned_size(&self) -> usize {
        self.unsigned_size
    }

    /// Size of the complete `KRSD` wire image, in bytes.
    pub fn signed_size(&self) -> usize {
        self.tlv_bytes.len()
    }

    /// Hex OTP fingerprint of the first hybrid signing authority, if one was added.
    pub fn otp_fingerprint(&self) -> Option<&str> {
        self.otp_fingerprint.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::RecordBuilder;
    use crate::crypto::Algorithm;
    use crate::crypto::MLDSA44_PUBLIC_KEY_LEN;
    use crate::crypto::MLDSA44_SIGNATURE_LEN;
    use crate::crypto::P256_SIGNATURE_LEN;
    use zerocopy::IntoBytes;

    /// Filler P-256 public key: `x = [1u8; 32]`, `y = [2u8; 32]`.
    const EC_PUBLIC_KEY: [u8; 64] = {
        let mut key = [1u8; 64];
        let mut i = 32;
        while i < 64 {
            key[i] = 2;
            i += 1;
        }
        key
    };

    /// A complete set of hybrid signing inputs, using filler key material.
    const MATERIAL: HybridMaterial<&[u8]> = HybridMaterial {
        ec_public_key: &EC_PUBLIC_KEY,
        mldsa_public_key: &[3u8; MLDSA44_PUBLIC_KEY_LEN],
        ec_signature: &[1u8; P256_SIGNATURE_LEN],
        mldsa_signature: &[2u8; MLDSA44_SIGNATURE_LEN],
    };

    /// `SHA2-256([1u8; 32] || [2u8; 32] || [3u8; 1312])`, for [`MATERIAL`].
    ///
    /// Pinned rather than computed: this is the value provisioned into RoT OTP
    /// to name the rotation authority, so a test must not derive it with the
    /// same function it is checking. The filler coordinates are byte-symmetric,
    /// so the value is the same whether hashed big- or little-endian; see
    /// `test_sigc_carries_little_endian_scalars` for the byte order itself.
    /// Verified against an independent SHA2-256:
    ///
    /// ```text
    /// python3 -c "import hashlib; print(hashlib.sha256(
    ///     bytes([1]*32 + [2]*32 + [3]*1312)).hexdigest())"
    /// ```
    const EXPECTED_OTP_FP: &str =
        "450b9724056546773e54021936e3d34962b8d6628c0fd3801e1e6fde79342682";

    /// Whether `needle` occurs contiguously inside `haystack`.
    fn contains_slice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn test_sigc_carries_little_endian_scalars() {
        let x: [u8; 32] = core::array::from_fn(|i| 0x10 + i as u8);
        let y: [u8; 32] = core::array::from_fn(|i| 0x50 + i as u8);
        let r: [u8; 32] = core::array::from_fn(|i| 0x90 + i as u8);
        let s: [u8; 32] = core::array::from_fn(|i| 0xc0 + i as u8);
        let mut ec_key = x.to_vec();
        ec_key.extend_from_slice(&y);
        let mut ec_sig = r.to_vec();
        ec_sig.extend_from_slice(&s);
        let material = HybridMaterial {
            ec_public_key: ec_key.as_slice(),
            mldsa_public_key: &[3u8; MLDSA44_PUBLIC_KEY_LEN],
            ec_signature: ec_sig.as_slice(),
            mldsa_signature: &[2u8; MLDSA44_SIGNATURE_LEN],
        };

        let (sigc, _) = build_hybrid_sigc(crypto_rust_proto::KeyDomain::Rotr, &material).unwrap();
        let wire = mutask_tlv_proto_conv::message_to_tlv(
            &crypto_rust_proto::__unstable::CONTRIB_OPENPROT_PROTO_CRYPTO_DESCRIPTOR_INFO,
            &sigc,
        )
        .unwrap();
        let wire = wire.as_bytes();

        // Every 256-bit integer is on the wire least-significant byte first,
        // and never in the big-endian order it was parsed from.
        for be in [x, y, r, s] {
            assert!(
                contains_slice(wire, &le_bytes(&be)),
                "{be:02x?} not LE on the wire"
            );
            assert!(
                !contains_slice(wire, &be),
                "{be:02x?} leaked as BE onto the wire"
            );
        }
    }

    /// Asserts that `bytes` inspect as a `KRSD` wrapping a `KROT` and a `SIGC`.
    fn assert_signed_shape(bytes: &[u8]) {
        let report = crate::inspect::inspect_file(bytes).unwrap();
        for tag in ["KRSD", "KROT", "SIGC"] {
            assert!(
                report.contains(&format!("Tag: '{}'", tag)),
                "expected a '{}' container in:\n{}",
                tag,
                report
            );
        }
    }

    #[test]
    fn test_hybrid_signature_integration() {
        let unsigned = RecordBuilder::new()
            .version(3)
            .image_vendor("VNDR")
            .image_family("FAM")
            .add_fingerprint(
                crypto_rust_proto::KeyDomain::PayloadProd,
                Algorithm::Mldsa,
                [0x11u8; 32],
            )
            .build_unsigned()
            .unwrap();

        let signed = SignedRecordBuilder::new(unsigned)
            .add_hybrid_signature(crypto_rust_proto::KeyDomain::Rotr, &MATERIAL)
            .unwrap()
            .build()
            .expect("Hybrid signature integration failed");

        assert_eq!(signed.otp_fingerprint(), Some(EXPECTED_OTP_FP));
        assert_eq!(signed.signed_size(), signed.as_bytes().len());
        assert!(signed.signed_size() > 3800 && signed.signed_size() <= 8192);
        assert_signed_shape(signed.as_bytes());
    }

    #[test]
    fn test_empty_signatures_rejected() {
        let unsigned = RecordBuilder::new()
            .version(1)
            .image_vendor("VNDR")
            .image_family("FAM")
            .add_fingerprint(
                crypto_rust_proto::KeyDomain::PayloadProd,
                Algorithm::P256,
                [0x01u8; 32],
            )
            .build_unsigned()
            .unwrap();

        assert!(SignedRecordBuilder::new(unsigned).build().is_err());
    }

    #[test]
    fn test_prebuilt_signature_containers_are_all_embedded() {
        let domain = crypto_rust_proto::KeyDomain::Rotr;

        let unsigned = RecordBuilder::new()
            .image_vendor("VNDR")
            .image_family("FAM")
            .add_fingerprint(
                crypto_rust_proto::KeyDomain::PayloadProd,
                Algorithm::P256,
                [0x01u8; 32],
            )
            .build_unsigned()
            .unwrap();

        let signed = SignedRecordBuilder::new(unsigned)
            .add_signature_container(build_hybrid_sigc(domain, &MATERIAL).unwrap().0)
            .add_signature_container(build_hybrid_sigc(domain, &MATERIAL).unwrap().0)
            .build()
            .expect("Signing with pre-built containers failed");

        assert_signed_shape(signed.as_bytes());
        // Both containers survive into the wire image.
        let report = crate::inspect::inspect_file(signed.as_bytes()).unwrap();
        assert_eq!(report.matches("Tag: 'SIGC'").count(), 2);
        // This path never parses a public key, so no fingerprint is reported.
        assert_eq!(signed.otp_fingerprint(), None);
    }

    #[test]
    fn test_sign_preserves_unknown_sub_tlvs_byte_for_byte() {
        let unsigned = RecordBuilder::new()
            .version(2)
            .image_vendor("GOOGLE")
            .image_family("FAMLY")
            .add_fingerprint(
                crypto_rust_proto::KeyDomain::PayloadProd,
                Algorithm::P256,
                [0xAAu8; 32],
            )
            .build_unsigned()
            .unwrap();

        // Inject a custom/unknown proprietary sub-TLV ("CUST", 1 word payload = 0xDEADBEEF)
        // directly into the frozen `KROT` binary image.
        let mut modified_krot_bytes = unsigned.to_bytes();
        let custom_sub_tlv: [u32; 3] = [
            u32::from_le_bytes(*b"CUST"),
            1, // word_len = 1 word
            0xDEAD_BEEF,
        ];
        modified_krot_bytes.extend_from_slice(custom_sub_tlv.as_bytes());
        // Update KROT header word_len (at byte offset 4..6) to include the 3 extra words.
        let old_word_len = u16::from_le_bytes([modified_krot_bytes[4], modified_krot_bytes[5]]);
        let new_word_len = old_word_len + 3;
        modified_krot_bytes[4..6].copy_from_slice(&new_word_len.to_le_bytes());

        let frozen_unsigned = UnsignedRecord::from_bytes(&modified_krot_bytes)
            .expect("Frozen unsigned record with custom sub-TLV should be valid");

        let signed = SignedRecordBuilder::new(frozen_unsigned)
            .add_hybrid_signature(crypto_rust_proto::KeyDomain::Rotr, &MATERIAL)
            .unwrap()
            .build()
            .expect("Signing frozen record failed");

        // Verify the KRSD header is followed by the EXACT byte-for-byte modified_krot_bytes!
        let signed_bytes = signed.as_bytes();
        let header_len = size_of::<TlvHeader>();
        assert_eq!(
            &signed_bytes[header_len..header_len + modified_krot_bytes.len()],
            &modified_krot_bytes[..],
            "Embedded KROT bytes in KRSD must be 100% byte-identical to input unsigned record!"
        );

        // Verify that `tlvtool inspect` surfaces the outer containers.
        assert_signed_shape(signed_bytes);
    }
}
