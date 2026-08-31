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

#![cfg_attr(not(test), no_std)]

use core::hint::black_box;
use crypto_tlv::HybridP256MlDsa44FingerprintDigest;
use crypto_tlv::HybridP256MlDsa44FingerprintExt;
use crypto_tlv::HybridP256MlDsa44PublicMaterial;
use crypto_tlv::HybridP256SlhDsaFingerprintDigest;
use crypto_tlv::HybridP256SlhDsaFingerprintExt;
use crypto_tlv::HybridP256SlhDsaPublicMaterial;
use crypto_tlv::KeyDomain;
use crypto_tlv::KeyFingerprint;
use crypto_tlv::KeyFingerprintExt;
use crypto_tlv::KeyFingerprintKeyType;
use crypto_tlv::MlDsa44FingerprintDigest;
use crypto_tlv::MlDsa44FingerprintExt;
use crypto_tlv::MlDsa44PublicMaterial;
use crypto_tlv::P256FingerprintDigest;
use crypto_tlv::P256FingerprintExt;
use crypto_tlv::P256PublicMaterial;
use crypto_tlv::PublicKey;
use crypto_tlv::PublicKeyExt;
use crypto_tlv::PublicKeyKeyMaterial;
use crypto_tlv::Rsa2048FingerprintDigest;
use crypto_tlv::Rsa2048FingerprintExt;
use crypto_tlv::Rsa2048PublicMaterial;
use crypto_tlv::Rsa3072FingerprintDigest;
use crypto_tlv::Rsa3072FingerprintExt;
use crypto_tlv::Rsa3072PublicMaterial;
use crypto_tlv::Rsa4096FingerprintDigest;
use crypto_tlv::Rsa4096FingerprintExt;
use crypto_tlv::Rsa4096PublicMaterial;
use crypto_tlv::Sha2_256Digest;
use crypto_tlv::SlhDsaFingerprintDigest;
use crypto_tlv::SlhDsaFingerprintExt;
use crypto_tlv::SlhDsaPublicMaterial;
use mutask_sha256_sw::Sha256;
use zerocopy::IntoBytes;

// =============================================================================
// Fingerprintable Key Trait & Implementations
// =============================================================================

/// Trait for cryptographic keys that can compute a canonical SHA-256 fingerprint.
pub trait FingerprintableKey {
    /// Feeds the canonical byte representation of the public key material into a SHA-256 hasher.
    fn update_hasher(&self, hasher: &mut Sha256);

    /// Computes the 32-byte SHA-256 fingerprint digest of this key.
    fn fingerprint_sha256(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        self.update_hasher(&mut hasher);
        hasher.finalize()
    }
}

impl FingerprintableKey for P256PublicMaterial {
    fn update_hasher(&self, hasher: &mut Sha256) {
        hasher.update(self.x.as_bytes());
        hasher.update(self.y.as_bytes());
    }
}

impl FingerprintableKey for SlhDsaPublicMaterial {
    fn update_hasher(&self, hasher: &mut Sha256) {
        hasher.update(self.slhdsa.as_bytes());
    }
}

impl FingerprintableKey for MlDsa44PublicMaterial {
    fn update_hasher(&self, hasher: &mut Sha256) {
        hasher.update(&self.mldsa);
    }
}

impl FingerprintableKey for HybridP256MlDsa44PublicMaterial {
    fn update_hasher(&self, hasher: &mut Sha256) {
        hasher.update(self.x.as_bytes());
        hasher.update(self.y.as_bytes());
        hasher.update(&self.mldsa);
    }
}

impl FingerprintableKey for HybridP256SlhDsaPublicMaterial {
    fn update_hasher(&self, hasher: &mut Sha256) {
        hasher.update(self.x.as_bytes());
        hasher.update(self.y.as_bytes());
        hasher.update(self.slhdsa.as_bytes());
    }
}

impl FingerprintableKey for Rsa2048PublicMaterial {
    fn update_hasher(&self, hasher: &mut Sha256) {
        hasher.update(&self.modulus);
    }
}

impl FingerprintableKey for Rsa3072PublicMaterial {
    fn update_hasher(&self, hasher: &mut Sha256) {
        hasher.update(&self.modulus);
    }
}

impl FingerprintableKey for Rsa4096PublicMaterial {
    fn update_hasher(&self, hasher: &mut Sha256) {
        hasher.update(&self.modulus);
    }
}

impl<'a> FingerprintableKey for PublicKeyKeyMaterial<'a> {
    fn update_hasher(&self, hasher: &mut Sha256) {
        match self {
            PublicKeyKeyMaterial::P256(item) => item.data.update_hasher(hasher),
            PublicKeyKeyMaterial::Slhdsa(item) => item.data.update_hasher(hasher),
            PublicKeyKeyMaterial::Mldsa(item) => item.data.update_hasher(hasher),
            PublicKeyKeyMaterial::HybridP256Slhdsa(item) => item.data.update_hasher(hasher),
            PublicKeyKeyMaterial::HybridP256Mldsa(item) => item.data.update_hasher(hasher),
            PublicKeyKeyMaterial::Rsa2048(item) => item.data.update_hasher(hasher),
            PublicKeyKeyMaterial::Rsa3072(item) => item.data.update_hasher(hasher),
            PublicKeyKeyMaterial::Rsa4096(item) => item.data.update_hasher(hasher),
        }
    }
}

impl<T: FingerprintableKey> FingerprintableKey for &T {
    fn update_hasher(&self, hasher: &mut Sha256) {
        (*self).update_hasher(hasher);
    }
}

// =============================================================================
// Constant-Time Comparison Helpers
// =============================================================================

/// Constant-time comparison for 32-byte arrays to prevent timing attacks.
#[inline(never)]
pub fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    black_box(diff) == 0
}

// =============================================================================
// Verification Functions
// =============================================================================

/// Verifies whether a given public key material and domain match the specified `KeyFingerprint` TLV item.
pub fn verify_key_matches_fingerprint(
    public_key: &PublicKeyKeyMaterial<'_>,
    key_domain: KeyDomain,
    fingerprint: &mutask_tlv::TlvItem<'_, KeyFingerprint>,
) -> bool {
    if key_domain != fingerprint.data.key_domain {
        return false;
    }

    let Some(fp_key_type) = fingerprint.key_type() else {
        return false;
    };

    match (public_key, fp_key_type) {
        (PublicKeyKeyMaterial::P256(pk), KeyFingerprintKeyType::P256(fp)) => {
            matches!(fp.digest(), Some(P256FingerprintDigest::Sha2256(d)) if constant_time_eq_32(&pk.data.fingerprint_sha256(), &d.data.data))
        }
        (PublicKeyKeyMaterial::Slhdsa(pk), KeyFingerprintKeyType::Slhdsa(fp)) => {
            matches!(fp.digest(), Some(SlhDsaFingerprintDigest::Sha2256(d)) if constant_time_eq_32(&pk.data.fingerprint_sha256(), &d.data.data))
        }
        (PublicKeyKeyMaterial::Mldsa(pk), KeyFingerprintKeyType::Mldsa(fp)) => {
            matches!(fp.digest(), Some(MlDsa44FingerprintDigest::Sha2256(d)) if constant_time_eq_32(&pk.data.fingerprint_sha256(), &d.data.data))
        }
        (PublicKeyKeyMaterial::HybridP256Mldsa(pk), KeyFingerprintKeyType::HybridP256Mldsa(fp)) => {
            matches!(fp.digest(), Some(HybridP256MlDsa44FingerprintDigest::Sha2256(d)) if constant_time_eq_32(&pk.data.fingerprint_sha256(), &d.data.data))
        }
        (
            PublicKeyKeyMaterial::HybridP256Slhdsa(pk),
            KeyFingerprintKeyType::HybridP256Slhdsa(fp),
        ) => {
            matches!(fp.digest(), Some(HybridP256SlhDsaFingerprintDigest::Sha2256(d)) if constant_time_eq_32(&pk.data.fingerprint_sha256(), &d.data.data))
        }
        (PublicKeyKeyMaterial::Rsa2048(pk), KeyFingerprintKeyType::Rsa2048(fp)) => {
            matches!(fp.digest(), Some(Rsa2048FingerprintDigest::Sha2256(d)) if constant_time_eq_32(&pk.data.fingerprint_sha256(), &d.data.data))
        }
        (PublicKeyKeyMaterial::Rsa3072(pk), KeyFingerprintKeyType::Rsa3072(fp)) => {
            matches!(fp.digest(), Some(Rsa3072FingerprintDigest::Sha2256(d)) if constant_time_eq_32(&pk.data.fingerprint_sha256(), &d.data.data))
        }
        (PublicKeyKeyMaterial::Rsa4096(pk), KeyFingerprintKeyType::Rsa4096(fp)) => {
            matches!(fp.digest(), Some(Rsa4096FingerprintDigest::Sha2256(d)) if constant_time_eq_32(&pk.data.fingerprint_sha256(), &d.data.data))
        }
        _ => false,
    }
}

/// Convenience helper to verify a parsed `PublicKey` TLV item against a `KeyFingerprint` TLV item.
pub fn verify_public_key_matches_fingerprint(
    public_key: &mutask_tlv::TlvItem<'_, PublicKey>,
    fingerprint: &mutask_tlv::TlvItem<'_, KeyFingerprint>,
) -> bool {
    let Some(km) = public_key.key_material() else {
        return false;
    };
    verify_key_matches_fingerprint(&km, public_key.data.key_domain, fingerprint)
}

/// Constant-time helper to check if a 32-byte digest matches a `Sha2_256Digest` TLV item.
pub fn verify_digest_matches_sha256(
    digest: &[u8; 32],
    expected: &mutask_tlv::TlvItem<'_, Sha2_256Digest>,
) -> bool {
    constant_time_eq_32(digest, &expected.data.data)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_tlv::HybridP256MlDsa44Fingerprint;
    use crypto_tlv::HybridP256SlhDsaFingerprint;
    use crypto_tlv::MlDsa44Fingerprint;
    use crypto_tlv::P256Fingerprint;
    use crypto_tlv::Rsa3072Fingerprint;
    use crypto_tlv::SlhDsaFingerprint;
    use mutask_tlv::TlvBuilder;
    use mutask_tlv::TlvData;

    #[test]
    fn test_fingerprintable_keys() {
        let p256 = P256PublicMaterial {
            x: [1, 2, 3, 4, 5, 6, 7, 8],
            y: [9, 10, 11, 12, 13, 14, 15, 16],
        };
        let mut exp_p256 = Sha256::new();
        exp_p256.update(p256.x.as_bytes());
        exp_p256.update(p256.y.as_bytes());
        assert_eq!(p256.fingerprint_sha256(), exp_p256.finalize());

        let slhdsa = SlhDsaPublicMaterial { slhdsa: [0x55; 8] };
        let mut exp_slh = Sha256::new();
        exp_slh.update(slhdsa.slhdsa.as_bytes());
        assert_eq!(slhdsa.fingerprint_sha256(), exp_slh.finalize());

        let mldsa = MlDsa44PublicMaterial {
            mldsa: [0x42; 1312],
        };
        let mut exp_mldsa = Sha256::new();
        exp_mldsa.update(&mldsa.mldsa);
        assert_eq!(mldsa.fingerprint_sha256(), exp_mldsa.finalize());

        let hybrid_mldsa = HybridP256MlDsa44PublicMaterial {
            x: [0x11; 8],
            y: [0x22; 8],
            mldsa: [0x33; 1312],
        };
        let mut exp_h_mldsa = Sha256::new();
        exp_h_mldsa.update(hybrid_mldsa.x.as_bytes());
        exp_h_mldsa.update(hybrid_mldsa.y.as_bytes());
        exp_h_mldsa.update(&hybrid_mldsa.mldsa);
        assert_eq!(hybrid_mldsa.fingerprint_sha256(), exp_h_mldsa.finalize());

        let hybrid_slhdsa = HybridP256SlhDsaPublicMaterial {
            x: [0x11; 8],
            y: [0x22; 8],
            slhdsa: [0x33; 8],
        };
        let mut exp_h_slhdsa = Sha256::new();
        exp_h_slhdsa.update(hybrid_slhdsa.x.as_bytes());
        exp_h_slhdsa.update(hybrid_slhdsa.y.as_bytes());
        exp_h_slhdsa.update(hybrid_slhdsa.slhdsa.as_bytes());
        assert_eq!(hybrid_slhdsa.fingerprint_sha256(), exp_h_slhdsa.finalize());

        let rsa3072 = Rsa3072PublicMaterial {
            modulus: [0x77; 384],
        };
        let mut exp_rsa3072 = Sha256::new();
        exp_rsa3072.update(&rsa3072.modulus);
        assert_eq!(rsa3072.fingerprint_sha256(), exp_rsa3072.finalize());
    }

    #[test]
    fn test_verify_rsa3072() {
        let rsa_mat = Rsa3072PublicMaterial {
            modulus: [0x77; 384],
        };

        let mut kf_words = [0u32; 64];
        let (kf, mut builder) = TlvBuilder::new::<KeyFingerprint>(&mut kf_words).unwrap();
        kf.key_domain = KeyDomain::PAYLOAD_PROD;
        builder
            .add_in::<Rsa3072Fingerprint, _>(|_fp, b| {
                let d = b.add::<Sha2_256Digest>()?;
                d.data = rsa_mat.fingerprint_sha256();
                Ok(())
            })
            .unwrap();
        let kf_bytes = builder.finish().into_bytes(&kf_words).unwrap();
        let fp_item = TlvData::overlay_bytes(kf_bytes)
            .unwrap()
            .iter::<KeyFingerprint>()
            .next()
            .unwrap();

        let mut pk_words = [0u32; 128];
        let (pk, mut pk_b) = TlvBuilder::new::<PublicKey>(&mut pk_words).unwrap();
        pk.key_domain = KeyDomain::PAYLOAD_PROD;
        *pk_b.add::<Rsa3072PublicMaterial>().unwrap() = rsa_mat;
        let pk_bytes = pk_b.finish().into_bytes(&pk_words).unwrap();
        let pk_item = TlvData::overlay_bytes(pk_bytes)
            .unwrap()
            .iter::<PublicKey>()
            .next()
            .unwrap();

        assert!(verify_public_key_matches_fingerprint(&pk_item, &fp_item));

        // A different RSA size must be rejected: the fingerprint is tagged
        // RSA3, so both the key type and the digest have to line up.
        let mut short_words = [0u32; 128];
        let (short_pk, mut short_b) = TlvBuilder::new::<PublicKey>(&mut short_words).unwrap();
        short_pk.key_domain = KeyDomain::PAYLOAD_PROD;
        *short_b.add::<Rsa2048PublicMaterial>().unwrap() = Rsa2048PublicMaterial {
            modulus: [0x77; 256],
        };
        let short_bytes = short_b.finish().into_bytes(&short_words).unwrap();
        let short_item = TlvData::overlay_bytes(short_bytes)
            .unwrap()
            .iter::<PublicKey>()
            .next()
            .unwrap();
        assert!(!verify_public_key_matches_fingerprint(
            &short_item,
            &fp_item
        ));
    }

    #[test]
    fn test_verify_p256() {
        let p256_mat = P256PublicMaterial {
            x: [1, 2, 3, 4, 5, 6, 7, 8],
            y: [9, 10, 11, 12, 13, 14, 15, 16],
        };
        let expected = p256_mat.fingerprint_sha256();

        let mut kf_words = [0u32; 64];
        let (kf, mut builder) = TlvBuilder::new::<KeyFingerprint>(&mut kf_words).unwrap();
        kf.key_domain = KeyDomain::PAYLOAD_PROD;
        builder
            .add_in::<P256Fingerprint, _>(|_fp, b| {
                let d = b.add::<Sha2_256Digest>()?;
                d.data = expected;
                Ok(())
            })
            .unwrap();
        let kf_bytes = builder.finish().into_bytes(&kf_words).unwrap();
        let fp_item = TlvData::overlay_bytes(kf_bytes)
            .unwrap()
            .iter::<KeyFingerprint>()
            .next()
            .unwrap();

        let mut pk_words = [0u32; 64];
        let (pk, mut pk_b) = TlvBuilder::new::<PublicKey>(&mut pk_words).unwrap();
        pk.key_domain = KeyDomain::PAYLOAD_PROD;
        *pk_b.add::<P256PublicMaterial>().unwrap() = p256_mat;
        let pk_bytes = pk_b.finish().into_bytes(&pk_words).unwrap();
        let pk_item = TlvData::overlay_bytes(pk_bytes)
            .unwrap()
            .iter::<PublicKey>()
            .next()
            .unwrap();

        assert!(verify_public_key_matches_fingerprint(&pk_item, &fp_item));
        assert!(!verify_key_matches_fingerprint(
            &pk_item.key_material().unwrap(),
            KeyDomain::PAYLOAD_DEV,
            &fp_item
        ));
    }

    #[test]
    fn test_verify_slhdsa() {
        let slhdsa_mat = SlhDsaPublicMaterial { slhdsa: [0x99; 8] };
        let expected = slhdsa_mat.fingerprint_sha256();

        let mut kf_words = [0u32; 64];
        let (kf, mut builder) = TlvBuilder::new::<KeyFingerprint>(&mut kf_words).unwrap();
        kf.key_domain = KeyDomain::PAYLOAD_PROD;
        builder
            .add_in::<SlhDsaFingerprint, _>(|_fp, b| {
                let d = b.add::<Sha2_256Digest>()?;
                d.data = expected;
                Ok(())
            })
            .unwrap();
        let kf_bytes = builder.finish().into_bytes(&kf_words).unwrap();
        let fp_item = TlvData::overlay_bytes(kf_bytes)
            .unwrap()
            .iter::<KeyFingerprint>()
            .next()
            .unwrap();

        let mut pk_words = [0u32; 64];
        let (pk, mut pk_b) = TlvBuilder::new::<PublicKey>(&mut pk_words).unwrap();
        pk.key_domain = KeyDomain::PAYLOAD_PROD;
        *pk_b.add::<SlhDsaPublicMaterial>().unwrap() = slhdsa_mat;
        let pk_bytes = pk_b.finish().into_bytes(&pk_words).unwrap();
        let pk_item = TlvData::overlay_bytes(pk_bytes)
            .unwrap()
            .iter::<PublicKey>()
            .next()
            .unwrap();

        assert!(verify_public_key_matches_fingerprint(&pk_item, &fp_item));
    }

    #[test]
    fn test_verify_hybrid_mldsa() {
        let mat = HybridP256MlDsa44PublicMaterial {
            x: [0x12; 8],
            y: [0x34; 8],
            mldsa: [0x56; 1312],
        };
        let expected = mat.fingerprint_sha256();

        let mut kf_words = [0u32; 64];
        let (kf, mut builder) = TlvBuilder::new::<KeyFingerprint>(&mut kf_words).unwrap();
        kf.key_domain = KeyDomain::PAYLOAD_PROD;
        builder
            .add_in::<HybridP256MlDsa44Fingerprint, _>(|_fp, b| {
                let d = b.add::<Sha2_256Digest>()?;
                d.data = expected;
                Ok(())
            })
            .unwrap();
        let kf_bytes = builder.finish().into_bytes(&kf_words).unwrap();
        let fp_item = TlvData::overlay_bytes(kf_bytes)
            .unwrap()
            .iter::<KeyFingerprint>()
            .next()
            .unwrap();

        let mut pk_words = [0u32; 512];
        let (pk, mut pk_b) = TlvBuilder::new::<PublicKey>(&mut pk_words).unwrap();
        pk.key_domain = KeyDomain::PAYLOAD_PROD;
        *pk_b.add::<HybridP256MlDsa44PublicMaterial>().unwrap() = mat;
        let pk_bytes = pk_b.finish().into_bytes(&pk_words).unwrap();
        let pk_item = TlvData::overlay_bytes(pk_bytes)
            .unwrap()
            .iter::<PublicKey>()
            .next()
            .unwrap();

        assert!(verify_public_key_matches_fingerprint(&pk_item, &fp_item));

        // Tampered key fails
        let mut tampered = mat;
        tampered.mldsa[0] ^= 0xff;
        let mut pk_words2 = [0u32; 512];
        let (pk2, mut pk_b2) = TlvBuilder::new::<PublicKey>(&mut pk_words2).unwrap();
        pk2.key_domain = KeyDomain::PAYLOAD_PROD;
        *pk_b2.add::<HybridP256MlDsa44PublicMaterial>().unwrap() = tampered;
        let pk_bytes2 = pk_b2.finish().into_bytes(&pk_words2).unwrap();
        let pk_item2 = TlvData::overlay_bytes(pk_bytes2)
            .unwrap()
            .iter::<PublicKey>()
            .next()
            .unwrap();
        assert!(!verify_public_key_matches_fingerprint(&pk_item2, &fp_item));
    }

    #[test]
    fn test_verify_hybrid_slhdsa() {
        let mat = HybridP256SlhDsaPublicMaterial {
            x: [0x11; 8],
            y: [0x22; 8],
            slhdsa: [0x33; 8],
        };
        let expected = mat.fingerprint_sha256();

        let mut kf_words = [0u32; 64];
        let (kf, mut builder) = TlvBuilder::new::<KeyFingerprint>(&mut kf_words).unwrap();
        kf.key_domain = KeyDomain::PAYLOAD_DEV;
        builder
            .add_in::<HybridP256SlhDsaFingerprint, _>(|_fp, b| {
                let d = b.add::<Sha2_256Digest>()?;
                d.data = expected;
                Ok(())
            })
            .unwrap();
        let kf_bytes = builder.finish().into_bytes(&kf_words).unwrap();
        let fp_item = TlvData::overlay_bytes(kf_bytes)
            .unwrap()
            .iter::<KeyFingerprint>()
            .next()
            .unwrap();

        let mut pk_words = [0u32; 64];
        let (pk, mut pk_b) = TlvBuilder::new::<PublicKey>(&mut pk_words).unwrap();
        pk.key_domain = KeyDomain::PAYLOAD_DEV;
        *pk_b.add::<HybridP256SlhDsaPublicMaterial>().unwrap() = mat;
        let pk_bytes = pk_b.finish().into_bytes(&pk_words).unwrap();
        let pk_item = TlvData::overlay_bytes(pk_bytes)
            .unwrap()
            .iter::<PublicKey>()
            .next()
            .unwrap();

        assert!(verify_public_key_matches_fingerprint(&pk_item, &fp_item));
    }

    #[test]
    fn test_verify_mldsa() {
        let mat = MlDsa44PublicMaterial {
            mldsa: [0x78; 1312],
        };
        let expected = mat.fingerprint_sha256();

        let mut kf_words = [0u32; 64];
        let (kf, mut builder) = TlvBuilder::new::<KeyFingerprint>(&mut kf_words).unwrap();
        kf.key_domain = KeyDomain::PAYLOAD_TEST;
        builder
            .add_in::<MlDsa44Fingerprint, _>(|_fp, b| {
                let d = b.add::<Sha2_256Digest>()?;
                d.data = expected;
                Ok(())
            })
            .unwrap();
        let kf_bytes = builder.finish().into_bytes(&kf_words).unwrap();
        let fp_item = TlvData::overlay_bytes(kf_bytes)
            .unwrap()
            .iter::<KeyFingerprint>()
            .next()
            .unwrap();

        let mut pk_words = [0u32; 512];
        let (pk, mut pk_b) = TlvBuilder::new::<PublicKey>(&mut pk_words).unwrap();
        pk.key_domain = KeyDomain::PAYLOAD_TEST;
        *pk_b.add::<MlDsa44PublicMaterial>().unwrap() = mat;
        let pk_bytes = pk_b.finish().into_bytes(&pk_words).unwrap();
        let pk_item = TlvData::overlay_bytes(pk_bytes)
            .unwrap()
            .iter::<PublicKey>()
            .next()
            .unwrap();

        assert!(verify_public_key_matches_fingerprint(&pk_item, &fp_item));

        // Key type mismatch (MlDsa key checked against P256 fingerprint)
        let mut p256_words = [0u32; 64];
        let (p256_kf, mut p256_b) = TlvBuilder::new::<KeyFingerprint>(&mut p256_words).unwrap();
        p256_kf.key_domain = KeyDomain::PAYLOAD_TEST;
        p256_b
            .add_in::<P256Fingerprint, _>(|_fp, b| {
                let d = b.add::<Sha2_256Digest>()?;
                d.data = expected;
                Ok(())
            })
            .unwrap();
        let p256_bytes = p256_b.finish().into_bytes(&p256_words).unwrap();
        let p256_fp = TlvData::overlay_bytes(p256_bytes)
            .unwrap()
            .iter::<KeyFingerprint>()
            .next()
            .unwrap();
        assert!(!verify_public_key_matches_fingerprint(&pk_item, &p256_fp));
    }

    #[test]
    fn test_verify_digest_matches_sha256() {
        let digest_data = [0x77u8; 32];
        let mut digest_words = [0u32; 16];
        let (digest_obj, builder) = TlvBuilder::new::<Sha2_256Digest>(&mut digest_words).unwrap();
        digest_obj.data = digest_data;
        let digest_bytes = builder.finish().into_bytes(&digest_words).unwrap();
        let tlv = TlvData::overlay_bytes(digest_bytes).unwrap();
        let digest_item = tlv.iter::<Sha2_256Digest>().next().unwrap();

        assert!(verify_digest_matches_sha256(&digest_data, &digest_item));

        let mut tampered = digest_data;
        tampered[0] ^= 0x01;
        assert!(!verify_digest_matches_sha256(&tampered, &digest_item));
    }

    #[test]
    fn test_constant_time_eq_32() {
        let a32 = [0xaa; 32];
        let b32 = [0xaa; 32];
        let mut c32 = [0xaa; 32];
        c32[31] = 0xab;
        assert!(constant_time_eq_32(&a32, &b32));
        assert!(!constant_time_eq_32(&a32, &c32));
    }
}
