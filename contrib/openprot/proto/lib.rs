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

pub mod chipid {
    pub use chipid_tlv::*;
}

pub mod crypto {
    pub use crypto_tlv::*;
}

pub mod identity {
    pub use identity_tlv::*;
}

pub mod key_rotation {
    pub use key_rotation_tlv::*;
}

#[cfg(test)]
extern crate alloc;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;
    use key_rotation::*;
    use openprot_tlv::TlvData;

    #[test]
    fn test_key_rotation_proto_macro_conv() {
        let signed_desc = protobuf::proto!(key_rotation_rust_proto::SignedDescriptor {
            descriptor: key_rotation_rust_proto::Descriptor {
                version: 2,
                image_vendor: identity_rust_proto::ImageVendor {
                    name: "GOOGLE".to_string(),
                },
                image_family: identity_rust_proto::ImageFamily {
                    name: "FAM1".to_string(),
                },
                legacy_image_family: key_rotation_rust_proto::LegacyImageFamily { family: 1 },
                fingerprint: [
                    crypto_rust_proto::KeyFingerprint {
                        key_domain: crypto_rust_proto::KeyDomain::PayloadProd,
                        p256: crypto_rust_proto::P256Fingerprint {
                            sha2_256: crypto_rust_proto::Sha2_256Digest {
                                data: vec![
                                    1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                ],
                            }
                        }
                    },
                    crypto_rust_proto::KeyFingerprint {
                        key_domain: crypto_rust_proto::KeyDomain::PayloadProd,
                        slhdsa: crypto_rust_proto::SlhDsaFingerprint {
                            sha2_256: crypto_rust_proto::Sha2_256Digest {
                                data: vec![
                                    5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                ],
                            }
                        }
                    },
                ],
            },
            signature: [crypto_rust_proto::SignatureContainer {
                signature: crypto_rust_proto::Signature {
                    p256: crypto_rust_proto::P256Signature {
                        r: vec![
                            9, 8, 7, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0,
                        ],
                        s: vec![
                            5, 4, 3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0,
                        ],
                    }
                }
            }],
        });

        let tlv_words = openprot_tlv_proto_conv::message_to_tlv(
            &key_rotation_rust_proto::__unstable::CONTRIB_OPENPROT_PROTO_KEY_ROTATION_DESCRIPTOR_INFO,
            &signed_desc,
        )
        .expect("Failed to convert SignedDescriptor to TLV");

        let tlv_data = TlvData::overlay(&tlv_words);
        let signed_item = tlv_data.iter::<SignedDescriptor>().next().unwrap();
        let desc_item = signed_item.descriptor().unwrap();
        assert_eq!(desc_item.data.version, 2);
        assert_eq!(desc_item.data.image_vendor.name, *b"GOOGLE\0\0");
        assert_eq!(desc_item.data.image_family.name, *b"FAM1\0\0\0\0");
        let legacy_family = desc_item.legacy_image_family().unwrap();
        assert_eq!(legacy_family.data.family, 1);

        // Get fingerprint
        let mut fp_iter = desc_item.fingerprint();
        let kf_item = fp_iter.next().unwrap();
        assert_eq!(kf_item.data.key_domain, KeyDomain::PAYLOAD_PROD);
        match kf_item.key_type().unwrap() {
            KeyFingerprintKeyType::P256(p256_item) => match p256_item.digest().unwrap() {
                P256FingerprintDigest::Sha2256(sha_item) => {
                    assert_eq!(sha_item.data.data[0..4], [1, 2, 3, 4]);
                }
                _ => panic!("Expected Sha256"),
            },
            _ => panic!("Expected P256"),
        }

        let kf_item_slh = fp_iter.next().unwrap();
        assert_eq!(kf_item_slh.data.key_domain, KeyDomain::PAYLOAD_PROD);
        match kf_item_slh.key_type().unwrap() {
            KeyFingerprintKeyType::Slhdsa(slh_item) => match slh_item.digest().unwrap() {
                SlhDsaFingerprintDigest::Sha2256(sha_item) => {
                    assert_eq!(sha_item.data.data[0..4], [5, 6, 7, 8]);
                }
                _ => panic!("Expected Sha256"),
            },
            _ => panic!("Expected Slhdsa"),
        }

        // Verify signature
        let mut sig_iter = signed_item.signature();
        let sigc_item = sig_iter.next().unwrap();
        let sig_item = sigc_item.signature().unwrap();
        match sig_item.signature().unwrap() {
            SignatureSignature::P256(item) => {
                assert_eq!(item.data.r[0..4], [0x06070809, 0, 0, 0]);
                assert_eq!(item.data.s[0..4], [0x02030405, 0, 0, 0]);
            }
            _ => panic!("Expected P256"),
        }
    }

    #[test]
    fn test_key_rotation_sealed_descriptor_proto_macro_conv() {
        let sealed_desc = protobuf::proto!(key_rotation_rust_proto::SealedDescriptor {
            descriptor: key_rotation_rust_proto::Descriptor {
                version: 1,
                image_vendor: identity_rust_proto::ImageVendor {
                    name: "GOOGLE".to_string(),
                },
                image_family: identity_rust_proto::ImageFamily {
                    name: "FAM1".to_string(),
                },
            },
            seal: crypto_rust_proto::KRSeal {
                kmsl: crypto_rust_proto::Kmac256Seal {
                    data: vec![
                        1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                }
            },
        });

        let tlv_words = openprot_tlv_proto_conv::message_to_tlv(
            &key_rotation_rust_proto::__unstable::CONTRIB_OPENPROT_PROTO_KEY_ROTATION_DESCRIPTOR_INFO,
            &sealed_desc,
        )
        .expect("Failed to convert SealedDescriptor to TLV");

        let tlv_data = TlvData::overlay(&tlv_words);
        let sealed_item = tlv_data.iter::<SealedDescriptor>().next().unwrap();
        let desc_item = sealed_item.descriptor().unwrap();
        assert_eq!(desc_item.data.version, 1);
        assert_eq!(desc_item.data.image_vendor.name, *b"GOOGLE\0\0");
        assert_eq!(desc_item.data.image_family.name, *b"FAM1\0\0\0\0");
        assert!(desc_item.legacy_image_family().is_none());

        let seal_item = sealed_item.seal().unwrap();
        match seal_item.seal().unwrap() {
            KRSealSeal::Kmsl(kmsl_item) => {
                assert_eq!(kmsl_item.data.data[0], 0x04030201);
            }
        }
    }
}
