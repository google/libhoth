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

//! Golden tests for the `inspect` report.
//!
//! Each test builds a record through the public builder API, renders it, and
//! compares the whole report to a committed `.golden` file. Comparing the full
//! text (rather than searching it for tag names) also covers byte offsets, word
//! counts, padding and the shape of the tree.
//!
//! To update the golden files after an intended change:
//!
//! ```text
//! UPDATE_GOLDEN=1 bazel run //tlvtool/tests:inspect_test
//! ```

use mutask_golden::assert_eq_golden;
use tlvtool::Algorithm;
use tlvtool::HybridMaterial;
use tlvtool::RecordBuilder;
use tlvtool::SignedRecordBuilder;
use tlvtool::inspect_file;

/// Filler P-256 public key: `x = [0x30..0x4f]`, `y = [0x50..0x6f]`.
fn ec_public_key() -> Vec<u8> {
    (0x30u8..0x70).collect()
}

/// An unsigned v1 record with both a P-256 and an ML-DSA-44 fingerprint.
fn v1_unsigned() -> Vec<u8> {
    let mut p256_fp = [0u8; 32];
    let mut mldsa_fp = [0u8; 32];
    for i in 0..32 {
        p256_fp[i] = i as u8 + 1;
        mldsa_fp[i] = i as u8 + 0x21;
    }

    RecordBuilder::new()
        .version(1)
        .image_vendor("GOOGLE")
        .image_family("FAMILYV1")
        .legacy_image_family(1)
        .add_fingerprint(
            crypto_rust_proto::KeyDomain::PayloadProd,
            Algorithm::P256,
            p256_fp,
        )
        .add_fingerprint(
            crypto_rust_proto::KeyDomain::PayloadProd,
            Algorithm::Mldsa,
            mldsa_fp,
        )
        .add_image_digest([0xaa; 32])
        .build_unsigned()
        .expect("failed to build the v1 record")
        .to_bytes()
}

/// An unsigned v2 record carrying a single fingerprint and an image digest.
fn v2_unsigned() -> tlvtool::UnsignedRecord {
    RecordBuilder::new()
        .version(2)
        .image_vendor("GOOGLE")
        .image_family("FAMILYV1")
        .add_fingerprint(
            crypto_rust_proto::KeyDomain::PayloadProd,
            Algorithm::P256,
            [0x50; 32],
        )
        .add_image_digest([0x77; 32])
        .build_unsigned()
        .expect("failed to build the v2 record")
}

#[test]
fn test_inspect_krr_v1_unsigned() {
    let report = inspect_file(&v1_unsigned()).unwrap();
    assert_eq_golden!(&report, "testdata/inspect_test/krr_v1_unsigned.golden");
}

#[test]
fn test_inspect_krr_v2_unsigned() {
    let report = inspect_file(v2_unsigned().as_bytes()).unwrap();
    assert_eq_golden!(&report, "testdata/inspect_test/krr_v2_unsigned.golden");
}

#[test]
fn test_inspect_krr_v2_signed_hybrid() {
    let ec = ec_public_key();
    let signed = SignedRecordBuilder::new(v2_unsigned())
        .add_hybrid_signature(
            crypto_rust_proto::KeyDomain::Rotr,
            &HybridMaterial {
                ec_public_key: ec.as_slice(),
                mldsa_public_key: &[0xbb; 1312],
                ec_signature: &[0x88; 64],
                mldsa_signature: &[0xaa; 2420],
            },
        )
        .expect("failed to attach the hybrid signature")
        .build()
        .expect("failed to build the signed record");

    let report = inspect_file(signed.as_bytes()).unwrap();
    assert_eq_golden!(&report, "testdata/inspect_test/krr_v2_signed_hybrid.golden");
}
