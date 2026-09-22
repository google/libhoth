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

//! Integration tests for the `tlvtool` command line interface.

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

/// Returns a [`Command`] for the built `tlvtool` binary.
fn tlvtool() -> Command {
    let r = runfiles::Runfiles::create().expect("failed to locate runfiles");
    Command::new(
        runfiles::rlocation!(r, "mutask/tlvtool/tlvtool").expect("tlvtool is not in the runfiles"),
    )
}

/// Runs `tlvtool` with `args` and returns stdout, or panics and shows stderr.
fn run(args: &[&str]) -> String {
    let out = tlvtool()
        .args(args)
        .output()
        .expect("failed to run tlvtool");
    assert!(
        out.status.success(),
        "`tlvtool {}` exited with {}:\n{}",
        args.join(" "),
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("tlvtool wrote non-UTF-8 to stdout")
}

const TEST_TEMPDIR: &str = "TEST_TMPDIR";

/// Writes `words` to a scratch file as little-endian TLV and returns its path.
fn write_words(name: &str, words: &[u32]) -> PathBuf {
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    let path =
        PathBuf::from(std::env::var(TEST_TEMPDIR).expect("TEST_TMPDIR is not set")).join(name);
    std::fs::write(&path, &bytes).expect("failed to write the record file");
    path
}

#[test]
fn test_inspect_reads_a_record_file() {
    let path = write_words(
        "inspect_input.bin",
        &[u32::from_le_bytes(*b"TEST"), 2, 0x1234_5678, 0x9abc_def0],
    );

    let report = run(&["inspect", path.to_str().unwrap()]);
    assert!(report.contains("Tag: 'TEST'"), "{report}");
    assert!(report.contains("TLV Structure Tree:"), "{report}");
}

#[test]
fn test_inspect_rejects_a_missing_file() {
    let out = tlvtool()
        .args(["inspect", "/nonexistent/record.bin"])
        .output()
        .expect("failed to run tlvtool");

    assert!(!out.status.success(), "a missing file must not exit zero");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Failed to read"), "{stderr}");
}

const CONFIG_JSON: &str = r#"{
    "version": 1,
    "image_vendor": "VNDR",
    "image_family": "FAM",
    "fingerprints": [
        {
            "key_domain": "prod",
            "algorithm": "p256",
            "fingerprint": "0102030400000000000000000000000000000000000000000000000000000000"
        }
    ]
}"#;

/// Writes [`CONFIG_JSON`] to a scratch file and returns its path.
fn write_config(name: &str) -> PathBuf {
    let path =
        PathBuf::from(std::env::var(TEST_TEMPDIR).expect("TEST_TMPDIR is not set")).join(name);
    std::fs::write(&path, CONFIG_JSON).expect("failed to write the build config");
    path
}

#[test]
fn test_build_writes_the_output_file() {
    let config = write_config("build_emit.json");
    let out = PathBuf::from(std::env::var(TEST_TEMPDIR).expect("TEST_TMPDIR is not set"))
        .join("build_emit.bin");

    let msg = run(&[
        "krr",
        "build",
        config.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ]);
    assert!(msg.contains("successfully written"), "{msg}");
    assert!(
        !std::fs::read(&out).unwrap().is_empty(),
        "wrote an empty record"
    );
}

#[test]
fn test_build_prints_the_record_without_an_output_path() {
    let config = write_config("build_dump.json");

    let report = run(&["krr", "build", config.to_str().unwrap()]);
    assert!(report.contains("Tag: 'KROT'"), "{report}");
    assert!(report.contains("TLV Structure Tree:"), "{report}");
}

#[test]
fn test_build_rejects_a_bad_config() {
    let config = PathBuf::from(std::env::var(TEST_TEMPDIR).expect("TEST_TMPDIR is not set"))
        .join("build_bad.json");
    std::fs::write(&config, "{ not json }").unwrap();

    let out = tlvtool()
        .args(["krr", "build", config.to_str().unwrap()])
        .output()
        .expect("failed to run tlvtool");

    assert!(!out.status.success(), "a bad config must not exit zero");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Failed to parse JSON config"), "{stderr}");
}

/// Filler hybrid signing inputs, written to scratch as `krr sign` expects them.
///
/// Returns the four paths in the order the command line takes them: EC public
/// key, ML-DSA public key, EC signature, ML-DSA signature.
fn write_key_material(prefix: &str) -> [PathBuf; 4] {
    let mut ec_public_key = vec![1u8; 32];
    ec_public_key.extend_from_slice(&[2u8; 32]);

    [
        ("ec.pub", ec_public_key),
        ("mldsa.pub", vec![3u8; 1312]),
        ("ec.sig", vec![1u8; 64]),
        ("mldsa.sig", vec![2u8; 2420]),
    ]
    .map(|(name, bytes)| {
        let path = PathBuf::from(std::env::var(TEST_TEMPDIR).expect("TEST_TMPDIR is not set"))
            .join(format!("{}_{}", prefix, name));
        std::fs::write(&path, bytes).expect("failed to write key material");
        path
    })
}

/// Builds an unsigned record with `krr build` and returns its path.
fn build_unsigned(prefix: &str) -> PathBuf {
    let config = write_config(&format!("{}_config.json", prefix));
    let record = PathBuf::from(std::env::var(TEST_TEMPDIR).expect("TEST_TMPDIR is not set"))
        .join(format!("{}.unsigned", prefix));
    run(&[
        "krr",
        "build",
        config.to_str().unwrap(),
        "-o",
        record.to_str().unwrap(),
    ]);
    record
}

/// Returns `krr sign` arguments for `record`, writing to `out` if given.
fn sign_args(record: &Path, keys: &[PathBuf; 4], out: Option<&Path>) -> Vec<String> {
    let mut args = vec![
        "krr".to_string(),
        "sign".to_string(),
        record.display().to_string(),
        "--ec-public-key".to_string(),
        keys[0].display().to_string(),
        "--mldsa-public-key".to_string(),
        keys[1].display().to_string(),
        "--ec-signature".to_string(),
        keys[2].display().to_string(),
        "--mldsa-signature".to_string(),
        keys[3].display().to_string(),
    ];
    if let Some(out) = out {
        args.push("-o".to_string());
        args.push(out.display().to_string());
    }
    args
}

#[test]
fn test_sign_writes_the_output_file() {
    let record = build_unsigned("sign_emit");
    let keys = write_key_material("sign_emit");
    let signed = PathBuf::from(std::env::var(TEST_TEMPDIR).expect("TEST_TMPDIR is not set"))
        .join("sign_emit.signed");

    let args = sign_args(&record, &keys, Some(&signed));
    let msg = run(&args.iter().map(String::as_str).collect::<Vec<_>>());

    assert!(msg.contains("successfully written"), "{msg}");
    assert!(msg.contains("Total Signed Size"), "{msg}");
    assert!(!std::fs::read(&signed).unwrap().is_empty());

    // The signed record must still inspect as a KRSD wrapping the original.
    let report = run(&["inspect", signed.to_str().unwrap()]);
    for tag in ["KRSD", "KROT", "SIGC"] {
        assert!(report.contains(&format!("Tag: '{tag}'")), "{report}");
    }
}

#[test]
fn test_sign_prints_the_record_without_an_output_path() {
    let record = build_unsigned("sign_dump");
    let keys = write_key_material("sign_dump");

    let args = sign_args(&record, &keys, None);
    let report = run(&args.iter().map(String::as_str).collect::<Vec<_>>());

    assert!(report.contains("Tag: 'KRSD'"), "{report}");
    assert!(report.contains("Target RoT OTP FP"), "{report}");
}

#[test]
fn test_sign_rejects_a_bad_key_file() {
    let record = build_unsigned("sign_bad");
    let mut keys = write_key_material("sign_bad");
    keys[0] = PathBuf::from(std::env::var(TEST_TEMPDIR).expect("TEST_TMPDIR is not set"))
        .join("sign_bad_short.pub");
    std::fs::write(&keys[0], [0u8; 8]).unwrap();

    let args = sign_args(&record, &keys, None);
    let out = tlvtool()
        .args(&args)
        .output()
        .expect("failed to run tlvtool");

    assert!(!out.status.success(), "a bad key must not exit zero");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Failed to attach hybrid signature"),
        "{stderr}"
    );
}
