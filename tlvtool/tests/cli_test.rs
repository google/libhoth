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

/// Writes `words` to a scratch file as little-endian TLV and returns its path.
fn write_words(name: &str, words: &[u32]) -> PathBuf {
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    let path =
        PathBuf::from(std::env::var("TEST_TMPDIR").expect("TEST_TMPDIR is not set")).join(name);
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
