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

//! This library provides a macro for comparing arbitrary text data to a
//! golden file, and allowing a person running a test to automatically set the
//! golden data to the "actual" data by setting an environment variable when
//! running the unit test.
//!
//! This is most useful when the data being compared is large, and
//! correctness can be easily determined by having a human look at a diff. Some
//! examples are the output of an HTML template, or the output of a large
//! formatted struct.

use std::path::Path;

/// assert that a string matches a golden file. Example:
///
/// ```
/// assert_eq_golden!("foo\nbar\nbaz\n", "testdata/test1.golden")
/// ```
#[macro_export]
macro_rules! assert_eq_golden {
    ($data:expr, $golden_file:literal) => {
        $crate::assert_eq_golden_impl(
            $data,
            include_str!($golden_file),
            std::path::Path::new($golden_file),
        )
    };
}

#[track_caller]
pub fn assert_eq_golden_impl(actual: &str, expected: &str, path: &Path) {
    if actual == expected {
        return;
    }
    let actual_lines: Vec<&str> = actual.split_inclusive('\n').collect();
    let expected_lines: Vec<&str> = expected.split_inclusive('\n').collect();
    let diff_lines = difflib::unified_diff(
        &expected_lines,
        &actual_lines,
        &path.to_string_lossy(),
        &path.with_extension("actual").to_string_lossy(),
        "",
        "",
        3,
    );
    for (key, value) in std::env::vars() {
        println!("{key}={value:?}")
    }
    if std::env::vars_os().any(|a| a.0 == "UPDATE_GOLDEN") {
        let Ok(oldpwd) = std::env::var("OLDPWD") else {
            panic!("OLDPWD env-var is not set; unable to update golden");
        };
        let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") else {
            panic!("CARGO_MANIFEST_DIR env-var is not set; unable to update golden");
        };
        let full_path = Path::new(&oldpwd).join(manifest_dir).join(path);

        println!("Updating golden-data at path {full_path:?}");
        std::fs::write(full_path, actual).unwrap();
        return;
    }
    let update_command = if let Ok(test_target) = std::env::var("TEST_TARGET") {
        format!("run ` UPDATE_GOLDEN=1 bazel run {test_target}`")
    } else {
        "run test with `UPDATE_GOLDEN=1` environment variable".into()
    };
    panic!(
        "Actual data differs from golden data;\n{}\nTo update golden data, {update_command}",
        diff_lines.join("")
    )
}

#[cfg(test)]
mod test {

    #[test]
    fn test_success() {
        assert_eq_golden!("foo\nbar\nbaz\n", "testdata/test1.golden")
    }

    #[test]
    #[should_panic(expected = "Actual data differs from golden data;
--- testdata/test1.golden\t
+++ testdata/test1.actual\t
@@ -1,3 +1,3 @@
 foo
-bar
+barr
 baz

To update golden data, run ` UPDATE_GOLDEN=1 bazel run ")]
    fn test_failure() {
        assert_eq_golden!("foo\nbarr\nbaz\n", "testdata/test1.golden")
    }
}
