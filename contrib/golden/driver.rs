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

use argh::FromArgs;
use std::path::Path;
use std::path::PathBuf;

#[derive(FromArgs, Debug)]
/// Reusable golden file comparison driver.
struct Cli {
    #[argh(option)]
    /// a line prefix. If a line starts with this prefix, the remaining content
    /// on that line will be redacted. Can be specified multiple times.
    redact_line_prefix: Vec<String>,

    #[argh(positional)]
    /// files to check: coming in pairs: [<actual_path> <golden_path>]...
    pairs: Vec<PathBuf>,
}

fn redact_content(s: &str, redact_prefixes: &[String]) -> String {
    if redact_prefixes.is_empty() {
        return s.to_string();
    }

    let mut result = String::with_capacity(s.len());

    for line in s.lines() {
        if let Some(prefix) = redact_prefixes
            .iter()
            .find(|&prefix| line.starts_with(prefix))
        {
            result.push_str(prefix);
            result.push_str("<REDACTED>\n");
        } else {
            result.push_str(line);
            result.push('\n');
        }
    }

    result
}

fn main() {
    let cli: Cli = argh::from_env();

    if cli.pairs.len() % 2 != 0 {
        eprintln!("Error: Positional arguments must come in pairs (actual_path, golden_path)");
        std::process::exit(1);
    }

    for [actual_path, golden_path] in cli.pairs.as_chunks::<2>().0 {
        let actual_raw = std::fs::read_to_string(actual_path).unwrap_or_else(|e| {
            panic!("Failed to read actual file {}: {e}", actual_path.display())
        });

        let actual = redact_content(&actual_raw, &cli.redact_line_prefix);

        let expected = std::fs::read_to_string(golden_path).unwrap_or_default();

        mutask_golden::assert_eq_golden_impl(&actual, &expected, Path::new(""), golden_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_content() {
        let prefixes = vec!["redact:".to_string(), "hide:".to_string()];

        // Empty input and empty prefixes
        assert_eq!(redact_content("", &[]), "");

        // Non-empty input and empty prefixes
        assert_eq!(redact_content("hello\nworld", &[]), "hello\nworld");

        // Input with no matching prefixes
        assert_eq!(redact_content("hello\nworld", &prefixes), "hello\nworld\n");

        // Input with matching prefixes
        assert_eq!(
            redact_content(
                "hello\nredact:secret info\nhide:private data\nkeep this",
                &prefixes
            ),
            "hello\nredact:<REDACTED>\nhide:<REDACTED>\nkeep this\n"
        );

        // Line starting with a prefix vs containing prefix elsewhere
        assert_eq!(
            redact_content("not a redact:prefix here\nredact:at start\n", &prefixes),
            "not a redact:prefix here\nredact:<REDACTED>\n"
        );

        // Multiple prefixes matching (the first matching prefix in the list is used)
        let overlapping_prefixes = vec!["pre".to_string(), "prefix".to_string()];
        assert_eq!(
            redact_content("prefix:data", &overlapping_prefixes),
            "pre<REDACTED>\n"
        );

        let non_overlapping_prefixes = vec!["pre:".to_string(), "prefix:".to_string()];
        assert_eq!(
            redact_content("prefix:data", &non_overlapping_prefixes),
            "prefix:<REDACTED>\n"
        );
    }
}
