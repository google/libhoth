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

//! Command line interface definitions and handlers.

use crate::inspect::inspect_file;
use anyhow::Context;
use anyhow::Result;
use argh::FromArgs;

#[derive(FromArgs, Debug, Clone, PartialEq, Eq)]
#[argh(subcommand, name = "inspect")]
/// Inspect and print a human-readable representation of a binary record.
pub struct InspectArgs {
    /// path to the binary TLV file.
    #[argh(positional)]
    pub file: String,
}

pub fn handle_inspect(args: InspectArgs) -> Result<String> {
    let record_bytes =
        std::fs::read(&args.file).with_context(|| format!("Failed to read {}", args.file))?;
    inspect_file(&record_bytes).with_context(|| format!("Failed to inspect {}", args.file))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_argh_subcommand_dispatch() {
        use argh::FromArgs;

        let inspect = InspectArgs::from_args(&["inspect"], &["record.bin"])
            .expect("Failed to parse 'inspect'");
        assert_eq!(inspect.file, "record.bin");
    }
}
