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

use crate::builder::RecordBuilder;
use crate::inspect::inspect_file;
use anyhow::Context;
use anyhow::Result;
use argh::FromArgs;

#[derive(FromArgs, Debug, Clone, PartialEq, Eq)]
#[argh(subcommand, name = "krr")]
/// Key Rotation Record commands.
pub struct KrrArgs {
    #[argh(subcommand)]
    pub command: KrrCommands,
}

#[derive(FromArgs, Debug, Clone, PartialEq, Eq)]
#[argh(subcommand)]
pub enum KrrCommands {
    Build(BuildArgs),
}

#[derive(FromArgs, Debug, Clone, PartialEq, Eq)]
#[argh(subcommand, name = "build")]
/// Build an unsigned Key Rotation record from a JSON configuration file.
pub struct BuildArgs {
    /// path to the JSON configuration file.
    #[argh(positional)]
    pub config: String,

    /// output file path (.unsigned). If omitted, prints human-readable record inspection to stdout.
    #[argh(option, short = 'o')]
    pub out: Option<String>,
}

#[derive(FromArgs, Debug, Clone, PartialEq, Eq)]
#[argh(subcommand, name = "inspect")]
/// Inspect and print a human-readable representation of a binary record.
pub struct InspectArgs {
    /// path to the binary record file.
    #[argh(positional)]
    pub file: String,
}

pub fn handle_krr(args: KrrArgs) -> Result<String> {
    match args.command {
        KrrCommands::Build(build_args) => handle_build(build_args),
    }
}

pub fn handle_build(args: BuildArgs) -> Result<String> {
    let unsigned = RecordBuilder::from_json_file(&args.config)
        .context("Failed to load build config")?
        .build_unsigned()
        .context("Failed to build record")?;

    match args.out.as_deref() {
        Some(path) => {
            std::fs::write(path, unsigned.as_bytes())
                .with_context(|| format!("Failed to write {path}"))?;
            Ok(format!(
                "Key rotation record successfully written to {path}"
            ))
        }
        None => inspect_file(unsigned.as_bytes()).context("Failed to inspect built record"),
    }
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

        let krr_build = KrrArgs::from_args(&["krr"], &["build", "config.json", "-o", "out.bin"])
            .expect("Failed to parse 'krr build'");
        match krr_build.command {
            KrrCommands::Build(b_args) => {
                assert_eq!(b_args.config, "config.json");
                assert_eq!(b_args.out.as_deref(), Some("out.bin"));
            }
        }

        let inspect = InspectArgs::from_args(&["inspect"], &["record.bin"])
            .expect("Failed to parse 'inspect'");
        assert_eq!(inspect.file, "record.bin");
    }
}
