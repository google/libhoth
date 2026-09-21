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

//! CLI entry point for `tlvtool`.

use argh::FromArgs;
use std::process::ExitCode;
use tlvtool::cli::InspectArgs;
use tlvtool::cli::handle_inspect;

// The top-level CLI structure, `Commands` enum, and dispatch logic are defined here
// rather than in `cli.rs` so that `tlvtool_lib` remains a modular library defining
// subcommand arguments and handlers, while `main.rs` owns binary CLI composition
// and dispatch to let downstream binaries compose extra subcommands without duplication.
#[derive(FromArgs, Debug, Clone, PartialEq, Eq)]
/// A tool to create, inspect, and manage OpenPRoT TLV binary files and records.
pub struct Cli {
    #[argh(subcommand)]
    pub command: Commands,
}

#[derive(FromArgs, Debug, Clone, PartialEq, Eq)]
#[argh(subcommand)]
pub enum Commands {
    Inspect(InspectArgs),
}

pub fn run_command(command: Commands) -> anyhow::Result<String> {
    match command {
        Commands::Inspect(args) => handle_inspect(args),
    }
}

fn main() -> ExitCode {
    let cli: Cli = argh::from_env();
    match run_command(cli.command) {
        Ok(msg) => {
            if !msg.is_empty() {
                println!("{}", msg);
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("Error: {:#}", err);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_main_cli_dispatch() {
        let cli_inspect = Cli::from_args(&["tlvtool"], &["inspect", "file.bin"])
            .expect("Failed to parse inspect");
        assert!(matches!(cli_inspect.command, Commands::Inspect(_)));
    }
}
