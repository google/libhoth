#!/bin/bash
# Regenerates the editor configs at the repository root:
#   compile_commands.json for clangd, and rust-project.json for rust-analyzer.
set -euo pipefail

cd "$(dirname "$0")"

# clangd needs the _virtual_includes and generated headers that only exist
# after a build.
bazel build //...
bazel run //tools/analyzers:refresh_compile_commands
bazel run @rules_rust//tools/rust_analyzer:gen_rust_project -- //...
