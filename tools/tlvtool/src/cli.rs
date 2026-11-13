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
use crate::builder::parse_digest32;
use crate::inspect::inspect_file;
use crate::signature::HybridSignatureFiles;
use crate::signature::SignedRecordBuilder;
use anyhow::Context;
use anyhow::Result;
use argh::FromArgs;
use std::path::Path;

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
    Sign(SignArgs),
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

    /// allow keys from test domains to be included in the record.
    #[argh(switch)]
    pub allow_test_keys: bool,
}

#[derive(FromArgs, Debug, Clone, PartialEq, Eq)]
#[argh(subcommand, name = "inspect")]
/// Inspect and print a human-readable representation of a binary record.
pub struct InspectArgs {
    /// path to the binary record file.
    #[argh(positional)]
    pub file: String,
}

#[derive(FromArgs, Debug, Clone, PartialEq, Eq)]
#[argh(subcommand, name = "sign")]
/// Attach offline signatures to a frozen unsigned Key Rotation record.
pub struct SignArgs {
    /// path to the unsigned record file (.unsigned).
    #[argh(positional)]
    pub record: String,

    /// output file path (.signed). If omitted, prints human-readable record inspection to stdout.
    #[argh(option, short = 'o')]
    pub out: Option<String>,

    /// path to EC (P-256) public key file (PEM/DER/raw).
    #[argh(option)]
    pub ec_public_key: String,

    /// path to ML-DSA-44 public key file (raw).
    #[argh(option)]
    pub mldsa_public_key: String,

    /// path to EC (P-256) signature file (DER/raw).
    #[argh(option)]
    pub ec_signature: String,

    /// path to ML-DSA-44 signature file (raw).
    #[argh(option)]
    pub mldsa_signature: String,

    /// expected SHA2-256 hash of the target RoT OTP key material (hex string).
    #[argh(option)]
    pub expected_otp_fingerprint: Option<String>,
}

pub fn handle_krr(args: KrrArgs) -> Result<String> {
    match args.command {
        KrrCommands::Build(build_args) => handle_build(build_args),
        KrrCommands::Sign(sig_args) => handle_sign(sig_args),
    }
}

pub fn handle_build(args: BuildArgs) -> Result<String> {
    let unsigned = RecordBuilder::from_json_file(&args.config)
        .context("Failed to load build config")?
        .allow_test_keys(args.allow_test_keys)
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

pub fn handle_sign(args: SignArgs) -> Result<String> {
    let mut builder = SignedRecordBuilder::from_unsigned_file(&args.record)
        .context("Failed to load unsigned record")?;

    if let Some(hex) = &args.expected_otp_fingerprint {
        builder = builder.expect_otp_fingerprint(parse_digest32("Expected OTP fingerprint", hex)?);
    }

    let signed = builder
        // Key rotation records are only ever countersigned by the RoT rotation
        // authority, so the signing key domain is fixed rather than selectable.
        .add_hybrid_signature_files(
            crypto_rust_proto::KeyDomain::Rotr,
            HybridSignatureFiles {
                ec_public_key: Path::new(&args.ec_public_key),
                mldsa_public_key: Path::new(&args.mldsa_public_key),
                ec_signature: Path::new(&args.ec_signature),
                mldsa_signature: Path::new(&args.mldsa_signature),
            },
        )
        .context("Failed to attach hybrid signature")?
        .build()
        .context("Failed to sign record")?;

    let report = match args.out.as_deref() {
        Some(path) => {
            std::fs::write(path, signed.as_bytes())
                .with_context(|| format!("Failed to write {path}"))?;
            format!("Signed key rotation record successfully written to {path}")
        }
        None => inspect_file(signed.as_bytes()).context("Failed to inspect built record")?,
    };
    let fingerprint = signed
        .otp_fingerprint()
        .map(|fp| format!("\n  Target RoT OTP FP  : {}", fp))
        .unwrap_or_default();

    Ok(format!(
        "{}\n  Unsigned Body Size : {} bytes\n  Total Signed Size  : {} bytes{}",
        report,
        signed.unsigned_size(),
        signed.signed_size(),
        fingerprint,
    ))
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
            _ => panic!("Expected Krr Build subcommand"),
        }

        let krr_sign = KrrArgs::from_args(
            &["krr"],
            &[
                "sign",
                "in.unsigned",
                "-o",
                "out.signed",
                "--ec-public-key",
                "ec.pub",
                "--mldsa-public-key",
                "mldsa.pub",
                "--ec-signature",
                "ec.sig",
                "--mldsa-signature",
                "mldsa.sig",
            ],
        )
        .expect("Failed to parse 'krr sign'");
        match krr_sign.command {
            KrrCommands::Sign(sig_args) => {
                assert_eq!(sig_args.record, "in.unsigned");
                assert_eq!(sig_args.out.as_deref(), Some("out.signed"));
                assert_eq!(sig_args.ec_public_key, "ec.pub");
                assert_eq!(sig_args.mldsa_public_key, "mldsa.pub");
                assert_eq!(sig_args.ec_signature, "ec.sig");
                assert_eq!(sig_args.mldsa_signature, "mldsa.sig");
            }
            _ => panic!("Expected Krr Sign subcommand"),
        }

        let inspect = InspectArgs::from_args(&["inspect"], &["record.bin"])
            .expect("Failed to parse 'inspect'");
        assert_eq!(inspect.file, "record.bin");
    }
}
