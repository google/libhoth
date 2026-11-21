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
use crate::krr::Krr;
use crate::krr::KrrRecordBuilder;
use crate::mauv::Mauv;
use crate::mauv::MauvRecordBuilder;
use crate::record::RecordKind;
use crate::record::parse_digest32;
use crate::signature::HybridSignatureFiles;
use crate::signature::SignedBuilder;
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
#[argh(subcommand, name = "mauv")]
/// Minimum Acceptable Update Version (MAUV) record commands.
pub struct MauvArgs {
    #[argh(subcommand)]
    pub command: MauvCommands,
}

#[derive(FromArgs, Debug, Clone, PartialEq, Eq)]
#[argh(subcommand)]
pub enum MauvCommands {
    Build(MauvBuildArgs),
    Sign(SignArgs),
}

#[derive(FromArgs, Debug, Clone, PartialEq, Eq)]
#[argh(subcommand, name = "build")]
/// Build an unsigned MAUV record from a JSON configuration file.
pub struct MauvBuildArgs {
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

#[derive(FromArgs, Debug, Clone, PartialEq, Eq)]
#[argh(subcommand, name = "sign")]
/// Attach offline signatures to a frozen unsigned record.
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

pub fn handle_mauv(args: MauvArgs) -> Result<String> {
    match args.command {
        MauvCommands::Build(build_args) => handle_mauv_build(build_args),
        MauvCommands::Sign(sig_args) => handle_mauv_sign(sig_args),
    }
}

/// Writes `bytes` to `out`, or returns their inspection report if there is none.
fn write_or_inspect(bytes: &[u8], out: Option<&str>, record_name: &str) -> Result<String> {
    match out {
        Some(path) => {
            std::fs::write(path, bytes).with_context(|| format!("Failed to write {path}"))?;
            Ok(format!("{record_name} successfully written to {path}"))
        }
        None => inspect_file(bytes).context("Failed to inspect built record"),
    }
}

pub fn handle_build(args: BuildArgs) -> Result<String> {
    let unsigned = KrrRecordBuilder::from_json_file(&args.config)
        .context("Failed to load build config")?
        .allow_test_keys(args.allow_test_keys)
        .build_unsigned()
        .context("Failed to build record")?;
    write_or_inspect(
        unsigned.as_bytes(),
        args.out.as_deref(),
        "Key rotation record",
    )
}

pub fn handle_mauv_build(args: MauvBuildArgs) -> Result<String> {
    let unsigned = MauvRecordBuilder::from_json_file(&args.config)
        .context("Failed to load build config")?
        .build_unsigned()
        .context("Failed to build record")?;
    write_or_inspect(unsigned.as_bytes(), args.out.as_deref(), "MAUV record")
}

pub fn handle_inspect(args: InspectArgs) -> Result<String> {
    let record_bytes =
        std::fs::read(&args.file).with_context(|| format!("Failed to read {}", args.file))?;
    inspect_file(&record_bytes).with_context(|| format!("Failed to inspect {}", args.file))
}

pub fn handle_sign(args: SignArgs) -> Result<String> {
    // Key rotation records are only ever countersigned by the RoT rotation
    // authority, so the signing key domain is fixed rather than selectable.
    sign_record::<Krr>(
        args,
        crypto_rust_proto::KeyDomain::Rotr,
        "Signed key rotation record",
    )
}

pub fn handle_mauv_sign(args: SignArgs) -> Result<String> {
    // MAUV records are only ever signed by the MAUV authority, so the signing
    // key domain is fixed rather than selectable.
    sign_record::<Mauv>(
        args,
        crypto_rust_proto::KeyDomain::Mauv,
        "Signed MAUV record",
    )
}

/// Attaches the hybrid signature named by `args` to an unsigned `K` record.
fn sign_record<K: RecordKind>(
    args: SignArgs,
    key_domain: crypto_rust_proto::KeyDomain,
    record_name: &str,
) -> Result<String> {
    let mut builder = SignedBuilder::<K>::from_unsigned_file(&args.record)
        .context("Failed to load unsigned record")?;

    if let Some(hex) = &args.expected_otp_fingerprint {
        builder = builder.expect_otp_fingerprint(parse_digest32("Expected OTP fingerprint", hex)?);
    }

    let signed = builder
        .add_hybrid_signature_files(
            key_domain,
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

    let report = write_or_inspect(signed.as_bytes(), args.out.as_deref(), record_name)?;
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

    #[test]
    fn test_cli_argh_mauv_subcommand_dispatch() {
        use argh::FromArgs;

        let build = MauvArgs::from_args(&["mauv"], &["build", "mauv.json", "-o", "out.bin"])
            .expect("Failed to parse 'mauv build'");
        match build.command {
            MauvCommands::Build(b_args) => {
                assert_eq!(b_args.config, "mauv.json");
                assert_eq!(b_args.out.as_deref(), Some("out.bin"));
            }
            _ => panic!("Expected Mauv Build subcommand"),
        }

        // A MAUV record carries no keys, so there is no test-key opt-in.
        assert!(
            MauvArgs::from_args(&["mauv"], &["build", "mauv.json", "--allow-test-keys"]).is_err()
        );

        let sign = MauvArgs::from_args(
            &["mauv"],
            &[
                "sign",
                "in.unsigned",
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
        .expect("Failed to parse 'mauv sign'");
        match sign.command {
            MauvCommands::Sign(sig_args) => {
                assert_eq!(sig_args.record, "in.unsigned");
                assert_eq!(sig_args.out, None);
                assert_eq!(sig_args.ec_public_key, "ec.pub");
            }
            _ => panic!("Expected Mauv Sign subcommand"),
        }
    }
}
