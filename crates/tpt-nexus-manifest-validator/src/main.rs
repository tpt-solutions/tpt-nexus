//! `nexus-validate-manifest` — CLI for the [5. VALIDATE] step.
//!
//! Re-checks that a `telos-proof.json` attestation still describes the `.telos`
//! source it claims to, and exits non-zero if it does not.
//!
//! ```text
//! nexus-validate-manifest <telos-proof.json> <source.telos>
//! ```
//!
//! Exit codes are distinct so the two failure modes can be scripted apart:
//!
//! | Code | Meaning |
//! |---|---|
//! | 0 | The attestation holds. |
//! | 1 | The source was modified after it was verified. |
//! | 2 | The manifest document itself was edited. |
//! | 3 | A file could not be read, or the arguments were wrong. |

use std::path::Path;
use std::process::ExitCode;

use tpt_nexus_manifest_validator::{inspect_files, ValidationError};

const USAGE: &str = "\
nexus-validate-manifest — verify a tpt-telos proof manifest against its source

USAGE:
    nexus-validate-manifest <telos-proof.json> <source.telos>

EXIT CODES:
    0    valid: the source matches its attestation
    1    the source was modified after verification
    2    the manifest document was tampered with
    3    I/O or usage error
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let [manifest_path, source_path] = match args.as_slice() {
        [m, s] => [m.clone(), s.clone()],
        _ => {
            eprintln!("error: expected exactly 2 arguments, got {}\n", args.len());
            eprint!("{USAGE}");
            return ExitCode::from(3);
        }
    };

    match inspect_files(Path::new(&manifest_path), Path::new(&source_path)) {
        Err(ValidationError::Io { path, source }) => {
            eprintln!("error: cannot read `{}`: {source}", path.display());
            ExitCode::from(3)
        }
        Err(other) => {
            // `inspect_files` only returns Io errors, but stay exhaustive
            // rather than unreachable!() in a binary.
            eprintln!("error: {other}");
            ExitCode::from(3)
        }
        Ok(report) => {
            println!("{}", report.render());
            if report.is_valid() {
                ExitCode::SUCCESS
            } else if report.manifest_was_modified() {
                ExitCode::from(2)
            } else {
                ExitCode::from(1)
            }
        }
    }
}
