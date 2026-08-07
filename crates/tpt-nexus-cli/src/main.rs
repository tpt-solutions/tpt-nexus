//! `nexus` — the command-line front end for tpt-nexus.
//!
//! Subcommands:
//! * `verify <file.telos>` — run the INTENT→VERIFY→ATTEST loop, print the
//!   derived capability table, and write the attestation to disk.
//! * `diff <a.telos> <b.telos>` — show the capability delta between two
//!   versions (security-regression view).
//! * `new <name> --template <t>` — scaffold a new `.telos` from a starter.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use tpt_archon_bridge::capability::Right;
use tpt_nexus_archon_emulator::derive_rights;
use tpt_nexus_orchestrator::{NexusOrchestrator, StaticAgent};

use tpt_nexus_cli::{capability_diff, render_capability_table, run_and_derive};

#[derive(Parser)]
enum Command {
    /// Verify a `.telos`, attest it, and print the derived capability table.
    Verify {
        /// Path to the `.telos` source.
        path: PathBuf,
    },
    /// Show the capability delta between two `.telos` sources.
    Diff {
        /// Baseline version (e.g. the committed file).
        a: PathBuf,
        /// Candidate version (e.g. the PR's file).
        b: PathBuf,
    },
    /// Scaffold a new `.telos` from a starter template.
    New {
        /// Name of the new file (without extension).
        name: String,
    },
}

fn main() -> ExitCode {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let cli = Command::parse();
    match cli {
        Command::Verify { path } => verify(&path),
        Command::Diff { a, b } => diff(&a, &b),
        Command::New { name } => new_project(&name),
    }
}

fn verify(path: &std::path::Path) -> ExitCode {
    let source = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot read {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };

    let artifact = match NexusOrchestrator::new().run_agent_loop(&source, &StaticAgent::new()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("verify failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let rights = match derive_rights(&artifact) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cannot derive capabilities: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("verified {} function(s)\n", rights.len());
    print!("{}", render_capability_table(&rights));

    let out_dir = PathBuf::from("nexus-out");
    match artifact.write_attestation(&out_dir) {
        Ok(att) => println!("\nattestation -> {}", att.manifest_path.display()),
        Err(e) => eprintln!("warning: could not write attestation: {e}"),
    }
    ExitCode::SUCCESS
}

fn diff(a: &std::path::Path, b: &std::path::Path) -> ExitCode {
    let baseline = match run_and_derive(a) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("baseline {} failed to verify: {e}", a.display());
            return ExitCode::FAILURE;
        }
    };
    let candidate = match run_and_derive(b) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("candidate {} failed to verify: {e}", b.display());
            return ExitCode::FAILURE;
        }
    };

    let delta = capability_diff(&baseline, &candidate);
    if delta.is_empty() {
        println!("no capability change between {} and {}", a.display(), b.display());
        return ExitCode::SUCCESS;
    }

    println!("capability delta: {} -> {}\n", a.display(), b.display());
    for (name, right) in &delta.added {
        println!("  + {name}  -> {right:?}");
    }
    for (name, right) in &delta.removed {
        println!("  - {name}  (was {right:?})");
    }
    for change in &delta.changed {
        println!(
            "  ~ {}  {from:?} -> {to:?}{}",
            change.func,
            from = change.from,
            to = change.to,
            if strengthens_note(change.from, change.to) {
                "  (strengthened)"
            } else {
                ""
            }
        );
    }

    if delta.has_strengthening() {
        eprintln!("\nSECURITY REGRESSION: a capability was strengthened");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn strengthens_note(from: Right, to: Right) -> bool {
    matches!(
        (from, to),
        (Right::Read, Right::ReadWrite)
            | (Right::Read, Right::Write)
            | (Right::Write, Right::ReadWrite)
    )
}

fn new_project(name: &str) -> ExitCode {
    let templates = std::env::var("NEXUS_TEMPLATES")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("..")
                .join("templates")
        });

    let src = templates.join("ledger.telos");
    if !src.exists() {
        eprintln!("no templates found at {}", templates.display());
        return ExitCode::FAILURE;
    }

    let dest = PathBuf::from(format!("{name}.telos"));
    if let Err(e) = std::fs::copy(&src, &dest) {
        eprintln!("cannot write {}: {e}", dest.display());
        return ExitCode::FAILURE;
    }
    println!("scaffolded {} from template `ledger`", dest.display());
    println!("next: nexus verify {}", dest.display());
    ExitCode::SUCCESS
}
