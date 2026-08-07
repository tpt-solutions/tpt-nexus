//! Example 1 — Monotonic Timestamp Query.
//!
//! Proves the INTENT -> VERIFY -> FEEDBACK -> ATTEST -> VALIDATE half of the
//! closed loop, then hands the artifact to Archon for MINT -> EXECUTE.
//!
//! Run with:
//!
//! ```text
//! cargo run -p out-nexus-examples --example example1_monotonic_timestamp
//! ```

use std::process::ExitCode;

use out_nexus_examples::{banner, init_tracing, telos_source};
use tpt_nexus_archon_emulator::{ArchonEmulator, SyscallRequest};
use tpt_nexus_manifest_validator::validate_files;
use tpt_nexus_orchestrator::{FeedbackFormatter, NexusOrchestrator, StaticAgent};

fn main() -> ExitCode {
    init_tracing();

    let intent = telos_source("monotonic_timestamp.telos");

    banner("1. INTENT", "the .telos contract");
    println!("{}", intent.trim());

    banner("2-3. VERIFY / FEEDBACK", "the agentic loop");
    let artifact = match NexusOrchestrator::new().run_agent_loop(&intent, &StaticAgent::new()) {
        Ok(artifact) => artifact,
        Err(e) => {
            eprintln!("\nrun failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let formatter = FeedbackFormatter::new();
    for record in artifact.functions() {
        println!("{}", formatter.function(record));
    }

    println!("\n{}", formatter.summary(&artifact.report.context));

    banner("4. ATTEST", "the proof manifest");
    println!("source hash:   {}", artifact.manifest.source_hash);
    println!("manifest hash: {}", artifact.manifest.manifest_hash);
    println!("verified at:   {}", artifact.manifest.verified_at);
    for (name, proof) in &artifact.manifest.functions {
        println!(
            "  {name}: verified={} checks={}/{}",
            proof.verified, proof.conclusions_passed, proof.conclusions_checked
        );
    }

    let out_dir = std::path::Path::new("out/example1");
    let attestation = match artifact.write_attestation(out_dir) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("cannot write attestation: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("\nwritten to {}", out_dir.display());

    banner("5. VALIDATE", "independent re-check of the attestation");
    match validate_files(&attestation.manifest_path, &attestation.source_path) {
        Ok(report) => println!("{}", report.render()),
        Err(e) => {
            eprintln!("attestation does not hold: {e}");
            return ExitCode::FAILURE;
        }
    }

    banner("6. MINT", "capability grants derived from the manifest");
    let mut emulator = ArchonEmulator::new();
    let pid = match emulator.load_artifact(&artifact) {
        Ok(pid) => pid,
        Err(e) => {
            eprintln!("emulator refused the artifact: {e}");
            return ExitCode::FAILURE;
        }
    };
    let process = emulator.process(pid).expect("just loaded");
    println!("process {pid} `{}`", process.name);
    for grant in &process.grants {
        println!(
            "  page {:>2}  {:?}  <- {}",
            grant.block_id, grant.right, grant.func_name
        );
    }

    banner("7. EXECUTE", "capability-checked syscalls");
    let page = process
        .page_of("append_sample")
        .expect("append_sample was granted a page");

    // `append_sample` mutates window state, so it holds Right::ReadWrite.
    let sample = b"ts=1700000000;bytes=16".to_vec();
    match emulator.handle_syscall(
        pid,
        SyscallRequest::WritePage {
            block_id: page,
            data: sample.clone(),
        },
    ) {
        Ok(response) => println!(
            "write_page(page {page}) -> {} byte(s) written",
            response.written_len().unwrap_or(0)
        ),
        Err(e) => {
            eprintln!("unexpected denial: {e}");
            return ExitCode::FAILURE;
        }
    }

    match emulator.handle_syscall(pid, SyscallRequest::ReadPage { block_id: page }) {
        Ok(response) => {
            let bytes = response.as_page().unwrap_or_default();
            println!(
                "read_page(page {page})  -> {:?}",
                String::from_utf8_lossy(&bytes[..sample.len()])
            );
        }
        Err(e) => {
            eprintln!("unexpected denial: {e}");
            return ExitCode::FAILURE;
        }
    }

    // The zero-copy path: the closure borrows the page frame in place.
    let first_byte = emulator
        .with_page(pid, page, |page| page.as_bytes()[0])
        .expect("read capability held");
    println!("with_page(page {page}) -> first byte {first_byte:#04x} (borrowed, not copied)");

    banner("LOG", "observable agentic state");
    let log_path = out_dir.join("run.jsonl");
    if let Err(e) = artifact.report.log.write_jsonl(&log_path) {
        eprintln!("cannot write run log: {e}");
        return ExitCode::FAILURE;
    }
    println!(
        "{} event(s) written to {}",
        artifact.report.log.len(),
        log_path.display()
    );

    println!("\nExample 1 complete.");
    ExitCode::SUCCESS
}
