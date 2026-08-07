//! Example 3 — Compiled Artifact.
//!
//! Demonstrates `BuildPolicy::Compile`: the generated Rust crate is actually
//! built with `cargo` and the compiled artifact bytes are carried on the
//! [`VerifiedArtifact`] (`image_bytes > 0`).
//!
//! Run with:
//!
//! ```text
//! cargo run -p out-nexus-examples --example example3_compiled_artifact
//! ```

use std::process::ExitCode;

use out_nexus_examples::{banner, init_tracing, telos_source};
use tpt_nexus_orchestrator::{BuildPolicy, NexusOrchestrator, StaticAgent};

fn main() -> ExitCode {
    init_tracing();

    let intent = telos_source("compiled_artifact.telos");

    banner("1-4. INTENT..ATTEST", "verify + attest (headless)");
    let artifact = match NexusOrchestrator::new()
        .with_build_policy(BuildPolicy::Compile)
        .run_agent_loop(&intent, &StaticAgent::new())
    {
        Ok(artifact) => artifact,
        // `cargo` is what runs this example, so it is present; if for some
        // reason the generated crate fails to build, report it loudly.
        Err(e) => {
            eprintln!("\nrun failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    assert!(
        artifact.all_verified(),
        "the fixture must verify before it can be compiled"
    );

    banner("4b. COMPILE", "cargo build the generated Rust crate");
    let bytes = artifact.compiled_binary.len();
    println!("compiled artifact: {bytes} byte(s)");
    if bytes == 0 {
        eprintln!("SECURITY/BUILD FAILURE: Compile policy produced no bytes");
        return ExitCode::FAILURE;
    }
    println!(
        "  first 8 bytes: {:02x?}",
        &artifact.compiled_binary[..bytes.min(8)]
    );

    banner("SUMMARY", "what the closed loop produced");
    println!("  verified functions : {}", artifact.functions().len());
    println!("  source hash        : {}", artifact.manifest.source_hash);
    println!("  manifest hash      : {}", artifact.manifest.manifest_hash);
    println!("  compiled artifact  : {bytes} byte(s)");

    println!("\nExample 3 complete: a verified .telos program is now a compiled artifact.");
    ExitCode::SUCCESS
}
