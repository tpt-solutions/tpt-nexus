//! Example 2 — Capability Boundary Test.
//!
//! Proves the [6. MINT] -> [7. EXECUTE] half of the loop enforces least
//! privilege: a function that was never proved to write state is granted
//! read-only access, and an attempt to write through that grant is refused by
//! tpt-archon's capability check.
//!
//! Run with:
//!
//! ```text
//! cargo run -p out-nexus-examples --example example2_capability_boundary
//! ```

use std::process::ExitCode;

use out_nexus_examples::{banner, init_tracing, telos_source};
use tpt_nexus_archon_emulator::{ArchonEmulator, ArchonError, Right, SyscallRequest};
use tpt_nexus_orchestrator::{NexusOrchestrator, StaticAgent};

fn main() -> ExitCode {
    init_tracing();

    let intent = telos_source("capability_boundary.telos");

    banner("1-4. INTENT..ATTEST", "verify both functions");
    let artifact = match NexusOrchestrator::new().run_agent_loop(&intent, &StaticAgent::new()) {
        Ok(artifact) => artifact,
        Err(e) => {
            eprintln!("run failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    for record in artifact.functions() {
        println!(
            "  {:<16} verified={}  mutates_state={}",
            record.func_name, record.verified, record.mutates_state
        );
    }

    banner("6. MINT", "rights derived from what was proved");
    let mut emulator = ArchonEmulator::new();
    let pid = match emulator.load_artifact(&artifact) {
        Ok(pid) => pid,
        Err(e) => {
            eprintln!("emulator refused the artifact: {e}");
            return ExitCode::FAILURE;
        }
    };

    let process = emulator.process(pid).expect("just loaded");
    for grant in &process.grants {
        println!(
            "  page {:>2}  {:?}  <- {}",
            grant.block_id, grant.right, grant.func_name
        );
    }

    let settle_page = process
        .page_of("settle")
        .expect("settle was granted a page");
    let query_page = process
        .page_of("current_balance")
        .expect("current_balance was granted a page");

    // Confirm the derivation actually produced different rights, so the denial
    // below is meaningful rather than accidental.
    let settle_right = process.grant_for(settle_page).map(|g| g.right);
    let query_right = process.grant_for(query_page).map(|g| g.right);
    assert_eq!(settle_right, Some(Right::ReadWrite), "settle mutates state");
    assert_eq!(query_right, Some(Right::Read), "current_balance is a query");

    banner("7. EXECUTE", "the mutator writes; the query may not");

    // Permitted: `settle` holds ReadWrite over its own page.
    match emulator.handle_syscall(
        pid,
        SyscallRequest::WritePage {
            block_id: settle_page,
            data: b"balance=100".to_vec(),
        },
    ) {
        Ok(response) => println!(
            "  ALLOWED  write_page(page {settle_page}) -> {} byte(s)  [settle: ReadWrite]",
            response.written_len().unwrap_or(0)
        ),
        Err(e) => {
            eprintln!("  settle's write was unexpectedly denied: {e}");
            return ExitCode::FAILURE;
        }
    }

    // Permitted: reading through a read-only grant is exactly what it is for.
    match emulator.handle_syscall(
        pid,
        SyscallRequest::ReadPage {
            block_id: query_page,
        },
    ) {
        Ok(response) => println!(
            "  ALLOWED  read_page(page {query_page})  -> {} byte(s)  [current_balance: Read]",
            response.as_page().map(<[u8]>::len).unwrap_or(0)
        ),
        Err(e) => {
            eprintln!("  the query's read was unexpectedly denied: {e}");
            return ExitCode::FAILURE;
        }
    }

    // Denied: the whole point. The process holds a capability for this page,
    // but only a read one.
    let attempted = emulator.handle_syscall(
        pid,
        SyscallRequest::WritePage {
            block_id: query_page,
            data: b"balance=999999".to_vec(),
        },
    );
    match attempted {
        Err(ArchonError::CapabilityViolation {
            pid: violating_pid,
            block_id,
            attempted,
            held,
        }) => {
            println!(
                "  DENIED   write_page(page {block_id}) -> CapabilityViolation \
                 (pid {violating_pid} attempted {attempted:?}, holds {held:?})"
            );
        }
        Err(other) => {
            eprintln!("  expected CapabilityViolation, got a different error: {other}");
            return ExitCode::FAILURE;
        }
        Ok(_) => {
            eprintln!("  SECURITY FAILURE: a read-only capability permitted a write");
            return ExitCode::FAILURE;
        }
    }

    // Also denied: a page this process was never granted at all.
    let ungranted = emulator.handle_syscall(
        pid,
        SyscallRequest::ReadPage {
            block_id: emulator.page_count() - 1,
        },
    );
    match ungranted {
        Err(ArchonError::CapabilityViolation { held: None, .. }) => {
            println!("  DENIED   read_page(ungranted page) -> CapabilityViolation (holds nothing)")
        }
        other => {
            eprintln!("  expected a capability violation for an ungranted page, got {other:?}");
            return ExitCode::FAILURE;
        }
    }

    banner("REVOKE", "termination invalidates every held capability");
    if let Err(e) = emulator.terminate(pid) {
        eprintln!("cannot terminate: {e}");
        return ExitCode::FAILURE;
    }
    match emulator.handle_syscall(
        pid,
        SyscallRequest::ReadPage {
            block_id: settle_page,
        },
    ) {
        Err(ArchonError::ProcessNotFound(_)) => {
            println!("  DENIED   read_page after terminate -> ProcessNotFound")
        }
        other => {
            eprintln!("  expected ProcessNotFound after termination, got {other:?}");
            return ExitCode::FAILURE;
        }
    }

    println!("\nExample 2 complete: the boundary held.");
    ExitCode::SUCCESS
}
