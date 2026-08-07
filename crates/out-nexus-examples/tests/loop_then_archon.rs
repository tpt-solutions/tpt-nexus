//! End-to-end integration test: the whole loop, from one `.telos` fixture,
//! through verify -> attest -> validate -> mint -> execute, against the real
//! tpt-telos and tpt-archon crates (no mocks).
//!
//! This is the executable form of the two runnable examples. The examples are
//! meant to be read; this is meant to pass in CI.

use out_nexus_examples::telos_source;
use tpt_nexus_archon_emulator::{ArchonEmulator, ArchonError, Right, SyscallRequest};
use tpt_nexus_orchestrator::{NexusOrchestrator, StaticAgent};

#[test]
fn full_loop_mints_and_enforces_capabilities() {
    let intent = telos_source("capability_boundary.telos");

    // 1-4. INTENT -> COMPILE -> VERIFY -> ATTEST
    let artifact = NexusOrchestrator::new()
        .run_agent_loop(&intent, &StaticAgent::new())
        .expect("the fixture verifies");
    assert!(artifact.all_verified());
    assert_eq!(artifact.functions().len(), 2);

    let settle = artifact
        .functions()
        .iter()
        .find(|f| f.func_name == "settle")
        .expect("settle recorded");
    let query = artifact
        .functions()
        .iter()
        .find(|f| f.func_name == "current_balance")
        .expect("current_balance recorded");
    assert!(settle.mutates_state, "settle writes state");
    assert!(!query.mutates_state, "current_balance is a read-only query");

    // 5. VALIDATE — re-derive the manifest hash and confirm it matches source.
    let verification = tpt_nexus_manifest_validator::validate_bytes(
        std::path::Path::new("<mem>/proof.json"),
        std::path::Path::new("<mem>/source.telos"),
        &artifact.manifest_json(),
        artifact.source_code.as_bytes(),
    );
    assert!(
        verification.is_valid(),
        "attestation must be self-consistent"
    );

    // 6. MINT — load into the Archon emulator.
    let mut emulator = ArchonEmulator::new();
    let pid = emulator.load_artifact(&artifact).expect("artifact loads");
    let process = emulator.process(pid).expect("loaded process exists");
    assert_eq!(process.grants.len(), 2);

    let settle_page = process.page_of("settle").expect("settle has a page");
    let query_page = process
        .page_of("current_balance")
        .expect("query has a page");
    assert_eq!(
        process.grant_for(settle_page).unwrap().right,
        Right::ReadWrite,
        "mutator earns write access"
    );
    assert_eq!(
        process.grant_for(query_page).unwrap().right,
        Right::Read,
        "query earns read-only access"
    );

    // 7. EXECUTE — permitted operations succeed, forbidden ones are refused by
    // tpt-archon itself.
    emulator
        .handle_syscall(
            pid,
            SyscallRequest::WritePage {
                block_id: settle_page,
                data: b"balance=100".to_vec(),
            },
        )
        .expect("settle's write is permitted");

    emulator
        .handle_syscall(
            pid,
            SyscallRequest::ReadPage {
                block_id: query_page,
            },
        )
        .expect("query's read is permitted");

    let forbidden = emulator.handle_syscall(
        pid,
        SyscallRequest::WritePage {
            block_id: query_page,
            data: b"balance=0".to_vec(),
        },
    );
    match forbidden {
        Err(ArchonError::CapabilityViolation { held, .. }) => {
            assert_eq!(held, Some(Right::Read), "the held right is the read one");
        }
        other => panic!("a read-only grant must refuse a write, got {other:?}"),
    }

    let ungranted = emulator.handle_syscall(
        pid,
        SyscallRequest::ReadPage {
            block_id: emulator.page_count() - 1,
        },
    );
    assert!(
        matches!(
            ungranted,
            Err(ArchonError::CapabilityViolation { held: None, .. })
        ),
        "a never-granted page is denied for holding nothing"
    );

    // REVOKE — termination removes the process entirely.
    emulator.terminate(pid).expect("terminate succeeds");
    assert!(
        emulator.process(pid).is_none(),
        "process gone after terminate"
    );
}
