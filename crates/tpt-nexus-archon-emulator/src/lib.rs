//! Capability-gated execution for attested tpt-telos artifacts.
//!
//! This crate is the [5. VALIDATE] → [6. MINT] → [7. EXECUTE] half of the TPT
//! closed loop. It takes a
//! [`VerifiedArtifact`](tpt_nexus_orchestrator::VerifiedArtifact) produced by
//! `tpt-nexus-orchestrator`, re-checks its attestation, derives capability
//! grants from what was actually proved, and services syscalls against them.
//!
//! ```text
//!   VerifiedArtifact
//!         |
//!         v
//! [5. VALIDATE]  re-hash source + manifest        -> InvalidAttestation
//!         |
//!         v
//! [6. MINT]      CapabilityIssuer::mint per verified function
//!         |                Right::ReadWrite if it mutates state, else Read
//!         v
//! [7. EXECUTE]   handle_syscall -> UnifiedMemory::map_read / map_write
//!                                 -> CapabilityViolation on denial
//! ```
//!
//! # Design stance: wrap, don't reimplement
//!
//! spec.txt §4.2 specified a `CSlotTable` of opaque `u64` tokens, an
//! `EmulatedPageTable`, and `MemoryView`s built from raw pointers, because at
//! the time it was written Archon looked like something you needed hardware to
//! run. That is no longer true, and building those would mean shipping a second
//! security model weaker than the real one. Concretely:
//!
//! | spec.txt §4.2 / §7 | Reality in tpt-archon | Consequence for nexus |
//! |---|---|---|
//! | `CSlotTable` of `u64` indices | `Capability` — private fields, mintable only by `CapabilityIssuer` | Tokens are unforgeable by construction; no table to protect |
//! | `MemoryView` = pointer + length | `MemoryView`/`&Page` — safe borrowed slices, "no new unsafe code or raw pointers" | Nexus adds no `unsafe`; the crate is `#![forbid(unsafe_code)]` |
//! | `ReadOnly` / `ReadWrite` | `Right::Read` / `Write` / `ReadWrite` | Three rights, and `Right::Write` is write-only, not implied by read |
//! | `EmulatedPageTable` bounds checks | `BufferPool` + `InMemoryBlockDevice` | Bounds enforced upstream; nexus only reports them |
//! | `CapabilityGrant::map_page()` | `grant_read` / `grant_write`, or `map_read` / `map_write` | Nexus uses the kernel's `UnifiedMemory` |
//!
//! What genuinely did not exist upstream — and is therefore what this crate
//! actually contributes — is the process and syscall framing:
//! `tpt_archon_kernel::scheduler` owns tasks with no lookup and no identity,
//! and `Capability` is a bearer token with no owner. [`ArchonEmulator`] adds a
//! process table over the scheduler's own ids, a per-process capability set,
//! and a value-returning syscall boundary.
//!
//! # Example
//!
//! ```no_run
//! use tpt_nexus_archon_emulator::{ArchonEmulator, ArchonError, SyscallRequest};
//! use tpt_nexus_orchestrator::{NexusOrchestrator, StaticAgent};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let intent = std::fs::read_to_string("examples/capability_boundary.telos")?;
//! let artifact = NexusOrchestrator::new().run_agent_loop(&intent, &StaticAgent::new())?;
//!
//! let mut emulator = ArchonEmulator::new();
//! let pid = emulator.load_artifact(&artifact)?;
//!
//! // A function that never mutates state was granted `Right::Read` only.
//! let page = emulator.process(pid).unwrap().page_of("current_balance").unwrap();
//! let denied = emulator.handle_syscall(pid, SyscallRequest::WritePage {
//!     block_id: page,
//!     data: vec![0xFF],
//! });
//! assert!(matches!(denied, Err(ArchonError::CapabilityViolation { .. })));
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod emulator;
pub mod error;
pub mod process;
pub mod syscall;

pub use emulator::{derive_rights, page_of, ArchonEmulator};
pub use error::ArchonError;
pub use process::{Grant, Process, ProcessId};
pub use syscall::{SyscallRequest, SyscallResponse};

// Re-exported so a consumer can reason about grants without adding tpt-archon
// to its own dependency list.
pub use tpt_archon_bridge::capability::{Capability, Resource, Right};
pub use tpt_archon_core::page::PAGE_SIZE;
