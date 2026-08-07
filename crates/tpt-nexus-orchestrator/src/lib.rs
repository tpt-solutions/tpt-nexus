//! The nexus agentic loop: `.telos` intent in, attested artifact out.
//!
//! This crate is the INTENT → VERIFY → ATTEST half of the TPT closed loop. It
//! drives a [`CodeAgent`] through tpt-telos's generate/verify/repair cycle,
//! records every attempt, and produces a [`VerifiedArtifact`] whose existence
//! is itself the proof that the contracts hold. The other half — turning that
//! artifact into capability grants — lives in `tpt-nexus-archon-emulator`.
//!
//! ```text
//! [1. INTENT]   .telos contract source
//!       |
//!       v
//! [2. VERIFY]   tpt_telos_sdk::compile  -- parse, transpile, verify
//!       |
//!       +--(FAIL)--> [3. FEEDBACK] counterexample -> agent rewrite -> loop
//!       |
//!       v (SUCCESS)
//! [4. ATTEST]   ProofManifest (SHA-256 over the source bytes)
//!       |
//!       v
//!   VerifiedArtifact  ->  tpt-nexus-manifest-validator  ->  tpt-nexus-archon-emulator
//! ```
//!
//! # Relationship to tpt-telos
//!
//! Nexus is glue, not a reimplementation. [`tpt_telos_sdk::compile`] already
//! performs the mechanical pipeline, and `tpt_telos_agent::transpile_func`
//! already runs a bounded repair loop with counterexample feedback. What this
//! crate adds is the policy and observability layer around them:
//!
//! | Concern | Where it lives |
//! |---|---|
//! | Parse, transpile, verify, codegen, manifest | `tpt-telos-sdk` |
//! | Generate → counterexample → rewrite loop | `tpt-telos-agent` |
//! | Per-check hint text | [`tpt_telos_sdk::format_hint`] |
//! | Unverified contracts are a hard error | [`NexusError::ContractsUnsatisfied`] |
//! | Iteration budget policy | [`LoopController`] |
//! | Replayable run log | [`RunLog`] |
//! | Prompt assembly from history | [`FeedbackFormatter`] |
//! | Write-access derivation for Archon | [`FunctionRecord::mutates_state`] |
//!
//! # Example
//!
//! ```
//! use tpt_nexus_orchestrator::{NexusOrchestrator, StaticAgent};
//!
//! let intent = r#"
//!     module Bank {
//!         invariant Wallet { balance >= 0 }
//!         func withdraw(w: Wallet, amount: PositiveInt)
//!             requires w.balance >= amount
//!             ensures w.balance == old(w.balance) - amount
//!         {
//!             mutate state { w.balance += amount }   // deliberately wrong
//!         }
//!     }
//! "#;
//!
//! let artifact = NexusOrchestrator::new()
//!     .run_agent_loop(intent, &StaticAgent::new())
//!     .expect("the agentic loop repairs the body");
//!
//! // The first attempt failed; a counterexample drove the fix.
//! let withdraw = &artifact.functions()[0];
//! assert!(withdraw.was_repaired());
//! assert!(!withdraw.iterations[0].counterexample.is_empty());
//! assert!(artifact.all_verified());
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod context;
pub mod error;
pub mod feedback;
pub mod log;
pub mod loop_controller;
pub mod orchestrator;
pub mod report;

pub use context::{AgentContext, Bindings, FunctionRecord, IterationRecord};
pub use error::NexusError;
pub use feedback::{render_bindings, FeedbackFormatter};
pub use log::{NexusEvent, RunLog};
pub use loop_controller::{LoopController, LoopVerdict};
pub use orchestrator::{Attestation, BuildPolicy, NexusOrchestrator, VerifiedArtifact};
pub use report::RunReport;

// Re-exported so a consumer can drive the loop with only this crate in its
// dependency list, mirroring what `tpt-telos-sdk` does for tpt-telos.
#[cfg(feature = "llm")]
pub use tpt_telos_sdk::LlmAgent;
pub use tpt_telos_sdk::{CheckResult, CodeAgent, FuncOutcome, Model, ProofManifest, StaticAgent};
