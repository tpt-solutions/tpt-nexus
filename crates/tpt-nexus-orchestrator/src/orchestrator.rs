//! [`NexusOrchestrator`]: the INTENT -> VERIFY -> ATTEST half of the closed loop.

use std::path::{Path, PathBuf};

use tpt_telos_sdk::{CodeAgent, ProofManifest};

use crate::context::{AgentContext, FunctionRecord};
use crate::error::NexusError;
use crate::log::{NexusEvent, RunLog};
use crate::loop_controller::{LoopController, LoopVerdict};
use crate::report::RunReport;

/// Whether a run shells out to `cargo` to produce real artifact bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BuildPolicy {
    /// Verify and attest only. `compiled_binary` comes back empty.
    ///
    /// The default, because it is hermetic and fast: no external toolchain, no
    /// filesystem writes, no network. Everything nexus is trying to prove about
    /// *verification* holds without invoking a compiler.
    #[default]
    Headless,
    /// Additionally write the generated project to a temporary directory and
    /// run `cargo build`, reading back the compiled Rust artifact.
    ///
    /// Required for a genuinely end-to-end demo, since spec.txt §6.1 defines
    /// `VerifiedArtifact::compiled_binary` as "the compiled Rust/Go code".
    Compile,
}

/// The final output of a successful agentic loop: verified, attested, and
/// (optionally) compiled.
///
/// Possession of this value is what authorizes capability minting in
/// `tpt-nexus-archon-emulator`. It cannot be constructed with unsatisfied
/// contracts — [`NexusOrchestrator::run_agent_loop`] returns
/// [`NexusError::ContractsUnsatisfied`] instead.
///
/// [`Debug`] is implemented by hand rather than derived: the wrapped
/// `tpt_telos_sdk::VerifiedArtifact` reaches `tpt_telos_agent::FuncOutcome`,
/// which is `Clone`-only. The hand-written impl prints the parts worth seeing
/// (hashes, function verdicts, sizes) and summarizes the rest.
#[derive(Clone)]
pub struct VerifiedArtifact {
    /// The final, verified `.telos` source.
    pub source_code: String,
    /// The cryptographic attestation over `source_code`.
    pub manifest: ProofManifest,
    /// Bytes of the compiled Rust artifact (`libgenerated_rust.rlib` / `.a`).
    ///
    /// Empty under [`BuildPolicy::Headless`].
    pub compiled_binary: Vec<u8>,
    /// The complete SDK pipeline output: parsed modules, per-function
    /// outcomes, and the generated dual-backend project.
    pub telos: tpt_telos_sdk::VerifiedArtifact,
    /// The run's iteration history and event log.
    pub report: RunReport,
}

/// Paths written by [`VerifiedArtifact::write_attestation`].
#[derive(Debug, Clone)]
pub struct Attestation {
    /// The `telos-proof.json` manifest.
    pub manifest_path: PathBuf,
    /// The `.telos` source the manifest attests to.
    pub source_path: PathBuf,
    /// The JSON-lines run log (every agent iteration + counterexample).
    pub run_log_path: PathBuf,
}

impl std::fmt::Debug for VerifiedArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedArtifact")
            .field("source_hash", &self.manifest.source_hash)
            .field("manifest_hash", &self.manifest.manifest_hash)
            .field("source_bytes", &self.source_code.len())
            .field("compiled_binary_bytes", &self.compiled_binary.len())
            .field("all_verified", &self.telos.all_verified)
            .field(
                "functions",
                &self
                    .report
                    .context
                    .functions
                    .iter()
                    .map(|r| (r.func_name.as_str(), r.verified, r.iterations.len()))
                    .collect::<Vec<_>>(),
            )
            .field("log_events", &self.report.log.len())
            .finish()
    }
}

impl VerifiedArtifact {
    /// Whether every function in the artifact verified.
    ///
    /// Always `true` for an artifact returned by
    /// [`NexusOrchestrator::run_agent_loop`]; exposed so downstream consumers
    /// can assert the invariant rather than assume it.
    pub fn all_verified(&self) -> bool {
        self.telos.all_verified
    }

    /// Per-function history, in pipeline order.
    pub fn functions(&self) -> &[FunctionRecord] {
        &self.report.context.functions
    }

    /// The attestation manifest as canonical JSON.
    ///
    /// Byte-exact: `tpt-telos` computes `manifest_hash` over this exact
    /// rendering, so reformatting it (for instance by round-tripping through
    /// another JSON library) invalidates the hash.
    pub fn manifest_json(&self) -> String {
        tpt_telos_codegen::proof::to_json(&self.manifest)
    }

    /// Write `telos-proof.json` and `source.telos` into `dir`.
    ///
    /// This materializes the [4. ATTEST] step of the state machine so that
    /// [5. VALIDATE] (`tpt-nexus-manifest-validator`) has real files to check.
    pub fn write_attestation(&self, dir: &Path) -> std::io::Result<Attestation> {
        std::fs::create_dir_all(dir)?;
        let manifest_path = dir.join("telos-proof.json");
        let source_path = dir.join("source.telos");
        let run_log_path = dir.join("run-log.jsonl");
        std::fs::write(&manifest_path, self.manifest_json())?;
        std::fs::write(&source_path, &self.source_code)?;
        // The "Observable Agentic State" trail is only useful if it lands next
        // to the attestation; otherwise the JSON-lines is serializable but never
        // persisted.
        std::fs::write(&run_log_path, self.report.to_jsonl())?;
        Ok(Attestation {
            manifest_path,
            source_path,
            run_log_path,
        })
    }

    /// Write the run log (one JSON object per agent iteration and event) to
    /// `dir/run-log.jsonl`, returning the path. See [`RunReport::to_jsonl`].
    pub fn write_run_log(&self, dir: &Path) -> std::io::Result<PathBuf> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("run-log.jsonl");
        std::fs::write(&path, self.report.to_jsonl())?;
        Ok(path)
    }
}

/// Drives a [`CodeAgent`] through tpt-telos's verify/repair loop and turns the
/// result into an attested [`VerifiedArtifact`].
///
/// This is the `Pipeline`-shaped struct spec.txt §6.1 sketched as
/// `telos_sdk::Pipeline`. tpt-telos now ships [`tpt_telos_sdk::compile`], which
/// covers the mechanical parse -> transpile -> codegen -> attest sequence, so
/// what nexus adds on top is the *policy* layer the SDK deliberately leaves to
/// its caller:
///
/// * unsatisfied contracts are a hard error, not a flag on a returned value;
/// * an iteration budget ([`LoopController`]) that a caller can tighten;
/// * a complete, replayable [`RunLog`] of the agent's reasoning;
/// * an on-disk attestation ready for independent validation.
#[derive(Debug, Clone)]
pub struct NexusOrchestrator {
    controller: LoopController,
    build: BuildPolicy,
}

impl Default for NexusOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

impl NexusOrchestrator {
    /// An orchestrator that verifies and attests, without invoking `cargo`.
    pub fn new() -> Self {
        Self {
            controller: LoopController::new(),
            build: BuildPolicy::Headless,
        }
    }

    /// Set whether the run shells out to `cargo` for real artifact bytes.
    pub fn with_build_policy(mut self, build: BuildPolicy) -> Self {
        self.build = build;
        self
    }

    /// Reject any function that needed more than `max_iterations` attempts.
    pub fn with_max_iterations(mut self, max_iterations: usize) -> Self {
        self.controller = LoopController::with_max_iterations(max_iterations);
        self
    }

    /// The configured iteration policy.
    pub fn controller(&self) -> LoopController {
        self.controller
    }

    /// The configured build policy.
    pub fn build_policy(&self) -> BuildPolicy {
        self.build
    }

    /// Run the closed loop over a `.telos` intent.
    ///
    /// `intent` is the `.telos` contract source. spec.txt §6.1 calls this
    /// parameter `initial_prompt`, imagining an agent that emits whole `.telos`
    /// files from a natural-language brief. The real
    /// [`CodeAgent`](tpt_telos_sdk::CodeAgent) contract is narrower and
    /// stronger: an agent proposes *function bodies* as typed `Stmt` trees
    /// against a fixed contract, which is why an agent can never produce
    /// unparseable output. The contract source is therefore the intent, and
    /// authoring it stays a human (or upstream-agent) responsibility.
    ///
    /// Stages, matching spec.txt §5:
    ///
    /// 1. **INTENT / VERIFY / FEEDBACK** — [`tpt_telos_sdk::compile`] parses the
    ///    source and runs tpt-telos's generate → verify → counterexample →
    ///    rewrite loop per function.
    /// 2. **Policy** — every function's history is classified by
    ///    [`LoopController`]; unverified functions or budget overruns abort.
    /// 3. **ATTEST** — the proof manifest over the source bytes is retained.
    /// 4. **Build** (optional) — the generated Rust project is compiled and its
    ///    artifact bytes captured.
    ///
    /// # Errors
    ///
    /// * [`NexusError::Pipeline`] — the source did not parse, or the agent or
    ///   code generator failed.
    /// * [`NexusError::ContractsUnsatisfied`] — the loop ran but a contract was
    ///   never satisfied. Carries the full [`RunReport`].
    /// * [`NexusError::IterationBudgetExceeded`] — a function verified, but
    ///   needed more attempts than allowed.
    /// * [`NexusError::Build`] — `cargo` ran and failed.
    ///
    /// # Examples
    ///
    /// ```
    /// use tpt_nexus_orchestrator::{NexusOrchestrator, StaticAgent};
    ///
    /// let intent = r#"
    ///     module Counter {
    ///         invariant Counter { value >= 0 }
    ///         func increment(c: Counter, by: PositiveInt)
    ///             requires c.value >= 0
    ///             ensures c.value == old(c.value) + by
    ///         ;
    ///     }
    /// "#;
    ///
    /// let artifact = NexusOrchestrator::new()
    ///     .run_agent_loop(intent, &StaticAgent::new())
    ///     .expect("contracts hold");
    ///
    /// assert!(artifact.all_verified());
    /// assert!(artifact.manifest.source_hash.starts_with("sha256:"));
    /// ```
    pub fn run_agent_loop(
        &self,
        intent: &str,
        agent: &dyn CodeAgent,
    ) -> Result<VerifiedArtifact, NexusError> {
        let mut log = RunLog::new();
        log.record(NexusEvent::RunStarted {
            agent: agent.name().to_string(),
            source_bytes: intent.len(),
        });

        // [1. INTENT] -> [2. VERIFY] -> [3. FEEDBACK], all inside tpt-telos.
        // The verifier can panic (e.g. a read-only body that assigns to a bare
        // local, which telos's IR rejects on re-extraction); catch it so the
        // whole run fails cleanly with a hint instead of unwinding out of nexus.
        let compiled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tpt_telos_sdk::compile(intent, agent)
        }));
        let telos = match compiled {
            Ok(Ok(artifact)) => artifact,
            Ok(Err(e)) => {
                log.record(NexusEvent::RunFailed {
                    reason: e.to_string(),
                });
                return Err(NexusError::Pipeline(e));
            }
            Err(payload) => {
                let reason = panic_message(&payload);
                log.record(NexusEvent::RunFailed {
                    reason: reason.clone(),
                });
                return Err(NexusError::Panic(reason));
            }
        };

        let context = AgentContext::from_outcomes(intent, &telos.outcomes);

        // Replay tpt-telos's own iteration history into the event log. This is
        // the "Observable Agentic State" requirement: one event per attempt,
        // including the candidate source and the counterexample that rejected
        // it.
        for record in &context.functions {
            for step in &record.iterations {
                log.record(NexusEvent::Iteration {
                    record: step.clone(),
                });
            }
        }

        // [Policy] Classify each function against the iteration budget.
        let mut verdicts: Vec<(String, LoopVerdict)> = Vec::new();
        for record in &context.functions {
            let verdict = self.controller.assess(record);
            log.record(NexusEvent::FunctionCompleted {
                func_name: record.func_name.clone(),
                target: record.target.clone(),
                verified: record.verified,
                mutates_state: record.mutates_state,
                iterations: record.iterations.len(),
                repaired: record.was_repaired(),
                verdict: format!("{verdict:?}"),
            });
            verdicts.push((record.func_name.clone(), verdict));
        }

        if !context.all_verified() {
            let hints = context.failure_hints();
            log.record(NexusEvent::RunFailed {
                reason: format!(
                    "{} function(s) unverified",
                    context.failed_functions().len()
                ),
            });
            return Err(NexusError::ContractsUnsatisfied {
                hints,
                report: Box::new(RunReport::new(context, log)),
            });
        }

        if let Some((func_name, verdict)) = verdicts
            .iter()
            .find(|(_, v)| matches!(v, LoopVerdict::BudgetExceeded { .. }))
        {
            let LoopVerdict::BudgetExceeded { iterations, budget } = verdict else {
                unreachable!("filtered to BudgetExceeded above")
            };
            log.record(NexusEvent::RunFailed {
                reason: format!("`{func_name}` exceeded the iteration budget"),
            });
            return Err(NexusError::IterationBudgetExceeded {
                func_name: func_name.clone(),
                iterations: *iterations,
                budget: *budget,
            });
        }

        // [4. ATTEST]
        log.record(NexusEvent::Attested {
            source_hash: telos.manifest.source_hash.clone(),
            manifest_hash: telos.manifest.manifest_hash.clone(),
            functions: telos.manifest.functions.len(),
        });

        // [Build] Optional: real compiled bytes.
        let compiled_binary = match self.build {
            BuildPolicy::Headless => Vec::new(),
            BuildPolicy::Compile => {
                log.record(NexusEvent::BuildStarted { backend: "rust" });
                let output = match tpt_telos_sdk::compile_project_tempdir(&telos) {
                    Ok(output) => output,
                    Err(e) => {
                        log.record(NexusEvent::RunFailed {
                            reason: e.to_string(),
                        });
                        return Err(NexusError::Build(e.to_string()));
                    }
                };
                let bytes = output.rust_artifact_bytes.unwrap_or_default();
                log.record(NexusEvent::BuildCompleted {
                    backend: "rust",
                    success: output.success,
                    artifact_bytes: bytes.len(),
                });
                if !output.success {
                    return Err(NexusError::Build(
                        "generated project failed to compile".to_string(),
                    ));
                }
                bytes
            }
        };

        log.record(NexusEvent::RunCompleted {
            all_verified: true,
            functions: context.functions.len(),
            total_iterations: context.total_iterations(),
        });

        let manifest = telos.manifest.clone();
        Ok(VerifiedArtifact {
            source_code: intent.to_string(),
            manifest,
            compiled_binary,
            telos,
            report: RunReport::new(context, log),
        })
    }

    /// Convenience wrapper: read a `.telos` file and run the loop over it.
    pub fn run_agent_loop_from_file(
        &self,
        path: &Path,
        agent: &dyn CodeAgent,
    ) -> Result<VerifiedArtifact, NexusError> {
        let intent = std::fs::read_to_string(path)?;
        self.run_agent_loop(&intent, agent)
    }
}

/// Best-effort rendering of a panic payload into a message.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "the telos verifier panicked with a non-string payload".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpt_telos_sdk::StaticAgent;

    const INTENT: &str = r#"
        module Counter {
            invariant Counter { value >= 0 }
            func increment(c: Counter, by: PositiveInt)
                requires c.value >= 0
                ensures c.value == old(c.value) + by
            ;
        }
    "#;

    /// A body that adds instead of subtracting: the loop must notice and repair.
    const BROKEN_INTENT: &str = r#"
        module Broken {
            invariant Wallet { balance >= 0 }
            func withdraw(w: Wallet, amount: PositiveInt)
                requires w.balance >= amount
                ensures w.balance == old(w.balance) - amount
            {
                mutate state {
                    w.balance += amount
                }
            }
        }
    "#;

    /// Two postconditions on one field that cannot both hold.
    const UNSATISFIABLE_INTENT: &str = r#"
        module M {
            invariant Counter { v >= 0 }
            func f(c: Counter)
                ensures c.v == 0
                ensures c.v == 1
            {
                mutate state { c.v = 0 }
            }
        }
    "#;

    #[test]
    fn verified_intent_produces_an_attested_artifact() {
        let artifact = NexusOrchestrator::new()
            .run_agent_loop(INTENT, &StaticAgent::new())
            .expect("counter contract holds");

        assert!(artifact.all_verified());
        assert_eq!(artifact.source_code, INTENT);
        assert!(artifact.manifest.source_hash.starts_with("sha256:"));
        assert!(!artifact.manifest.manifest_hash.is_empty());
        assert_eq!(artifact.functions().len(), 1);
        assert_eq!(artifact.functions()[0].func_name, "increment");
        // Headless is the default: no cargo invoked, so no bytes.
        assert!(artifact.compiled_binary.is_empty());
    }

    #[test]
    fn synthesized_mutator_is_recognized_as_writing_state() {
        let artifact = NexusOrchestrator::new()
            .run_agent_loop(INTENT, &StaticAgent::new())
            .unwrap();
        assert!(
            artifact.functions()[0].mutates_state,
            "increment writes c.value, so it needs write access"
        );
    }

    #[test]
    fn unsatisfiable_contract_is_an_error_not_an_artifact() {
        let err = NexusOrchestrator::new()
            .run_agent_loop(UNSATISFIABLE_INTENT, &StaticAgent::new())
            .expect_err("contradictory postconditions cannot verify");

        match err {
            NexusError::ContractsUnsatisfied { hints, report } => {
                assert!(!hints.is_empty(), "failure hints must be surfaced");
                assert!(hints.iter().any(|h| h.contains("FAILED")));
                // The full history survives the failure path.
                assert!(!report.log.is_empty());
                assert_eq!(report.context.failed_functions().len(), 1);
            }
            other => panic!("expected ContractsUnsatisfied, got {other:?}"),
        }
    }

    #[test]
    fn parse_failure_surfaces_as_a_pipeline_error() {
        let err = NexusOrchestrator::new()
            .run_agent_loop("this is not telos source", &StaticAgent::new())
            .expect_err("garbage must not parse");
        assert!(matches!(err, NexusError::Pipeline(_)), "got {err:?}");
    }

    #[test]
    fn broken_body_is_repaired_and_the_history_shows_it() {
        let artifact = NexusOrchestrator::new()
            .run_agent_loop(BROKEN_INTENT, &StaticAgent::new())
            .expect("the loop repairs the body");

        let record = &artifact.functions()[0];
        assert!(record.verified);
        assert!(
            record.was_repaired(),
            "expected fail-then-fix, got iterations: {:?}",
            record
                .iterations
                .iter()
                .map(|s| (s.iteration, &s.action, s.passed))
                .collect::<Vec<_>>()
        );
        assert!(!record.first_attempt_passed());
        // The counterexample that drove the repair is retained.
        let first = &record.iterations[0];
        assert!(!first.counterexample.is_empty());
    }

    #[test]
    fn tight_iteration_budget_rejects_a_repaired_function() {
        let err = NexusOrchestrator::new()
            .with_max_iterations(1)
            .run_agent_loop(BROKEN_INTENT, &StaticAgent::new())
            .expect_err("repair needs more than one iteration");

        match err {
            NexusError::IterationBudgetExceeded {
                func_name,
                iterations,
                budget,
            } => {
                assert_eq!(func_name, "withdraw");
                assert!(iterations > budget);
                assert_eq!(budget, 1);
            }
            other => panic!("expected IterationBudgetExceeded, got {other:?}"),
        }
    }

    #[test]
    fn run_log_captures_every_iteration() {
        let artifact = NexusOrchestrator::new()
            .run_agent_loop(BROKEN_INTENT, &StaticAgent::new())
            .unwrap();

        let logged = artifact.report.log.events_of_kind("iteration").count();
        assert_eq!(logged, artifact.report.context.total_iterations());
        assert!(logged >= 2, "a repair implies at least two attempts");

        // The log round-trips to JSON-lines.
        let jsonl = artifact.report.to_jsonl();
        assert_eq!(jsonl.lines().count(), artifact.report.log.len());
    }

    #[test]
    fn attestation_is_written_to_disk() {
        let artifact = NexusOrchestrator::new()
            .run_agent_loop(INTENT, &StaticAgent::new())
            .unwrap();

        let dir = std::env::temp_dir().join(format!(
            "nexus-attest-test-{}-{}",
            std::process::id(),
            line!()
        ));
        let attestation = artifact.write_attestation(&dir).unwrap();

        let manifest_json = std::fs::read_to_string(&attestation.manifest_path).unwrap();
        let source = std::fs::read_to_string(&attestation.source_path).unwrap();
        assert_eq!(source, INTENT);
        assert!(manifest_json.contains("source_hash"));
        // The written manifest is byte-exact with what the hash covers.
        assert_eq!(manifest_json, artifact.manifest_json());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn build_policy_defaults_to_headless() {
        let orchestrator = NexusOrchestrator::new();
        assert_eq!(orchestrator.build_policy(), BuildPolicy::Headless);
        assert_eq!(
            orchestrator.controller().max_iterations,
            LoopController::TELOS_INTERNAL_MAX_ITERATIONS
        );
    }

    /// Regression test for the upstream telos fix: a read-only body that reads
    /// into a bare local (`out = a.balance`) now verifies instead of panicking
    /// on IR re-extraction. It must still be derived as `Read` (not a mutation).
    #[test]
    fn read_only_bare_local_verifies_as_read() {
        const BARE_LOCAL: &str = r#"
            module M {
                invariant Account { balance >= 0 }
                func snapshot(a: Account, out: Int)
                    requires a.balance >= 0
                    ensures out == a.balance
                {
                    out = a.balance
                }
            }
        "#;

        let artifact = NexusOrchestrator::new()
            .run_agent_loop(BARE_LOCAL, &StaticAgent::new())
            .expect("upstream telos accepts a bare-local read now");
        let record = &artifact.functions()[0];
        assert!(record.verified);
        assert!(
            !record.mutates_state,
            "a bare-local read is not a struct-field mutation, so it earns Read"
        );
    }

    #[test]
    fn attestation_writes_the_run_log_beside_the_manifest() {
        let artifact = NexusOrchestrator::new()
            .run_agent_loop(INTENT, &StaticAgent::new())
            .unwrap();

        let dir = std::env::temp_dir().join(format!(
            "nexus-runlog-test-{}-{}",
            std::process::id(),
            line!()
        ));
        let attestation = artifact.write_attestation(&dir).unwrap();

        let run_log = std::fs::read_to_string(&attestation.run_log_path).unwrap();
        // The run log is JSON-lines: one object per recorded event.
        assert!(run_log.lines().count() >= 2, "expected a non-empty run log");
        assert!(run_log.contains("iteration") || run_log.contains("RunStarted"));

        // `write_run_log` independently writes the same content.
        let standalone = artifact.write_run_log(&dir).unwrap();
        assert_eq!(
            std::fs::read_to_string(&standalone).unwrap(),
            run_log
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
