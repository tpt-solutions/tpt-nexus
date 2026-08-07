//! Observable Agentic State: the structured run log.
//!
//! spec.txt §3 requires that "every iteration of the agent's code, every
//! failure, and every counterexample must be logged to reconstruct the
//! 'thought process' of the agent". This module is that guarantee, and it
//! answers TODO §6's two open questions:
//!
//! * **Logging approach** — `tracing`, so a host application can route nexus
//!   events into whatever subscriber it already runs, with no sink plumbing
//!   in nexus's own API.
//! * **Sink/format** — *both*. Every event is emitted as a `tracing` event
//!   (human-readable console) *and* retained in a [`RunLog`] that serializes to
//!   JSON-lines ([`RunLog::to_jsonl`]), so a run can be replayed after the fact.
//!
//! The third requirement — that formatter output and log output cannot drift —
//! is met structurally rather than by convention: [`NexusEvent::Iteration`]
//! carries the very same [`IterationRecord`] value that
//! [`FeedbackFormatter::iteration`](crate::FeedbackFormatter::iteration)
//! renders. There is one struct, constructed once per iteration in
//! [`AgentContext::from_outcomes`](crate::AgentContext::from_outcomes); the
//! prompt text and the JSON line are two views of it, not two derivations.

use std::io::Write;
use std::path::Path;

use serde::Serialize;

use crate::context::IterationRecord;

/// A single structured event in a nexus run.
///
/// Serializes with an `event` tag discriminator, so a JSON-lines file can be
/// filtered with `jq 'select(.event == "iteration")'` without a schema.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum NexusEvent {
    /// [1. INTENT] A run began.
    RunStarted {
        /// The agent servicing the run.
        agent: String,
        /// Size of the `.telos` intent, in bytes.
        source_bytes: usize,
    },
    /// [2. VERIFY] / [3. FEEDBACK] One turn of the agentic loop.
    ///
    /// Flattened so iteration fields sit at the top level of the JSON line
    /// alongside `event`, which is what makes the log greppable.
    #[serde(rename = "iteration")]
    Iteration {
        /// The iteration, shared verbatim with the feedback formatter.
        #[serde(flatten)]
        record: IterationRecord,
    },
    /// A function reached a final state, verified or not.
    FunctionCompleted {
        /// The function.
        func_name: String,
        /// Backend the router selected.
        target: String,
        /// Whether its contracts hold.
        verified: bool,
        /// Whether the accepted body writes a struct field.
        mutates_state: bool,
        /// Loop turns consumed.
        iterations: usize,
        /// True when the loop failed at least once before succeeding.
        repaired: bool,
        /// The [`LoopVerdict`](crate::LoopVerdict), rendered.
        verdict: String,
    },
    /// [4. ATTEST] A proof manifest was produced.
    Attested {
        /// `sha256:` digest of the source bytes.
        source_hash: String,
        /// `sha256:` digest of the manifest document.
        manifest_hash: String,
        /// Functions recorded in the manifest.
        functions: usize,
    },
    /// The generated project was handed to `cargo`.
    BuildStarted {
        /// Backend being built.
        backend: &'static str,
    },
    /// `cargo` finished.
    BuildCompleted {
        /// Backend that was built.
        backend: &'static str,
        /// Whether the build succeeded.
        success: bool,
        /// Size of the artifact read back, in bytes.
        artifact_bytes: usize,
    },
    /// The run ended.
    RunCompleted {
        /// Whether every function verified.
        all_verified: bool,
        /// Functions processed.
        functions: usize,
        /// Loop turns across all functions.
        total_iterations: usize,
    },
    /// The run ended in an error.
    RunFailed {
        /// Human-readable cause.
        reason: String,
    },
}

impl NexusEvent {
    /// The event's discriminator, matching the serialized `event` field.
    pub fn kind(&self) -> &'static str {
        match self {
            NexusEvent::RunStarted { .. } => "run_started",
            NexusEvent::Iteration { .. } => "iteration",
            NexusEvent::FunctionCompleted { .. } => "function_completed",
            NexusEvent::Attested { .. } => "attested",
            NexusEvent::BuildStarted { .. } => "build_started",
            NexusEvent::BuildCompleted { .. } => "build_completed",
            NexusEvent::RunCompleted { .. } => "run_completed",
            NexusEvent::RunFailed { .. } => "run_failed",
        }
    }
}

/// The complete, ordered event stream of one run.
///
/// Retained in memory and returned on both the success and failure paths, so
/// the agent's reasoning is reconstructable either way.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RunLog {
    /// Every recorded event, in order.
    pub events: Vec<NexusEvent>,
}

impl RunLog {
    /// An empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an event, mirroring it to `tracing` as it goes.
    pub fn record(&mut self, event: NexusEvent) {
        emit_tracing(&event);
        self.events.push(event);
    }

    /// Number of recorded events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether nothing has been recorded.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Every event of a given kind, e.g. `"iteration"`.
    pub fn events_of_kind<'a>(
        &'a self,
        kind: &'a str,
    ) -> impl Iterator<Item = &'a NexusEvent> + 'a {
        self.events.iter().filter(move |e| e.kind() == kind)
    }

    /// Render as JSON-lines: one self-contained JSON object per line.
    ///
    /// # Examples
    ///
    /// ```
    /// use tpt_nexus_orchestrator::{NexusEvent, RunLog};
    ///
    /// let mut log = RunLog::new();
    /// log.record(NexusEvent::RunStarted { agent: "static-synth".into(), source_bytes: 42 });
    /// let jsonl = log.to_jsonl();
    /// assert!(jsonl.starts_with(r#"{"event":"run_started""#));
    /// assert_eq!(jsonl.lines().count(), 1);
    /// ```
    pub fn to_jsonl(&self) -> String {
        let mut out = String::new();
        for event in &self.events {
            // Serialization of these plain owned types cannot fail; a
            // hypothetical failure is logged rather than panicking a run that
            // has otherwise succeeded.
            match serde_json::to_string(event) {
                Ok(line) => {
                    out.push_str(&line);
                    out.push('\n');
                }
                Err(e) => {
                    tracing::error!(error = %e, kind = event.kind(), "failed to serialize event");
                }
            }
        }
        out
    }

    /// Write the JSON-lines log to `path`, creating parent directories.
    pub fn write_jsonl(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut file = std::fs::File::create(path)?;
        file.write_all(self.to_jsonl().as_bytes())
    }
}

/// Mirror an event into `tracing` at an appropriate level.
///
/// Failures are `warn`/`error`; everything else is `info`, with the interesting
/// fields promoted to structured tracing fields so a JSON subscriber gets the
/// same data a JSON-lines file would.
fn emit_tracing(event: &NexusEvent) {
    match event {
        NexusEvent::RunStarted {
            agent,
            source_bytes,
        } => {
            tracing::info!(agent = %agent, source_bytes, "nexus run started");
        }
        NexusEvent::Iteration { record } => {
            if record.passed {
                tracing::info!(
                    func = %record.func_name,
                    iteration = record.iteration,
                    action = %record.action,
                    "candidate verified"
                );
            } else {
                tracing::warn!(
                    func = %record.func_name,
                    iteration = record.iteration,
                    action = %record.action,
                    counterexample = %crate::feedback::render_bindings(&record.counterexample, usize::MAX),
                    "candidate rejected"
                );
            }
        }
        NexusEvent::FunctionCompleted {
            func_name,
            target,
            verified,
            mutates_state,
            iterations,
            repaired,
            verdict,
        } => {
            if *verified {
                tracing::info!(
                    func = %func_name, target = %target, iterations, repaired,
                    mutates_state, verdict = %verdict, "function verified"
                );
            } else {
                tracing::error!(
                    func = %func_name, target = %target, iterations,
                    verdict = %verdict, "function failed verification"
                );
            }
        }
        NexusEvent::Attested {
            source_hash,
            manifest_hash,
            functions,
        } => {
            tracing::info!(
                source_hash = %source_hash, manifest_hash = %manifest_hash, functions,
                "proof manifest generated"
            );
        }
        NexusEvent::BuildStarted { backend } => {
            tracing::info!(backend, "build started");
        }
        NexusEvent::BuildCompleted {
            backend,
            success,
            artifact_bytes,
        } => {
            if *success {
                tracing::info!(backend, artifact_bytes, "build succeeded");
            } else {
                tracing::error!(backend, "build failed");
            }
        }
        NexusEvent::RunCompleted {
            all_verified,
            functions,
            total_iterations,
        } => {
            tracing::info!(
                all_verified,
                functions,
                total_iterations,
                "nexus run completed"
            );
        }
        // The final run-failure is reported by the caller (which has the full
        // `NexusError` and the right CLI context); emitting it here too would
        // double-print the same failure in two formats. The event is still
        // retained in the `RunLog` for structured/JSON-lines observability.
        NexusEvent::RunFailed { .. } => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iteration_record(passed: bool) -> IterationRecord {
        IterationRecord {
            func_name: "transfer".to_string(),
            iteration: 0,
            action: "generate".to_string(),
            candidate_source: "from.balance += amount".to_string(),
            passed,
            counterexample: [("from.balance'".to_string(), 5)].into_iter().collect(),
        }
    }

    #[test]
    fn jsonl_has_one_object_per_event() {
        let mut log = RunLog::new();
        log.record(NexusEvent::RunStarted {
            agent: "static-synth".to_string(),
            source_bytes: 10,
        });
        log.record(NexusEvent::Iteration {
            record: iteration_record(false),
        });
        log.record(NexusEvent::RunCompleted {
            all_verified: false,
            functions: 1,
            total_iterations: 1,
        });

        let jsonl = log.to_jsonl();
        assert_eq!(jsonl.lines().count(), 3);
        for line in jsonl.lines() {
            let value: serde_json::Value = serde_json::from_str(line).expect("valid JSON line");
            assert!(value.get("event").is_some(), "every line is tagged");
        }
    }

    #[test]
    fn iteration_fields_are_flattened_for_grepping() {
        let mut log = RunLog::new();
        log.record(NexusEvent::Iteration {
            record: iteration_record(false),
        });
        let line = log.to_jsonl();
        let value: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(value["event"], "iteration");
        assert_eq!(value["func_name"], "transfer");
        assert_eq!(value["passed"], false);
        // The counterexample survives into the log verbatim.
        assert_eq!(value["counterexample"]["from.balance'"], 5);
    }

    #[test]
    fn log_event_and_formatter_share_one_record() {
        // The anti-drift guarantee: what the agent is told and what is logged
        // are the same value, not two renderings of two copies.
        let record = iteration_record(false);
        let prompt = crate::FeedbackFormatter::new().iteration(&record);

        let mut log = RunLog::new();
        log.record(NexusEvent::Iteration {
            record: record.clone(),
        });
        let line = log.to_jsonl();
        let value: serde_json::Value = serde_json::from_str(line.trim()).unwrap();

        let logged: IterationRecord = serde_json::from_value(serde_json::json!({
            "func_name": value["func_name"],
            "iteration": value["iteration"],
            "action": value["action"],
            "candidate_source": value["candidate_source"],
            "passed": value["passed"],
            "counterexample": value["counterexample"],
        }))
        .unwrap();

        assert_eq!(logged, record);
        assert_eq!(crate::FeedbackFormatter::new().iteration(&logged), prompt);
    }

    #[test]
    fn events_can_be_filtered_by_kind() {
        let mut log = RunLog::new();
        log.record(NexusEvent::Iteration {
            record: iteration_record(false),
        });
        log.record(NexusEvent::Iteration {
            record: iteration_record(true),
        });
        log.record(NexusEvent::RunFailed {
            reason: "nope".to_string(),
        });
        assert_eq!(log.events_of_kind("iteration").count(), 2);
        assert_eq!(log.events_of_kind("run_failed").count(), 1);
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn empty_log_renders_empty() {
        assert!(RunLog::new().is_empty());
        assert_eq!(RunLog::new().to_jsonl(), "");
    }
}
