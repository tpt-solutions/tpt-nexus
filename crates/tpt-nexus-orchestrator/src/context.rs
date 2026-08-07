//! [`AgentContext`]: the accumulated, serializable state of one agentic run.
//!
//! Everything the agent "saw" and everything it produced is projected into
//! plain owned data here — no borrowed `FuncOutcome`s, no `HashMap` iteration
//! order, no non-`Debug` types. That is what makes the same values usable for
//! all three consumers at once: the [`FeedbackFormatter`](crate::FeedbackFormatter)
//! prompt text, the JSON-lines event log, and assertions in tests.
//!
//! Counterexamples are stored as [`BTreeMap`] rather than the verifier's
//! [`Model`](tpt_telos_sdk::Model) (a `HashMap`) specifically so that rendered
//! output and logged output are byte-identical across runs.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tpt_telos_parser::ast::{Expr, Stmt};
use tpt_telos_sdk::FuncOutcome;

/// A deterministic counterexample: variable name -> integer value.
///
/// Pre-state fields are `"base.field"`; post-state fields carry a trailing
/// apostrophe, `"base.field'"`.
pub type Bindings = BTreeMap<String, i64>;

/// One turn of the agentic loop for one function.
///
/// This is the atomic unit of "Observable Agentic State": it is what the
/// formatter renders and what the event log serializes, so the two can never
/// drift. `Deserialize` is derived so an external tool can replay a
/// JSON-lines run log back into typed records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IterationRecord {
    /// The function being transpiled.
    pub func_name: String,
    /// 0-based iteration index, as reported by tpt-telos.
    pub iteration: usize,
    /// What the agent did: `"generate"`, `"rewrite"`, or
    /// `"synthesize-from-ensures"`.
    pub action: String,
    /// The candidate body the agent produced this turn, rendered as `.telos`
    /// source.
    pub candidate_source: String,
    /// Whether every contract held for this candidate.
    pub passed: bool,
    /// The concrete assignment that broke the contract. Empty when `passed`.
    pub counterexample: Bindings,
}

/// The full history of one function's journey through the loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionRecord {
    /// The function's name.
    pub func_name: String,
    /// Backend the router selected: `"rust"`, `"go"`, or `"python"`.
    pub target: String,
    /// Name of the agent that produced the code, e.g. `"static-synth"`.
    pub agent: String,
    /// Whether the function ended up satisfying its contracts.
    pub verified: bool,
    /// Whether the accepted body writes to a struct field.
    ///
    /// Derived from the *final, verified* candidate — not from the source the
    /// developer wrote — and consumed by
    /// `tpt-nexus-archon-emulator` to pick between `Right::Read` and
    /// `Right::ReadWrite`. A pure query gets read-only access; only a mutator
    /// earns write access.
    pub mutates_state: bool,
    /// Every turn of the loop, in order.
    pub iterations: Vec<IterationRecord>,
    /// One rendered hint per verification check of the final result, produced
    /// by [`tpt_telos_sdk::format_hint`].
    pub check_hints: Vec<String>,
}

impl FunctionRecord {
    /// Whether the agent's very first candidate already satisfied the contract.
    ///
    /// `false` here with `verified == true` is the interesting case: the agent
    /// got it wrong, saw a counterexample, and repaired itself.
    pub fn first_attempt_passed(&self) -> bool {
        self.iterations.first().is_some_and(|s| s.passed)
    }

    /// True when the loop failed at least once and still reached a verified
    /// body — the "fail, feed back, fix" narrative.
    pub fn was_repaired(&self) -> bool {
        self.verified && !self.first_attempt_passed()
    }

    /// The iterations that failed verification, oldest first.
    pub fn failed_iterations(&self) -> impl Iterator<Item = &IterationRecord> {
        self.iterations.iter().filter(|s| !s.passed)
    }
}

/// The accumulated state of a complete agentic run: the source history plus the
/// per-iteration verification outcomes for every function.
///
/// This is nexus's answer to spec.txt §4.1 `AgentContext`. It deliberately
/// *wraps* the history `tpt_telos_agent::transpile_func` already tracks in its
/// `Vec<LoopStep>` rather than re-deriving it, so there is exactly one source
/// of truth for what happened.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentContext {
    /// The `.telos` intent that started the run.
    pub intent: String,
    /// The agent that serviced it.
    pub agent: String,
    /// One record per transpiled function, in pipeline order.
    pub functions: Vec<FunctionRecord>,
}

impl AgentContext {
    /// Project a finished SDK artifact into an owned, serializable history.
    pub fn from_outcomes(intent: &str, outcomes: &[FuncOutcome]) -> Self {
        let agent = outcomes
            .first()
            .map(|o| o.agent.clone())
            .unwrap_or_else(|| "none".to_string());

        let functions = outcomes
            .iter()
            .map(|o| FunctionRecord {
                func_name: o.func_name.clone(),
                target: o.target.as_str().to_string(),
                agent: o.agent.clone(),
                verified: o.verified,
                mutates_state: mutates_state(&o.final_candidate.stmts),
                iterations: o
                    .iterations
                    .iter()
                    .map(|step| IterationRecord {
                        func_name: o.func_name.clone(),
                        iteration: step.iteration,
                        action: step.action.clone(),
                        candidate_source: tpt_telos_agent::render_candidate(&step.candidate),
                        passed: step.passed,
                        counterexample: step
                            .counterexample
                            .as_ref()
                            .map(|m| m.iter().map(|(k, v)| (k.clone(), *v)).collect())
                            .unwrap_or_default(),
                    })
                    .collect(),
                check_hints: o
                    .result
                    .checks
                    .iter()
                    .map(tpt_telos_sdk::format_hint)
                    .collect(),
            })
            .collect();

        AgentContext {
            intent: intent.to_string(),
            agent,
            functions,
        }
    }

    /// Whether every function satisfied its contracts.
    pub fn all_verified(&self) -> bool {
        self.functions.iter().all(|f| f.verified)
    }

    /// The functions whose contracts were never satisfied.
    pub fn failed_functions(&self) -> Vec<&FunctionRecord> {
        self.functions.iter().filter(|f| !f.verified).collect()
    }

    /// The functions the loop had to repair before they verified.
    pub fn repaired_functions(&self) -> Vec<&FunctionRecord> {
        self.functions.iter().filter(|f| f.was_repaired()).collect()
    }

    /// Total loop iterations across every function — the run's "agentic cost".
    pub fn total_iterations(&self) -> usize {
        self.functions.iter().map(|f| f.iterations.len()).sum()
    }

    /// Hints for every failing check, across every function.
    pub fn failure_hints(&self) -> Vec<String> {
        self.functions
            .iter()
            .filter(|f| !f.verified)
            .flat_map(|f| {
                f.check_hints
                    .iter()
                    .filter(|h| h.contains("FAILED"))
                    .map(|h| format!("{}: {h}", f.func_name))
            })
            .collect()
    }
}

/// Whether a statement list writes to a struct field.
///
/// Both spellings count: an explicit `mutate state { ... }` block, and a bare
/// assignment whose target is a field access. Assignments to plain locals do
/// not — they are function-scoped and need no memory capability. Recurses into
/// `if` and `match` bodies, since a conditional write is still a write.
fn mutates_state(stmts: &[Stmt]) -> bool {
    stmts.iter().any(|stmt| match stmt {
        Stmt::MutateState(assigns) => assigns
            .iter()
            .any(|a| matches!(a.target, Expr::Field { .. })),
        Stmt::Assign(a) => matches!(a.target, Expr::Field { .. }),
        Stmt::If(i) => {
            mutates_state(&i.then_body) || i.else_body.as_deref().is_some_and(mutates_state)
        }
        Stmt::Match(m) => m.arms.iter().any(|arm| mutates_state(&arm.body)),
        Stmt::Let(_) | Stmt::Return(_) => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpt_telos_parser::ast::{Assign, AssignOp};

    fn field_assign(base: &str, field: &str) -> Assign {
        Assign {
            target: Expr::Field {
                base: base.to_string(),
                field: field.to_string(),
            },
            op: AssignOp::Set,
            value: Expr::Int(1),
        }
    }

    fn var_assign(name: &str) -> Assign {
        Assign {
            target: Expr::Var(name.to_string()),
            op: AssignOp::Set,
            value: Expr::Int(1),
        }
    }

    #[test]
    fn mutate_state_block_counts_as_mutation() {
        let stmts = vec![Stmt::MutateState(vec![field_assign("w", "balance")])];
        assert!(mutates_state(&stmts));
    }

    #[test]
    fn bare_field_assignment_counts_as_mutation() {
        let stmts = vec![Stmt::Assign(field_assign("w", "balance"))];
        assert!(mutates_state(&stmts));
    }

    #[test]
    fn local_variable_assignment_is_not_a_mutation() {
        // A pure query writes only its own locals; it needs no write capability.
        let stmts = vec![Stmt::Assign(var_assign("out"))];
        assert!(!mutates_state(&stmts));
    }

    #[test]
    fn empty_body_is_not_a_mutation() {
        assert!(!mutates_state(&[]));
    }

    #[test]
    fn conditional_write_is_still_a_write() {
        let stmts = vec![Stmt::If(tpt_telos_parser::ast::IfStmt {
            condition: Expr::Int(1),
            then_body: vec![Stmt::Assign(var_assign("out"))],
            else_body: Some(vec![Stmt::Assign(field_assign("w", "balance"))]),
        })];
        assert!(mutates_state(&stmts));
    }
}
