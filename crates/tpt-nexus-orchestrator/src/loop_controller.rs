//! [`LoopController`]: iteration policy over tpt-telos's own agentic loop.
//!
//! # Why this does *not* retry
//!
//! spec.txt §4.1 describes a `LoopController` that "manages the retry logic"
//! and "enforces a maximum iteration count (e.g. 5 attempts)". When nexus was
//! specified it was not yet clear that tpt-telos already does exactly this:
//! `tpt_telos_agent::transpile_func` runs its own generate → verify →
//! counterexample → rewrite loop, bounded at 8 iterations, and falls back to
//! contract-derived synthesis if the agent stops making progress.
//!
//! Wrapping that in a second, outer retry loop would re-run an identical
//! deterministic computation and report inflated iteration counts, while
//! obscuring which attempt actually produced the accepted body. So nexus takes
//! the other option recorded in TODO §2: **no duplicate loop**. The controller
//! classifies the history tpt-telos already produced and enforces a budget over
//! it.
//!
//! The budget is still real, and still nexus's call to make: it is the policy
//! knob a caller uses to say "if this needed more than N attempts, I do not
//! want the artifact", independently of how patient tpt-telos happens to be.

use crate::context::FunctionRecord;

/// How one function's loop history is classified against the iteration budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopVerdict {
    /// The first candidate already satisfied the contract.
    FirstAttempt {
        /// Loop turns consumed.
        iterations: usize,
    },
    /// The agent failed, consumed a counterexample, and recovered.
    Repaired {
        /// Loop turns consumed.
        iterations: usize,
    },
    /// Verified, but only after using more iterations than the budget allows.
    BudgetExceeded {
        /// Loop turns consumed.
        iterations: usize,
        /// The budget that was exceeded.
        budget: usize,
    },
    /// The contract was never satisfied.
    Failed {
        /// Loop turns consumed.
        iterations: usize,
    },
}

impl LoopVerdict {
    /// Whether this verdict permits the run to produce a `VerifiedArtifact`.
    pub fn is_acceptable(&self) -> bool {
        matches!(
            self,
            LoopVerdict::FirstAttempt { .. } | LoopVerdict::Repaired { .. }
        )
    }

    /// Iterations tpt-telos actually used.
    pub fn iterations(&self) -> usize {
        match self {
            LoopVerdict::FirstAttempt { iterations }
            | LoopVerdict::Repaired { iterations }
            | LoopVerdict::Failed { iterations }
            | LoopVerdict::BudgetExceeded { iterations, .. } => *iterations,
        }
    }
}

/// Iteration policy applied to tpt-telos's loop history.
#[derive(Debug, Clone, Copy)]
pub struct LoopController {
    /// Maximum loop iterations nexus will accept for a single function.
    pub max_iterations: usize,
}

impl LoopController {
    /// The internal iteration cap `tpt_telos_agent::transpile_func` enforces.
    ///
    /// tpt-telos keeps this private (`MAX_ITERS`), so it is mirrored here as
    /// the default budget: with this value nexus never rejects a run that
    /// tpt-telos itself was willing to complete, and the budget only bites when
    /// a caller deliberately tightens it.
    pub const TELOS_INTERNAL_MAX_ITERATIONS: usize = 8;

    /// A controller whose budget matches tpt-telos's own internal cap.
    pub fn new() -> Self {
        Self {
            max_iterations: Self::TELOS_INTERNAL_MAX_ITERATIONS,
        }
    }

    /// A controller with a tighter (or looser) budget.
    pub fn with_max_iterations(max_iterations: usize) -> Self {
        Self { max_iterations }
    }

    /// Classify one function's history.
    ///
    /// # Examples
    ///
    /// ```
    /// use tpt_nexus_orchestrator::{LoopController, LoopVerdict};
    /// # use tpt_nexus_orchestrator::{FunctionRecord, IterationRecord};
    /// # fn step(i: usize, passed: bool) -> IterationRecord {
    /// #     IterationRecord {
    /// #         func_name: "f".into(), iteration: i, action: "generate".into(),
    /// #         candidate_source: String::new(), passed,
    /// #         counterexample: Default::default(),
    /// #     }
    /// # }
    /// # let record = FunctionRecord {
    /// #     func_name: "f".into(), target: "rust".into(), agent: "static-synth".into(),
    /// #     verified: true, mutates_state: true,
    /// #     iterations: vec![step(0, false), step(1, true)], check_hints: vec![],
    /// # };
    /// let verdict = LoopController::new().assess(&record);
    /// assert_eq!(verdict, LoopVerdict::Repaired { iterations: 2 });
    /// assert!(verdict.is_acceptable());
    /// ```
    pub fn assess(&self, record: &FunctionRecord) -> LoopVerdict {
        let iterations = record.iterations.len();
        if !record.verified {
            return LoopVerdict::Failed { iterations };
        }
        if iterations > self.max_iterations {
            return LoopVerdict::BudgetExceeded {
                iterations,
                budget: self.max_iterations,
            };
        }
        if record.first_attempt_passed() {
            LoopVerdict::FirstAttempt { iterations }
        } else {
            LoopVerdict::Repaired { iterations }
        }
    }
}

impl Default for LoopController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::IterationRecord;

    fn step(iteration: usize, passed: bool) -> IterationRecord {
        IterationRecord {
            func_name: "f".to_string(),
            iteration,
            action: if iteration == 0 {
                "generate"
            } else {
                "rewrite"
            }
            .to_string(),
            candidate_source: String::new(),
            passed,
            counterexample: Default::default(),
        }
    }

    fn record(verified: bool, steps: Vec<IterationRecord>) -> FunctionRecord {
        FunctionRecord {
            func_name: "f".to_string(),
            target: "rust".to_string(),
            agent: "static-synth".to_string(),
            verified,
            mutates_state: true,
            iterations: steps,
            check_hints: vec![],
        }
    }

    #[test]
    fn clean_first_attempt_is_reported_as_such() {
        let verdict = LoopController::new().assess(&record(true, vec![step(0, true)]));
        assert_eq!(verdict, LoopVerdict::FirstAttempt { iterations: 1 });
        assert!(verdict.is_acceptable());
    }

    #[test]
    fn failure_then_fix_is_reported_as_repaired() {
        let verdict =
            LoopController::new().assess(&record(true, vec![step(0, false), step(1, true)]));
        assert_eq!(verdict, LoopVerdict::Repaired { iterations: 2 });
        assert!(verdict.is_acceptable());
    }

    #[test]
    fn unverified_history_is_never_acceptable() {
        let verdict = LoopController::new().assess(&record(false, vec![step(0, false)]));
        assert_eq!(verdict, LoopVerdict::Failed { iterations: 1 });
        assert!(!verdict.is_acceptable());
    }

    #[test]
    fn tightened_budget_rejects_an_otherwise_verified_function() {
        let verdict = LoopController::with_max_iterations(1)
            .assess(&record(true, vec![step(0, false), step(1, true)]));
        assert_eq!(
            verdict,
            LoopVerdict::BudgetExceeded {
                iterations: 2,
                budget: 1
            }
        );
        assert!(!verdict.is_acceptable());
    }

    #[test]
    fn default_budget_never_rejects_what_telos_accepted() {
        // tpt-telos gives up after TELOS_INTERNAL_MAX_ITERATIONS, so a history
        // at exactly that length must still pass the default budget.
        let steps: Vec<IterationRecord> = (0..LoopController::TELOS_INTERNAL_MAX_ITERATIONS)
            .map(|i| step(i, i == LoopController::TELOS_INTERNAL_MAX_ITERATIONS - 1))
            .collect();
        assert!(LoopController::new()
            .assess(&record(true, steps))
            .is_acceptable());
    }
}
