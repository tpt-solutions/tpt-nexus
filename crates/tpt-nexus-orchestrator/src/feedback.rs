//! [`FeedbackFormatter`]: turning a counterexample into something an agent can act on.
//!
//! # Why this exists, and what changed
//!
//! `spec.txt` assumed a `VerificationReport` carrying an `agent_hint` field.
//! No such field existed in tpt-telos, so nexus was going to have to synthesize
//! hints from raw [`Model`](tpt_telos_sdk::Model) counterexamples itself.
//!
//! tpt-telos has since grown [`tpt_telos_sdk::format_hint`], which renders a
//! single [`CheckResult`](tpt_telos_sdk::CheckResult) — clause kind, disjunction
//! and interval-approximation caveats, and the counterexample — as one line.
//! So this module no longer *reimplements* hinting; it **delegates** to the SDK
//! for check-level text and adds the layer the SDK does not provide: assembling
//! whole-run, iteration-aware **prompts** addressed to the agent.
//!
//! Two things are deliberately kept here rather than pulled from the SDK:
//!
//! * [`render_bindings`] duplicates the SDK's post-state key convention
//!   (`base.field'` -> `base.field (post-state)`) because the SDK's own
//!   `render_binding` is private. The convention is asserted in tests below so
//!   the two cannot silently diverge.
//! * Per-*iteration* counterexamples live on `LoopStep`, not `CheckResult`, so
//!   `format_hint` cannot reach them. Iteration prompts are rendered from
//!   [`IterationRecord`] — the same struct the event log serializes.

use crate::context::{AgentContext, Bindings, FunctionRecord, IterationRecord};

/// Renders verification feedback as prompt text for a code agent.
///
/// The formatter is intentionally stateless and cheap to construct; it exists
/// as a type rather than free functions so callers can tune presentation
/// (currently: how many counterexample bindings to show) without threading
/// arguments through every call site.
#[derive(Debug, Clone)]
pub struct FeedbackFormatter {
    /// Maximum counterexample bindings to include before eliding the rest.
    /// Keeps a pathological model from blowing an LLM's context window.
    pub max_bindings: usize,
}

impl Default for FeedbackFormatter {
    fn default() -> Self {
        Self { max_bindings: 24 }
    }
}

impl FeedbackFormatter {
    /// A formatter with default presentation settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cap the number of counterexample bindings rendered per hint.
    pub fn with_max_bindings(mut self, max_bindings: usize) -> Self {
        self.max_bindings = max_bindings;
        self
    }

    /// Render a single loop iteration as a feedback fragment.
    ///
    /// Passing iterations render as a one-line confirmation; failing ones carry
    /// the candidate body and the concrete assignment that broke it.
    ///
    /// # Examples
    ///
    /// ```
    /// use tpt_nexus_orchestrator::{FeedbackFormatter, IterationRecord};
    ///
    /// let record = IterationRecord {
    ///     func_name: "transfer".into(),
    ///     iteration: 0,
    ///     action: "generate".into(),
    ///     candidate_source: "from.balance += amount".into(),
    ///     passed: false,
    ///     counterexample: [("from.balance".to_string(), 1), ("from.balance'".to_string(), 5)]
    ///         .into_iter()
    ///         .collect(),
    /// };
    /// let text = FeedbackFormatter::new().iteration(&record);
    /// assert!(text.contains("iteration 0"));
    /// assert!(text.contains("from.balance (post-state)=5"));
    /// ```
    pub fn iteration(&self, record: &IterationRecord) -> String {
        let mut out = format!(
            "iteration {} [{}] {}: {}",
            record.iteration,
            record.action,
            record.func_name,
            if record.passed { "PASSED" } else { "FAILED" }
        );

        if !record.candidate_source.trim().is_empty() {
            out.push_str("\n  candidate:");
            for line in record.candidate_source.lines() {
                out.push_str("\n    ");
                out.push_str(line);
            }
        }

        if !record.passed && !record.counterexample.is_empty() {
            out.push_str("\n  counterexample: ");
            out.push_str(&render_bindings(&record.counterexample, self.max_bindings));
        }

        out
    }

    /// Render the whole history of one function: every attempt, then the
    /// per-check hints from the final verification result.
    pub fn function(&self, record: &FunctionRecord) -> String {
        let mut out = format!(
            "function `{}` -> {} via {} ({} iteration(s), {})",
            record.func_name,
            record.target,
            record.agent,
            record.iterations.len(),
            if record.verified {
                "VERIFIED"
            } else {
                "UNVERIFIED"
            }
        );

        for step in &record.iterations {
            out.push('\n');
            for line in self.iteration(step).lines() {
                out.push_str("  ");
                out.push_str(line);
                out.push('\n');
            }
            out.pop();
        }

        if !record.check_hints.is_empty() {
            out.push_str("\n  checks:");
            for hint in &record.check_hints {
                for line in hint.lines() {
                    out.push_str("\n    ");
                    out.push_str(line);
                }
            }
        }

        out
    }

    /// Build a repair prompt for a function that never verified.
    ///
    /// This is the text that would be handed back to an LLM agent for another
    /// attempt. It states the contract, the last thing the agent tried, why it
    /// was wrong, and what to do next — everything needed to make progress
    /// without re-reading the whole run.
    pub fn repair_prompt(&self, context: &AgentContext, record: &FunctionRecord) -> String {
        let mut out = String::new();
        out.push_str("Your previous implementation does not satisfy its formal contract.\n\n");

        out.push_str("## Contract source\n\n");
        out.push_str(context.intent.trim());
        out.push_str("\n\n");

        out.push_str(&format!("## Function\n\n`{}`\n\n", record.func_name));

        if let Some(last) = record.iterations.last() {
            out.push_str("## Your last attempt\n\n");
            out.push_str(last.candidate_source.trim());
            out.push_str("\n\n");
        }

        let failures: Vec<&IterationRecord> = record.failed_iterations().collect();
        if !failures.is_empty() {
            out.push_str("## Counterexamples found\n\n");
            for step in failures {
                out.push_str(&format!(
                    "- iteration {}: {}\n",
                    step.iteration,
                    if step.counterexample.is_empty() {
                        "no model produced".to_string()
                    } else {
                        render_bindings(&step.counterexample, self.max_bindings)
                    }
                ));
            }
            out.push('\n');
        }

        let failing_checks: Vec<&String> = record
            .check_hints
            .iter()
            .filter(|h| h.contains("FAILED"))
            .collect();
        if !failing_checks.is_empty() {
            out.push_str("## Unsatisfied clauses\n\n");
            for hint in failing_checks {
                out.push_str(hint);
                out.push('\n');
            }
            out.push('\n');
        }

        out.push_str(
            "## Task\n\nRewrite the function body so every `ensures` clause and every \
             invariant holds for all inputs permitted by the `requires` clauses, including \
             the counterexample values above. Change only the body; the contract is fixed.",
        );
        out
    }

    /// A short human-readable summary of an entire run.
    pub fn summary(&self, context: &AgentContext) -> String {
        let verified = context.functions.iter().filter(|f| f.verified).count();
        let repaired = context.repaired_functions().len();
        let mut out = format!(
            "{}/{} function(s) verified, {} repaired by the loop, {} total iteration(s), agent `{}`",
            verified,
            context.functions.len(),
            repaired,
            context.total_iterations(),
            context.agent,
        );
        for record in &context.functions {
            out.push_str(&format!(
                "\n  - {} [{}] {} iteration(s){}",
                record.func_name,
                if record.verified { "ok" } else { "FAILED" },
                record.iterations.len(),
                if record.was_repaired() {
                    ", repaired after counterexample"
                } else {
                    ""
                },
            ));
        }
        out
    }
}

/// Render a counterexample as `name=value` pairs, sorted, with post-state keys
/// made readable.
///
/// Matches the convention used by [`tpt_telos_sdk::format_hint`]: a trailing
/// apostrophe means "the value of this field *after* the function runs", which
/// is rendered as `<base>.<field> (post-state)=<value>` rather than leaking the
/// solver's internal priming syntax.
///
/// # Examples
///
/// ```
/// use tpt_nexus_orchestrator::render_bindings;
///
/// let model = [("w.balance".to_string(), 10), ("w.balance'".to_string(), 7)]
///     .into_iter()
///     .collect();
/// assert_eq!(
///     render_bindings(&model, 8),
///     "w.balance=10, w.balance (post-state)=7"
/// );
/// ```
pub fn render_bindings(bindings: &Bindings, max: usize) -> String {
    if bindings.is_empty() {
        return "(none)".to_string();
    }
    // `Bindings` is a BTreeMap, so iteration is already sorted and stable.
    let mut parts: Vec<String> = bindings
        .iter()
        .take(max)
        .map(|(k, v)| render_binding(k, *v))
        .collect();
    if bindings.len() > max {
        parts.push(format!("... ({} more)", bindings.len() - max));
    }
    parts.join(", ")
}

/// Render one binding, rewriting a primed post-state key into readable text.
fn render_binding(key: &str, value: i64) -> String {
    match key.strip_suffix('\'') {
        Some(base) => format!("{base} (post-state)={value}"),
        None => format!("{key}={value}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bindings(pairs: &[(&str, i64)]) -> Bindings {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    fn failing_iteration() -> IterationRecord {
        IterationRecord {
            func_name: "transfer".to_string(),
            iteration: 0,
            action: "generate".to_string(),
            candidate_source: "mutate state {\n  from.balance += amount\n}".to_string(),
            passed: false,
            counterexample: bindings(&[("amount", 4), ("from.balance", 1), ("from.balance'", 5)]),
        }
    }

    #[test]
    fn post_state_keys_are_rendered_readably() {
        let text = render_bindings(&bindings(&[("w.balance'", 5)]), 8);
        assert_eq!(text, "w.balance (post-state)=5");
    }

    #[test]
    fn pre_state_keys_are_rendered_verbatim() {
        let text = render_bindings(&bindings(&[("w.balance", 5)]), 8);
        assert_eq!(text, "w.balance=5");
    }

    #[test]
    fn binding_convention_matches_the_telos_sdk() {
        // Guards against drift: the SDK's own `render_binding` is private, so
        // this asserts our copy agrees with `format_hint`'s observable output.
        use std::collections::HashMap;
        let mut model: HashMap<String, i64> = HashMap::new();
        model.insert("from.balance'".to_string(), 5);
        model.insert("from.balance".to_string(), 1);
        let check = tpt_telos_sdk::CheckResult {
            description: "ensures from.balance == old(from.balance) - amount".to_string(),
            passed: false,
            is_ensures: true,
            is_approximation: false,
            counterexample: Some(model),
            or_group: None,
            location: None,
        };
        let sdk_hint = tpt_telos_sdk::format_hint(&check);
        let ours = render_bindings(&bindings(&[("from.balance", 1), ("from.balance'", 5)]), 8);
        assert!(
            sdk_hint.contains(&ours),
            "nexus rendering `{ours}` must appear verbatim in the SDK hint `{sdk_hint}`"
        );
    }

    #[test]
    fn empty_counterexample_renders_as_none() {
        assert_eq!(render_bindings(&Bindings::new(), 8), "(none)");
    }

    #[test]
    fn bindings_are_elided_past_the_limit() {
        let text = render_bindings(&bindings(&[("a", 1), ("b", 2), ("c", 3)]), 2);
        assert!(text.contains("a=1"));
        assert!(text.contains("b=2"));
        assert!(text.contains("... (1 more)"));
        assert!(!text.contains("c=3"));
    }

    #[test]
    fn iteration_reports_failure_with_candidate_and_model() {
        let text = FeedbackFormatter::new().iteration(&failing_iteration());
        assert!(text.contains("iteration 0"));
        assert!(text.contains("[generate]"));
        assert!(text.contains("FAILED"));
        assert!(text.contains("from.balance += amount"));
        assert!(text.contains("from.balance (post-state)=5"));
    }

    #[test]
    fn passing_iteration_omits_the_counterexample_line() {
        let mut record = failing_iteration();
        record.passed = true;
        record.counterexample = Bindings::new();
        let text = FeedbackFormatter::new().iteration(&record);
        assert!(text.contains("PASSED"));
        assert!(!text.contains("counterexample"));
    }

    #[test]
    fn repair_prompt_carries_contract_attempt_and_model() {
        let record = FunctionRecord {
            func_name: "transfer".to_string(),
            target: "rust".to_string(),
            agent: "static-synth".to_string(),
            verified: false,
            mutates_state: true,
            iterations: vec![failing_iteration()],
            check_hints: vec![
                "[ensures] ensures from.balance == old(from.balance) - amount — FAILED".to_string(),
            ],
        };
        let context = AgentContext {
            intent: "module Bank { func transfer() ; }".to_string(),
            agent: "static-synth".to_string(),
            functions: vec![record.clone()],
        };
        let prompt = FeedbackFormatter::new().repair_prompt(&context, &record);
        assert!(prompt.contains("## Contract source"));
        assert!(prompt.contains("module Bank"));
        assert!(prompt.contains("## Your last attempt"));
        assert!(prompt.contains("from.balance += amount"));
        assert!(prompt.contains("from.balance (post-state)=5"));
        assert!(prompt.contains("## Unsatisfied clauses"));
        assert!(prompt.contains("## Task"));
    }
}
