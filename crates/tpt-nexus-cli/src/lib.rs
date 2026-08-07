//! Library backing the `nexus` CLI: the capability-derivation reporting and the
//! `diff` that turns "two versions of a program" into "what changed about the
//! security surface". Kept separate from `main.rs` so the logic is unit-testable
//! without invoking the argument parser.

pub mod policy;
pub mod signing;
pub mod trace;

use std::collections::BTreeMap;
use std::path::Path;

use tpt_archon_bridge::capability::Right;
use tpt_nexus_archon_emulator::derive_rights;
use tpt_nexus_orchestrator::{CodeAgent, NexusError, NexusOrchestrator, StaticAgent};

pub use policy::Policy;
pub use signing::Keypair;
pub use trace::{render_trace_html, render_trace_markdown};

/// Choose the code agent for a run.
///
/// By default — and always when the `llm` feature is disabled — this is the
/// offline, deterministic [`StaticAgent`]. When the `llm` feature is compiled
/// in and `NEXUS_AGENT=llm` is set, a real [`LlmAgent`](tpt_nexus_orchestrator::LlmAgent)
/// is constructed from the `TELAS_LLM_*` environment variables. If those are
/// missing or invalid the choice falls back to the static agent rather than
/// failing, so the env var is purely additive.
pub fn select_agent() -> Box<dyn CodeAgent> {
    #[cfg(feature = "llm")]
    {
        if std::env::var("NEXUS_AGENT").as_deref() == Ok("llm") {
            match tpt_nexus_orchestrator::LlmAgent::from_env() {
                Ok(agent) => return Box::new(agent),
                Err(e) => {
                    eprintln!(
                        "warning: NEXUS_AGENT=llm requested but LlmAgent init failed: {e}; \
                         falling back to StaticAgent"
                    );
                }
            }
        }
    }
    Box::new(StaticAgent::new())
}

/// A capability that changed between two versions of a program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RightChange {
    pub func: String,
    pub from: Right,
    pub to: Right,
}

/// The capability delta between two derived grant sets.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CapabilityDiff {
    /// Functions present in `b` but not `a`, with the right they earned.
    pub added: Vec<(String, Right)>,
    /// Functions present in `a` but not `b`, with the right they had.
    pub removed: Vec<(String, Right)>,
    /// Functions in both, whose right changed.
    pub changed: Vec<RightChange>,
}

impl CapabilityDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }

    /// True when the change makes something *stronger*: a newly added
    /// `ReadWrite`, or any right that escalated to a broader one. This is the
    /// signal a supply-chain / review gate cares about.
    pub fn has_strengthening(&self) -> bool {
        self.added
            .iter()
            .any(|(_, right)| *right == Right::ReadWrite)
            || self.changed.iter().any(|c| strengthens(c.from, c.to))
    }
}

/// Whether `to` is a stronger capability than `from`.
fn strengthens(from: Right, to: Right) -> bool {
    matches!(
        (from, to),
        (Right::Read, Right::ReadWrite)
            | (Right::Read, Right::Write)
            | (Right::Write, Right::ReadWrite)
    )
}

/// Compute the capability delta between two derived grant sets.
///
/// `a` is the baseline (e.g. the committed version); `b` is the candidate
/// (e.g. the PR). The ordering matters for `has_strengthening`.
pub fn capability_diff(a: &BTreeMap<String, Right>, b: &BTreeMap<String, Right>) -> CapabilityDiff {
    let mut diff = CapabilityDiff::default();
    for (name, right) in b {
        match a.get(name) {
            None => diff.added.push((name.clone(), *right)),
            Some(old) if old != right => diff.changed.push(RightChange {
                func: name.clone(),
                from: *old,
                to: *right,
            }),
            Some(_) => {}
        }
    }
    for (name, right) in a {
        if !b.contains_key(name) {
            diff.removed.push((name.clone(), *right));
        }
    }
    diff
}

/// Run the full verify loop on `path` and return the derived capability set
/// (function name -> right). Fails if the program does not verify.
pub fn run_and_derive(path: &Path) -> Result<BTreeMap<String, Right>, NexusError> {
    let source = std::fs::read_to_string(path)?;
    let artifact = NexusOrchestrator::new().run_agent_loop(&source, select_agent().as_ref())?;
    derive_rights(&artifact).map_err(|e| NexusError::Panic(format!("{e}")))
}

/// Render a derived capability set as a Markdown table, ready to paste into a
/// pull-request comment or a report.
pub fn render_capability_table(rights: &BTreeMap<String, Right>) -> String {
    let mut out = String::from("| function | right |\n|---|---|\n");
    for (name, right) in rights {
        out.push_str(&format!("| `{name}` | {right:?} |\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(pairs: &[(&str, Right)]) -> BTreeMap<String, Right> {
        pairs.iter().map(|(n, r)| (n.to_string(), *r)).collect()
    }

    #[test]
    fn diff_detects_added_read_write_as_strengthening() {
        let a = set(&[("read", Right::Read)]);
        let b = set(&[("read", Right::Read), ("write", Right::ReadWrite)]);
        let d = capability_diff(&a, &b);
        assert!(!d.is_empty());
        assert!(d.has_strengthening(), "new ReadWrite is a regression");
        assert_eq!(d.added, vec![("write".to_string(), Right::ReadWrite)]);
    }

    #[test]
    fn diff_detects_escalation_and_removal() {
        let a = set(&[("f", Right::Read), ("g", Right::ReadWrite)]);
        let b = set(&[("f", Right::ReadWrite)]);
        let d = capability_diff(&a, &b);
        assert!(d.has_strengthening());
        assert_eq!(d.changed.len(), 1);
        assert_eq!(d.changed[0].to, Right::ReadWrite);
        assert_eq!(d.removed, vec![("g".to_string(), Right::ReadWrite)]);
    }

    #[test]
    fn identical_surfaces_diff_to_empty() {
        let a = set(&[("f", Right::Read)]);
        let d = capability_diff(&a, &a);
        assert!(d.is_empty());
        assert!(!d.has_strengthening());
    }
}
