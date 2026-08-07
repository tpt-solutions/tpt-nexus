//! [`RunReport`]: the two observability artifacts of a run, kept together.

use serde::Serialize;

use crate::context::AgentContext;
use crate::log::RunLog;

/// Everything nexus knows about a run, independent of whether it succeeded.
///
/// Carried on [`VerifiedArtifact`](crate::VerifiedArtifact) *and* on
/// [`NexusError::ContractsUnsatisfied`](crate::NexusError::ContractsUnsatisfied),
/// because a failed run is precisely when the agent's reasoning most needs to
/// be inspectable.
#[derive(Debug, Clone, Serialize)]
pub struct RunReport {
    /// The agent's accumulated source and verification history.
    pub context: AgentContext,
    /// The ordered structured event stream.
    pub log: RunLog,
}

impl RunReport {
    /// Bundle a context and its log.
    pub fn new(context: AgentContext, log: RunLog) -> Self {
        Self { context, log }
    }

    /// The run's event stream as JSON-lines.
    pub fn to_jsonl(&self) -> String {
        self.log.to_jsonl()
    }

    /// A short human-readable summary of the run.
    pub fn summary(&self) -> String {
        crate::FeedbackFormatter::new().summary(&self.context)
    }
}
