//! Error type for the nexus orchestration loop.

use std::fmt;

use crate::report::RunReport;

/// Everything that can stop a nexus run from producing a
/// [`VerifiedArtifact`](crate::VerifiedArtifact).
///
/// Note the deliberate asymmetry with [`tpt_telos_sdk::SdkError`]: for the SDK,
/// a program whose contracts do not hold is a *successful* compile with
/// `all_verified == false`. For nexus it is a hard error
/// ([`NexusError::ContractsUnsatisfied`]), because a `VerifiedArtifact` is the
/// token that unlocks Archon capability grants. An artifact that exists but was
/// not verified would break the "Manifest as Root of Trust" principle the whole
/// harness is built to demonstrate.
#[derive(Debug)]
pub enum NexusError {
    /// The pipeline itself could not run: parse, agent, or codegen failure.
    Pipeline(tpt_telos_sdk::SdkError),

    /// The pipeline ran to completion but at least one function's contracts
    /// were never satisfied, even after the agentic repair loop gave up.
    ///
    /// The full run report is carried along so the caller can log or render the
    /// agent's entire "thought process" — this is the failure path that most
    /// needs observability.
    ContractsUnsatisfied {
        /// One rendered hint per failing check, in function order.
        hints: Vec<String>,
        /// The complete iteration history and event log for the run.
        report: Box<RunReport>,
    },

    /// The agentic loop needed more iterations than the configured budget.
    ///
    /// Only reachable when the budget is set below tpt-telos's own internal
    /// cap; see [`LoopController`](crate::LoopController).
    IterationBudgetExceeded {
        /// The function that overran.
        func_name: String,
        /// Loop turns tpt-telos actually used.
        iterations: usize,
        /// The configured budget.
        budget: usize,
    },

    /// `cargo` ran but the generated Rust did not compile, or produced no
    /// readable artifact.
    Build(String),

    /// The telos verifier panicked (e.g. a read-only function body that assigns
    /// to a bare local, which telos's IR rejects). Caught so the whole run
    /// fails cleanly instead of unwinding out of nexus.
    ///
    /// This variant is reserved for *genuine* telos panics. Unrelated failures
    /// (policy parse errors, ambiguous function names) have their own variants
    /// and must not be funnelled through here.
    Panic(String),

    /// A `nexus.toml` policy failed to load or validate (bad TOML, an unknown
    /// right string, ...). Distinct from [`NexusError::Panic`] so the
    /// diagnostic does not misleadingly suggest a telos verifier crash.
    Policy(String),

    /// Two modules declare a function with the same name, which makes capability
    /// grants (keyed by bare function name) ambiguous. Surfaced as its own
    /// variant so the diagnostic names the offending function.
    AmbiguousFunctionName(String),

    /// Writing the generated project, the manifest, or the run log failed.
    Io(std::io::Error),
}

impl fmt::Display for NexusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NexusError::Pipeline(e) => write!(f, "telos pipeline failed: {e}"),
            NexusError::ContractsUnsatisfied { hints, report } => {
                let failed = report.context.failed_functions();
                write!(
                    f,
                    "contracts unsatisfied for {} of {} function(s): {}",
                    failed.len(),
                    report.context.functions.len(),
                    failed
                        .iter()
                        .map(|r| r.func_name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )?;
                for hint in hints {
                    write!(f, "\n  {hint}")?;
                }
                Ok(())
            }
            NexusError::IterationBudgetExceeded {
                func_name,
                iterations,
                budget,
            } => write!(
                f,
                "`{func_name}` needed {iterations} iteration(s), exceeding the configured budget of {budget}"
            ),
            NexusError::Build(msg) => write!(f, "build failed: {msg}"),
            NexusError::Panic(msg) => write!(
                f,
                "telos verifier panicked: {msg}\n\
                 hint: telos only admits field assignments in a function body; \
                 a read-only function must read state into a `let` binding, not assign to a bare local"
            ),
            NexusError::Policy(msg) => write!(f, "policy error: {msg}"),
            NexusError::AmbiguousFunctionName(name) => write!(
                f,
                "function name `{name}` is declared in more than one module; \
                 capability grants are keyed by bare function name and would be ambiguous"
            ),
            NexusError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for NexusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NexusError::Pipeline(e) => Some(e),
            NexusError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<tpt_telos_sdk::SdkError> for NexusError {
    fn from(e: tpt_telos_sdk::SdkError) -> Self {
        NexusError::Pipeline(e)
    }
}

impl From<std::io::Error> for NexusError {
    fn from(e: std::io::Error) -> Self {
        NexusError::Io(e)
    }
}
