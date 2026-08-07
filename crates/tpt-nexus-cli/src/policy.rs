//! `nexus.toml` policy: explicit control over the capability derivation.
//!
//! Today nexus derives grants automatically from what each function was proved
//! to do. That is the right default, but a project that ships `.telos` programs
//! wants to *pin* its security surface: force a risky mutator down to `Read`,
//! name the agent that is allowed to drive the loop, and document the intended
//! grant set in version control. A `nexus.toml` is that pin.
//!
//! ```toml
//! # "static" (default) or "llm".
//! agent = "static"
//!
//! # Force a function's derived right. Names match the bare function name the
//! # emulator mints under. Anything not listed keeps its derived right.
//! [[grant]]
//! func  = "settle"
//! right = "ReadWrite"
//! [[grant]]
//! func  = "current_balance"
//! right = "Read"
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;
use tpt_archon_bridge::capability::Right;
use tpt_nexus_orchestrator::{CodeAgent, NexusError, StaticAgent};

/// A parsed `nexus.toml`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Policy {
    /// Which agent drives the verify loop. `"static"` or `"llm"`.
    #[serde(default)]
    pub agent: Option<String>,

    /// Per-function right overrides.
    #[serde(default)]
    pub grant: Vec<GrantOverride>,
}

/// One `[[grant]]` entry.
#[derive(Debug, Clone, Deserialize)]
pub struct GrantOverride {
    /// Bare function name (matches the emulator's grant key).
    pub func: String,
    /// Right to force, as `"Read"` / `"Write"` / `"ReadWrite"`.
    pub right: String,
}

/// Parse a right from its TOML string form (`"Read"` / `"Write"` /
/// `"ReadWrite"`). A free function rather than `impl FromStr for Right`, since
/// `Right` lives in an external crate and the orphan rule forbids that impl.
pub fn parse_right(s: &str) -> Result<Right, String> {
    match s {
        "Read" => Ok(Right::Read),
        "Write" => Ok(Right::Write),
        "ReadWrite" => Ok(Right::ReadWrite),
        other => Err(format!(
            "unknown right `{other}` (expected Read, Write, or ReadWrite)"
        )),
    }
}

impl Policy {
    /// Load and parse a `nexus.toml` from disk.
    pub fn load(path: &Path) -> Result<Self, NexusError> {
        let text = std::fs::read_to_string(path)?;
        Self::from_toml(&text)
    }

    /// Parse from a TOML string (handy for tests and embedded policies).
    pub fn from_toml(text: &str) -> Result<Self, NexusError> {
        let doc: Policy = toml::from_str(text)
            .map_err(|e| NexusError::Panic(format!("invalid nexus.toml: {e}")))?;
        doc.validate()
    }

    /// Reject a policy that names an unknown right before any work starts.
    fn validate(self) -> Result<Self, NexusError> {
        for g in &self.grant {
            parse_right(&g.right)
                .map_err(|e| NexusError::Panic(format!("grant `{}`: {e}", g.func)))?;
        }
        Ok(self)
    }

    /// The agent this policy selects, falling back to the deterministic
    /// [`StaticAgent`] when the policy says nothing or names an unavailable
    /// agent (the LLM agent requires the `llm` feature + `TELAS_LLM_*` env).
    pub fn agent(&self) -> Box<dyn CodeAgent> {
        if self.agent.as_deref() == Some("llm") {
            #[cfg(feature = "llm")]
            {
                if let Ok(agent) = tpt_nexus_orchestrator::LlmAgent::from_env() {
                    return Box::new(agent);
                }
            }
        }
        Box::new(StaticAgent::new())
    }

    /// Overlay this policy's right overrides on a derived grant set. Functions
    /// not named in the policy keep their derived right.
    pub fn apply(&self, mut rights: BTreeMap<String, Right>) -> BTreeMap<String, Right> {
        for g in &self.grant {
            if let Ok(right) = parse_right(&g.right) {
                rights.insert(g.func.clone(), right);
            }
        }
        rights
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_policy_is_a_noop() {
        let p = Policy::from_toml("").unwrap();
        let mut rights = BTreeMap::new();
        rights.insert("f".to_string(), Right::Read);
        assert_eq!(p.apply(rights.clone()), rights);
    }

    #[test]
    fn overrides_replace_derived_rights() {
        let p = Policy::from_toml(
            r#"
            [[grant]]
            func = "risky"
            right = "Read"
            "#,
        )
        .unwrap();
        let mut rights = BTreeMap::new();
        rights.insert("risky".to_string(), Right::ReadWrite);
        rights.insert("safe".to_string(), Right::Read);
        let applied = p.apply(rights);
        assert_eq!(applied["risky"], Right::Read, "override forced down");
        assert_eq!(applied["safe"], Right::Read, "unlisted keeps derived");
    }

    #[test]
    fn unknown_right_is_rejected_up_front() {
        let err = Policy::from_toml(
            r#"
            [[grant]]
            func = "x"
            right = "Superuser"
            "#,
        )
        .unwrap_err();
        assert!(format!("{err:?}").contains("Superuser"));
    }
}
