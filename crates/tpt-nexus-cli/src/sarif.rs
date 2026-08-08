//! SARIF output for `verify` and `diff`, so nexus findings surface in GitHub
//! code-scanning / the Security tab alongside other static analyzers.
//!
//! We emit SARIF 2.1.0 by hand (no extra dependency) because the schema is
//! small and stable for our needs: one `result` per granted capability (for
//! `verify`) or per capability delta (for `diff`). A strengthening is reported
//! at `error` level so it fails a code-scanning gate.

use serde_json::{json, Value};
use std::collections::BTreeMap;

use tpt_archon_bridge::capability::Right;

use crate::CapabilityDiff;

/// Human-readable name for a [`Right`].
pub fn right_name(right: Right) -> &'static str {
    match right {
        Right::Read => "Read",
        Right::Write => "Write",
        Right::ReadWrite => "ReadWrite",
    }
}

/// Build a SARIF document describing the derived capability surface.
pub fn sarif_for_rights(rights: &BTreeMap<String, Right>, source: &str) -> Value {
    let results: Vec<Value> = rights
        .iter()
        .map(|(func, right)| {
            json!({
                "ruleId": format!("nexus/capability/{}", right_name(*right)),
                "level": if *right == Right::ReadWrite { "warning" } else { "note" },
                "message": {
                    "text": format!(
                        "function `{}` was derived the `{}` capability",
                        func, right_name(*right)
                    )
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": source },
                        "region": { "startLine": 1 }
                    }
                }]
            })
        })
        .collect();
    base_sarif(results)
}

/// Build a SARIF document describing a capability delta between two versions.
pub fn sarif_for_diff(delta: &CapabilityDiff) -> Value {
    let mut results: Vec<Value> = Vec::new();

    for (func, right) in &delta.added {
        results.push(json!({
            "ruleId": "nexus/capability/added",
            "level": if *right == Right::ReadWrite { "warning" } else { "note" },
            "message": {
                "text": format!("new capability `{}` ({})", func, right_name(*right))
            }
        }));
    }
    for change in &delta.changed {
        let level = if crate::strengthens(change.from, change.to) {
            "error"
        } else {
            "note"
        };
        results.push(json!({
            "ruleId": "nexus/capability/changed",
            "level": level,
            "message": {
                "text": format!(
                    "capability `{}` changed {} -> {}",
                    change.func, right_name(change.from), right_name(change.to)
                )
            }
        }));
    }
    for (func, right) in &delta.removed {
        results.push(json!({
            "ruleId": "nexus/capability/removed",
            "level": "note",
            "message": {
                "text": format!("removed capability `{}` ({})", func, right_name(*right))
            }
        }));
    }
    base_sarif(results)
}

/// Wrap a list of results in a minimal valid SARIF 2.1.0 document.
fn base_sarif(results: Vec<Value>) -> Value {
    json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "nexus",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/TPT-Org/tpt-nexus"
                }
            },
            "results": results
        }]
    })
}

/// Serialize a SARIF document to pretty JSON.
pub fn to_string(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|e| format!("{{\"error\":{e}}}"))
}
