//! Experimental WASM bindings for the tpt-nexus verify → derive half of the loop.
//!
//! See `README.md` for scope and build instructions. This is intentionally a
//! thin, browser-friendly surface: it verifies a `.telos` source and returns the
//! derived capability surface as JSON. It does **not** mint or execute (the
//! `tpt-archon` kernel cannot run in a browser).

use serde_json::json;
use std::collections::BTreeMap;
use tpt_nexus_orchestrator::{NexusOrchestrator, StaticAgent};
use wasm_bindgen::prelude::*;

/// Verify `source` and return the derived capability surface as a JSON string.
///
/// The returned object is `{ ok, source_hash, verified, rights }` where `rights`
/// maps each function name to `"Read"` or `"ReadWrite"`. On failure, `ok` is
/// false and `error` carries the reason.
#[wasm_bindgen]
pub fn verify_and_derive(source: &str) -> String {
    let orchestrator = NexusOrchestrator::new();
    let artifact = match orchestrator.run_agent_loop(source, &StaticAgent::new()) {
        Ok(a) => a,
        Err(e) => return json!({ "ok": false, "error": e.to_string() }).to_string(),
    };

    let rights: BTreeMap<String, String> = artifact
        .functions()
        .iter()
        .map(|r| {
            let right = if r.mutates_state {
                "ReadWrite"
            } else {
                "Read"
            };
            (r.func_name.clone(), right.to_string())
        })
        .collect();

    json!({
        "ok": true,
        "source_hash": artifact.manifest.source_hash,
        "verified": artifact.all_verified(),
        "rights": rights,
    })
    .to_string()
}
