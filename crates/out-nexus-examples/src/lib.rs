//! Shared helpers for the nexus end-to-end examples.

use std::path::{Path, PathBuf};

/// Locate the repo-root `examples/` directory holding the `.telos` fixtures.
///
/// Resolved relative to this crate's manifest so the examples run identically
/// from the workspace root or from the crate directory.
pub fn telos_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("examples")
}

/// Read one of the `.telos` fixtures by file name.
pub fn telos_source(name: &str) -> String {
    let path = telos_dir().join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Install a console subscriber so the run's `tracing` events are visible.
///
/// Ignores an existing global subscriber, so it is safe to call from anywhere.
pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
}

/// Print a section heading.
pub fn banner(step: &str, title: &str) {
    println!("\n=== [{step}] {title} ===");
}
