//! `nexus` — the command-line front end for tpt-nexus.
//!
//! Subcommands:
//! * `verify <file.telos>` — run the INTENT→VERIFY→ATTEST loop, print the
//!   derived capability table, and write the attestation to disk.
//! * `diff <a.telos> <b.telos>` — show the capability delta between two
//!   versions (security-regression view).
//! * `trace <file.telos>` — render the agent's full reasoning trace as a
//!   shareable Markdown or HTML artifact.
//! * `sign <telos-proof.json>` — produce an ed25519 signature over a manifest.
//! * `new <name> --template <t>` — scaffold a new `.telos` from a starter.
//! * `watch <file.telos>` — re-verify a file whenever it changes on disk.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use tpt_archon_bridge::capability::Right;
use tpt_nexus_archon_emulator::derive_rights;
use tpt_nexus_orchestrator::{BuildPolicy, NexusOrchestrator};

use tpt_nexus_cli::{
    capability_diff, render_capability_table, render_trace_html, render_trace_markdown,
    run_and_derive, select_agent, signing, Policy,
};

#[derive(Parser)]
enum Command {
    /// Verify a `.telos`, attest it, and print the derived capability table.
    Verify {
        /// Path to the `.telos` source.
        path: PathBuf,
        /// Also run `cargo build` on the generated crate and report real bytes.
        #[arg(long)]
        compile: bool,
        /// Apply a `nexus.toml` policy (right overrides, agent selection).
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    /// Show the capability delta between two `.telos` sources.
    Diff {
        /// Baseline version (e.g. the committed file).
        a: PathBuf,
        /// Candidate version (e.g. the PR's file).
        b: PathBuf,
    },
    /// Render the agent's full reasoning trace as a shareable artifact.
    Trace {
        /// Path to the `.telos` source.
        path: PathBuf,
        /// Emit HTML instead of Markdown.
        #[arg(long)]
        html: bool,
    },
    /// Produce an ed25519 signature over a proof manifest.
    Sign {
        /// Path to the `telos-proof.json` to sign.
        manifest: PathBuf,
        /// Hex-encoded ed25519 secret key; generated and printed if omitted.
        #[arg(long)]
        secret_key: Option<String>,
    },
    /// Scaffold a new `.telos` from a starter template.
    New {
        /// Name of the new file (without extension).
        name: String,
        /// Starter template: counter, ledger, kv_store, oracle, rate_limiter.
        #[arg(long, default_value = "ledger")]
        template: String,
    },
    /// Re-verify a `.telos` file whenever it changes on disk.
    Watch {
        /// Path to the `.telos` source to watch.
        path: PathBuf,
    },
}

fn main() -> ExitCode {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let cli = Command::parse();
    match cli {
        Command::Verify {
            path,
            compile,
            policy,
        } => verify(&path, compile, policy.as_deref()),
        Command::Diff { a, b } => diff(&a, &b),
        Command::Trace { path, html } => trace(&path, html),
        Command::Sign {
            manifest,
            secret_key,
        } => sign(&manifest, secret_key.as_deref()),
        Command::New { name, template } => new_project(&name, &template),
        Command::Watch { path } => watch(&path),
    }
}

fn verify(
    path: &std::path::Path,
    compile: bool,
    policy_path: Option<&std::path::Path>,
) -> ExitCode {
    let source = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot read {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };

    let policy = match policy_path.map(Policy::load) {
        Some(Ok(p)) => Some(p),
        Some(Err(e)) => {
            eprintln!("cannot load policy {}: {e}", policy_path.unwrap().display());
            return ExitCode::FAILURE;
        }
        None => None,
    };
    // A policy can force the LLM agent even without NEXUS_AGENT set.
    let agent = policy
        .as_ref()
        .map(|p| p.agent())
        .unwrap_or_else(select_agent);

    let mut orchestrator = NexusOrchestrator::new();
    if compile {
        orchestrator = orchestrator.with_build_policy(BuildPolicy::Compile);
    }

    let artifact = match orchestrator.run_agent_loop(&source, agent.as_ref()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("verify failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Apply any right overrides from the policy before reporting/attesting.
    let rights = match derive_rights(&artifact) {
        Ok(r) => match policy.as_ref() {
            Some(p) => p.apply(r),
            None => r,
        },
        Err(e) => {
            eprintln!("cannot derive capabilities: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("verified {} function(s)\n", rights.len());
    print!("{}", render_capability_table(&rights));
    if let Some(p) = policy_path {
        println!("\n(policy {})", p.display());
    }

    let out_dir = PathBuf::from("nexus-out");
    match artifact.write_attestation(&out_dir) {
        Ok(att) => println!("\nattestation -> {}", att.manifest_path.display()),
        Err(e) => eprintln!("warning: could not write attestation: {e}"),
    }
    if compile {
        println!(
            "compiled artifact -> {} byte(s)",
            artifact.compiled_binary.len()
        );
    }
    ExitCode::SUCCESS
}

fn trace(path: &std::path::Path, html: bool) -> ExitCode {
    let source = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot read {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };
    let artifact = match NexusOrchestrator::new().run_agent_loop(&source, select_agent().as_ref()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("trace failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let rendered = if html {
        render_trace_html(&artifact.report)
    } else {
        render_trace_markdown(&artifact.report)
    };
    println!("{rendered}");
    ExitCode::SUCCESS
}

fn sign(manifest: &std::path::Path, secret_key: Option<&str>) -> ExitCode {
    let json = match std::fs::read_to_string(manifest) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot read {}: {e}", manifest.display());
            return ExitCode::FAILURE;
        }
    };
    let keypair = match secret_key {
        Some(hex) => match signing::Keypair::from_secret_hex(hex) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("invalid secret key: {e}");
                return ExitCode::FAILURE;
            }
        },
        None => signing::Keypair::generate(),
    };
    let signature = keypair.sign(json.as_bytes());
    let sig_path = manifest.with_extension("json.sig");
    match std::fs::write(&sig_path, signing::to_hex(&signature)) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("cannot write {}: {e}", sig_path.display());
            return ExitCode::FAILURE;
        }
    }
    let ok = signing::verify(&keypair.public_hex(), json.as_bytes(), &signature);
    println!("public key : {}", keypair.public_hex());
    println!(
        "signature  -> {}  (verify self-check: {})",
        sig_path.display(),
        ok
    );
    ExitCode::SUCCESS
}

fn diff(a: &std::path::Path, b: &std::path::Path) -> ExitCode {
    let baseline = match run_and_derive(a) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("baseline {} failed to verify: {e}", a.display());
            return ExitCode::FAILURE;
        }
    };
    let candidate = match run_and_derive(b) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("candidate {} failed to verify: {e}", b.display());
            return ExitCode::FAILURE;
        }
    };

    let delta = capability_diff(&baseline, &candidate);
    if delta.is_empty() {
        println!(
            "no capability change between {} and {}",
            a.display(),
            b.display()
        );
        return ExitCode::SUCCESS;
    }

    println!("capability delta: {} -> {}\n", a.display(), b.display());
    for (name, right) in &delta.added {
        println!("  + {name}  -> {right:?}");
    }
    for (name, right) in &delta.removed {
        println!("  - {name}  (was {right:?})");
    }
    for change in &delta.changed {
        let suffix = if strengthens_note(change.from, change.to) {
            "  (strengthened)"
        } else {
            ""
        };
        println!(
            "  ~ {}  {:?} -> {:?}{}",
            change.func, change.from, change.to, suffix
        );
    }

    if delta.has_strengthening() {
        eprintln!("\nSECURITY REGRESSION: a capability was strengthened");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn strengthens_note(from: Right, to: Right) -> bool {
    matches!(
        (from, to),
        (Right::Read, Right::ReadWrite)
            | (Right::Read, Right::Write)
            | (Right::Write, Right::ReadWrite)
    )
}

fn new_project(name: &str, template: &str) -> ExitCode {
    let templates = std::env::var("NEXUS_TEMPLATES")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("..")
                .join("templates")
        });

    if !templates.is_dir() {
        eprintln!("no templates found at {}", templates.display());
        return ExitCode::FAILURE;
    }

    let src = templates.join(format!("{template}.telos"));
    if !src.exists() {
        // Help the user by listing what *is* available.
        let available: Vec<String> = std::fs::read_dir(&templates)
            .map(|entries| {
                entries
                    .flatten()
                    .filter_map(|e| {
                        let name = e.file_name().to_string_lossy().to_string();
                        name.strip_suffix(".telos").map(|s| s.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default();
        eprintln!(
            "no template `{template}` (available: {})",
            available.join(", ")
        );
        return ExitCode::FAILURE;
    }

    let dest = PathBuf::from(format!("{name}.telos"));
    if let Err(e) = std::fs::copy(&src, &dest) {
        eprintln!("cannot write {}: {e}", dest.display());
        return ExitCode::FAILURE;
    }
    println!("scaffolded {} from template `{}`", dest.display(), template);
    println!("next: nexus verify {}", dest.display());
    ExitCode::SUCCESS
}

fn watch(path: &std::path::Path) -> ExitCode {
    let source = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot read {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };

    println!("watching {} (ctrl-c to stop)", path.display());
    let mut last = source;
    let mut last_modified = modified_seconds(path);
    let mut runs = 0usize;
    loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let modified = modified_seconds(path);
        if modified == last_modified {
            continue;
        }
        last_modified = modified;
        let current = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("re-read failed: {e}");
                continue;
            }
        };
        if current == last {
            continue;
        }
        last = current.clone();

        runs += 1;
        match NexusOrchestrator::new().run_agent_loop(&current, select_agent().as_ref()) {
            Ok(artifact) => {
                let rights = derive_rights(&artifact).map(|r| r.len()).unwrap_or(0);
                println!(
                    "[run {runs}] verified {} function(s), {} grant(s)",
                    artifact.functions().len(),
                    rights
                );
            }
            Err(e) => eprintln!("[{runs}] verify failed: {e}"),
        }
    }
}

/// Best-effort last-modified time in seconds, for change detection.
fn modified_seconds(path: &std::path::Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
