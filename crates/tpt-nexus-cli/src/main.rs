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

use clap::{CommandFactory, Parser};
use tpt_archon_bridge::capability::Right;
use tpt_nexus_orchestrator::{BuildPolicy, NexusError, NexusOrchestrator};

/// `nexus diff` exit-code contract (matches `nexus-validate-manifest`'s own
/// 0/1/2/3 scheme by reserving 0/1/2 here):
///   0 = clean (no capability change)
///   1 = security regression (a capability was strengthened)
///   2 = error (a side could not be verified)
const DIFF_CLEAN: ExitCode = ExitCode::SUCCESS;
fn diff_regression() -> ExitCode {
    ExitCode::from(1)
}
fn diff_error() -> ExitCode {
    ExitCode::from(2)
}

use tpt_nexus_archon_emulator::{derive_rights, ArchonEmulator};
use tpt_nexus_cli::{
    capability_diff, render_capability_table, render_trace_html, render_trace_markdown,
    run_and_derive, select_agent, signing, Policy,
};

/// tpt-nexus: close the loop between tpt-telos (verified intent) and tpt-archon
/// (capability-gated execution). Run `nexus verify <file>.telos` to derive and
/// attest a program's capability surface.
#[derive(Parser)]
#[command(name = "nexus", version, about = "tpt-nexus: verify, attest, and gate .telos programs against tpt-archon", long_about = None)]
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
        /// Directory to write the attestation into (default: `nexus-out`).
        #[arg(long)]
        output: Option<PathBuf>,
        /// Emit the derived grant set as JSON instead of a human table.
        #[arg(long)]
        json: bool,
    },
    /// Show the capability delta between two `.telos` sources.
    Diff {
        /// Baseline version (e.g. the committed file).
        a: PathBuf,
        /// Candidate version (e.g. the PR's file).
        b: PathBuf,
        /// Emit the capability delta as JSON instead of a human table.
        #[arg(long)]
        json: bool,
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
        /// Starter template: counter, ledger, kv_store, oracle, rate_limiter, multi_module.
        #[arg(long, default_value = "ledger")]
        template: String,
        /// Overwrite an existing file with the same name.
        #[arg(long)]
        force: bool,
    },
    /// Re-verify a `.telos` file whenever it changes on disk.
    Watch {
        /// Path to the `.telos` source to watch.
        path: PathBuf,
    },
    /// Generate shell completions (bash, zsh, fish, powershell, elvish).
    Completions {
        /// The shell to generate completions for.
        shell: clap_complete::Shell,
    },
    /// Verify an ed25519 signature over a proof manifest with a public key.
    VerifySignature {
        /// Path to the `telos-proof.json` that was signed.
        manifest: PathBuf,
        /// Path to the `.sig` file produced by `nexus sign`.
        signature: PathBuf,
        /// Hex-encoded ed25519 public key to verify against.
        #[arg(long)]
        pubkey: String,
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
            output,
            json,
        } => verify(&path, compile, policy.as_deref(), output.as_deref(), json),
        Command::Diff { a, b, json } => diff(&a, &b, json),
        Command::Trace { path, html } => trace(&path, html),
        Command::Sign {
            manifest,
            secret_key,
        } => sign(&manifest, secret_key.as_deref()),
        Command::New {
            name,
            template,
            force,
        } => new_project(&name, &template, force),
        Command::Watch { path } => watch(&path),
        Command::Completions { shell } => completions(shell),
        Command::VerifySignature {
            manifest,
            signature,
            pubkey,
        } => verify_signature(&manifest, &signature, &pubkey),
    }
}

fn verify(
    path: &std::path::Path,
    compile: bool,
    policy_path: Option<&std::path::Path>,
    output: Option<&std::path::Path>,
    json: bool,
) -> ExitCode {
    let source = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("cannot read {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };

    let policy = match policy_path.map(Policy::load) {
        Some(Ok(p)) => Some(p),
        Some(Err(e)) => {
            tracing::error!("cannot load policy {}: {e}", policy_path.unwrap().display());
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
            tracing::error!("verify failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Derive the right each function earns, then apply any policy overrides. The
    // *same* map is what the emulator mints against, so an override is enforced —
    // not just printed.
    let rights = match derive_rights(&artifact) {
        Ok(r) => match policy.as_ref() {
            Some(p) => p.apply(r),
            None => r,
        },
        Err(e) => {
            tracing::error!("cannot derive capabilities: {e}");
            return ExitCode::FAILURE;
        }
    };

    // [6. MINT] Actually mint the capabilities through the emulator so policy
    // overrides are enforced at the kernel boundary, not just rendered in a table.
    let mut emulator = ArchonEmulator::new();
    let pid = match emulator.load_artifact_with_rights(&artifact, &rights) {
        Ok(pid) => pid,
        Err(e) => {
            tracing::error!("cannot mint capabilities: {e}");
            return ExitCode::FAILURE;
        }
    };

    let minted = emulator.process(pid).map(|p| p.grants.len()).unwrap_or(0);
    let out_dir = output
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("nexus-out"));
    let attestation = match artifact.write_attestation(&out_dir) {
        Ok(att) => Some(att.manifest_path.display().to_string()),
        Err(e) => {
            tracing::warn!("could not write attestation: {e}");
            None
        }
    };

    if json {
        let grants: serde_json::Map<String, serde_json::Value> = rights
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::json!(format!("{v:?}"))))
            .collect();
        let value = serde_json::json!({
            "verified": rights.len(),
            "grants": grants,
            "policy": policy_path.map(|p| p.display().to_string()),
            "minted_grants": minted,
            "attestation": attestation,
            "compiled_bytes": artifact.compiled_binary.len(),
        });
        println!("{value}");
        return ExitCode::SUCCESS;
    }

    println!("verified {} function(s)\n", rights.len());
    print!("{}", render_capability_table(&rights));
    if let Some(p) = policy_path {
        println!("\n(policy {})", p.display());
    }
    println!(
        "\nminted {} capability grant(s) into Archon process {pid}",
        minted
    );

    if let Some(att) = attestation {
        println!("\nattestation -> {att}");
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
            tracing::error!("cannot read {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };
    let artifact = match NexusOrchestrator::new().run_agent_loop(&source, select_agent().as_ref()) {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("trace failed: {e}");
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
            tracing::error!("cannot read {}: {e}", manifest.display());
            return ExitCode::FAILURE;
        }
    };
    let (keypair, generated) = match secret_key {
        Some(hex) => match signing::Keypair::from_secret_hex(hex) {
            Ok(k) => (k, false),
            Err(e) => {
                tracing::error!("invalid secret key: {e}");
                return ExitCode::FAILURE;
            }
        },
        None => (signing::Keypair::generate(), true),
    };
    let signature = keypair.sign(json.as_bytes());
    let sig_path = manifest.with_extension("json.sig");
    match std::fs::write(&sig_path, signing::to_hex(&signature)) {
        Ok(()) => {}
        Err(e) => {
            tracing::error!("cannot write {}: {e}", sig_path.display());
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
    if generated {
        println!(
            "\nSECRET KEY (save this now — it is shown only once):\n  {}",
            keypair.secret_hex()
        );
    }
    // The self-check proves the on-disk signature actually verifies; a failure
    // here means something is fundamentally wrong with the signing pipeline, so
    // it must be a hard error rather than a silent success.
    if ok {
        ExitCode::SUCCESS
    } else {
        tracing::error!("internal self-check failed: signature did not verify");
        ExitCode::FAILURE
    }
}

fn diff(a: &std::path::Path, b: &std::path::Path, json: bool) -> ExitCode {
    // Exit-code contract (matches `nexus-validate-manifest`):
    //   0 = clean (no capability change)
    //   1 = security regression (a capability was strengthened)
    //   2 = error (could not verify one side)
    let baseline = match run_and_derive(a) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("{}: {}", cannot_read(&e, a), e);
            return diff_error();
        }
    };
    let candidate = match run_and_derive(b) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("{}: {}", cannot_read(&e, b), e);
            return diff_error();
        }
    };

    let delta = capability_diff(&baseline, &candidate);
    if delta.is_empty() {
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "a": a.display().to_string(),
                    "b": b.display().to_string(),
                    "changed": false,
                    "strengthening": false,
                })
            );
        } else {
            println!(
                "no capability change between {} and {}",
                a.display(),
                b.display()
            );
        }
        return DIFF_CLEAN;
    }

    if json {
        let added: Vec<serde_json::Value> = delta
            .added
            .iter()
            .map(|(n, r)| serde_json::json!({ "func": n, "right": format!("{r:?}") }))
            .collect();
        let removed: Vec<serde_json::Value> = delta
            .removed
            .iter()
            .map(|(n, r)| serde_json::json!({ "func": n, "right": format!("{r:?}") }))
            .collect();
        let changed: Vec<serde_json::Value> = delta
            .changed
            .iter()
            .map(|c| {
                serde_json::json!({
                    "func": c.func,
                    "from": format!("{:?}", c.from),
                    "to": format!("{:?}", c.to),
                })
            })
            .collect();
        let value = serde_json::json!({
            "a": a.display().to_string(),
            "b": b.display().to_string(),
            "changed": true,
            "strengthening": delta.has_strengthening(),
            "added": added,
            "removed": removed,
            "changed_grants": changed,
        });
        println!("{value}");
        return if delta.has_strengthening() {
            diff_regression()
        } else {
            DIFF_CLEAN
        };
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
        println!("\nSECURITY REGRESSION: a capability was strengthened");
        diff_regression()
    } else {
        DIFF_CLEAN
    }
}

/// Render the phrasing every other subcommand uses for a missing/unreadable
/// file, including when `run_and_derive` failed purely because the file could not
/// be read (an `Io` error) rather than because verification failed.
fn cannot_read(e: &NexusError, path: &std::path::Path) -> String {
    match e {
        NexusError::Io(_) => format!("cannot read {}", path.display()),
        _ => format!("{} failed to verify", path.display()),
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

/// Print shell completion scripts for the given shell to stdout.
fn completions(shell: clap_complete::Shell) -> ExitCode {
    let mut cmd = Command::command();
    let name = cmd.get_name().to_string();
    clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
    ExitCode::SUCCESS
}

/// Verify an ed25519 signature over a proof manifest against a public key. This
/// closes the one-way-signing gap: `nexus sign` produces a `.sig`, and this
/// command lets any reviewer confirm it was made with the project's key.
fn verify_signature(
    manifest: &std::path::Path,
    signature: &std::path::Path,
    pubkey: &str,
) -> ExitCode {
    let json = match std::fs::read_to_string(manifest) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("cannot read {}: {e}", manifest.display());
            return ExitCode::FAILURE;
        }
    };
    let sig_hex = match std::fs::read_to_string(signature) {
        Ok(s) => s.trim().to_string(),
        Err(e) => {
            tracing::error!("cannot read {}: {e}", signature.display());
            return ExitCode::FAILURE;
        }
    };
    let sig_bytes = match signing::from_hex(&sig_hex) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("invalid signature file: {e}");
            return ExitCode::FAILURE;
        }
    };
    let ok = signing::verify(pubkey, json.as_bytes(), &sig_bytes);
    if ok {
        println!("signature valid for {}", manifest.display());
        ExitCode::SUCCESS
    } else {
        tracing::error!("signature verification FAILED for {}", manifest.display());
        ExitCode::FAILURE
    }
}

fn new_project(name: &str, template: &str, force: bool) -> ExitCode {
    let templates = std::env::var("NEXUS_TEMPLATES")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("..")
                .join("templates")
        });

    if !templates.is_dir() {
        tracing::error!("no templates found at {}", templates.display());
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
        tracing::error!(
            "no template `{template}` (available: {})",
            available.join(", ")
        );
        return ExitCode::FAILURE;
    }

    let dest = PathBuf::from(format!("{name}.telos"));
    if dest.exists() && !force {
        tracing::error!(
            "{} already exists (use --force to overwrite)",
            dest.display()
        );
        return ExitCode::FAILURE;
    }
    if let Err(e) = std::fs::copy(&src, &dest) {
        tracing::error!("cannot write {}: {e}", dest.display());
        return ExitCode::FAILURE;
    }
    // Also copy the sample policy when there is one; never clobber an existing
    // project policy.
    let policy_src = templates.join("nexus.toml");
    let policy_dest = PathBuf::from("nexus.toml");
    if policy_src.is_file() && !policy_dest.exists() {
        let _ = std::fs::copy(&policy_src, &policy_dest);
    }
    println!("scaffolded {} from template `{}`", dest.display(), template);
    println!("next: nexus verify {}", dest.display());
    ExitCode::SUCCESS
}

fn watch(path: &std::path::Path) -> ExitCode {
    let source = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("cannot read {}: {e}", path.display());
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
                tracing::error!("re-read failed: {e}");
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
            Err(e) => tracing::error!("[{runs}] verify failed: {e}"),
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
