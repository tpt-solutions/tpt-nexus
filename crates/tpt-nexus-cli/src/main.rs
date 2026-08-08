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
//! * `init` — scaffold a `nexus.toml` policy file in the current directory.
//! * `doctor` — diagnose the local environment (siblings, toolchain, templates)
//!   before a build, so path-dep failures are caught early.
//! * `watch <file.telos>` — re-verify a file whenever it changes on disk.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::ExitCode;

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;

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

use tpt_nexus_archon_emulator::{
    derive_rights, ArchonEmulator, ArchonError, Grant, SyscallRequest,
};
use tpt_nexus_cli::{
    capability_diff, render_capability_table, render_trace_html, render_trace_markdown,
    resolve_grant_key, run_and_derive,
    sarif::{sarif_for_diff, sarif_for_rights, to_string as sarif_to_string},
    select_agent, signing, Policy,
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
        /// Require the attestation to carry a valid ed25519 signature from this
        /// hex public key. Makes `verify` enforce provenance, not just correctness.
        #[arg(long)]
        require_signature: Option<String>,
        /// Path to the `.sig` file (defaults to `<output>/telos-proof.json.sig`).
        #[arg(long)]
        sig: Option<PathBuf>,
        /// Write the derived capability surface as SARIF 2.1.0 (for GitHub
        /// code-scanning) to this path.
        #[arg(long)]
        sarif: Option<PathBuf>,
    },
    /// Show the capability delta between two `.telos` sources.
    ///
    /// Exit-code contract (matches `nexus-validate-manifest`'s 0/1/2 scheme):
    ///   0 = clean: no capability change, OR a *weakening* (a right was reduced,
    ///       e.g. `ReadWrite` → `Read` — a safe reduction, never a regression).
    ///   1 = security regression: a capability was strengthened (a new
    ///       `ReadWrite` or any escalation — treat as a supply-chain alert).
    ///   2 = error: one side could not be verified.
    Diff {
        /// Baseline version (e.g. the committed file).
        a: PathBuf,
        /// Candidate version (e.g. the PR's file).
        b: PathBuf,
        /// Emit the capability delta as JSON instead of a human table.
        #[arg(long)]
        json: bool,
        /// Write the capability delta as SARIF 2.1.0 to this path.
        #[arg(long)]
        sarif: Option<PathBuf>,
    },
    /// Adversarially exercise the derived grant set: confirm every granted
    /// capability only permits what it should, and deny everything else. A real
    /// "tightness" check that complements `assert_grants!` in CI.
    Fuzz {
        /// Path to the `.telos` source to fuzz.
        path: PathBuf,
        /// Number of randomized syscall rounds to generate.
        #[arg(long, default_value_t = 256)]
        iterations: usize,
    },
    /// Serve an attestation/trace directory over HTTP so it can be opened in a
    /// browser (a zero-dependency static file server).
    Serve {
        /// Directory to serve (default: `nexus-out`).
        #[arg(long, default_value = "nexus-out")]
        dir: PathBuf,
        /// TCP port to listen on.
        #[arg(long, default_value_t = 8080)]
        port: u16,
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
    /// Scaffold a `nexus.toml` policy file in the current directory.
    Init {
        /// Overwrite an existing `nexus.toml`.
        #[arg(long)]
        force: bool,
    },
    /// Diagnose the local environment before building: sibling repos, the Rust
    /// toolchain, the templates directory, and a local `nexus.toml`.
    Doctor,
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
            require_signature,
            sig,
            sarif,
        } => verify(VerifyOpts {
            path: &path,
            compile,
            policy_path: policy.as_deref(),
            output: output.as_deref(),
            json,
            require_signature: require_signature.as_deref(),
            sig: sig.as_deref(),
            sarif: sarif.as_deref(),
        }),
        Command::Diff { a, b, json, sarif } => diff(&a, &b, json, sarif.as_deref()),
        Command::Fuzz { path, iterations } => fuzz(&path, iterations),
        Command::Serve { dir, port } => serve(&dir, port),
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
        Command::Init { force } => init_project(force),
        Command::Doctor => doctor(),
        Command::Watch { path } => watch(&path),
        Command::Completions { shell } => completions(shell),
        Command::VerifySignature {
            manifest,
            signature,
            pubkey,
        } => verify_signature(&manifest, &signature, &pubkey),
    }
}

/// Bundled options for [`verify`], kept in one struct so the CLI entry point
/// stays under the clippy `too-many-arguments` budget as flags grow.
struct VerifyOpts<'a> {
    path: &'a std::path::Path,
    compile: bool,
    policy_path: Option<&'a std::path::Path>,
    output: Option<&'a std::path::Path>,
    json: bool,
    require_signature: Option<&'a str>,
    sig: Option<&'a std::path::Path>,
    sarif: Option<&'a std::path::Path>,
}

fn verify(opts: VerifyOpts) -> ExitCode {
    let VerifyOpts {
        path,
        compile,
        policy_path,
        output,
        json,
        require_signature,
        sig,
        sarif,
    } = opts;
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
    let derived = match derive_rights(&artifact) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("cannot derive capabilities: {e}");
            return ExitCode::FAILURE;
        }
    };
    // A policy that names a function absent from the derived set is a silent
    // no-op (a typo'd `func`); surface it so the surface is what the author
    // thinks it is. Resolution accepts the bare `func` (matching `module::func`
    // suffixes) so single-module policies don't false-warn.
    if let Some(p) = policy.as_ref() {
        for g in &p.grant {
            if resolve_grant_key(&derived, &g.func).is_none() {
                tracing::warn!(
                    "policy grant `{}` matches no verified function; ignoring",
                    g.func
                );
            }
        }
    }
    let rights = match policy.as_ref() {
        Some(p) => p.apply(derived),
        None => derived,
    };

    // [SARIF] Optionally emit the derived surface as SARIF 2.1.0 for GitHub
    // code-scanning / the Security tab.
    if let Some(sarif_path) = sarif {
        let doc = sarif_for_rights(&rights, path.to_str().unwrap_or("<source>"));
        if let Err(e) = std::fs::write(sarif_path, sarif_to_string(&doc)) {
            tracing::error!("cannot write SARIF {}: {e}", sarif_path.display());
            return ExitCode::FAILURE;
        }
    }

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

    // [enforce provenance] When a trusted pubkey is supplied, confirm a
    // *pre-existing, signed* attestation at `out_dir` still describes this source
    // — without overwriting the signed artifact. This is the CI gate: a trusted
    // signature survives, and a source that diverged from it is refused.
    let attestation = if let Some(pubkey) = require_signature {
        let manifest_path = out_dir.join("telos-proof.json");
        let sig_path = sig
            .map(PathBuf::from)
            .unwrap_or_else(|| manifest_path.with_extension("json.sig"));
        match check_signed_attestation(&artifact, &manifest_path, &sig_path, pubkey) {
            Ok(()) => Some(manifest_path.display().to_string()),
            Err(e) => {
                tracing::error!("{e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        match artifact.write_attestation(&out_dir) {
            Ok(att) => Some(att.manifest_path.display().to_string()),
            Err(e) => {
                tracing::warn!("could not write attestation: {e}");
                None
            }
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

fn diff(
    a: &std::path::Path,
    b: &std::path::Path,
    json: bool,
    sarif: Option<&std::path::Path>,
) -> ExitCode {
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

    // [SARIF] Optionally emit the delta as SARIF (strengthenings at error level).
    if let Some(sarif_path) = sarif {
        let doc = sarif_for_diff(&delta, &b.display().to_string());
        if let Err(e) = std::fs::write(sarif_path, sarif_to_string(&doc)) {
            tracing::error!("cannot write SARIF {}: {e}", sarif_path.display());
            return diff_error();
        }
    }

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

/// The directory nexus looks in for starter `.telos` templates. Overridable via
/// `NEXUS_TEMPLATES`; defaults to `templates/` next to the workspace root.
fn templates_dir() -> PathBuf {
    std::env::var("NEXUS_TEMPLATES")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("..")
                .join("templates")
        })
}

/// Scaffold a `nexus.toml` policy file into the current directory from the
/// bundled template, so a project can pin its capability surface in version
/// control without hand-writing TOML.
fn init_project(force: bool) -> ExitCode {
    let src = templates_dir().join("nexus.toml");
    if !src.is_file() {
        tracing::error!("no template policy found at {}", src.display());
        return ExitCode::FAILURE;
    }
    let dest = PathBuf::from("nexus.toml");
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
    println!("scaffolded {} from {}", dest.display(), src.display());
    println!("next: nexus verify examples/capability_boundary.telos --policy nexus.toml");
    ExitCode::SUCCESS
}

/// Diagnose the local environment before a build. Catches the most common
/// adoption failure — missing sibling repos (path deps) or a missing toolchain —
/// and reports it in plain language instead of a cryptic cargo error.
fn doctor() -> ExitCode {
    let mut problems = 0usize;
    let mut check = |label: &str, ok: bool, detail: &str| {
        if ok {
            println!("[OK]   {label}: {detail}");
        } else {
            println!("[FAIL] {label}: {detail}");
            problems += 1;
        }
    };

    let telos = PathBuf::from("../tpt-telos");
    let archon = PathBuf::from("../tpt-archon");
    check(
        "tpt-telos sibling",
        telos.is_dir(),
        &format!("{}", telos.display()),
    );
    check(
        "tpt-archon sibling",
        archon.is_dir(),
        &format!("{}", archon.display()),
    );

    let cargo_ok = std::process::Command::new("cargo")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    check("cargo toolchain", cargo_ok, "cargo --version");
    let rustc_ok = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    check("rustc toolchain", rustc_ok, "rustc --version");

    let templates = templates_dir();
    check(
        "templates directory",
        templates.is_dir(),
        &format!("{}", templates.display()),
    );

    let local_policy = PathBuf::from("nexus.toml");
    if local_policy.is_file() {
        println!("[OK]   local nexus.toml present");
    } else {
        println!("[WARN] no local nexus.toml (run `nexus init` to scaffold one)");
    }

    println!();
    if problems == 0 {
        println!("environment OK");
        ExitCode::SUCCESS
    } else {
        println!("{problems} problem(s) found — fix the above before building");
        ExitCode::FAILURE
    }
}

/// Verify an on-disk attestation's ed25519 signature against a hex public key.
/// Returns `Ok(true)` when the signature is valid, `Ok(false)` when present but
/// invalid, and `Err` when a file cannot be read or the signature is malformed.
fn check_signature(
    manifest: &std::path::Path,
    sig: &std::path::Path,
    pubkey: &str,
) -> Result<bool, String> {
    let msg =
        std::fs::read(manifest).map_err(|e| format!("cannot read {}: {e}", manifest.display()))?;
    let sig_hex =
        std::fs::read_to_string(sig).map_err(|e| format!("cannot read {}: {e}", sig.display()))?;
    let sig_bytes =
        signing::from_hex(sig_hex.trim()).map_err(|e| format!("invalid signature file: {e}"))?;
    Ok(signing::verify(pubkey, &msg, &sig_bytes))
}

/// In provenance mode, confirm the on-disk attestation at `manifest_path` is
/// (a) signed by `pubkey` and (b) describes the same source we just verified.
/// The signed artifact is never overwritten, so a trusted CI signature survives
/// re-verification.
fn check_signed_attestation(
    artifact: &tpt_nexus_orchestrator::VerifiedArtifact,
    manifest_path: &std::path::Path,
    sig_path: &std::path::Path,
    pubkey: &str,
) -> Result<(), String> {
    if !manifest_path.is_file() {
        return Err(format!(
            "no attestation at {} to verify (run `nexus verify` once, then `nexus sign` it)",
            manifest_path.display()
        ));
    }
    if !sig_path.is_file() {
        return Err(format!(
            "no signature at {} (run `nexus sign {}`)",
            sig_path.display(),
            manifest_path.display()
        ));
    }
    match check_signature(manifest_path, sig_path, pubkey) {
        Ok(true) => {}
        Ok(false) => {
            return Err(format!(
                "attestation signature is INVALID for the supplied pubkey ({pubkey})"
            ))
        }
        Err(e) => return Err(e),
    }
    // The signed attestation must describe the exact source we just verified,
    // so a source edited after signing is caught even if it still verifies.
    let on_disk = std::fs::read_to_string(manifest_path)
        .map_err(|e| format!("cannot read {}: {e}", manifest_path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&on_disk)
        .map_err(|e| format!("attestation is not valid JSON: {e}"))?;
    let signed_hash = value
        .get("source_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "attestation has no source_hash".to_string())?;
    if signed_hash != artifact.manifest.source_hash {
        return Err(format!(
            "signed attestation describes a different source (signed={signed_hash}, verified={})",
            artifact.manifest.source_hash
        ));
    }
    Ok(())
}

/// Adversarially exercise the derived grant set to prove it is *tight*: every
/// granted capability permits exactly what its right allows, and nothing else is
/// permitted. A randomized pass plus a deterministic per-grant check.
fn fuzz(path: &std::path::Path, iterations: usize) -> ExitCode {
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
            tracing::error!("fuzz: verify failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let rights = match derive_rights(&artifact) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("fuzz: cannot derive capabilities: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut emulator = ArchonEmulator::new();
    let pid = match emulator.load_artifact_with_rights(&artifact, &rights) {
        Ok(pid) => pid,
        Err(e) => {
            tracing::error!("fuzz: cannot mint capabilities: {e}");
            return ExitCode::FAILURE;
        }
    };
    let grants: Vec<Grant> = match emulator.process(pid) {
        Some(p) => p.grants.clone(),
        None => {
            tracing::error!("fuzz: process vanished after load");
            return ExitCode::FAILURE;
        }
    };
    if grants.is_empty() {
        println!("fuzz: no grants to exercise");
        return ExitCode::SUCCESS;
    }

    let mut rng = StdRng::seed_from_u64(0x9E3779B97F4A7C15);
    let mut tested = 0usize;
    let mut violations = 0usize;

    // Deterministic tightness check: the allowed direction must succeed, and the
    // forbidden direction (if any) must be denied.
    for g in &grants {
        let allowed = if g.right.allows_read() {
            SyscallRequest::ReadPage {
                block_id: g.block_id,
            }
        } else {
            SyscallRequest::WritePage {
                block_id: g.block_id,
                data: vec![0u8; 4],
            }
        };
        if emulator.handle_syscall(pid, allowed).is_err() {
            violations += 1;
            println!(
                "VIOLATION: {} (right {:?}) allowed op was denied",
                g.func_name, g.right
            );
        }
        let forbidden: Option<SyscallRequest> = if !g.right.allows_write() {
            Some(SyscallRequest::WritePage {
                block_id: g.block_id,
                data: vec![0u8; 4],
            })
        } else if !g.right.allows_read() {
            Some(SyscallRequest::ReadPage {
                block_id: g.block_id,
            })
        } else {
            None
        };
        if let Some(op) = forbidden {
            if !matches!(
                emulator.handle_syscall(pid, op),
                Err(ArchonError::CapabilityViolation { .. })
            ) {
                violations += 1;
                println!(
                    "VIOLATION: {} (right {:?}) forbidden op was NOT denied",
                    g.func_name, g.right
                );
            }
        }
        tested += 1;
    }

    // Randomized pass: pick a granted page, pick a direction, expect the outcome
    // to always match the right.
    for _ in 0..iterations {
        let g = &grants[rng.gen_range(0..grants.len())];
        let write = rng.gen_bool(0.5);
        let op = if write {
            SyscallRequest::WritePage {
                block_id: g.block_id,
                data: random_vec(&mut rng, 16),
            }
        } else {
            SyscallRequest::ReadPage {
                block_id: g.block_id,
            }
        };
        let allowed = if write {
            g.right.allows_write()
        } else {
            g.right.allows_read()
        };
        match (allowed, emulator.handle_syscall(pid, op)) {
            (true, Err(_)) | (false, Ok(_)) => {
                violations += 1;
                println!(
                    "VIOLATION: {} (right {:?}) inconsistent outcome on {}",
                    g.func_name,
                    g.right,
                    if write { "write" } else { "read" }
                );
            }
            _ => {}
        }
        tested += 1;
    }

    println!(
        "fuzzed {tested} operations across {} grant(s); {violations} violation(s)",
        grants.len()
    );
    if violations == 0 {
        ExitCode::SUCCESS
    } else {
        tracing::error!("fuzz found {violations} capability-surface inconsistencies");
        ExitCode::FAILURE
    }
}

/// Fill a small random byte vector (kept well under a page so writes are legal).
fn random_vec(rng: &mut StdRng, max: usize) -> Vec<u8> {
    let len = rng.gen_range(0..max);
    (0..len).map(|_| rng.gen()).collect()
}

/// Serve a directory of attestation/trace artifacts over HTTP so it can be opened
/// in a browser. Minimal, dependency-free static file server; `nexus trace
/// --html` produces the file worth opening.
fn serve(dir: &std::path::Path, port: u16) -> ExitCode {
    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("cannot bind 127.0.0.1:{port}: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "nexus serve: http://127.0.0.1:{port}/  (serving {})",
        dir.display()
    );
    println!("ctrl-c to stop");
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => serve_one(&mut stream, dir),
            Err(e) => tracing::warn!("accept error: {e}"),
        }
    }
    ExitCode::SUCCESS
}

/// Handle one HTTP connection: serve a file from `dir`, or 404.
fn serve_one(stream: &mut std::net::TcpStream, dir: &std::path::Path) {
    use std::io::Read;
    let mut buf = [0u8; 1024];
    let req = match stream.read(&mut buf) {
        Ok(n) if n > 0 => String::from_utf8_lossy(&buf[..n]).to_string(),
        _ => return,
    };
    // Parse the request line: `GET /path HTTP/1.1`.
    let path = req
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .trim_start_matches('/')
        .to_string();
    let rel = if path.is_empty() {
        "index.html".to_string()
    } else {
        path
    };

    // Resolve within `dir` and reject traversal outside it.
    let target = dir.join(&rel);
    let Ok(canonical) = target.canonicalize() else {
        write_status(stream, "404 Not Found", "text/plain", b"not found");
        return;
    };
    let Ok(dir_canonical) = dir.canonicalize() else {
        write_status(stream, "404 Not Found", "text/plain", b"not found");
        return;
    };
    if !canonical.starts_with(&dir_canonical) {
        write_status(stream, "403 Forbidden", "text/plain", b"forbidden");
        return;
    }
    match std::fs::read(&canonical) {
        Ok(bytes) => write_status(stream, "200 OK", content_type(&canonical), &bytes),
        Err(_) => write_status(stream, "404 Not Found", "text/plain", b"not found"),
    }
}

/// Write a minimal HTTP/1.1 response.
fn write_status(stream: &mut std::net::TcpStream, status: &str, content_type: &str, body: &[u8]) {
    use std::io::Write;
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream
        .write_all(header.as_bytes())
        .and_then(|_| stream.write_all(body));
}

/// Guess a content type from a file extension (only what we serve).
fn content_type(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("json") => "application/json",
        Some("css") => "text/css",
        Some("js") => "application/javascript",
        _ => "text/plain; charset=utf-8",
    }
}
