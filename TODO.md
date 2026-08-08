# TPT Nexus — TODO

Tracks the build of `tpt-nexus`, the integration harness proving the closed
loop `tpt-telos` (intent + verification + attestation) → `tpt-archon`
(capability-gated execution) actually works end-to-end.

**Status:** §1–§11 are complete and green. `cargo fmt --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, and
`cargo test --workspace` all pass (**81 tests + doctests**, including the
`loop_then_archon` e2e test and the new CLI integration tests in
`crates/tpt-nexus-cli/tests/cli.rs`). Three runnable examples
(`example1`–`example3`) and six starter templates (including a multi-module
`multi_module.telos`) work against the real `tpt-telos-sdk` and `tpt-archon`
crates. The `telos-sdk` row in §0 was updated: the SDK now exists, so nexus
builds against it. The CLI now also exposes `verify --policy/--json/--output`,
`diff --json` (with distinct 0/1/2 exit codes), `sign` (recovering and printing
the secret key), `verify-signature`, `completions`, `new --force`, and `watch`.

**Decisions locked in before starting (see "Spec vs. reality" below for why):**
- **Reuse real crates.** Nexus is a thin glue/demo layer over the existing,
  tested `tpt-telos-agent` / `tpt-telos-codegen` / `tpt-telos-verifier` and
  `tpt-archon-kernel` / `tpt-archon-bridge` APIs — not a from-scratch
  simulation, and not the `telos-sdk` crate (see below, it doesn't exist).
- **Archon layer: `tpt-archon-kernel`** (scheduler + memory + ipc), itself
  built on `tpt-archon-bridge`'s capability primitives.
- **Demo agent: `StaticAgent`** (offline, deterministic) for `examples/`. No
  API key required to build or run this repo. Real-LLM support
  (`tpt_telos_agent::llm_agent::LlmAgent`) is a later stretch goal, not v1.
- **Dependency style:** local path deps into `../tpt-telos` and
  `../tpt-archon` for everything nexus touches. Both are pre-1.0 and
  actively changing; pinning to crates.io versions now would fight the
  "prove today's integration actually works" goal. (`tpt-telos-*` crates
  are published; `tpt-archon-bridge`/`-kernel` are not yet, so path deps are
  required there regardless.)

---

## 0. Spec vs. reality — read this before writing code

`spec.txt` describes some APIs that don't exist yet, or exist under
different names/shapes. Confirmed by reading both sibling repos directly.
Do **not** "fix" nexus code to match the spec's literal names — update
`spec.txt` instead once the real design is settled (see §7).

| spec.txt says | Reality | Where |
|---|---|---|
| `tpt-telos` dependency is `telos-sdk` | **Now exists** (`tpt-telos-sdk`). Nexus depends on it for the pipeline (`compile`/`compile_static`/`compile_project_tempdir`, `StaticAgent`, `VerifiedArtifact`, `ProofManifest`), and adds three more explicit deps the SDK doesn't re-export: `tpt-telos-agent` (`render_candidate`), `tpt-telos-parser` (`ast::{Stmt,Expr}` for `mutates_state`), `tpt-telos-codegen` (`proof::{to_json, verify_manifest}`). | `../tpt-telos/crates/tpt-telos-sdk` |
| `telos_sdk::Pipeline` struct | No `Pipeline` type anywhere in `tpt-telos`. The CLI (`tpt-telos-cli/src/main.rs`) calls parse → verify → route → codegen manually, stage by stage. Nexus's `NexusOrchestrator` **is** the first real `Pipeline`-shaped struct — that's genuine new value, not duplicated work. | — |
| `telos_sdk::Manifest` | `ProofManifest` (`schema_version`, `source_hash`, `verified_at`, `functions`, `manifest_hash`) | `tpt-telos-codegen/src/proof.rs:34` |
| `VerificationReport` with `counterexample` + `agent_hint` | `VerificationResult` / `CheckResult.counterexample: Option<Model>`. **No `agent_hint` field exists anywhere.** Nexus's `FeedbackFormatter` must synthesize the human-readable hint itself from the `Model` counterexample. | `tpt-telos-verifier/src/verify.rs:11` |
| `nexus-manifest-validator` (recompute SHA-256, compare) | Already fully implemented as `verify_manifest()`, including manifest-JSON tamper detection (more than the spec asks for). Nexus's crate should be a thin CLI wrapper, not a reimplementation. | `tpt-telos-codegen/src/proof.rs:165` |
| `CapabilityGrant::map_page()` | Method is `grant_read`/`grant_write` (on `CapabilityGrant`) or `map_read`/`map_write` (on the lower-level `UnifiedPageCache`/`UnifiedMemory`). | `tpt-archon-bridge/src/grant.rs:51` |
| `CSlotTable`, opaque `u64` token | **Does not exist.** Capability tokens are `Capability` — a private-field struct minted only by `CapabilityIssuer` (unforgeable by construction), not a raw integer index. | `tpt-archon-bridge/src/capability.rs:56` |
| `MemoryView` = raw pointer + length | `MemoryView`/`MemoryViewMut` are safe borrowed-slice wrappers (`&[u8]`/`&mut [u8]`). Doc comment explicitly: *"No new unsafe code or raw pointers are introduced."* | `tpt-archon-bridge/src/grant.rs:6,17` |
| `ReadOnly` / `ReadWrite` access levels | `Right::Read` / `Write` / `ReadWrite` — no `ReadOnly` variant. | `tpt-archon-bridge/src/capability.rs:22` |
| `ArchonEmulator::load_artifact() -> ProcessId` / `handle_syscall(pid, request)` | **Does not exist in `tpt-archon-kernel`.** Kernel has `scheduler::spawn(task) -> u64`, `memory::UnifiedMemory` (wraps a page cache with capability-checked `map_read`/`map_write`), and `ipc`. Nexus's `nexus-archon-emulator` genuinely needs to build this process/syscall-shaped wrapper — that part of the spec is real, novel work, not duplication. | `tpt-archon-kernel/src/{scheduler,memory,ipc}.rs` |
| "Emulation over Implementation" (user-space emulator needed because bare metal isn't available) | `tpt-archon-kernel`'s README already describes itself as an implemented, user-space-first capability microkernel. The premise for *why* an emulator is needed may already be moot — worth a sentence in the updated spec instead of silently building a redundant layer. | `tpt-archon/README.md` |

---

## 1. Repo scaffolding

- [x] `git init` (currently not a git repo)
- [x] Root `Cargo.toml` workspace, matching sibling `[workspace.package]` conventions (edition 2021, rust-version 1.74, dual MIT/Apache-2.0)
- [x] Decide crate naming: `tpt-nexus-orchestrator` / `tpt-nexus-archon-emulator` / `tpt-nexus-manifest-validator` (matches `tpt-<repo>-<component>` convention used by telos/archon) rather than spec's bare `nexus-*` names
- [x] `LICENSE-MIT` + `LICENSE-APACHE`
- [x] `.gitignore`
- [x] `README.md` (what nexus proves, how to run the two examples, dependency graph)
- [x] `AGENTS.md` / `CLAUDE.md` (build commands, crate map, link to this TODO)
- [x] `CHANGELOG.md`
- [x] `.github/workflows/ci.yml` (fmt, clippy, `cargo test --workspace`)
- [x] Path-dependency wiring to `../tpt-telos/crates/*` and `../tpt-archon/crates/*` (confirm both checkouts are siblings at build time; document the assumption in README)

---

## 2. `tpt-nexus-orchestrator` (the agentic loop)

- [x] Path deps: `tpt-telos-parser`, `tpt-telos-ir`, `tpt-telos-verifier`, `tpt-telos-agent`, `tpt-telos-codegen`, `tpt-telos-router`
- [x] `AgentContext`: source-code history + accumulated `FuncOutcome`/`VerificationResult` per iteration (wraps what `tpt_telos_agent::transpile_func` already tracks in `LoopStep`, doesn't duplicate it)
- [x] `FeedbackFormatter`: renders a `Model` counterexample (from `CheckResult.counterexample`) into a readable prompt fragment — this is where the missing `agent_hint` concept from spec.txt actually gets built, since telos doesn't provide one
- [x] `LoopController`: decide whether nexus needs its own outer retry wrapper around `transpile_func`'s existing 8-iteration internal loop, or just surfaces/relabels its `Vec<LoopStep>` history. Default: no duplicate loop — just report telos's own iteration history
- [x] `VerifiedArtifact { compiled_binary: Vec<u8>, manifest: ProofManifest, source_code: String }`
- [x] `compiled_binary` sourced the same way `telos build` does: shell out to `cargo build` on the codegen'd Rust crate, read the resulting binary bytes
- [x] `run_agent_loop(initial_prompt, agent: &dyn CodeAgent) -> Result<VerifiedArtifact, NexusError>` — thin orchestration: parse → `transpile_module` → codegen render → `cargo build` → `generate_manifest`
- [x] `NexusError` (wraps parse/verify/build/IO failures with enough context to log)
- [x] Observable Agentic State: structured log of every `LoopStep` (iteration, action, candidate source text, passed, counterexample) — pick a format (see §6)

## 3. `tpt-nexus-manifest-validator`

- [x] Thin CLI (or lib fn) that reads `telos-proof.json` + the source `.telos` file from disk and calls `tpt_telos_codegen::proof::verify_manifest`
- [x] Report `ManifestVerification` clearly (source hash mismatch vs. manifest tampering are distinct failure modes — surface both)
- [x] Non-zero exit / typed `Err` when `tampered == true`

## 4. `tpt-nexus-archon-emulator` (the capability runtime)

- [x] Path deps: `tpt-archon-core`, `tpt-archon-bridge`, `tpt-archon-kernel`
- [x] `ArchonEmulator`: wraps `tpt_archon_kernel::scheduler` (task spawn), `tpt_archon_kernel::memory::UnifiedMemory`, and `tpt_archon_bridge::capability::CapabilityIssuer`
- [x] `load_artifact(&VerifiedArtifact) -> Result<ProcessId, NexusError>`: derive capability grants from the artifact's manifest (map verified functions → `Resource::Page`/`Channel` + `Right`), mint via `CapabilityIssuer`, register the binary as a scheduler task, return the task id as `ProcessId`
- [x] `SyscallRequest` / `SyscallResponse`: nexus-defined types (genuinely new — nothing upstream has this shape). Keep the first version minimal: only what Examples 1–2 need (e.g. `ReadPage { block_id }`, `WritePage { block_id, data }`)
- [x] `handle_syscall(pid, request)`: look up the process's `Capability`, call `CapabilityGrant::grant_read`/`grant_write` via `UnifiedMemory`, map `CacheError::Denied` → `ArchonError::CapabilityViolation`
- [x] `ArchonError` (`CapabilityViolation`, `OutOfBounds`, `ProcessNotFound`, ...)
- [x] Explicitly do **not** reimplement `CSlotTable`/raw pointers — the safety guarantees already live in `tpt-archon-bridge`; nexus only adds the process/syscall framing on top

---

## 5. `examples/`

- [x] **Example 1 — Monotonic Timestamp Query**: `.telos` source with `requires: timestamps strictly increasing` / `ensures: memory usage < 4MB`. Run through `tpt-nexus-orchestrator` with `StaticAgent`. Verify against `StaticAgent`'s actual deterministic behavior — confirm whether it naturally fails-then-fixes like the spec narrative claims, or adjust the example/expectation to match what `StaticAgent` really does (don't force a fake failure just to match the narrative)
- [x] **Example 2 — Capability Boundary Test**: compiled code attempts to write to a `Right::Read`-only capability. Run through `tpt-nexus-archon-emulator`. Assert `handle_syscall` returns `ArchonError::CapabilityViolation`
- [x] End-to-end integration test: INTENT → VERIFY → ATTEST → VALIDATE → MINT → EXECUTE, wired together for at least Example 1

## 6. Observability

- [x] Pick a logging approach (`tracing` crate is the obvious default) satisfying "Observable Agentic State" — every iteration, failure, and counterexample must be reconstructable after the fact
- [x] Decide log sink/format: JSON-lines event log per run vs. human-readable console vs. both
- [x] Make sure `FeedbackFormatter` output and the log event for the same iteration are the same underlying data (no drift between what the "agent" sees and what gets logged)

## 7. Docs

- [x] README walkthrough: clone both sibling repos, run Example 1 and Example 2, explain what each proves
- [x] Rewrite/annotate `spec.txt` (or add `spec2.txt`-style addendum) reconciling the interface sketches in §6 with the actual names in §0 above, so the design doc stops drifting from the code
- [x] Re-derive §7 (Security & Threat Model) against real enforcement points: `Right::Read/Write/ReadWrite` not `ReadOnly/ReadWrite`, `Capability` not `CSlotTable`, etc.

## 8. Explicitly out of scope for v1 (spec §9)

- Real bare-metal ARM64 execution
- Distributed capabilities over gRPC
- Eidos deep integration (`.eidos` files, dependent-type proofs)

## 9. Stretch / later

- [x] Swap `StaticAgent` for `tpt_telos_agent::llm_agent::LlmAgent` behind an env var/flag once ready to demo against a real LLM provider (already supports OpenAI/Anthropic/Ollama/OpenRouter/Grok — no new plumbing needed on telos's side). In nexus: `NEXUS_AGENT=llm` selects it at runtime behind the `llm` feature; `nexus.toml` `agent = "llm"` selects it from policy.
- [x] Revisit whether `tpt-archon-kernel`'s existing "user-space first, already implemented" status changes the "why an emulator" framing in the spec (see §0 last row)

---

## 10. Review findings (2026-08-08) — bugs, missing features, innovations

Tracked after a code review of the orchestrator, emulator, validator, and
examples. Grouped by kind; the "Bugs" block is being fixed this session.

### 10.1 Bugs / correctness (fix now)

- [x] **Page allocator never recycles.** `load_artifact` bumps `self.next_block`
  and never frees it; `terminate` only revokes capabilities (`emulator.rs:227-237`,
  `emulator.rs:421-438`). A long-running emulator eventually hits `OutOfBounds`
  on every load once `next_block >= page_count`. Fix: maintain a free list (or
  recompute the low-water mark from surviving processes) and reuse block ids.
- [x] **Run log is never persisted.** `write_attestation` writes only
  `telos-proof.json` + `source.telos` (`orchestrator.rs:120-130`); `RunReport::to_jsonl`
  exists (`log.rs:179`, `report.rs:29`) but nothing writes it to disk. "Observable
  Agentic State" is serializable but not durable. Fix: add `write_run_log(dir)`
  and have `write_attestation` optionally emit it too.
- [x] **Multi-module name collisions collapse grants.** `load_artifact` iterates
  `artifact.manifest.functions.keys()` (`emulator.rs:229`); `ProofManifest.functions`
  is keyed by bare function name, so two same-named functions in different modules
  merge into one grant and `page_of("name")` becomes ambiguous. Fix: detect
  duplicate function names at load time and return a descriptive `ArchonError`.
- [x] **`BuildPolicy::Compile` is dead in practice.** The real-compile path
  (`orchestrator.rs:334-360`) has no test or example, and default `Headless` makes
  Example 2 print `image_bytes = 0`. Fix: add a toolchain-gated test (or a third
  example using `with_build_policy(Compile)`) so the path can't silently rot.
  → `tests::compile_policy_produces_real_artifact_bytes` plus `example3_compiled_artifact`.
- [x] **telos panics escape `run_agent_loop`.** Resolved: `run_agent_loop` now
  wraps `tpt_telos_sdk::compile` in `std::panic::catch_unwind` and returns
  `NexusError::Panic` with a hint (`orchestrator.rs`). Note: as of the latest
  telos, a bare-local read (`out = a.balance`) *verifies* rather than panicking
  (upstream fix), so the catch is now a defensive net, not a hot path — covered
  by `read_only_bare_local_verifies_as_read`.

### 10.2 Missing features

- [x] **Top-level `nexus verify` CLI** running the whole loop (only
   `nexus-validate-manifest` exists today). Should accept `*.telos`, print the
   capability table, and exit non-zero on unverified — the CI entrypoint.
   → `tpt-nexus-cli` `verify` (with `--compile` and `--policy`).
- [x] **`nexus.toml` policy config**: explicit function→page mapping, right
   overrides (force `Read` for a risky mutator), agent selection. Today the
   derivation is fully automatic. → `tpt-nexus-cli::policy`, `verify --policy`.
- [x] **Emulator negative-path tests**: tampered manifest → `InvalidAttestation`;
   re-admission after `revoke`. → `emulator.rs` `tampered_source_is_rejected_at_mint`,
   `tampered_manifest_is_rejected_at_mint`, `process_can_be_readmitted_after_revoke`.

### 10.3 Innovations

- [x] **Capability diff / security-regression detection** — `nexus diff a.telos b.telos`
   renders the delta in the derived grant set (new `ReadWrite` on a page = supply-chain
   alert). Highest-value, most differentiating idea.
- [x] **Signed attestations (ed25519)** — a hash proves manifest↔source match, but
   anyone can re-attest after editing. A signed manifest makes attestation
   tamper-*evident*, not just checkable. → `tpt-nexus-cli::signing`, `nexus sign`.
- [x] **Policy-as-code + PR comment** — emit the capability table as Markdown; a
   GitHub Action posts it on PRs. → `nexus verify` table + `.github/actions/nexus-verify`.
- [x] **Reasoning-trace as HTML/Markdown** — render the counterexample→fix loop
   (already in `RunLog`) into a shareable artifact for trust/demos.
   → `tpt-nexus-cli::trace`, `nexus trace`.
- [x] **`assert_grants!` macro** so users write policy tests against their own
   `.telos` without hand-rolling the emulator. → `tpt-nexus-archon-emulator`.

### 10.4 Usability / automation / adoption

- [x] **Starter template gallery** under `templates/`: `counter`, `ledger`,
   `kv_store`, `oracle`, `rate-limiter`, and a multi-module `multi_module` — each a
   minimal, already-verified, commented `.telos` shipped alongside a sample
   `nexus.toml` (so `nexus new` copies both). New users copy one and go.
- [x] **`nexus new <name>`** scaffolding that clones a template + writes config.
- [x] **`nexus watch examples/`** dev loop (re-verify on save).
- [x] **Composite GitHub Action** + pre-commit hook (`fmt`+`clippy`) in a `justfile`.
- [x] **Compatibility matrix test** pinning `../tpt-telos` + `../tpt-archon` and
   running the e2e test on each bump.
- [x] **Docs**: README "Quickstart", a "how grants are derived" diagram, and a
   note on the read-only `.telos` story (a bare-local read verifies and is derived
   as `Read`; only a struct-field write earns `ReadWrite`).
- [x] **Third example showing `Compile`** so `image_bytes > 0` and the "compiled
   artifact" claim is visually demonstrated.

---

## 11. Review findings (session 2) — independent verification + new issues

A second review independently verified §10.1's 5 bug fixes against the code
(all confirmed real, all covered by tests) but found that several §10.2/§10.3
items marked `[x]` are only partially real — the code exists but has defects
serious enough that the checkmark overstated what was working. Tracked here
so nothing regresses to "looks done, isn't." Full findings/rationale in the
review plan; this section is the execution checklist.

### 11.1 Bugs (new, not in §10.1)

- [x] **`nexus sign` discards the generated secret key.** `Keypair::generate()`
   makes a fresh key but there's no accessor to read it back, and `sign()`
   never prints it despite `--help` promising it's "printed if omitted."
   Fix: add `Keypair::secret_hex()`, print it with a "save this now" warning
   when generated.
- [x] **Policy right-overrides never reach the capability-minting path.**
   `nexus verify`'s `policy.apply(rights)` only affects the printed table;
   `ArchonEmulator::load_artifact` calls the un-overridden `derive_rights`
   directly and has no policy parameter. A pinned-down `Read` isn't actually
   enforced — cosmetic only, contradicts README's claim. Fix: give
   `load_artifact` a policy-aware entry point; add a test proving a
   `Read`-forced mutator is denied a write via the emulator.
- [x] **`NexusError::Panic` misused as a generic catch-all.** Unrelated
   failures (duplicate function name, bad policy TOML) are funneled through
   `NexusError::Panic`, whose `Display` always appends a "bare local
   assignment" hint that's only true for genuine telos panics. Fix: add
   proper error variants for policy/ambiguity failures.
- [x] **Two starter templates fail to parse.** `templates/kv_store.telos:2`
   and `templates/rate_limiter.telos:2` use comma-separated invariant clauses,
   which isn't valid `.telos` grammar. Fix: one clause per `invariant` block,
   matching every working example.
- [x] **Root `justfile` doesn't parse with real `just`.** `[fmt]` / `[ci:...]`
   blocks aren't valid recipe declarations (`just --list` fails outright).
   Fix: rewrite with valid `name:` recipe syntax.
- [x] **Rough edges**: `nexus sign`'s self-check computes `ok` but always
   returns `ExitCode::SUCCESS`; `nexus new <name>` silently overwrites an
   existing file with no `--force` gate; `nexus diff` reports a missing file
   as a verification failure with a leaked raw OS error instead of the
   `"cannot read {path}"` phrasing every other subcommand uses.

### 11.2 Doc/reality drift

- [x] Fill in real GitHub URLs in `README.md:3` (currently literal
   `https://github.com/...` placeholders) and reconcile the `tpt-solutions`
   vs. `TPT-Org` org-name mismatch across `Cargo.toml`, README, CI YAML, and
   the composite action.
- [x] Fix TODO.md §10.4's stale "plus a `nexus.toml`" claim (make it true, or
   correct the checklist).
- [x] Fix `signing.rs`'s doc comment, which claims `nexus verify` checks
   signatures — no such code path exists yet (see §11.6).
- [x] Give the "compatibility matrix" CI job real matrix entries (currently
   both axes are `[main]`, i.e. not actually a matrix) or relabel it.
- [x] Add `nexus-validate-manifest` to the README Quickstart as the literal
   step-5 (VALIDATE) command — currently only named in the crates table.
- [x] Update the stale "55 tests" status line in TODO.md (actual: 66 + 8
   doctests).

### 11.3 Onboarding / adoption (highest leverage for faster adoption)

- [x] Add a "Prerequisites" block near the top of README.md, before
   Quickstart: state plainly that two sibling repos are required, give
   copy-pasteable `git clone` commands, show the expected directory layout.
- [x] Add a `just setup` recipe (or `scripts/bootstrap.sh`) that clones the
   sibling repos if missing, mirroring what CI already does.
- [x] Comment the five templates using the narrative style already proven in
   `examples/*.telos` (explain `invariant`/`requires`/`ensures`/`mutate
   state` inline) instead of the current zero-comment files.
- [x] Add `nexus-out/` to `.gitignore` (currently every local `nexus verify`
   run leaves untracked cruft).
- [x] Stretch: a minimal multi-module template/example demonstrating mixed
   `Read`/`ReadWrite` grants across module boundaries — a headline value
   prop with no current demonstration.

### 11.4 CLI ergonomics quick wins

- [x] Add `#[command(version, about, ...)]` to the top-level `clap` command so
   `nexus --version` and a real `nexus --help` description work.
- [x] Remove the duplicate error print on verification failure (both
   `tracing::error!` and `eprintln!` fire for the same failure, in two
   different formats).
- [x] Add distinct exit codes to `nexus diff` (clean / security-regression /
   error), matching the 0/1/2/3 contract `nexus-validate-manifest` already
   documents for itself.
- [x] Nice-to-have if time allows: `--output <dir>` flag on `verify` instead
   of the hardcoded `nexus-out/`.

### 11.5 Test coverage gaps

- [x] Add a test exercising `ArchonEmulator::with_page` (the zero-copy path)
   under `cargo test` — currently only exercised by an example `cargo test`
   never runs.
- [x] Add tests that genuinely exhaust the page allocator (`OutOfBounds`) and
   send an oversized write payload (`PayloadTooLarge`).
- [x] Add `crates/tpt-nexus-cli/tests/` integration tests covering `sign`
   (secret recoverable), `new` (overwrite protection), and `verify --policy`
   (override actually enforced) — the missing coverage that let the lost
   secret-key bug ship uncaught.

### 11.6 Larger / innovation items (do last)

- [x] `nexus verify --json` / `nexus diff --json` for CI-machine-readable
   output.
- [x] `nexus completions <shell>` via `clap_complete`.
- [x] `nexus verify-signature <manifest> <sig> <pubkey>` subcommand, closing
   the one-way-signing gap.
- [x] `CONTRIBUTING.md` (translate `AGENTS.md` for human contributors) +
   minimal `.github/ISSUE_TEMPLATE/` and `PULL_REQUEST_TEMPLATE.md`.
- [x] Dependabot config for third-party deps (not the intentionally-unpinned
    sibling path deps).

---

## 12. Review findings (session 3) — adoption, CI, usability, innovation

A third review (independent read of the CLI, emulator, orchestrator, CI action,
and a smoke test of all six shipped templates — all verify green) confirmed the
§10/§11 "done" claims hold up. The remaining work is wiring the headline
innovations into CI/adoption, closing a few real gaps, and adding ambitious
differentiators. Tracked here so nothing regresses to "looks done, isn't."

### 12.1 Bugs / gaps (fix first)

- [x] **`nexus-verify` composite action is a stub for its own value prop.**
    `.github/actions/nexus-verify/action.yml` declares `fail-on-strengthening`
    and `comment` but never uses them — it runs `nexus verify` and posts static
    boilerplate, never `nexus diff`, never the real capability table. Wire
    `nexus diff` (base↔head), honor `fail-on-strengthening`, and post the actual
    derived table as the PR comment. → action.yml now runs `nexus diff` per file,
    gates on `fail-on-strengthening`, and posts the per-file capability table.
- [x] **`nexus verify` never checks signatures.** `sign`/`verify-signature`
    exist, but there is no `nexus verify --require-signature --pubkey <hex>`
    [--sig <path>], so a CI gate cannot enforce "must be signed by a trusted
    key". Add the flag; read `<out>/telos-proof.json[.sig]` and verify, failing
    verify (non-zero) when missing/invalid. → `verify --require-signature <pubkey>`
    validates the *existing* signed attestation against the verified source
    (signature + source_hash match) without overwriting the signed artifact.
- [x] **Policy over-specification is silent.** `Policy::apply` inserts a
    `[[grant]]` for a func name not in the artifact with no warning — a typo'd
    func is a silent no-op. Warn (tracing) for each policy grant whose func is
    absent from the derived grant set. → `apply` now only overrides existing
    derived rights (no phantom grants), and `verify` warns on unknown funcs.
- [ ] **Document `nexus diff` exit semantics for a *weakening*.** `ReadWrite→Read`
    currently returns exit 0 (clean); acceptable (it is a reduction) but the
    README/help must say so explicitly.

### 12.2 Missing features

- [ ] **Namespaced grants (`module::func`).** `derive_rights` (emulator.rs:548)
    *rejects* duplicate func names across modules, so `multi_module.telos`
    dodges the interesting case with unique names. Real multi-module support
    (distinct grants per `module::func`, not a hard reject) is the genuine
    differentiator. Touches derive_rights, `load_artifact` keying, `page_of`,
    policy matching, and the `assert_grants!` macro.
- [x] **`nexus init`** — scaffold a `nexus.toml` (from `templates/nexus.toml`)
    into the current directory, optionally with a starter `.telos`. → `nexus init`
    copies `templates/nexus.toml` to `./nexus.toml` (`--force` to overwrite).
- [ ] **SARIF output** for `verify`/`diff` (besides `--json`) so findings show
    in GitHub code-scanning / Security tab.
- [x] **`nexus doctor`** — diagnose missing siblings (`../tpt-telos`,
    `../tpt-archon`), the Rust toolchain, the `templates/` dir, and a local
    `nexus.toml` *before* a cryptic cargo path-dep error. Exit non-zero on
    problems. → `nexus doctor` reports each check and exits non-zero on failure.
- [x] **Zero-setup trial.** Path deps force a manual 3-repo clone. Add a
    `Dockerfile` + `.devcontainer.json` (and/or a git-submodule bootstrap) so
    `git clone` + one command runs the whole loop with no manual sibling clone.
    → `Dockerfile` clones both siblings; `.devcontainer/` wraps it.

### 12.3 Innovations (differentiators)

- [ ] **Capability fuzzing / adversarial escalation tester** — auto-generate
    syscall sequences against a loaded artifact to prove the derived grant set
    is *tight* (complements `assert_grants!`). High-value and on-theme.
- [ ] **`nexus serve`** — a tiny static viewer for the existing HTML trace
    (trace.rs) so reviews/demos are shareable without the CLI.
- [ ] **VS Code extension** — `.telos` syntax highlighting + inline
    `nexus verify` on save (reuses the `watch` logic).
- [ ] **WASM build** for an in-browser verify→attest→mint→execute demo.
- [ ] **Policy-diff PR bot** — comment the security delta (subsumed by the
    §12.1 action fix, but call it out as the end state).

### 12.4 Usability / automation / adoption

- [x] **README Quickstart** uses placeholder `nexus diff a.telos b.telos`
    (main.rs:96). Ship a real before/after pair so the regression view is
    copy-pasteable. → `examples/diff_demo_before.telos` / `diff_demo_after.telos`
    + README step 3.
- [x] **README `verify --policy` example** using the shipped `templates/nexus.toml`.
    → README steps 9–10 (`nexus init` + `verify --policy nexus.toml`) and `doctor`.
- [x] **CI `verify-examples` just recipe** (justfile:23) covers `examples/`;
    extend it to loop over `templates/` so shipped scaffolds cannot rot. → justfile
    `verify-examples` now loops the six templates.
- [ ] **Publish/install path:** `cargo install`, Homebrew tap, or prebuilt
    binaries once the repo is public (path deps block `cargo install` today).


