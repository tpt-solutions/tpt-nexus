# TPT Nexus — TODO

Tracks the build of `tpt-nexus`, the integration harness proving the closed
loop `tpt-telos` (intent + verification + attestation) → `tpt-archon`
(capability-gated execution) actually works end-to-end.

**Status (as of the latest build session):** §1–§7 are complete and green —
`cargo fmt --check`, `cargo clippy -D warnings`, and `cargo test --workspace`
all pass (55 tests, including the `loop_then_archon` e2e test). Both runnable
examples work against the real `tpt-telos-sdk` and `tpt-archon` crates. The only
carried-over item is the §9 LLM stretch goal. The `telos-sdk` row in §0 was
updated: the SDK now exists, so nexus builds against it (see the edits below).

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
   `rate-limiter`, `oracle`, `kv-store` — each a minimal, already-verified `.telos`
   plus a `nexus.toml`. New users copy one and go.
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


