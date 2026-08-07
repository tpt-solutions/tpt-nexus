# CHANGELOG

All notable changes to tpt-nexus are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
Semantic Versioning.

## [0.1.0] - Unreleased

### Added
- `tpt-nexus-orchestrator`: the INTENT → COMPILE → VERIFY → ATTEST loop around
  `tpt-telos-sdk`, including a `LoopController` that drives self-repair from
  verifier feedback, a `FeedbackFormatter` that converts counterexamples into
  natural-language hints, a JSON-lines `RunLog`, and the `Right` derivation
  (`FunctionRecord::mutates_state`) used to mint Archon capabilities.
- `tpt-nexus-manifest-validator`: step 5 of the loop. Re-derives the source and
  manifest hashes from `tpt-telos-codegen` and distinguishes a tampered manifest
  from a wrong source. Ships a `nexus-validate-manifest` CLI.
- `tpt-nexus-archon-emulator`: steps 6–7. A thin, `#![forbid(unsafe_code)]`
  process layer over the real `tpt-archon` kernel and bridge that mints one page
  capability per verified function and services read/write syscalls through
  archon's own capability check. Ships the `assert_grants!` macro for
  capability-surface regression tests.
- `out-nexus-examples`: three runnable examples (a fail-then-fix repair loop, a
  capability-boundary test, and a real `cargo`-built compiled artifact) plus an
  end-to-end integration test that drives the full pipeline against the real
  upstream crates.
- `tpt-nexus-cli` (`nexus`): `verify` (with `--compile` and `--policy`),
  `diff` (capability security-regression view), `trace` (Markdown/HTML reasoning
  artifact), `sign` (ed25519-signed attestations), `new --template`
  (starter gallery), and `watch` (re-verify on change).
- `nexus.toml` policy: explicit per-function right overrides and agent selection,
  applied via `nexus verify --policy`.
- Signed attestations: ed25519 signatures over the proof manifest make an
  attestation tamper-*evident*, not merely hash-checkable.
- Starter template gallery (`templates/`) with `counter`, `kv_store`, `ledger`,
  `oracle`, `rate_limiter`.
- Developer automation: `justfile`, `.pre-commit-config.yaml`, a composite
  `nexus-verify` GitHub Action, and a CI compatibility-matrix job pinning the
  `tpt-telos` / `tpt-archon` siblings.
- Repository scaffolding: workspace `Cargo.toml`, dual MIT/Apache-2.0 licenses,
  `.gitignore`, and a CI workflow.

### Notes
- Built against `tpt-telos-sdk` and the live `tpt-archon` crates via local path
  dependencies; no verifier or kernel primitives are reimplemented.
- The offline `StaticAgent` drives the examples by default. A real LLM agent is
  available behind the `llm` feature flag (`NEXUS_AGENT=llm` with
  `TELAS_LLM_*` env vars) and requires no changes to nexus's own code.
