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
  archon's own capability check.
- `out-nexus-examples`: two runnable examples (a fail-then-fix repair loop and a
  capability-boundary test) plus an end-to-end integration test that drives the
  full pipeline against the real upstream crates.
- Repository scaffolding: workspace `Cargo.toml`, dual MIT/Apache-2.0 licenses,
  `.gitignore`, and a CI workflow.

### Notes
- Built against `tpt-telos-sdk` and the live `tpt-archon` crates via local path
  dependencies; no verifier or kernel primitives are reimplemented.
- The offline `StaticAgent` drives the examples; an LLM-backed agent is a
  stretch goal behind the `llm` feature flag.
