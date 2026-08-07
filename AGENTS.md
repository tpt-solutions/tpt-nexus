# Agent Guide (AGENTS.md / CLAUDE.md)

This file is for AI coding agents working in `tpt-nexus`. It mirrors `README.md`
but is written for machines that will edit the code.

## What this repo is

An integration harness between `tpt-telos` (intent → verify → attest) and
`tpt-archon` (capability-checked kernel). It proves a verified, attested program
earns exactly the memory rights its proof implies, then runs it under archon's
real enforcement. It does **not** reimplement telos or archon.

## Layout

- `crates/tpt-nexus-orchestrator/` — INTENT→VERIFY→ATTEST loop, feedback, run
  log, `Right` derivation. **No `unsafe`.**
- `crates/tpt-nexus-manifest-validator/` — step 5 (anti-tamper manifest check).
  Library + `nexus-validate-manifest` binary.
- `crates/tpt-nexus-archon-emulator/` — steps 6–7. Process layer over real
  archon. `#![forbid(unsafe_code)]`.
- `crates/out-nexus-examples/` — examples + `tests/loop_then_archon.rs` e2e.
- `examples/*.telos` — the `.telos` fixtures the examples load.

## Dependencies (pin locally, do not add a registry copy)

The workspace `Cargo.toml` depends on sibling repos by path:

- `../tpt-telos/crates/*` — `tpt-telos-sdk` (pipeline), plus `tpt-telos-agent`
  (`render_candidate`), `tpt-telos-parser` (`ast::{Stmt,Expr}` for
  `mutates_state`), `tpt-telos-codegen` (`proof::{to_json, verify_manifest}`).
- `../tpt-archon/crates/*` — `tpt-archon-bridge` (`capability`),
  `tpt-archon-kernel` (`scheduler`), `tpt-archon-core` (`page_cache`,
  `buffer_pool`, `block_device`).

Do not vendor these. If you change a telos/archon API, edit the sibling repo and
bump the path dep if needed.

## Key invariants when editing

- **No `unsafe`** anywhere in nexus.
- The verifier is the source of truth for correctness. Nexus must treat an
  unverified function as a hard error (`NexusError::ContractsUnsatisfied`), never
  a soft flag.
- The `Right` derivation is a security boundary: `ReadWrite` only when the
  accepted body writes a struct field (`Expr::Field` assignment target under
  `mutate state`/`assign`); everything else is `Read`. Keep
  `FunctionRecord::mutates_state` and the formatter's `IterationRecord` in sync
  (they share a type; there is a test asserting they cannot drift).
- Enforcement always happens inside archon. Nexus never decides access itself —
  it cannot, because `Capability`'s fields are private. Pass the `Capability` to
  `UnifiedMemory::map_read`/`map_write` and let archon return `Denied`.

## `.telos` fixture rules (observed from `tpt-telos-ir`)

- A function body may only assign to **struct fields** (`a.balance = ...`), not to
  bare locals. A bare local assignment `out = a.balance` PANICS on re-extraction.
- A read-only function reads into a `let` binding (`let snapshot = a.balance`)
  and states its property over its inputs; it is then derived as `Read`.
- `mutate state { ... }` with a field assignment is a mutator → `ReadWrite`.

## How to verify your changes

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

CI runs exactly these. `RUSTFLAGS=-D warnings` must stay clean.

## Typical tasks

- Adding a new example: drop a `examples/*.telos` fixture, add
  `crates/out-nexus-examples/examples/*.rs`, and prefer a `tests/*.rs`
  integration test that asserts the full loop.
- Changing the grant policy: edit `tpt-nexus-archon-emulator`'s
  `load_artifact` grant loop and the `mutates_state` helper in the orchestrator
  together; update the e2e test and Example 2.
- Changing the loop/feedback: edit the orchestrator; keep `LoopController` free
  of any duplication of telos's internal retry (it only classifies history and
  enforces a budget).
