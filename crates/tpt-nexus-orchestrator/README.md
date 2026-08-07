# tpt-nexus-orchestrator

The **INTENT → VERIFY → ATTEST** orchestration loop for [`tpt-nexus`](https://github.com/tpt-solutions/tpt-nexus), built directly on the `tpt-telos` SDK.

It owns the closed loop around the `tpt-telos` verifier:

- drives the verifier and feeds counterexamples back as hints for an offline
  self-repair loop (`LoopController`, `StaticAgent` — no API key required),
- records a fully observable per-iteration run log (`IterationRecord`),
- derives the Archon `Right` for each verified function from its proof
  (`FunctionRecord::mutates_state` → `Read` vs `ReadWrite`).

This crate contains **no `unsafe`** and never decides memory access itself; it
only supplies the framing that `tpt-telos` and `tpt-archon` leave to the
integrator.

## Key types

- `LoopController` — classifies verification history and enforces a retry budget.
  It deliberately does *not* re-implement telos's internal retry logic.
- `FunctionRecord::mutates_state` — the security boundary that decides whether a
  function earns `ReadWrite` (it writes a struct field) or `Read` (pure query).

## Relationship to the rest of nexus

- Step 5 (anti-tamper manifest check) lives in
  `tpt-nexus-manifest-validator`.
- Steps 6–7 (capability minting + execution under `tpt-archon`) live in
  `tpt-nexus-archon-emulator`.

See the [workspace README](https://github.com/tpt-solutions/tpt-nexus) for the
full seven-step loop.
