# Contributing to tpt-nexus

Thanks for wanting to improve the tpt-telos ↔ tpt-archon integration harness.
This document is the human-facing companion to [`AGENTS.md`](./AGENTS.md), which
is written for AI coding agents.

## What nexus is

nexus is a *thin* glue and demo layer. It does **not** reimplement a verifier or a
kernel. It proves that a verified, attested `.telos` program earns exactly the
memory rights its proof implies, then runs it under tpt-archon's real capability
enforcement. The two hard rules that follow from that:

- **No `unsafe`.** Anywhere in nexus. Enforcement always happens inside the
  sibling crates; nexus only frames processes, syscalls, and the manifest re-check.
- **Reuse the real crates.** Build against the local `../tpt-telos` and
  `../tpt-archon` path dependencies. Do not vendor them and do not invent APIs
  that already exist upstream — see `spec.txt` and `AGENTS.md` §0 ("Spec vs.
  reality") before writing code that "matches the spec."

## Getting set up

1. Clone the three repos as siblings (see `README.md` "Prerequisites"):
   `tpt-telos`, `tpt-archon`, `tpt-nexus`.
2. `just setup` clones any missing siblings.
3. Build and test: `just` (or the three commands in the README Quickstart).

## Before you open a PR

Run the same gate CI runs:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

A pre-commit hook lives in `.pre-commit-config.yaml`; the `justfile` mirrors it.
CI runs exactly those three commands, so a green local run is a strong signal.

## What makes a good change

- **Bug fixes** should come with a regression test. The orchestrator, emulator,
  and CLI all have `#[cfg(test)]` suites plus `crates/tpt-nexus-cli/tests/`
  integration tests.
- **The right-derivation is a security boundary.** `ReadWrite` only when the
  accepted body writes a struct field; everything else is `Read`. Keep
  `FunctionRecord::mutates_state` and the formatter's `IterationRecord` in sync —
  there is a test asserting they cannot drift.
- **Policy overrides must be enforced, not cosmetic.** If you add a way to
  influence the capability surface, prove via a test that the emulator actually
  denies/permits accordingly.
- Add your change to `TODO.md` (mark the item done) and, if user-facing, to the
  README Quickstart.

## Commit / PR style

- Keep commits focused; one logical change per commit.
- PRs should explain the *why*, link the relevant `TODO.md` item, and include the
  test output for the three-command gate.
- The `nexus-verify` composite action can post the derived capability table as a
  PR comment — a broadened `ReadWrite` on a page is a supply-chain alert worth
  reviewing.
