# tpt-nexus-cli

Command-line interface for [`tpt-nexus`](https://github.com/tpt-solutions/tpt-nexus):
verify, attest, and diff `.telos` capability surfaces, and sign attestations.

It wraps `tpt-nexus-orchestrator` (the INTENT → VERIFY → ATTEST loop) and
`tpt-nexus-archon-emulator` (capability minting + execution) behind a single
binary, `nexus`.

## Commands

```text
# Verify a .telos program, print the derived capability table, write the attestation.
nexus verify examples/capability_boundary.telos

# Prove the "compiled artifact" claim end to end (shells out to cargo).
nexus verify examples/compiled_artifact.telos --compile

# Security-regression view: what changed about the capability surface?
nexus diff a.telos b.telos

# Render the agent's reasoning trace as a shareable Markdown/HTML artifact.
nexus trace examples/monotonic_timestamp.telos

# Sign an attestation (ed25519) so it is tamper-evident.
nexus sign nexus-out/telos-proof.json

# Scaffold a new program from a starter template.
nexus new my_service --template ledger

# Re-verify a file whenever it changes on disk.
nexus watch examples/monotonic_timestamp.telos
```

## Agent modes

By default the CLI runs the offline `StaticAgent` (no network/HTTP
dependencies). Enable the LLM-backed `CodeAgent` with the `llm` feature and set
`NEXUS_AGENT=llm` at runtime (with `TELAS_LLM_KEY`, etc.) to drive the loop with
a real model.

## Relationship to the rest of nexus

This crate is a thin front end. The loop and capability derivation logic live in
the `tpt-nexus-orchestrator` and `tpt-nexus-archon-emulator` crates.

See the [workspace README](https://github.com/tpt-solutions/tpt-nexus) for the
full seven-step loop.
