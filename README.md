# tpt-nexus

**The integration harness that closes the loop between [`tpt-telos`](https://github.com/...) and [`tpt-archon`](https://github.com/...).**

`tpt-telos` turns intent into verified code and an attestation. `tpt-archon` is a
capability-checked kernel. Nexus is the missing middle: it proves that a
verified, attested program earns *exactly* the memory rights its proof implies,
then runs it under Archon's real capability enforcement.

```
 intent ─▶ COMPILE ─▶ VERIFY ─▶ ATTEST ─▶ VALIDATE ─▶ MINT ─▶ EXECUTE
                      │                          │          │
                      ▼                          ▼          ▼
                tpt-telos-sdk            manifest        tpt-archon
                (verify + attest)        validator       (capability check)
```

The whole chain runs end-to-end against the **real upstream crates** — no
re-implemented verifier, no fake kernel. Nexus adds the two layers telos and
archon leave to the integrator: a feedback/self-repair loop around the verifier,
and the derivation of Archon capabilities from a proof.

## Why it exists

Neither telos nor archon knows about the other:

- telos records *that* a function was proved, not *what memory it may touch*.
- archon enforces capabilities but has no notion of "a verified program".
- archon's scheduler has no process table, kill, or capability lookup; its
  `Capability` is a bear-token with no provenance.

Nexus fills those gaps and nothing else. Every enforcement decision is still made
inside the upstream crates; nexus only supplies the framing (processes,
grants, the manifest re-check).

## The seven-step loop

1. **INTENT** — a `.telos` source file: `module`, `func`, `requires`/`ensures`,
   `invariant`.
2. **COMPILE** — `tpt_telos_sdk::compile` lowers intent to an IR program.
3. **VERIFY** — the verifier checks each contract. On failure, a `LoopController`
   feeds the counterexample back as a hint and re-attempts (offline, via
   `StaticAgent` — no API key).
4. **ATTEST** — `tpt_telos_codegen::proof::generate_manifest` produces a
   `ProofManifest` (source hash + per-function conclusions), serialized to JSON.
5. **VALIDATE** — `tpt-nexus-manifest-validator` re-derives both hashes and
   confirms the manifest matches the source. This is the anti-tamper gate:
   a manifest whose source was swapped after attestation is rejected.
6. **MINT** — `tpt-nexus-archon-emulator` derives one page capability per
   verified function. The *right* is derived from the proof: a function whose
   accepted body writes a struct field earns `ReadWrite`; a pure query earns
   `Read`. This is least privilege, derived from a proof.
7. **EXECUTE** — the artifact is loaded as an Archon process; syscalls are
   serviced only when the process holds the right capability. The denial is
   `tpt-archon`'s own `CacheError::Denied`, enriched with what the process held.

## Crates

| Crate | Role |
|-------|------|
| `tpt-nexus-orchestrator` | The INTENT→VERIFY→ATTEST loop, feedback formatter, run log, and the `Right` derivation (`FunctionRecord::mutates_state`). |
| `tpt-nexus-manifest-validator` | Step 5. CLI `nexus-validate-manifest` plus a library that distinguishes a tampered manifest from a wrong source. |
| `tpt-nexus-archon-emulator` | Steps 6–7. A thin process layer over the real `tpt-archon` kernel/bridge, `#![forbid(unsafe_code)]`. |
| `out-nexus-examples` | The two runnable examples and the end-to-end integration test. |

## Quickstart

```text
# 1. Verify a .telos program, print the derived capability table, write the
#    attestation to nexus-out/.
cargo run -p tpt-nexus-cli -- verify examples/capability_boundary.telos

# 2. Prove the "compiled artifact" claim end to end (shells out to cargo).
cargo run -p tpt-nexus-cli -- verify examples/compiled_artifact.telos --compile

# 3. Security-regression view: what changed about the capability surface?
cargo run -p tpt-nexus-cli -- diff a.telos b.telos

# 4. Render the agent's reasoning trace as a shareable Markdown/HTML artifact.
cargo run -p tpt-nexus-cli -- trace examples/monotonic_timestamp.telos

# 5. Sign an attestation (ed25519) so it is tamper-evident, not just checkable.
cargo run -p tpt-nexus-cli -- sign nexus-out/telos-proof.json

# 6. Scaffold a new program from a starter template.
cargo run -p tpt-nexus-cli -- new my_service --template ledger

# 7. Re-verify a file whenever it changes on disk.
cargo run -p tpt-nexus-cli -- watch examples/monotonic_timestamp.telos

# Quality gate (also run in CI / pre-commit).
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

`example1` shows a genuine fail-then-fix repair loop. `example2` shows a
read-only query (`Read`) and a mutator (`ReadWrite`) minted from the same
module, then proves a write through the read-only grant is refused by archon.
`example3` demonstrates the real `cargo build` of the generated Rust crate.

## How grants are derived

Nexus mints **one page capability per verified function**. The *right* is not
something the `.telos` author writes — it is **derived from what the program
was proved to do**:

```text
                .telos function
                     │
                     ▼
        did the accepted body write a struct field?
                     │
        ┌────────────┴─────────────┐
        │ yes                     │ no (pure query)
        ▼                         ▼
   Right::ReadWrite          Right::Read
   (mutator earns write)     (query earns read-only)
```

The derivation lives in one place —
`tpt-nexus-archon-emulator::derive_rights` — and is shared by the runtime
(`load_artifact`), the `nexus verify` table, and `nexus diff`, so the reported
surface can never drift from what is actually minted. A `nexus.toml` policy can
*override* a derived right (e.g. force a risky mutator down to `Read`) and pin
the surface in version control.

### The read-only `.telos` story

A function that only *reads* state is derived as `Read`, and therefore cannot
be granted write access. tpt-telos's IR admits only **struct-field assignments**
in a function body, so a read-only function reads into a `let` binding
(`let snapshot = a.balance`) and states its property over its inputs. That
binding is not a mutation — nexus's `mutates_state` check (which recurses
through `if`/`match` bodies) sees no field write and derives `Read`.

## Run it

```text
cargo run -p out-nexus-examples --example example1_monotonic_timestamp
cargo run -p out-nexus-examples --example example2_capability_boundary
cargo run -p out-nexus-examples --example example3_compiled_artifact
cargo test --workspace
```

## Status & upstream gaps

- Built directly against `tpt-telos-sdk` (the SDK telos now ships for
  integrators) and the live `tpt-archon` crates via local path dependencies.
- `UnifiedMemory` (the archon wrapper) does not expose its `CorePageCache`, so
  the zero-copy `MemoryView` path of `tpt_archon_bridge` is unreachable from the
  kernel layer; nexus uses `UnifiedMemory::map_read`/`map_write` directly.
- `tpt-telos-ir` rejects bare local-variable assignment in a function body (only
  field assignments are admitted) and `panic!`s on re-extraction otherwise; a
  read-only function therefore reads into a `let` binding rather than assigning
  to an output variable.
- `Capability` is unforgeable (private fields, no `Debug`); nexus retains the
  tokens itself so it can `revoke` them on termination.

See `spec.txt` for the original design brief and the reconciliation notes.
