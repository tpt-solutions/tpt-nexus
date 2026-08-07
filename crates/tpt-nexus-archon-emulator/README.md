# tpt-nexus-archon-emulator

A user-space **process and syscall framing** over the
[`tpt-archon`](https://github.com/tpt-solutions/tpt-archon) capability
microkernel, gated on `tpt-telos` proof manifests.

This crate implements steps 6–7 of the `tpt-nexus` loop:

- **MINT** — derives one page capability per verified function. The *right*
  (`Read` / `ReadWrite`) is derived from the proof, not written by hand, and is
  least-privilege by construction. A `nexus.toml` policy may override a derived
  right and pin the surface in version control.
- **EXECUTE** — loads the artifact as an Archon process; syscalls are serviced
  only when the process holds the matching capability. The denial is `tpt-archon`'s
  own `CacheError::Denied`, enriched with what the process actually held.

All enforcement happens inside `tpt-archon`. Nexus never decides access itself —
it passes the `Capability` to `UnifiedMemory::map_read`/`map_write` and lets
archon return `Denied`. This crate is `#![forbid(unsafe_code)]`.

## Key entry points

- `load_artifact` — re-verifies the manifest (via
  `tpt-nexus-manifest-validator`) and mints grants.
- `derive_rights` — the single source of truth for the `Read`/`ReadWrite`
  derivation, shared by the runtime, the `nexus verify` table, and `nexus diff`.

## Relationship to the rest of nexus

- Steps 1–4 (intent → verify → attest) live in `tpt-nexus-orchestrator`.
- Step 5 (manifest validation) lives in `tpt-nexus-manifest-validator`, which
  this crate calls before minting.

See the [workspace README](https://github.com/tpt-solutions/tpt-nexus) for the
full seven-step loop.
