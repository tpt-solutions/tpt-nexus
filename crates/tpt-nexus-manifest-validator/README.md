# tpt-nexus-manifest-validator

Independent validation of [`tpt-telos`](https://github.com/tpt-solutions/tpt-telos)
proof manifests: **source-hash integrity** and **manifest tamper detection**.

This crate is step 5 of the `tpt-nexus` loop. After `tpt-telos` attests a
program (step 4), this crate **re-derives both hashes** and confirms the
manifest matches the source. It is the anti-tamper gate: a manifest whose source
was swapped after attestation is rejected, and a wrong source cannot be
retrofitted to a valid manifest.

It ships both:

- a library (`verify_manifest` / `ManifestVerification`) used by the rest of
  nexus, and
- a standalone binary, `nexus-validate-manifest`, for checking a proof manifest
  from the command line or CI.

The verifier output here is treated as authoritative — an unverified function is
a hard error, never a soft flag.

## Binary

```text
nexus-validate-manifest <source.telos> <telos-proof.json>
```

## Relationship to the rest of nexus

- Step 4 (attest) and the manifest format come from `tpt-telos-codegen`.
- Steps 6–7 (capability minting + execution) live in
  `tpt-nexus-archon-emulator`, which re-runs this validator before minting.

See the [workspace README](https://github.com/tpt-solutions/tpt-nexus) for the
full seven-step loop.
