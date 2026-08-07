# out-nexus-examples

End-to-end demonstrations of the `tpt-nexus` closed loop.

This crate is **not published** (`publish = false`). It exists to exercise the
other crates and to document the integration contract in runnable form.

## Examples

```text
cargo run -p out-nexus-examples --example example1_monotonic_timestamp
cargo run -p out-nexus-examples --example example2_capability_boundary
cargo run -p out-nexus-examples --example example3_compiled_artifact
cargo test --workspace
```

- `example1` shows a genuine fail-then-fix repair loop.
- `example2` shows a read-only query (`Read`) and a mutator (`ReadWrite`) minted
  from the same module, then proves a write through the read-only grant is
  refused by archon.
- `example3` demonstrates the real `cargo build` of the generated Rust crate.

The `tests/loop_then_archon.rs` integration test asserts the full loop against
the real upstream crates.

See the [workspace README](https://github.com/tpt-solutions/tpt-nexus) for the
full seven-step loop.
