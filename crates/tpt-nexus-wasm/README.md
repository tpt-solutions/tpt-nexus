# Experimental: browser/WASM demo of verify → derive

This crate wraps the nexus verify+derive half behind a `wasm-bindgen`
interface so it can run in the browser as an interactive "paste your `.telos`,
see its derived capability surface" demo.

> **Scope / limitations**
>
> This deliberately covers only the *verify → derive* half of the loop. The
> `tpt-archon` emulator (capability minting + syscalls) cannot run in a browser.
> The orchestrator's `BuildPolicy::Compile` arm is gated behind
> `#[cfg(not(target_arch = "wasm32"))]`, so the WASM entry point can only use
> `BuildPolicy::Headless` (no `cargo` call, which does not exist on wasm). So:
> 1. The WASM entry point uses `BuildPolicy::Headless` only (no `cargo` call).
> 2. The capability *minting/execute* half is intentionally out of scope for
>    the browser.

## Build

```text
# one-time
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

# build the demo bundle into pkg/
just wasm
```

Then serve `pkg/` (plus a small HTML page that calls `verify_and_derive`)
with any static server.

Note: this crate is intentionally **not** a workspace member, so it never
affects `cargo test --workspace` or CI. Build it explicitly with
`cargo build -p tpt-nexus-wasm` (host) or `wasm-pack build` (wasm).
