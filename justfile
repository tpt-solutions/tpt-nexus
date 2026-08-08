# tpt-nexus task runner. Run `just` with no arguments to run the quality gate,
# or `just <recipe>` for a single step. See `just --list`.

# Default: run the whole quality gate (fmt + clippy + test).
default:
    just fmt
    just clippy
    just test

# Check formatting without modifying files.
fmt:
    cargo fmt --all -- --check

# Lint, denying any warning (mirrors CI's RUSTFLAGS=-D warnings).
clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Run the full test suite.
test:
    cargo test --workspace

# Verify the bundled example .telos files end to end.
verify-examples:
    cargo run -q -p tpt-nexus-cli -- verify examples/monotonic_timestamp.telos
    cargo run -q -p tpt-nexus-cli -- verify examples/capability_boundary.telos
    cargo run -q -p tpt-nexus-cli -- verify examples/compiled_artifact.telos --compile
    # Shipped starter templates are adoption fodder: they must always verify.
    for t in counter ledger kv_store oracle rate_limiter multi_module; do \
        cargo run -q -p tpt-nexus-cli -- verify "templates/$$t.telos"; \
    done

# Adversarially fuzz every bundled example and template: prove the derived
# capability surface is tight (allowed ops succeed, forbidden ops are denied).
fuzz-examples:
    for f in examples/*.telos; do \
        cargo run -q -p tpt-nexus-cli -- fuzz "$$f"; \
    done
    for t in counter ledger kv_store oracle rate_limiter multi_module; do \
        cargo run -q -p tpt-nexus-cli -- fuzz "templates/$$t.telos"; \
    done

# Build the experimental WASM browser demo (needs wasm-pack + wasm32 target).
wasm:
    rustup target add wasm32-unknown-unknown
    cd crates/tpt-nexus-wasm && wasm-pack build --target web --out-dir ../../pkg

# Clone the sibling repos (tpt-telos, tpt-archon) into the parent directory if
# they are missing, mirroring what CI does. Requires `git` and network access.
setup:
    #!/usr/bin/env bash
    set -euo pipefail
    root="$(cd "$(dirname "$(justfile)")" && pwd)"
    parent="$(dirname "$root")"
    for repo in tpt-telos tpt-archon; do
        if [ ! -d "$parent/$repo" ]; then
            git clone "https://github.com/TPT-Org/$repo.git" "$parent/$repo"
        else
            echo "$parent/$repo already present"
        fi
    done
