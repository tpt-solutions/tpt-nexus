[fmt]
    cargo fmt --all -- --check

[clippy]
    cargo clippy --workspace --all-targets -- -D warnings

[test]
    cargo test --workspace

[verify-examples]
    cargo run -q -p tpt-nexus-cli -- verify examples/monotonic_timestamp.telos
    cargo run -q -p tpt-nexus-cli -- verify examples/capability_boundary.telos
    cargo run -q -p tpt-nexus-cli -- verify examples/compiled_artifact.telos --compile

[ci:fmt clippy test]
    just fmt
    just clippy
    just test

[default]
    just ci
