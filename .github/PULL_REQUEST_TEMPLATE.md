## Summary

<!-- What does this change do, and why? Link the relevant TODO.md item. -->

## Capability surface impact

<!-- If this touches the right-derivation or policy overrides, paste the before/after
     `nexus verify` (or `nexus diff`) capability table. A new ReadWrite on a page
     is a security-relevant change that reviewers must see. -->

## Test plan

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] (if applicable) regression test added for the bug/feature
