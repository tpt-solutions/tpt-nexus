# Publishing & install

`nexus` is developed as a glue layer over two *sibling* repos consumed as path
dependencies. That is intentional for proving today's integration, but it blocks
the usual install paths. This document records the steps to make `nexus`
installable (`cargo install`, Homebrew, prebuilt binaries) once the repo is
public.

## Prerequisites for a publishable build

1. **Replace path deps with published/versioned deps.** In the workspace
   `Cargo.toml`, the `tpt-telos-*` and `tpt-archon-*` entries point at
   `../tpt-telos/...` and `../tpt-archon/...`. For a release, point them at
   crates.io versions (or git refs):

   ```toml
   tpt-telos-sdk = "0.1"
   tpt-archon-bridge = "0.1"
   # ... etc
   ```

   This requires the sibling crates to be published first (they are pre-1.0 and
   `tpt-archon-*` is not yet on crates.io — publish those, or use git deps).

2. **`cargo install`** then works from a checkout:

   ```text
   cargo install --path crates/tpt-nexus-cli
   ```

## Homebrew (optional)

Add a formula that builds from a tagged release tarball, e.g.:

```ruby
class Nexus < Formula
  desc "Verify, attest, and gate .telos programs against tpt-archon"
  homepage "https://github.com/TPT-Org/tpt-nexus"
  url "https://github.com/TPT-Org/tpt-nexus/archive/refs/tags/v0.1.0.tar.gz"
  depends_on "rust"
  def install
    system "cargo", "install", "--locked", "--root", prefix, "--path", "crates/tpt-nexus-cli"
  end
end
```

## Prebuilt binaries (CI)

The existing `ci.yml` already builds the CLI; add a release job that uploads
`target/release/nexus` as a GitHub Release asset for Linux/macOS/Windows. Users
then download a single binary — no Rust toolchain or sibling clones required.

## Release order

The crates must be published bottom-up (dependencies before dependents):

1. `tpt-archon-core`, `tpt-archon-bridge`, `tpt-archon-kernel`
2. `tpt-telos-sdk` (and its siblings)
3. `tpt-nexus-orchestrator`, `tpt-nexus-manifest-validator`,
   `tpt-nexus-archon-emulator`
4. `tpt-nexus-cli` (the installable binary)

Each `cargo publish` must be run from the crate directory after the previous
ones are available on crates.io.
