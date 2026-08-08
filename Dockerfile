# Zero-setup development image for tpt-nexus.
#
# nexus builds against its two sibling repos as path dependencies, so this image
# clones tpt-telos and tpt-archon as siblings of the nexus checkout, then builds
# the CLI. Run the whole loop without manually cloning three repositories:
#
#   docker build -t nexus .
#   docker run --rm -v "$PWD:/work" nexus verify /work/examples/capability_boundary.telos
#
FROM rust:1.74

WORKDIR /src

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Siblings must sit next to the nexus checkout (path deps in Cargo.toml).
RUN git clone --depth 1 https://github.com/TPT-Org/tpt-telos.git /tpt-telos \
    && git clone --depth 1 https://github.com/TPT-Org/tpt-archon.git /tpt-archon

COPY . .

RUN cargo build --release -p tpt-nexus-cli

ENTRYPOINT ["cargo", "run", "-q", "--release", "-p", "tpt-nexus-cli", "--"]
