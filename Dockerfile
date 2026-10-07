# syntax=docker/dockerfile:1

# Build stage: compile the proxy only.
FROM rust:1-slim-bookworm AS builder
WORKDIR /build

# Dependency layer: cached until Cargo.toml/Cargo.lock change.
COPY Cargo.toml Cargo.lock ./
ARG BIN_FEATURES=""
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && echo '' > src/lib.rs \
    && cargo build --release --locked ${BIN_FEATURES:+--features $BIN_FEATURES} \
    && rm -rf src

COPY src ./src
# Touch so cargo sees the real sources as newer than the placeholder build.
# The release profile already sets strip = true.
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --locked ${BIN_FEATURES:+--features $BIN_FEATURES}

# Runtime stage. The proxy binary is self-contained, so nothing but CA roots is
# needed to run it.
#
# The UPSTREAM MCP server's runtime does NOT come from this image: stdio2http
# spawns it as a child process, so whatever interpreter it needs (node, python,
# go, bun, ...) must be installed here too, and its program path passed via
# `--command`. Without it the child spawn fails at startup.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/stdio2http /usr/local/bin/stdio2http

# Run unprivileged: the proxy needs no write access and only spawns a child.
USER nobody:nogroup
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/stdio2http"]

# TLS notes (no image change — usage only):
# - Manual cert: mount the cert + key read-only; `nobody` needs read
#   permission on the mount, nothing more.
#     docker run --rm -p 443:8080 -v certs:/certs:ro stdio2http \
#       --command ... --tls-cert /certs/fullchain.pem --tls-key /certs/privkey.pem
# - ACME auto-issuance (binary built with `--features acme`): the cache dir
#   must be writable by `nobody`, so mount it RW.
#     docker run --rm -p 8080:8080 -p 80:80 -v acme-cache:/var/lib/stdio2http/acme:rw stdio2http \
#       --command ... --host 0.0.0.0 \
#       --acme-email ops@example.com --acme-domain mcp.example.com \
#       --acme-cache-dir /var/lib/stdio2http/acme