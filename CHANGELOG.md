# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0](https://github.com/mimi1vx/stdio2http/compare/v0.2.1...v0.3.0) - 2026-10-22

### Added

- *(http)* answer CORS preflight for configured origins

### Fixed

- *(upstream)* bound the startup tools/list probe by the init timeout
- *(http)* bind MCP sessions to the authenticating key
- *(http)* report and exit on an unavailable upstream
- *(http)* bound graceful shutdown and close SSE streams on signal
- *(proxy)* forward client _meta and strip spoofed caller identity
- *(acme)* schedule renewal from notAfter; write cache atomically with 0600
- *(proxy)* forward caller identity on list requests without params
- *(acme)* match loopback directory hosts exactly
- *(config)* reject reserved mcp path and unparsable api keys
- *(acme)* register a new account when no cache exists

### Other

- bump the cargo-deps group across 1 directory with 2 updates
- *(readme)* align clippy command with locked CI invocation
- *(proxy,shutdown)* cover X-API-Key header and SIGINT drain
- *(readme)* document mcp-path reservation, CORS semantics, fixture pre-build
- *(docker)* drop container publishing and docs
- *(tls)* prove readiness before the untrusted-CA rejection

## [0.2.1](https://github.com/mimi1vx/stdio2http/compare/v0.2.0...v0.2.1) - 2026-10-15

### Added

- publish Docker image to GHCR on release (default + acme)

### Fixed

- migrate PEM parsing to pki-types PemObject, drop rustls-pemfile

### Other

- bump the gha-deps group with 5 updates
- bump the cargo-deps group with 3 updates

## [0.2.0](https://github.com/mimi1vx/stdio2http/compare/v0.1.0...v0.2.0) - 2026-10-06

### Added

- *(https)* native TLS termination with mTLS and ACME wiring
- *(https)* TLS/ACME config flags plus grouped Dependabot config

### Fixed

- *(security)* patch RUSTSEC-2026-0009 with time 0.3.47
- *(https)* accept space-separated inline PEM with leading dashes

### Other

- refresh AGENTS.md against current codebase
- bump the cargo-deps group with 2 updates
- bump actions/checkout from 5 to 7 in the gha-deps group
- TLS/HTTPS section, cert guidance, dependabot policy
- *(https)* TLS end-to-end suite over real HTTPS

## [0.1.0](https://github.com/mimi1vx/stdio2http/releases/tag/v0.1.0) - 2026-10-06

### Added

- bridge a stdio-only MCP server onto Streamable HTTP

### Other

- pin crates-io-auth-action to v1.0.5 (no floating v1 tag)
- release via OIDC trusted publishing, no registry token
- release auth (registry token vs trusted publishing)
- publish prep — dual license, crate metadata, README badges, CI + release-plz
- add agent runbook and correct auth/dead-child claims
- initial commit
