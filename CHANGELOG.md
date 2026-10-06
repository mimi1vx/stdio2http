# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
