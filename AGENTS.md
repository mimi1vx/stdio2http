# stdio2http

Single Rust binary: spawns one stdio MCP server as a child, re-exposes it over MCP Streamable HTTP. No workspace — root crate + standalone fixture crate.

## Commands

```sh
cargo build --locked --manifest-path tests/fixtures/mock-mcp-server/Cargo.toml  # e2e fixture first: tests locate it via cargo metadata but never build it
cargo test --locked                     # unit + e2e (offline, spawns fixture)
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --all -- --check              # rustfmt.toml: edition 2024, max_width 100
curl -fsS localhost:8080/healthz       # smoke test (-> ok)
```

- Full e2e binary: `./target/release/stdio2http --command <program> [--arg ...]`
- CI (`.github/workflows/ci.yml`): fmt + clippy + test (with fixture pre-build) + `audit-check` + docker build / `--help` smoke. Docker `healthz` check is help-only: the runtime stage ships no interpreter for a live upstream child.

## Architecture

- `src/main.rs` — parse `Config`, spawn `Upstream`, serve, shut down child on exit.
- `src/config.rs` — clap + `STDIO2HTTP_*` env, no config file. Flags win over env.
- `src/upstream.rs` — `TokioChildProcess` + `.serve()` → `Arc<Peer<RoleClient>>`. One long-lived child, `peer_info` snapshotted once. A dead child is fatal (non-zero exit, no restart).
- `src/proxy.rs` — `ServerHandler` forwarding every method to the shared peer. Map failures to opaque `internal_error`; never leak child stderr or process env to the client.
- `src/http.rs` — axum router: `/healthz` (`ok`) + `/mcp` via `StreamableHttpService` with `LocalSessionManager`. rmcp owns sessions/SSE/`Mcp-Session-Id`/negotiation — do not reimplement. `SIGTERM`/`SIGINT` shut down in ~1s and reap the child.
- `src/auth.rs` — tower layer on `/mcp` only; `/healthz` and CORS preflight stay open. Modes `none`/`bearer`/`identity-forward`. Keys via `Authorization: Bearer` or `X-API-Key`, constant-time compare (`subtle`), never logged. Missing and wrong keys give identical `401` + `WWW-Authenticate: Bearer realm="mcp"`.
- `tests/proxy.rs` + `tests/fixtures/mock-mcp-server/` (`echo`, `whoami` tools) — e2e uses port `0`, real rmcp Streamable HTTP client.

## Gotchas

- `rmcp = "=3.5.1"` pinned in both crates. Server needs `transport-streamable-http-server` + `transport-streamable-http-server-session`; do not enable the non-default `local` feature. After touching features, verify with `cargo tree -e features | grep streamable`.
- `allowed_hosts` defaults to loopback only (DNS-rebinding guard). Off-host deployments must pass `--allowed-host`; `--disable-allowed-hosts` only behind a validating proxy.
- `--api-key KEY` (bare) forwards the secret itself as `_meta["io.stdio2http/caller"]`; prefer `KEY=SUBJECT`. `identity-forward` is advisory `_meta`, not process isolation; shared upstream state is shared across all callers.
- TLS is opt-in per listener (`src/tls.rs`, `src/acme.rs`): no TLS flags → plain HTTP; any cert/ACME/client-CA input → same `host:port` speaks HTTPS only, no redirect. ACME needs `cargo build --features acme`. mTLS verifies at the handshake so `/healthz` needs a client cert too.
- Notifications and server→client requests do not forward (`progress`, `list_changed`, `logging/message`, `sampling`, `elicitation`, `roots`). A tool needing them fails — that is a design limit, not a bug to patch around.
- `unsafe_code = "forbid"`, clippy `pedantic = warn`. Dockerfile is cached-deps multi-stage (`rust:1-slim-bookworm` → `debian:bookworm-slim`, `USER nobody`); the upstream interpreter (node/python/...) must be installed in the runtime image separately.
- No `opencode.json`. `br`/`bd` is the issue tracker (see below).

## Dependency updates

- `.github/dependabot.yml`: `cargo` + `github-actions` + `docker`, weekly, one grouped PR per ecosystem (`*`), `chore` prefix + `dependencies` label. No `ignore:` on `rmcp`.
- Merge bar is green `ci.yml`: `cargo fmt --all -- --check`, `cargo clippy --all-targets --locked -- -D warnings`, fixture pre-build + `cargo test --locked`, `audit-check`, docker build + `--help` smoke.
- `rmcp` bumps additionally need `cargo tree -e features | grep streamable` showing `transport-streamable-http-server` + `-session` (never `local`) plus full `cargo test --locked` green.
- `dtolnay/rust-toolchain@stable` tracks a branch, so expect few/no PRs for it by design.
- Release is release-plz (`release.yml`): merge to `main`, then merge the bot's `release-pr` version-bump PR — never hand-edit versions/`CHANGELOG.md` or `cargo publish` (OIDC trusted publishing, no token).

<!-- br-agent-instructions-v1 -->

---

## Beads Workflow Integration

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) (`br`/`bd`) for issue tracking. Issues are stored in `.beads/` and tracked in git.

### Essential Commands

```bash
# View ready issues (open, unblocked, not deferred)
br ready              # or: bd ready

# List and search
br list --status=open # All open issues
br show <id>          # Full issue details with dependencies
br search "keyword"   # Full-text search

# Create and update
br create --title="..." --description="..." --type=task --priority=2
br update <id> --status=in_progress
br close <id> --reason="Completed"
br close <id1> <id2>  # Close multiple issues at once

# Sync with git
br sync --flush-only  # Export DB to JSONL
br sync --status      # Check sync status
```

### Workflow Pattern

1. **Start**: Run `br ready` to find actionable work
2. **Claim**: Use `br update <id> --status=in_progress`
3. **Work**: Implement the task
4. **Complete**: Use `br close <id>`
5. **Sync**: Always run `br sync --flush-only` at session end

### Key Concepts

- **Dependencies**: Issues can block other issues. `br ready` shows only open, unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers 0-4, not words)
- **Types**: task, bug, feature, epic, chore, docs, question
- **Blocking**: `br dep add <issue> <depends-on>` to add dependencies

### Session Protocol

**Before ending any session, run this checklist:**

```bash
git status              # Check what changed
git add <files>         # Stage code changes
br sync --flush-only    # Export beads changes to JSONL
git commit -m "..."     # Commit everything
git push                # Push to remote
```

### Best Practices

- Check `br ready` at session start to find available work
- Update status as you work (in_progress → closed)
- Create new issues with `br create` when you discover tasks
- Use descriptive titles and set appropriate priority/type
- Always sync before ending session

<!-- end-br-agent-instructions -->
