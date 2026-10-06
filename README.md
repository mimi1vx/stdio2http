# stdio2http

[![crates.io](https://img.shields.io/crates/v/stdio2http.svg)](https://crates.io/crates/stdio2http)
[![docs.rs](https://docs.rs/stdio2http/badge.svg)](https://docs.rs/stdio2http)
[![CI](https://github.com/mimi1vx/stdio2http/actions/workflows/ci.yml/badge.svg)](https://github.com/mimi1vx/stdio2http/actions)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

Re-exposes a **stdio-only MCP server** over **MCP Streamable HTTP**, so HTTP
clients on a container network can use a server that ships no HTTP transport.

It spawns the stdio server as a single long-lived child process and bridges to
it with [`rmcp`](https://crates.io/crates/rmcp). Session ids, `Mcp-Session-Id`,
SSE framing, `Last-Event-ID`, content negotiation, and protocol negotiation are
all handled by rmcp — none of that is reimplemented here.

```text
                    ┌──────────────────────────────┐
 HTTP client  ──────▶│ /mcp  StreamableHttpService  │
                    │      (rmcp owns sessions)     │
                    └───────────────┬──────────────┘
                                    │ ServerHandler::call_tool, list_tools, …
                          ┌─────────▼──────────┐
                          │   ProxyHandler     │
                          └─────────┬──────────┘
                                    │ rmcp client Peer (Arc, shared)
                          ┌─────────▼──────────┐
                          │ stdio MCP child    │
                          │ (TokioChildProcess)│
                          └────────────────────┘
```

One child serves every HTTP session: the service factory clones the `Arc<Peer>`,
so all sessions multiplex over the same process by JSON-RPC request id.

## Installation

```sh
cargo install stdio2http
```

For a reproducible build pinned to the lockfile:

```sh
cargo install --locked stdio2http
```

## Build and run

```sh
cargo build --release
./target/release/stdio2http --command <program> [--arg <arg> ...]
```

In a container:

```sh
docker build -t stdio2http .

docker run --rm -p 8080:8080 stdio2http \
  --command node \
  --arg /app/dist/server.js \
  --arg --stdio
```

> **The upstream runtime must exist in the image.** `stdio2http` spawns the
> upstream as a child process, so whatever interpreter it needs — node, python,
> go, bun — must be installed in your image too. The proxy binary alone cannot
> spawn a server that has no interpreter.

Verify it is up:

```sh
curl -fsS localhost:8080/healthz   # -> ok
```

Then point any Streamable HTTP MCP client at `http://<host>:8080/mcp`.

## Configuration

Flags and environment variables, no config file. Every flag has a matching
`STDIO2HTTP_*` variable; flags win over the environment.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--command` | `STDIO2HTTP_COMMAND` | *required* | Program to spawn |
| `--arg` | `STDIO2HTTP_ARGS` | — | Argument for the child; repeat per argument |
| `--child-env` | `STDIO2HTTP_CHILD_ENV` | — | `KEY=VALUE` for the child; repeat |
| `--cwd` | `STDIO2HTTP_CWD` | inherit | Working directory for the child |
| `--host` | `STDIO2HTTP_HOST` | `127.0.0.1` | Bind address |
| `--port` | `STDIO2HTTP_PORT` | `8080` | Bind port (`0` picks an ephemeral one) |
| `--mcp-path` | `STDIO2HTTP_MCP_PATH` | `/mcp` | Where the transport is mounted |
| `--allowed-host` | `STDIO2HTTP_ALLOWED_HOSTS` | loopback only | Accepted `Host` values; repeat, comma-separated |
| `--allowed-origin` | `STDIO2HTTP_ALLOWED_ORIGINS` | unset | Accepted `Origin` values; repeat, comma-separated |
| `--auth-mode` | `STDIO2HTTP_AUTH_MODE` | `none` | `none`, `bearer`, or `identity-forward` |
| `--api-key` | `STDIO2HTTP_API_KEYS` | — | `KEY` or `KEY=SUBJECT`; repeat, comma-separated |
| `--log-level` | `STDIO2HTTP_LOG_LEVEL` | `info` | `error`, `warn`, `info`, `debug`, `trace` |
| `--init-timeout-ms` | `STDIO2HTTP_INIT_TIMEOUT_MS` | `10000` | Budget for spawn plus handshake |
| `--disable-allowed-hosts` | `STDIO2HTTP_DISABLE_ALLOWED_HOSTS` | `false` | Accept every `Host` header |

A concrete example:

```sh
docker run --rm -p 8080:8080 stdio2http \
  --command /usr/local/bin/some-mcp-server \
  --child-env SOME_TOKEN=abc123 \
  --host 0.0.0.0 \
  --allowed-host internal.svc \
  --allowed-origin https://console.example.com \
  --auth-mode identity-forward \
  --api-key 'alice-key=alice' \
  --api-key 'bob-key=bob'
```

### Host validation

rmcp defaults `allowed_hosts` to loopback only, to prevent DNS rebinding against
a locally running server. **A deployment reachable off-host must set
`--allowed-host`** (repeatable) or requests are rejected. `--disable-allowed-hosts`
removes the check entirely; use it only when a trusted proxy in front already
validates the header.

## Authentication

`--auth-mode` selects one of three modes. The layer covers `/mcp` only:
`/healthz` stays open. Keys are compared in
constant time, and no configured or presented key is ever logged.

### `none`

No authentication. Callers are anonymous.

### `bearer`

Require a matching key, presented either way:

```http
Authorization: Bearer <key>
X-API-Key: <key>
```

A missing key and a wrong key produce the identical `401` with
`WWW-Authenticate: Bearer realm="mcp"`, so the response reveals nothing about
which keys exist. The upstream sees no caller identity.

### `identity-forward`

Verify exactly as in `bearer`, then attach the caller's subject to every
forwarded request as a namespaced `_meta` key:

```json
{ "params": { "_meta": { "io.stdio2http/caller": "alice" } } }
```

Write `--api-key 'KEY=SUBJECT'` to name the caller. With a bare `--api-key KEY`,
the key itself becomes the subject — which means **the secret is forwarded to the
upstream**; prefer the `KEY=SUBJECT` form.

The upstream server must actually read that key to act on it. If it does not,
this mode degrades to `bearer`: authenticated, but the child cannot tell callers
apart.

## Limitations

These are deliberate and load-bearing.

1. **No TLS.** The proxy speaks plain HTTP. Run it behind a terminating proxy or
   on a trusted network. An API key crossing an untrusted network in cleartext
   is an API key in the wrong hands.
2. **Shared upstream state.** One child serves every caller, so any state it
   keeps per connection is shared across all HTTP callers. Fine for a
   single-tenant container; not a multi-tenant boundary.
3. **Identity is advisory, not isolation.** Identity reaches the child as
   `_meta` on a request, not as process isolation or per-caller environment
   variables. A child that ignores the key cannot tell callers apart, and a
   malicious caller controls the `_meta` it sends.

## Known gap: notifications and server→client requests do not forward

The bridge proxies requests and responses. Anything the **upstream initiates** has
no path back to the HTTP client:

- `progress` — long-running tools appear to hang with no progress reporting
- `notifications/tools/list_changed` and the other list-changed notifications
- `logging/message`
- server→client requests: `sampling/createMessage`, `elicitation/create`, `roots/list`

In practice: a long-running tool call will complete, but the client sees no
progress events while it runs. A tool that calls `sampling` will fail. If your
upstream depends on any of these, `stdio2http` is the wrong tool — a bridge that
handles these explicitly is a different design.

## Operational behavior

- **A child that fails to start is fatal.** `stdio2http` exits non-zero; it does not restart the
  child. If the child dies later, calls fail with an opaque `internal_error`
  and the proxy still does not restart it. Let your orchestrator handle it.
- **`SIGTERM`/`SIGINT` shut down gracefully**, within about a second, and reap
  the child. Container stop signals work as expected.
- **Startup logs** the child pid, upstream name and version, negotiated protocol
  version, and tool count. Upstream failures are logged locally and returned to
  the client as an opaque `internal_error` — the child's stderr and this
  process's environment never reach an HTTP caller.

## Development

```sh
cargo test          # unit + end-to-end
cargo clippy --all-targets -- -D warnings
```

The end-to-end tests build and spawn a deterministic fixture MCP server from
`tests/fixtures/mock-mcp-server/`, so `cargo test` needs no network access.

### Release

Releases are automated by release-plz (`.github/workflows/release.yml`):
merge to `main`, then merge the `release-pr` bot's version-bump PR —
publishing to crates.io and the GitHub Release happen automatically.

Registry auth is OIDC Trusted Publishing — no long-lived secrets.
Once the crate exists, it lists this repo + workflow as a trusted
publisher (`crates.io/crates/stdio2http/settings`); the `release` job
mints a short-lived token via `rust-lang/crates.io-auth-action`.
crates.io has no "pending publisher" for new crates, so the `0.1.0`
bootstrap is one manual `cargo publish` (after `cargo login`) plus
adding the trusted publisher; everything after that is OIDC.

## License

Dual-licensed under MIT OR Apache-2.0. © 2026 Ondřej Súkup.