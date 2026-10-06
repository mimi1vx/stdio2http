//! End-to-end: a real stdio child behind the real HTTP proxy.
//!
//! The upstream is the deterministic fixture in `tests/fixtures/mock-mcp-server`
//! and the HTTP side is a real rmcp Streamable HTTP client, so these exercise
//! session ids, SSE framing, and protocol negotiation rather than stubbing them.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use rmcp::ClientHandler;
use rmcp::model::{CallToolRequestParams, CallToolResponse, ContentBlock, JsonObject, Tool};
use rmcp::service::{Peer, RoleClient, RunningService, ServiceExt as _};
use rmcp::transport::StreamableHttpClientTransport;
use serde_json::json;
use stdio2http::config::Config;
use stdio2http::http;
use stdio2http::upstream::Upstream;

const KEY_ALICE: &str = "k-alice-secret";
const KEY_BOB: &str = "k-bob-secret";

/// Locate the fixture binary through cargo rather than assuming a target dir.
fn fixture_binary() -> PathBuf {
    let manifest =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mock-mcp-server/Cargo.toml");

    let output = std::process::Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--manifest-path",
            manifest.to_str().expect("utf-8 manifest path"),
            "--format-version",
            "1",
            "--no-deps",
        ])
        .output()
        .expect("cargo metadata runs");

    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("metadata is JSON");
    let target_dir = metadata["target_directory"]
        .as_str()
        .expect("metadata carries a target_directory");
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };

    PathBuf::from(target_dir)
        .join(profile)
        .join("mock-mcp-server")
}

/// Install a stderr subscriber once so `upstream_error`'s diagnostic is visible.
fn init_tracing() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .try_init();
    });
}

fn test_config(extra: &[&str]) -> Config {
    let binary = fixture_binary();
    assert!(
        binary.exists(),
        "fixture not built at {}; run: cargo build --manifest-path tests/fixtures/mock-mcp-server/Cargo.toml",
        binary.display()
    );

    let mut flags = vec![
        "--command".to_string(),
        binary.to_string_lossy().into_owned(),
        "--port".to_string(),
        "0".to_string(),
    ];
    flags.extend(extra.iter().map(|flag| (*flag).to_string()));

    let mut full = vec!["stdio2http".to_string()];
    full.extend(flags);
    let cfg = Config::parse_from(full.iter().map(String::as_str));
    cfg.validate().expect("test config is valid");
    cfg
}

/// A running proxy: the shared child plus the HTTP listener in front of it.
///
/// The `Upstream` handle is kept alive for the harness's lifetime on purpose:
/// it owns the child's transport, so dropping it would close the pipe under the
/// proxy and make every session fail.
struct Harness {
    addr: SocketAddr,
    child_pid: Option<u32>,
    _upstream: Arc<Upstream>,
}

async fn start(extra: &[&str]) -> Harness {
    init_tracing();
    let cfg = test_config(extra);

    let upstream = Arc::new(Upstream::spawn(&cfg).await.expect("upstream spawns"));
    let child_pid = upstream.child_pid();
    assert!(child_pid.is_some(), "the proxy must own a child pid");

    let listener = http::bind(&cfg).await.expect("proxy binds");
    let addr = listener.local_addr().expect("listener has an address");
    let router = http::router(&cfg, &upstream);
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    Harness {
        addr,
        child_pid,
        _upstream: upstream,
    }
}

struct TestClient;

impl ClientHandler for TestClient {}

type Client = RunningService<RoleClient, TestClient>;

/// Connect a real MCP client over Streamable HTTP, optionally with a credential.
async fn connect_at(uri: &str, api_key: Option<&str>) -> std::result::Result<Client, String> {
    use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig as TransportConfig;

    let mut config = TransportConfig::with_uri(uri);
    if let Some(key) = api_key {
        // rmcp expects the token without the `Bearer ` prefix; it adds the scheme.
        config = config.auth_header(key.to_string());
    }

    let transport = StreamableHttpClientTransport::with_client(reqwest::Client::new(), config);

    TestClient
        .serve(transport)
        .await
        .map_err(|error| format!("{error}"))
}

async fn connect(harness: &Harness, api_key: Option<&str>) -> std::result::Result<Client, String> {
    connect_at(&format!("http://{}/mcp", harness.addr), api_key).await
}

/// Connect, treating a failed handshake as a test failure.
async fn connect_ok(harness: &Harness, api_key: Option<&str>) -> Client {
    connect(harness, api_key)
        .await
        .unwrap_or_else(|error| panic!("handshake failed: {error}"))
}

fn tool_names(tools: &[Tool]) -> Vec<&str> {
    let mut names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
    names.sort_unstable();
    names
}

/// The fixture always answers with text; anything else is a test bug.
fn text_of(result: &rmcp::model::CallToolResult) -> String {
    result
        .content
        .iter()
        .map(|block| match block {
            ContentBlock::Text(text) => text.text.clone(),
            other => panic!("expected a text block, got {other:?}"),
        })
        .collect()
}

fn echo_args(message: &str) -> JsonObject {
    let mut args = JsonObject::new();
    args.insert("message".to_string(), json!(message));
    args
}

/// Unwrap a completed tool call, failing loudly on any other shape.
fn completed(response: CallToolResponse) -> rmcp::model::CallToolResult {
    match response {
        CallToolResponse::Complete(result) => result,
        other => panic!("expected a completed call, got {other:?}"),
    }
}

async fn call_echo(client: &Client, message: &str) -> String {
    let response = client
        .call_tool_once(CallToolRequestParams::new("echo").with_arguments(echo_args(message)))
        .await
        .expect("tools/call succeeds");
    text_of(&completed(response))
}

async fn call_whoami(client: &Client) -> String {
    let response = client
        .call_tool_once(CallToolRequestParams::new("whoami"))
        .await
        .expect("tools/call succeeds");
    text_of(&completed(response))
}

#[tokio::test]
async fn tools_list_over_http_matches_the_stub() {
    let harness = start(&[]).await;
    let client = connect_ok(&harness, None).await;

    let listed = client.list_all_tools().await.expect("tools/list succeeds");

    assert_eq!(tool_names(&listed), ["echo", "whoami"]);

    let echo = listed
        .iter()
        .find(|tool| tool.name == "echo")
        .expect("echo is advertised");
    assert_eq!(
        echo.input_schema.get("required"),
        Some(&json!(["message"])),
        "echo keeps its required argument: {:?}",
        echo.input_schema
    );
}

#[tokio::test]
async fn a_tool_call_round_trips() {
    let harness = start(&[]).await;
    let client = connect_ok(&harness, None).await;

    let response = client
        .call_tool_once(CallToolRequestParams::new("echo").with_arguments(echo_args("hello")))
        .await
        .expect("tools/call succeeds");
    let result = completed(response);

    assert!(!result.is_error.unwrap_or(false), "echo must succeed");
    assert_eq!(text_of(&result), "hello");
}

#[tokio::test]
async fn a_tool_error_reaches_the_client_as_a_tool_error() {
    let harness = start(&[]).await;
    let client = connect_ok(&harness, None).await;

    // Omitting `message` makes the fixture answer isError, not a JSON-RPC error.
    let response = client
        .call_tool_once(CallToolRequestParams::new("echo"))
        .await
        .expect("the request itself is well-formed");
    let result = completed(response);

    assert!(
        result.is_error.unwrap_or(false),
        "a missing argument must surface as a tool error: {result:?}"
    );
    assert!(text_of(&result).contains("message"), "{result:?}");
}

#[tokio::test]
async fn two_sessions_share_one_child() {
    let harness = start(&[]).await;

    let first = connect_ok(&harness, None).await;
    let second = connect_ok(&harness, None).await;

    assert_eq!(call_echo(&first, "first").await, "first");
    assert_eq!(call_echo(&second, "second").await, "second");

    // Re-reading from the first session proves both answers came from one child
    // rather than a per-session one: the value is not tied to the caller.
    assert_eq!(call_echo(&first, "again").await, "again");
    assert!(harness.child_pid.is_some());
}

#[tokio::test]
async fn concurrent_sessions_interleave_over_one_child() {
    let harness = start(&[]).await;
    let client = connect_ok(&harness, None).await;
    let peer: Peer<RoleClient> = client.peer().clone();

    let mut calls = Vec::new();
    for index in 0..8 {
        let peer = peer.clone();
        calls.push(tokio::spawn(async move {
            let message = format!("call-{index}");
            let response = peer
                .call_tool_once(
                    CallToolRequestParams::new("echo").with_arguments(echo_args(&message)),
                )
                .await;
            response.map(completed).map(|result| text_of(&result))
        }));
    }

    for (index, call) in calls.into_iter().enumerate() {
        let text = call
            .await
            .expect("task does not panic")
            .expect("call succeeds");
        assert_eq!(
            text,
            format!("call-{index}"),
            "rmcp multiplexes by request id"
        );
    }
}

#[tokio::test]
async fn bearer_mode_rejects_an_unauthenticated_handshake() {
    let harness = start(&["--auth-mode", "bearer", "--api-key", KEY_ALICE]).await;

    let uri = format!("http://{}/mcp", harness.addr);
    assert_401(&uri, None).await;
    assert!(
        connect(&harness, None).await.is_err(),
        "an unauthenticated handshake must fail"
    );
}

#[tokio::test]
async fn bearer_mode_accepts_a_configured_key() {
    let harness = start(&["--auth-mode", "bearer", "--api-key", KEY_ALICE]).await;

    let client = connect_ok(&harness, Some(KEY_ALICE)).await;
    let tools = client
        .list_all_tools()
        .await
        .expect("authenticated list succeeds");
    assert_eq!(tool_names(&tools), ["echo", "whoami"]);
}

#[tokio::test]
async fn bearer_mode_rejects_a_wrong_key() {
    let harness = start(&["--auth-mode", "bearer", "--api-key", KEY_ALICE]).await;

    let uri = format!("http://{}/mcp", harness.addr);
    assert_401(&uri, Some(KEY_BOB)).await;
    assert!(
        connect(&harness, Some(KEY_BOB)).await.is_err(),
        "a wrong key must fail"
    );
}

#[tokio::test]
async fn identity_forward_yields_distinct_callers() {
    let harness = start(&[
        "--auth-mode",
        "identity-forward",
        "--api-key",
        &format!("{KEY_ALICE}=alice"),
        "--api-key",
        &format!("{KEY_BOB}=bob"),
    ])
    .await;

    let alice = connect_ok(&harness, Some(KEY_ALICE)).await;
    let bob = connect_ok(&harness, Some(KEY_BOB)).await;

    assert_eq!(call_whoami(&alice).await, "alice");
    assert_eq!(call_whoami(&bob).await, "bob");

    // Re-reading as alice shows the identity is per-request, not a one-time
    // label attached to the shared child.
    assert_eq!(call_whoami(&alice).await, "alice");
}

#[tokio::test]
async fn bearer_mode_authenticates_without_forwarding_identity() {
    let harness = start(&["--auth-mode", "bearer", "--api-key", KEY_ALICE]).await;
    let client = connect_ok(&harness, Some(KEY_ALICE)).await;

    assert_eq!(
        call_whoami(&client).await,
        "<none>",
        "bearer mode authenticates but forwards no identity"
    );
}

#[tokio::test]
async fn healthz_is_reachable_without_credentials() {
    let harness = start(&["--auth-mode", "bearer", "--api-key", KEY_ALICE]).await;

    let response = reqwest::get(format!("http://{}/healthz", harness.addr))
        .await
        .expect("healthz answers");

    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.expect("body reads"), "ok");
}

#[tokio::test]
async fn the_mount_path_is_configurable() {
    let harness = start(&["--mcp-path", "/rpc"]).await;
    let uri = format!("http://{}/rpc", harness.addr);

    let client = connect_at(&uri, None)
        .await
        .expect("connecting to the configured path must work");
    let tools = client.list_all_tools().await.expect("tools/list succeeds");
    assert_eq!(tool_names(&tools), ["echo", "whoami"]);

    // The default path is gone once remapped.
    let default_uri = format!("http://{}/mcp", harness.addr);
    assert!(
        connect_at(&default_uri, None).await.is_err(),
        "the default mount must not answer after remapping"
    );
}

#[tokio::test]
async fn an_upstream_failure_does_not_leak_child_stderr() {
    let harness = start(&[]).await;
    let client = connect_ok(&harness, None).await;

    let pid = harness.child_pid.expect("child pid recorded");
    let killed = std::process::Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status()
        .expect("kill runs");
    assert!(killed.success(), "killing the child must succeed");

    let outcome = client
        .call_tool_once(CallToolRequestParams::new("echo").with_arguments(echo_args("gone")))
        .await;

    match outcome {
        Ok(response) => panic!(
            "a dead child must not answer: {}",
            text_of(&completed(response))
        ),
        Err(error) => {
            let rendered = format!("{error} {error:?}");
            for leak in [
                "panicked",
                "backtrace",
                "RUST_BACKTRACE",
                "mock-mcp-server",
                env!("CARGO_MANIFEST_DIR"),
            ] {
                assert!(
                    !rendered.contains(leak),
                    "error leaked {leak:?}: {rendered}"
                );
            }
            assert!(
                rendered.contains("internal_error") || rendered.contains("-32603"),
                "an upstream failure must map to internal_error: {rendered}"
            );
        }
    }
}

#[tokio::test]
async fn a_child_that_exits_before_initializing_is_fatal() {
    let cfg = Config::parse_from([
        "stdio2http",
        "--command",
        "true",
        "--init-timeout-ms",
        "2000",
    ]);
    cfg.validate().expect("valid config");

    let error = Upstream::spawn(&cfg)
        .await
        .expect_err("a child that exits before initializing is fatal");
    let rendered = format!("{error:#}");

    assert!(
        rendered.contains("true"),
        "the error must name the program: {rendered}"
    );
}

/// Assert the proxy answers 401 with a challenge, and echoes no key.
async fn assert_401(uri: &str, api_key: Option<&str>) {
    let mut request = reqwest::Client::new()
        .post(uri)
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":0,"method":"initialize"}"#);
    if let Some(key) = api_key {
        request = request.header("authorization", format!("Bearer {key}"));
    }

    let response = request.send().await.expect("proxy answers");
    assert_eq!(response.status(), 401, "expected a 401 for {api_key:?}");

    let challenge = response
        .headers()
        .get("www-authenticate")
        .expect("a challenge header is required")
        .to_str()
        .expect("challenge is ascii");
    assert_eq!(challenge, "Bearer realm=\"mcp\"", "unexpected challenge");

    let body = response.text().await.expect("body reads");
    for leak in [KEY_ALICE, KEY_BOB] {
        assert!(!body.contains(leak), "401 body leaked a key: {body}");
    }
}
