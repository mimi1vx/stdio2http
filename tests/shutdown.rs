//! Shutdown end-to-end: `SIGTERM` with an open SSE stream exits promptly.
//!
//! Spawns the real `stdio2http` binary (plain HTTP), completes an MCP
//! handshake, holds one standalone `GET /mcp` SSE stream open, then sends
//! `SIGTERM`. The process must exit within the 3s drain deadline plus slack,
//! and the upstream child must be reaped (its pid gone).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::json;

const OFFERED_VERSION: &str = "2025-11-25";
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
/// The drain deadline in `src/http.rs`, plus 2s of scheduling slack.
const EXIT_TIMEOUT: Duration = Duration::from_secs(5);

/// Locate the fixture binary through cargo rather than assuming a target dir.
fn fixture_binary() -> PathBuf {
    let manifest =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mock-mcp-server/Cargo.toml");

    let output = Command::new(env!("CARGO"))
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

/// The binary under test; `cargo test` builds it before running this target.
fn proxy_binary() -> PathBuf {
    let path = PathBuf::from(env!("CARGO_BIN_EXE_stdio2http"));
    assert!(path.exists(), "proxy binary missing at {}", path.display());
    path
}

/// A running proxy child plus its address. Dropping kills and reaps the child.
struct Proxy {
    addr: SocketAddr,
    child: Option<Child>,
    stderr: Arc<Mutex<Vec<u8>>>,
}

impl Proxy {
    fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr.lock().expect("stderr buffer")).into_owned()
    }

    /// Poll `http://addr/healthz` until it answers `ok`.
    async fn wait_ready(&mut self, client: &reqwest::Client) {
        let start = Instant::now();
        loop {
            if let Ok(response) = client
                .get(format!("http://{}/healthz", self.addr))
                .timeout(IO_TIMEOUT)
                .send()
                .await
                && response.status() == 200
                && response.text().await.unwrap_or_default() == "ok"
            {
                return;
            }
            if let Some(status) = self.try_exit() {
                panic!(
                    "proxy exited during startup ({status:?}): {}",
                    self.stderr_text()
                );
            }
            assert!(
                start.elapsed() < STARTUP_TIMEOUT,
                "proxy never became ready: {}",
                self.stderr_text()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn try_exit(&mut self) -> Option<std::process::ExitStatus> {
        self.child
            .as_mut()
            .and_then(|child| child.try_wait().expect("exit status reads"))
    }

    /// The upstream fixture pid, from the `pid=Some(...)` startup log line.
    /// Stderr carries ANSI escapes, so they are stripped before scanning.
    fn fixture_pid(&self) -> u32 {
        let text = strip_ansi(&self.stderr_text());
        let marker = "pid=Some(";
        let start = text
            .find(marker)
            .unwrap_or_else(|| panic!("startup never logged the child pid: {text}"))
            + marker.len();
        let end = text[start..].find(')').expect("pid log is terminated");
        text[start..start + end]
            .parse()
            .unwrap_or_else(|_| panic!("pid log is numeric: {text}"))
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Drop `ESC[...m` color sequences so log lines can be scanned as text.
fn strip_ansi(text: &str) -> String {
    let mut plain = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(char) = chars.next() {
        if char != '\u{1b}' {
            plain.push(char);
            continue;
        }
        for char in chars.by_ref() {
            if char == 'm' {
                break;
            }
        }
    }
    plain
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("loopback binds")
        .local_addr()
        .expect("listener has an address")
        .port()
}

async fn spawn_plain() -> Proxy {
    let fixture = fixture_binary();
    assert!(
        fixture.exists(),
        "fixture not built at {}; run: cargo build --manifest-path tests/fixtures/mock-mcp-server/Cargo.toml",
        fixture.display()
    );
    let port = free_port();
    let mut command = Command::new(proxy_binary());
    command
        .args([
            "--command",
            fixture.to_str().expect("fixture path is UTF-8"),
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("proxy spawns");
    let pipe = child.stderr.take().expect("stderr is piped");

    let stderr = Arc::new(Mutex::new(Vec::new()));
    let drain = Arc::clone(&stderr);
    std::thread::spawn(move || {
        use std::io::Read as _;
        let mut pipe = pipe;
        let mut buf = [0_u8; 4096];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(read) => drain
                    .lock()
                    .expect("stderr buffer")
                    .extend_from_slice(&buf[..read]),
            }
        }
    });
    let mut proxy = Proxy {
        addr: SocketAddr::from(([127, 0, 0, 1], port)),
        child: Some(child),
        stderr,
    };
    let client = reqwest::Client::new();
    proxy.wait_ready(&client).await;
    proxy
}

/// Full handshake; returns the session id plus the negotiated protocol version.
async fn handshake(client: &reqwest::Client, addr: SocketAddr) -> (String, String) {
    let initialize = client
        .post(format!("http://{addr}/mcp"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .body(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": OFFERED_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "shutdown-e2e", "version": "0.0.0"},
                },
            })
            .to_string(),
        )
        .timeout(IO_TIMEOUT)
        .send()
        .await
        .expect("initialize is answered");
    assert_eq!(initialize.status(), 200, "initialize is accepted");
    let session = initialize
        .headers()
        .get("mcp-session-id")
        .expect("initialize issues a session id")
        .to_str()
        .expect("session id is ascii")
        .to_owned();

    let initialized = client
        .post(format!("http://{addr}/mcp"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Session-Id", &session)
        .body(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
        .timeout(IO_TIMEOUT)
        .send()
        .await
        .expect("initialized is answered");
    assert_eq!(initialized.status(), 202, "initialized is accepted");

    (session, OFFERED_VERSION.to_owned())
}

fn child_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .is_ok_and(|status| status.success())
}

#[tokio::test]
async fn sigterm_with_an_open_sse_stream_exits_within_the_drain_deadline() {
    let mut proxy = spawn_plain().await;
    let client = reqwest::Client::new();
    let (session, version) = handshake(&client, proxy.addr).await;
    let fixture_pid = proxy.fixture_pid();

    // One idle standalone SSE stream: the shape that used to pin the process
    // open past the deadline after SIGTERM.
    let sse = client
        .get(format!("http://{}/mcp", proxy.addr))
        .header("Accept", "text/event-stream")
        .header("Mcp-Session-Id", &session)
        .header("MCP-Protocol-Version", &version)
        .timeout(IO_TIMEOUT)
        .send()
        .await
        .expect("the SSE stream opens");
    assert_eq!(sse.status(), 200, "the SSE stream is accepted");
    assert!(
        sse.headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .starts_with("text/event-stream"),
        "the stream is an SSE stream"
    );

    let proxy_pid = proxy.child.as_ref().expect("proxy is running").id();
    let sent = Command::new("kill")
        .args(["-TERM", &proxy_pid.to_string()])
        .status()
        .expect("kill runs");
    assert!(sent.success(), "SIGTERM is delivered");

    let start = Instant::now();
    let status = loop {
        if let Some(status) = proxy.try_exit() {
            break status;
        }
        assert!(
            start.elapsed() < EXIT_TIMEOUT,
            "proxy with an open SSE stream must exit within {EXIT_TIMEOUT:?} of SIGTERM"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(
        status.success(),
        "a SIGTERM shutdown exits zero: {status:?}"
    );
    // The stream held only by this test must not keep anything alive: dropping
    // it here would otherwise be what finally lets the process go.
    drop(sse);

    assert!(
        !child_alive(fixture_pid),
        "the upstream child (pid {fixture_pid}) is reaped on shutdown"
    );
}
