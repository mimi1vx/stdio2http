//! TLS end-to-end: the real `stdio2http` binary serving `https://`.
//!
//! Each test spawns the built binary (via `CARGO_BIN_EXE_stdio2http`) with
//! `rcgen`-generated certificates on a free loopback port, then drives it
//! with a minimal HTTPS client. The pinned `reqwest` has no TLS features, so
//! neither it nor the rmcp Streamable HTTP client can speak HTTPS here — the
//! client below is a small HTTP/1.1 exchange over [`rustls`] plus a blocking
//! [`TcpStream`], run inside `spawn_blocking`. It parses the status line and
//! headers and collects the SSE `data:` events that carry JSON-RPC
//! responses; request bodies are plain JSON-RPC, wire-compatible with the
//! rmcp server. Chunked framing needs no decoder: a chunk-size line is hex
//! digits only, so it can never start with `data:`.
//!
//! Everything stays offline: certificates are generated in-process, ports are
//! loopback-only, and no ACME host is touched.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const KEY_ALICE: &str = "k-alice-secret";
const KEY_BOB: &str = "k-bob-secret";
/// Version the test client offers; the server negotiates one it supports and
/// later requests echo that answer back in the `MCP-Protocol-Version` header.
const OFFERED_VERSION: &str = "2025-11-25";
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);

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

    let metadata: Value = serde_json::from_slice(&output.stdout).expect("metadata is JSON");
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

/// A temp file removed on drop so parallel tests never share state.
struct TempFile(PathBuf);

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

impl TempFile {
    fn write(name: &str, contents: &str) -> Self {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "stdio2http-tls-e2e-{}-{id}-{name}",
            std::process::id()
        ));
        std::fs::write(&path, contents).expect("test fixture writes");
        Self(path)
    }

    fn utf8(&self) -> &str {
        self.0.to_str().expect("temp path is UTF-8")
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Certificates for one test: a CA, a server leaf it signed (SANs for
/// loopback, server-auth EKU), and a client leaf (client-auth EKU).
struct Pki {
    ca: String,
    server_cert: String,
    server_key: String,
    client_cert: String,
    client_key: String,
}

impl Pki {
    fn generate() -> Self {
        use rcgen::{
            BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        };

        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params build");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().expect("CA key generates");
        let ca_cert = ca_params.self_signed(&ca_key).expect("CA self-signs");
        let issuer = Issuer::new(ca_params, ca_key);

        let mut server_params =
            CertificateParams::new(vec!["127.0.0.1".to_owned(), "localhost".to_owned()])
                .expect("server params build");
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate().expect("server key generates");
        let server_cert = server_params
            .signed_by(&server_key, &issuer)
            .expect("CA signs server leaf");

        let (client_cert, client_key) = client_leaf(&issuer);
        Self {
            ca: ca_cert.pem(),
            server_cert: server_cert.pem(),
            server_key: server_key.serialize_pem(),
            client_cert,
            client_key,
        }
    }
}

/// A client leaf signed by `issuer`, as PEM strings.
fn client_leaf(issuer: &rcgen::Issuer<'_, rcgen::KeyPair>) -> (String, String) {
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair};

    let mut params =
        CertificateParams::new(vec!["tls-e2e-client".to_owned()]).expect("client params build");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let key = KeyPair::generate().expect("client key generates");
    let cert = params.signed_by(&key, issuer).expect("CA signs client");
    (cert.pem(), key.serialize_pem())
}

/// A client identity from a *different* CA than the server trusts.
fn foreign_client_identity() -> (String, String) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};

    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params build");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().expect("CA key generates");
    let ca_cert = ca_params.self_signed(&ca_key).expect("CA self-signs");
    let issuer = Issuer::new(ca_params, ca_key);
    let _ = ca_cert;
    client_leaf(&issuer)
}

/// What the test client trusts and (optionally) presents.
#[derive(Clone)]
struct TlsClient {
    ca_pem: Vec<u8>,
    identity: Option<(Vec<u8>, Vec<u8>)>,
}

impl TlsClient {
    fn trust(ca_pem: &str) -> Self {
        Self {
            ca_pem: ca_pem.as_bytes().to_vec(),
            identity: None,
        }
    }

    fn with_identity(&self, cert_pem: &str, key_pem: &str) -> Self {
        Self {
            ca_pem: self.ca_pem.clone(),
            identity: Some((cert_pem.as_bytes().to_vec(), key_pem.as_bytes().to_vec())),
        }
    }

    fn config(&self) -> Arc<rustls::ClientConfig> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};

        let certs = rustls_pemfile::certs(&mut &*self.ca_pem)
            .collect::<Result<Vec<_>, _>>()
            .expect("CA PEM parses");
        assert!(!certs.is_empty(), "CA PEM holds a certificate");
        let mut roots = rustls::RootCertStore::empty();
        for cert in certs {
            let owned = CertificateDer::from(cert.as_ref().to_vec());
            roots.add(owned).expect("CA enters the root store");
        }

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(rustls::ALL_VERSIONS)
            .expect("ring provides TLS versions")
            .with_root_certificates(roots);

        let mut config = if let Some((cert_pem, key_pem)) = &self.identity {
            let chain = rustls_pemfile::certs(&mut &cert_pem[..])
                .collect::<Result<Vec<CertificateDer<'_>>, _>>()
                .expect("client cert PEM parses")
                .into_iter()
                .map(|cert| CertificateDer::from(cert.as_ref().to_vec()))
                .collect::<Vec<_>>();
            assert!(!chain.is_empty(), "client PEM holds a certificate");
            let key: PrivateKeyDer<'_> = rustls_pemfile::private_key(&mut &key_pem[..])
                .expect("client key PEM parses")
                .expect("client PEM holds a key");
            builder
                .with_client_auth_cert(chain, key.clone_key())
                .expect("client identity loads")
        } else {
            builder.with_no_client_auth()
        };
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }

    /// TCP connect plus TLS handshake. Any error here is a handshake-level
    /// rejection: the server never saw HTTP.
    fn connect(
        &self,
        addr: SocketAddr,
    ) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, String> {
        let sock = TcpStream::connect(addr).map_err(|error| format!("tcp connect: {error}"))?;
        sock.set_read_timeout(Some(IO_TIMEOUT))
            .map_err(|error| format!("read timeout: {error}"))?;
        sock.set_write_timeout(Some(IO_TIMEOUT))
            .map_err(|error| format!("write timeout: {error}"))?;
        let name = rustls::pki_types::ServerName::from(addr.ip());
        let conn = rustls::ClientConnection::new(self.config(), name)
            .map_err(|error| format!("tls handshake: {error}"))?;
        Ok(rustls::StreamOwned::new(conn, sock))
    }
}

/// A parsed HTTPS response: status, headers, and any SSE `data:` payloads.
#[derive(Debug)]
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    events: Vec<Value>,
    body: Vec<u8>,
}

fn response_header(response: &HttpResponse, name: &str) -> Option<String> {
    response
        .headers
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.clone())
}

/// Send one raw request; with `want_id`, return once the SSE event carrying
/// that JSON-RPC id arrives (the stream may stay open afterwards, so the
/// socket is closed early). Without it, read a plain body by content length,
/// else until the server closes the connection.
fn exchange(
    client: &TlsClient,
    addr: SocketAddr,
    request: &[u8],
    want_id: Option<i64>,
) -> Result<HttpResponse, String> {
    let mut stream = client.connect(addr)?;
    stream
        .write_all(request)
        .map_err(|error| format!("write request: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("flush request: {error}"))?;

    let mut raw: Vec<u8> = Vec::new();
    let mut chunk = [0_u8; 8192];
    let deadline = Instant::now() + IO_TIMEOUT;
    let header_len = loop {
        if let Some(end) = find_subslice(&raw, b"\r\n\r\n") {
            break end + 4;
        }
        if Instant::now() > deadline {
            return Err("timed out reading response headers".to_owned());
        }
        read_into(&mut stream, &mut raw, &mut chunk)?;
    };

    let head = String::from_utf8_lossy(&raw[..header_len]).into_owned();
    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or_default();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| format!("bad status line: {status_line:?}"))?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| format!("bad header line: {line:?}"))?;
        headers.push((key.trim().to_lowercase(), value.trim().to_owned()));
    }

    let content_length = headers
        .iter()
        .find(|(key, _)| key == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok());
    let mut body = raw[header_len..].to_vec();
    let mut events = Vec::new();
    let mut scanned = 0_usize;

    loop {
        scan_lines(&body, &mut scanned, &mut events);
        if let Some(id) = want_id {
            if events
                .iter()
                .any(|event| event.get("id") == Some(&json!(id)))
            {
                break;
            }
        } else if let Some(length) = content_length
            && body.len() >= length
        {
            body.truncate(length);
            scan_lines(&body, &mut scanned, &mut events);
            break;
        }
        if Instant::now() > deadline {
            if want_id.is_some() {
                return Err(format!(
                    "timed out waiting for JSON-RPC response; events seen: {events:?}"
                ));
            }
            break;
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => body.extend_from_slice(&chunk[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                if want_id.is_some() {
                    return Err(format!(
                        "timed out waiting for JSON-RPC response; events seen: {events:?}"
                    ));
                }
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => {
                if want_id.is_none() {
                    break;
                }
                return Err(format!("read response: {error}"));
            }
        }
    }
    scan_lines(&body, &mut scanned, &mut events);

    Ok(HttpResponse {
        status,
        headers,
        events,
        body,
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn read_into(
    stream: &mut rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
    raw: &mut Vec<u8>,
    chunk: &mut [u8],
) -> Result<(), String> {
    match stream.read(chunk) {
        Ok(0) => Err(format!(
            "connection closed before headers arrived: {:?}",
            String::from_utf8_lossy(raw)
        )),
        Ok(read) => {
            raw.extend_from_slice(&chunk[..read]);
            Ok(())
        }
        Err(error) => Err(format!("read response: {error}")),
    }
}

/// Collect complete `data:` lines as JSON values; `scanned` tracks how far
/// the body was already processed so re-scans stay cheap.
fn scan_lines(body: &[u8], scanned: &mut usize, events: &mut Vec<Value>) {
    while let Some(relative) = find_subslice(&body[*scanned..], b"\n") {
        let end = *scanned + relative;
        let line = String::from_utf8_lossy(&body[*scanned..end]).into_owned();
        *scanned = end + 1;
        let trimmed = line.strip_suffix('\r').unwrap_or(&line);
        if let Some(payload) = trimmed.strip_prefix("data:") {
            let payload = payload.strip_prefix(' ').unwrap_or(payload);
            if payload.is_empty() {
                continue;
            }
            if let Ok(event) = serde_json::from_str::<Value>(payload) {
                events.push(event);
            }
        }
    }
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

    /// Poll `https://addr/healthz` until it answers `ok`. A dead child
    /// ends the poll with its stderr quoted; the caller decides whether a
    /// bind collision is worth a respawn.
    async fn wait_ready(&mut self, client: &TlsClient) -> Result<(), String> {
        let request = get_bytes(self.addr, "/healthz", &[]);
        let start = Instant::now();
        loop {
            let attempt = tokio::task::spawn_blocking({
                let client = client.clone();
                let request = request.clone();
                let addr = self.addr;
                move || exchange(&client, addr, &request, None)
            })
            .await
            .expect("client thread runs");
            if let Ok(response) = &attempt
                && response.status == 200
                && response.body == b"ok"
            {
                return Ok(());
            }
            if let Some(status) = self.try_exit() {
                return Err(format!(
                    "proxy exited during startup ({status:?}): {}",
                    self.stderr_text()
                ));
            }
            if start.elapsed() > STARTUP_TIMEOUT {
                return Err(format!(
                    "proxy never became ready: last attempt {attempt:?}; stderr: {}",
                    self.stderr_text()
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn try_exit(&mut self) -> Option<std::process::ExitStatus> {
        self.child
            .as_mut()
            .and_then(|child| child.try_wait().expect("exit status reads"))
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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("loopback binds")
        .local_addr()
        .expect("listener has an address")
        .port()
}

/// Spawn the real binary. With `ready` the harness waits for `https://healthz`
/// to answer; without it the caller owns startup (for tests where the child
/// is expected to die or to reject the handshake).
///
/// A discovered free port can be stolen before the child binds; a child that
/// dies with a bind error is respawned on a fresh port a few times. Any other
/// early exit fails fast with the child's stderr quoted.
async fn spawn_proxy(
    extra_args: &[String],
    extra_envs: &[(&str, &str)],
    ready: Option<&TlsClient>,
) -> Proxy {
    let Some(ready) = ready else {
        return spawn_once(extra_args, extra_envs);
    };
    let mut attempts = 0;
    loop {
        let mut proxy = spawn_once(extra_args, extra_envs);
        match proxy.wait_ready(ready).await {
            Ok(()) => return proxy,
            Err(_message) if proxy.stderr_text().contains("already in use") && attempts < 3 => {
                attempts += 1;
            }
            Err(message) => panic!("{message}"),
        }
    }
}

fn spawn_once(extra_args: &[String], extra_envs: &[(&str, &str)]) -> Proxy {
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
        .args(extra_args)
        .envs(extra_envs.iter().copied())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("proxy spawns");
    let pipe = child.stderr.take().expect("stderr is piped");

    let stderr = Arc::new(Mutex::new(Vec::new()));
    let drain = Arc::clone(&stderr);
    std::thread::spawn(move || {
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
    Proxy {
        addr: SocketAddr::from(([127, 0, 0, 1], port)),
        child: Some(child),
        stderr,
    }
}

fn get_bytes(addr: SocketAddr, path: &str, headers: &[(&str, &str)]) -> Vec<u8> {
    let mut head = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (key, value) in headers {
        head.push_str(key);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    head.into_bytes()
}

fn post_bytes(addr: SocketAddr, path: &str, body: &[u8], headers: &[(&str, &str)]) -> Vec<u8> {
    let mut head = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (key, value) in headers {
        head.push_str(key);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    let mut request = head.into_bytes();
    request.extend_from_slice(body);
    request
}

/// One blocking exchange on the blocking pool; join failures are test bugs.
async fn https(
    addr: SocketAddr,
    client: &TlsClient,
    request: Vec<u8>,
    want_id: Option<i64>,
) -> Result<HttpResponse, String> {
    tokio::task::spawn_blocking({
        let client = client.clone();
        move || exchange(&client, addr, &request, want_id)
    })
    .await
    .expect("client thread runs")
}

async fn get_healthz(proxy: &Proxy, client: &TlsClient) -> Result<HttpResponse, String> {
    https(
        proxy.addr,
        client,
        get_bytes(proxy.addr, "/healthz", &[]),
        None,
    )
    .await
}

/// POST one JSON-RPC message to `/mcp`, returning the full response.
async fn post_mcp(
    proxy: &Proxy,
    client: &TlsClient,
    body: &Value,
    session: Option<&Session>,
    api_key: Option<&str>,
    want_id: Option<i64>,
) -> Result<HttpResponse, String> {
    let bytes = serde_json::to_vec(body).expect("body serializes");
    let auth = api_key.map(|key| format!("Bearer {key}"));
    let mut headers: Vec<(&str, &str)> = Vec::new();
    if let Some(session) = session {
        headers.push(("Mcp-Session-Id", session.id.as_str()));
        headers.push(("MCP-Protocol-Version", session.version.as_str()));
    }
    if let Some(auth) = &auth {
        headers.push(("Authorization", auth.as_str()));
    }
    https(
        proxy.addr,
        client,
        post_bytes(proxy.addr, "/mcp", &bytes, &headers),
        want_id,
    )
    .await
}

/// An established MCP session: the id the server issued plus the protocol
/// version it negotiated.
#[derive(Debug, Clone)]
struct Session {
    id: String,
    version: String,
}

/// Full handshake: `initialize` (id 1), then `notifications/initialized`.
async fn handshake(proxy: &Proxy, client: &TlsClient, api_key: Option<&str>) -> Session {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": OFFERED_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "tls-e2e", "version": "0.0.0"},
        },
    });
    let response = post_mcp(proxy, client, &body, None, api_key, Some(1))
        .await
        .expect("initialize is answered");
    assert_eq!(response.status, 200, "initialize status: {response:?}");
    let event = response
        .events
        .iter()
        .find(|event| event.get("id") == Some(&json!(1)))
        .unwrap_or_else(|| panic!("no initialize event in {response:?}"));
    let result = result_of(event);
    let version = result
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("initialize result has no protocolVersion: {result}"))
        .to_owned();
    let id = response_header(&response, "mcp-session-id")
        .unwrap_or_else(|| panic!("initialize issues no session id: {response:?}"));
    let session = Session { id, version };

    let initialized = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    let response = post_mcp(proxy, client, &initialized, Some(&session), api_key, None)
        .await
        .expect("initialized is accepted");
    assert_eq!(response.status, 202, "initialized status: {response:?}");
    session
}

fn result_of(event: &Value) -> &Value {
    if let Some(error) = event.get("error") {
        panic!("server answered with a JSON-RPC error: {error}");
    }
    event
        .get("result")
        .unwrap_or_else(|| panic!("response has neither result nor error: {event}"))
}

/// One request/response round-trip inside `session`.
async fn rpc(
    proxy: &Proxy,
    client: &TlsClient,
    session: &Session,
    api_key: Option<&str>,
    id: i64,
    method: &str,
    params: Value,
) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
    let response = post_mcp(proxy, client, &body, Some(session), api_key, Some(id))
        .await
        .unwrap_or_else(|error| panic!("{method} is answered: {error}"));
    assert_eq!(response.status, 200, "{method} status: {response:?}");
    let event = response
        .events
        .iter()
        .find(|event| event.get("id") == Some(&json!(id)))
        .unwrap_or_else(|| panic!("no {method} event in {response:?}"));
    result_of(event).clone()
}

async fn list_tool_names(
    proxy: &Proxy,
    client: &TlsClient,
    session: &Session,
    api_key: Option<&str>,
) -> Vec<String> {
    let result = rpc(proxy, client, session, api_key, 2, "tools/list", json!({})).await;
    let mut names: Vec<String> = result
        .get("tools")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("tools/list has no tools array: {result}"))
        .iter()
        .map(|tool| {
            tool.get("name")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("tool has no name: {tool}"))
                .to_owned()
        })
        .collect();
    names.sort();
    names
}

fn text_of(result: &Value) -> &str {
    result
        .get("content")
        .and_then(Value::as_array)
        .and_then(|content| content.first())
        .and_then(|block| block.get("text"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("tool result has no text content: {result}"))
}

#[tokio::test]
async fn file_pem_serves_healthz_and_mcp_round_trip() {
    let pki = Pki::generate();
    let cert = TempFile::write("cert.pem", &pki.server_cert);
    let key = TempFile::write("key.pem", &pki.server_key);
    let client = TlsClient::trust(&pki.ca);
    let proxy = spawn_proxy(
        &[
            "--tls-cert".to_owned(),
            cert.utf8().to_owned(),
            "--tls-key".to_owned(),
            key.utf8().to_owned(),
        ],
        &[],
        Some(&client),
    )
    .await;

    let health = get_healthz(&proxy, &client)
        .await
        .expect("healthz answers over TLS");
    assert_eq!(health.status, 200);
    assert_eq!(health.body, b"ok");

    let session = handshake(&proxy, &client, None).await;
    assert_eq!(
        list_tool_names(&proxy, &client, &session, None).await,
        ["echo", "whoami"]
    );
    let echo = rpc(
        &proxy,
        &client,
        &session,
        None,
        3,
        "tools/call",
        json!({"name": "echo", "arguments": {"message": "hello"}}),
    )
    .await;
    assert_eq!(text_of(&echo), "hello");
}

#[tokio::test]
async fn inline_pem_serves_healthz_and_tools_list() {
    let pki = Pki::generate();
    let client = TlsClient::trust(&pki.ca);
    let proxy = spawn_proxy(
        &[],
        &[
            ("STDIO2HTTP_TLS_CERT_PEM", pki.server_cert.as_str()),
            ("STDIO2HTTP_TLS_KEY_PEM", pki.server_key.as_str()),
        ],
        Some(&client),
    )
    .await;

    let health = get_healthz(&proxy, &client)
        .await
        .expect("healthz answers over TLS");
    assert_eq!(health.status, 200);
    assert_eq!(health.body, b"ok");

    let session = handshake(&proxy, &client, None).await;
    assert_eq!(
        list_tool_names(&proxy, &client, &session, None).await,
        ["echo", "whoami"]
    );
}

#[tokio::test]
async fn tls_rejects_a_server_certificate_from_an_untrusted_ca() {
    let pki = Pki::generate();
    let other = Pki::generate();
    let proxy = spawn_proxy(
        &[],
        &[
            ("STDIO2HTTP_TLS_CERT_PEM", pki.server_cert.as_str()),
            ("STDIO2HTTP_TLS_KEY_PEM", pki.server_key.as_str()),
        ],
        None,
    )
    .await;
    // No readiness poll here: it would burn the whole startup timeout, since
    // every handshake fails by design. One attempt is enough — the positive
    // tests prove the same binary comes up with these certs.
    let untrusting = TlsClient::trust(&other.ca);
    let outcome = get_healthz(&proxy, &untrusting).await;
    assert!(
        outcome.is_err(),
        "a server certificate outside the trust store must fail verification"
    );

    // Positive control on the same server: the right CA verifies fine.
    let trusting = TlsClient::trust(&pki.ca);
    let start = Instant::now();
    let health = loop {
        match get_healthz(&proxy, &trusting).await {
            Ok(health) => break health,
            Err(_) if start.elapsed() < STARTUP_TIMEOUT => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("healthz never answered: {error}"),
        }
    };
    assert_eq!(health.status, 200);
}

#[tokio::test]
async fn bearer_mode_rejects_missing_and_wrong_key() {
    let pki = Pki::generate();
    let client = TlsClient::trust(&pki.ca);
    let proxy = spawn_proxy(
        &[
            "--auth-mode".to_owned(),
            "bearer".to_owned(),
            "--api-key".to_owned(),
            KEY_ALICE.to_owned(),
        ],
        &[
            ("STDIO2HTTP_TLS_CERT_PEM", pki.server_cert.as_str()),
            ("STDIO2HTTP_TLS_KEY_PEM", pki.server_key.as_str()),
        ],
        Some(&client),
    )
    .await;

    // Health stays open: the 401 below is the auth layer, not a dead server.
    let health = get_healthz(&proxy, &client).await.expect("healthz answers");
    assert_eq!(health.status, 200);

    for key in [None, Some(KEY_BOB)] {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": OFFERED_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "tls-e2e", "version": "0.0.0"},
            },
        });
        let response = post_mcp(&proxy, &client, &body, None, key, None)
            .await
            .expect("the proxy answers");
        assert_eq!(response.status, 401, "key {key:?} must be refused");
        assert_eq!(
            response_header(&response, "www-authenticate").as_deref(),
            Some("Bearer realm=\"mcp\""),
            "a challenge header is required"
        );
        let text = String::from_utf8_lossy(&response.body).into_owned();
        for secret in [KEY_ALICE, KEY_BOB] {
            assert!(!text.contains(secret), "401 body leaked a key: {text}");
        }
    }
}

#[tokio::test]
async fn bearer_mode_accepts_the_configured_key() {
    let pki = Pki::generate();
    let client = TlsClient::trust(&pki.ca);
    let proxy = spawn_proxy(
        &[
            "--auth-mode".to_owned(),
            "bearer".to_owned(),
            "--api-key".to_owned(),
            KEY_ALICE.to_owned(),
        ],
        &[
            ("STDIO2HTTP_TLS_CERT_PEM", pki.server_cert.as_str()),
            ("STDIO2HTTP_TLS_KEY_PEM", pki.server_key.as_str()),
        ],
        Some(&client),
    )
    .await;

    let session = handshake(&proxy, &client, Some(KEY_ALICE)).await;
    assert_eq!(
        list_tool_names(&proxy, &client, &session, Some(KEY_ALICE)).await,
        ["echo", "whoami"]
    );
    // Bearer mode authenticates but forwards no identity.
    let whoami = rpc(
        &proxy,
        &client,
        &session,
        Some(KEY_ALICE),
        3,
        "tools/call",
        json!({"name": "whoami"}),
    )
    .await;
    assert_eq!(text_of(&whoami), "<none>");
}

#[tokio::test]
async fn identity_forward_distinguishes_callers() {
    let pki = Pki::generate();
    let client = TlsClient::trust(&pki.ca);
    let proxy = spawn_proxy(
        &[
            "--auth-mode".to_owned(),
            "identity-forward".to_owned(),
            "--api-key".to_owned(),
            format!("{KEY_ALICE}=alice"),
            "--api-key".to_owned(),
            format!("{KEY_BOB}=bob"),
        ],
        &[
            ("STDIO2HTTP_TLS_CERT_PEM", pki.server_cert.as_str()),
            ("STDIO2HTTP_TLS_KEY_PEM", pki.server_key.as_str()),
        ],
        Some(&client),
    )
    .await;

    let alice = handshake(&proxy, &client, Some(KEY_ALICE)).await;
    let bob = handshake(&proxy, &client, Some(KEY_BOB)).await;
    let who_alice = rpc(
        &proxy,
        &client,
        &alice,
        Some(KEY_ALICE),
        4,
        "tools/call",
        json!({"name": "whoami"}),
    )
    .await;
    let who_bob = rpc(
        &proxy,
        &client,
        &bob,
        Some(KEY_BOB),
        4,
        "tools/call",
        json!({"name": "whoami"}),
    )
    .await;
    assert_eq!(text_of(&who_alice), "alice");
    assert_eq!(text_of(&who_bob), "bob");
}

#[tokio::test]
async fn plain_http_on_a_tls_port_fails() {
    let pki = Pki::generate();
    let client = TlsClient::trust(&pki.ca);
    let proxy = spawn_proxy(
        &[],
        &[
            ("STDIO2HTTP_TLS_CERT_PEM", pki.server_cert.as_str()),
            ("STDIO2HTTP_TLS_KEY_PEM", pki.server_key.as_str()),
        ],
        Some(&client),
    )
    .await;

    // The server is up (TLS healthz answers), so whatever the plaintext
    // probe gets back is the TLS layer refusing it — not a dead server.
    let health = get_healthz(&proxy, &client)
        .await
        .expect("healthz answers over TLS");
    assert_eq!(health.status, 200);

    let addr = proxy.addr;
    let outcome = tokio::task::spawn_blocking(move || {
        let mut sock = TcpStream::connect(addr).map_err(|error| format!("tcp: {error}"))?;
        sock.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| format!("timeout: {error}"))?;
        sock.write_all(b"GET /healthz HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n")
            .map_err(|error| format!("write: {error}"))?;
        let mut bytes = Vec::new();
        match sock.read_to_end(&mut bytes) {
            Ok(_) => Ok(bytes),
            Err(error) => Err(format!("read: {error}")),
        }
    })
    .await
    .expect("probe thread runs");

    match outcome {
        Err(_) => {}
        Ok(bytes) => {
            assert!(
                !bytes.starts_with(b"HTTP/"),
                "plaintext HTTP was answered: {bytes:?}"
            );
            assert!(
                bytes.first() == Some(&0x15) || bytes.is_empty(),
                "expected a TLS alert or a closed connection, got {bytes:?}"
            );
        }
    }
}

fn mtls_args(cert: &TempFile, key: &TempFile, ca: &TempFile) -> Vec<String> {
    vec![
        "--tls-cert".to_owned(),
        cert.utf8().to_owned(),
        "--tls-key".to_owned(),
        key.utf8().to_owned(),
        "--tls-client-ca".to_owned(),
        ca.utf8().to_owned(),
    ]
}

#[tokio::test]
async fn mtls_rejects_connections_without_a_client_certificate() {
    let pki = Pki::generate();
    let cert = TempFile::write("cert.pem", &pki.server_cert);
    let key = TempFile::write("key.pem", &pki.server_key);
    let ca = TempFile::write("ca.pem", &pki.ca);
    let bare = TlsClient::trust(&pki.ca);
    let identified = bare.with_identity(&pki.client_cert, &pki.client_key);
    let proxy = spawn_proxy(&mtls_args(&cert, &key, &ca), &[], Some(&identified)).await;

    // Without a client certificate the handshake dies: every path — the open
    // `/healthz` included — is behind rustls verification.
    let health = get_healthz(&proxy, &bare).await;
    assert!(health.is_err(), "healthz without a cert must fail");
    let init = post_mcp(
        &proxy,
        &bare,
        &json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
        None,
        None,
        Some(1),
    )
    .await;
    assert!(init.is_err(), "an MCP call without a cert must fail");

    // Positive control: the same server answers with a client certificate.
    let health = get_healthz(&proxy, &identified)
        .await
        .expect("healthz answers with a client certificate");
    assert_eq!(health.status, 200);
}

#[tokio::test]
async fn mtls_accepts_a_certificate_from_the_configured_ca() {
    let pki = Pki::generate();
    let cert = TempFile::write("cert.pem", &pki.server_cert);
    let key = TempFile::write("key.pem", &pki.server_key);
    let ca = TempFile::write("ca.pem", &pki.ca);
    let client = TlsClient::trust(&pki.ca).with_identity(&pki.client_cert, &pki.client_key);
    let proxy = spawn_proxy(&mtls_args(&cert, &key, &ca), &[], Some(&client)).await;

    let health = get_healthz(&proxy, &client).await.expect("healthz answers");
    assert_eq!(health.status, 200);

    let session = handshake(&proxy, &client, None).await;
    assert_eq!(
        list_tool_names(&proxy, &client, &session, None).await,
        ["echo", "whoami"]
    );
}

#[tokio::test]
async fn mtls_rejects_a_certificate_from_another_ca() {
    let pki = Pki::generate();
    let cert = TempFile::write("cert.pem", &pki.server_cert);
    let key = TempFile::write("key.pem", &pki.server_key);
    let ca = TempFile::write("ca.pem", &pki.ca);
    let legit = TlsClient::trust(&pki.ca).with_identity(&pki.client_cert, &pki.client_key);
    let proxy = spawn_proxy(&mtls_args(&cert, &key, &ca), &[], Some(&legit)).await;

    let (foreign_cert, foreign_key) = foreign_client_identity();
    let foreign = TlsClient::trust(&pki.ca).with_identity(&foreign_cert, &foreign_key);
    let health = get_healthz(&proxy, &foreign).await;
    assert!(
        health.is_err(),
        "a foreign client certificate must fail the handshake"
    );
}

#[tokio::test]
async fn mismatched_cert_and_key_fails_startup() {
    let first = Pki::generate();
    let second = Pki::generate();
    let cert = TempFile::write("cert.pem", &first.server_cert);
    let key = TempFile::write("key.pem", &second.server_key);
    let mut proxy = spawn_proxy(
        &[
            "--tls-cert".to_owned(),
            cert.utf8().to_owned(),
            "--tls-key".to_owned(),
            key.utf8().to_owned(),
        ],
        &[],
        None,
    )
    .await;

    let start = Instant::now();
    let status = loop {
        if let Some(status) = proxy.try_exit() {
            break status;
        }
        assert!(
            start.elapsed() < STARTUP_TIMEOUT,
            "proxy with a mismatched pair should exit, stderr: {}",
            proxy.stderr_text()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(!status.success(), "a mismatched pair must fail startup");
    assert!(
        proxy.stderr_text().contains("TLS setup failed"),
        "the failure names TLS setup: {}",
        proxy.stderr_text()
    );
}
