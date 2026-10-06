//! Axum wiring: `/healthz`, the `/mcp` Streamable HTTP mount, graceful shutdown.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::Router;
use axum::routing::{MethodFilter, get};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use tower::Service;

use crate::auth::AuthState;
use crate::config::Config;
use crate::proxy::ProxyHandler;
use crate::upstream::Upstream;

/// What `/healthz` answers with.
pub const HEALTH_BODY: &str = "ok";

/// Every method the Streamable HTTP transport answers.
const ALL_METHODS: MethodFilter = MethodFilter::GET
    .or(MethodFilter::POST)
    .or(MethodFilter::DELETE)
    .or(MethodFilter::OPTIONS)
    .or(MethodFilter::HEAD)
    .or(MethodFilter::PUT)
    .or(MethodFilter::PATCH)
    .or(MethodFilter::TRACE);

/// Build the rmcp transport configuration from our own config.
fn server_config(cfg: &Config) -> StreamableHttpServerConfig {
    let mut config = StreamableHttpServerConfig::default();

    if cfg.disable_allowed_hosts {
        tracing::warn!(
            "Host header validation is off; only do this behind a proxy that already validates it"
        );
        config = config.disable_allowed_hosts();
    } else if !cfg.allowed_hosts.is_empty() {
        config = config.with_allowed_hosts(cfg.allowed_hosts.clone());
    }

    if !cfg.allowed_origins.is_empty() {
        config = config.with_allowed_origins(cfg.allowed_origins.clone());
    }

    config
}

/// Mount a Streamable HTTP service behind the auth layer, leaving `/healthz` open.
///
/// Generic over the service so tests can substitute a stub for the real child.
pub fn router_with<S>(cfg: &Config, mcp: S) -> Router
where
    S: Service<http::Request<axum::body::Body>, Error = std::convert::Infallible>
        + Clone
        + Send
        + Sync
        + 'static,
    S::Response: axum::response::IntoResponse + 'static,
    S::Future: Send + 'static,
{
    let guarded = axum::routing::MethodRouter::new()
        .on_service(ALL_METHODS, mcp)
        .layer(axum::middleware::from_fn_with_state(
            AuthState::new(cfg.auth_mode, &cfg.api_keys),
            crate::auth::require,
        ));

    Router::new()
        .route(&cfg.mcp_path, guarded)
        .route("/healthz", get(|| async { HEALTH_BODY }))
}

/// Build the router backed by the shared upstream child.
pub fn router(cfg: &Config, upstream: &Arc<Upstream>) -> Router {
    let peer = Arc::clone(upstream.peer());
    let info = Arc::new(upstream.info().clone());
    let service = StreamableHttpService::new(
        move || Ok(ProxyHandler::new(Arc::clone(&peer), Arc::clone(&info))),
        Arc::new(LocalSessionManager::default()),
        server_config(cfg),
    );
    router_with(cfg, service)
}

/// Bind the listener. Port `0` selects an ephemeral port.
///
/// # Errors
///
/// Returns an error if the address cannot be bound.
pub async fn bind(cfg: &Config) -> Result<tokio::net::TcpListener> {
    let addr = cfg.socket_addr();
    tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))
}

/// Resolve once the process is asked to stop.
async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = interrupt => tracing::info!("received SIGINT, shutting down"),
        () = terminate => tracing::info!("received SIGTERM, shutting down"),
    }
}

/// Serve until a shutdown signal arrives, then return so the caller can reap the child.
///
/// A configured certificate (or ACME selection) switches the listener to
/// HTTPS-only TLS on the same `host:port`; plain HTTP on that port then fails
/// at the handshake instead of serving. mTLS, when configured, is enforced by
/// rustls for every connection — `/healthz` included — while `/mcp` auth
/// modes apply unchanged on top.
///
/// # Errors
///
/// Returns an error if the address cannot be bound, the TLS identity cannot
/// be loaded, or the server fails.
pub async fn serve(cfg: &Config, upstream: &Arc<Upstream>) -> Result<()> {
    if cfg.tls_enabled() {
        serve_tls(cfg, upstream).await
    } else {
        serve_plain(cfg, upstream).await
    }
}

async fn serve_plain(cfg: &Config, upstream: &Arc<Upstream>) -> Result<()> {
    let listener = bind(cfg).await?;
    let local = listener
        .local_addr()
        .context("listener has no local address")?;
    tracing::info!(%local, path = %cfg.mcp_path, "stdio2http listening");

    axum::serve(listener, router(cfg, upstream))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server failed")
}

async fn serve_tls(cfg: &Config, upstream: &Arc<Upstream>) -> Result<()> {
    if cfg.has_manual_cert() {
        serve_manual_tls(cfg, upstream).await
    } else if cfg.uses_acme() {
        serve_acme(cfg, upstream).await
    } else {
        // mTLS-alone: `Config::validate` rejects this; fail closed here too so
        // a caller that skipped validation still gets the same message.
        anyhow::bail!(
            "--tls-client-ca* requires a server certificate (--tls-cert/--tls-key) or ACME (--acme-domain)"
        )
    }
}

async fn serve_manual_tls(cfg: &Config, upstream: &Arc<Upstream>) -> Result<()> {
    let addr = cfg.socket_addr();
    let material = crate::tls::load(cfg).context("TLS setup failed")?;
    let info = &material.info;
    tracing::info!(
        %addr,
        path = %cfg.mcp_path,
        subject = %info.subject,
        expiry = %info.expiry,
        fingerprint = %info.fingerprint,
        mtls = info.mtls,
        acme = cfg.uses_acme(),
        "stdio2http listening (https)"
    );

    let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(material.server_config));
    let handle = axum_server::Handle::new();
    let shutdown = handle.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        shutdown.graceful_shutdown(None);
    });

    axum_server::tls_rustls::bind_rustls(addr, tls)
        .handle(handle)
        .serve(router(cfg, upstream).into_make_service())
        .await
        .context("HTTPS server failed")
}

/// Serve HTTPS with an ACME-issued certificate, renewing in the background.
///
/// Bind order matters: the HTTP-01 challenge listener goes up first and stays
/// for the process lifetime (renewals need it), then `ensure_cert_with`
/// issues into the same shared token map the listener serves.
async fn serve_acme(cfg: &Config, upstream: &Arc<Upstream>) -> Result<()> {
    use crate::acme::{AcmeConfig, AcmeManager, ChallengeTokens, serve_challenges};

    let acme_cfg = AcmeConfig::from_config(cfg).map_err(anyhow::Error::msg)?;
    let manager = AcmeManager::load_or_create(acme_cfg.clone()).await?;

    // The CA dials this port from outside, so it binds all interfaces rather
    // than `cfg.host`.
    let challenge_addr = std::net::SocketAddr::from(([0, 0, 0, 0], acme_cfg.http_port));
    let challenge_listener = tokio::net::TcpListener::bind(challenge_addr)
        .await
        .with_context(|| format!("failed to bind ACME challenge listener on {challenge_addr}"))?;
    let tokens = ChallengeTokens::new();
    {
        let tokens = tokens.clone();
        tokio::spawn(async move {
            if let Err(error) =
                serve_challenges(challenge_listener, tokens, shutdown_signal()).await
            {
                tracing::error!(error = format!("{error:#}"), "ACME challenge server failed");
            }
        });
    }

    // Without the `acme` feature this bails with the rebuild hint; with it,
    // this issues (or skips when the cache is fresh) into the shared map.
    manager.ensure_cert_with(&tokens).await?;

    let snapshot = manager
        .cert_handle()
        .current()
        .context("ACME issuance produced no certificate")?;
    // mTLS-with-ACME: the client CA still comes from `Config`.
    let ca_pem = crate::tls::client_ca_pem(cfg).context("TLS setup failed")?;
    let material = crate::tls::build(
        snapshot.cert_pem.as_bytes(),
        snapshot.key_pem.as_bytes(),
        ca_pem.as_deref(),
    )
    .context("TLS setup failed")?;
    let info = &material.info;
    let addr = cfg.socket_addr();
    tracing::info!(
        %addr,
        path = %cfg.mcp_path,
        subject = %info.subject,
        expiry = %info.expiry,
        fingerprint = %info.fingerprint,
        mtls = info.mtls,
        acme = true,
        "stdio2http listening (https)"
    );

    let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(material.server_config));
    let handle = axum_server::Handle::new();
    let shutdown = handle.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        shutdown.graceful_shutdown(None);
    });

    // Renewals publish into the same shared map the challenge listener serves.
    // Dropping the handle detaches the task; it runs for the process lifetime.
    #[cfg(feature = "acme")]
    let _renewal_task = AcmeManager::spawn_renewal_task(&manager, tokens.clone());

    // Rotation watcher: renewals install into the shared handle; poll the
    // generation counter and reload the acceptor without dropping connections.
    {
        let cert = manager.cert_handle();
        let tls = tls.clone();
        let seen = snapshot.generation;
        tokio::spawn(async move {
            rotation_watcher(cert, tls, ca_pem, seen).await;
        });
    }

    axum_server::tls_rustls::bind_rustls(addr, tls)
        .handle(handle)
        .serve(router(cfg, upstream).into_make_service())
        .await
        .context("HTTPS server failed")
}

/// Poll the shared cert handle; on generation change, rebuild via
/// `tls::build` and swap with `reload_from_config`.
///
/// A full rebuild (rather than `reload_from_pem`) preserves the mTLS verifier:
/// axum-server's PEM reload helper installs `with_no_client_auth`, which would
/// silently drop client-certificate enforcement after the first rotation.
/// Never logs key material, only the new fingerprint and expiry.
async fn rotation_watcher(
    cert: crate::acme::SharedCert,
    tls: axum_server::tls_rustls::RustlsConfig,
    ca_pem: Option<Vec<u8>>,
    mut seen: u64,
) {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let Some(snapshot) = cert.current() else {
            continue;
        };
        if snapshot.generation == seen {
            continue;
        }
        seen = snapshot.generation;
        match crate::tls::build(
            snapshot.cert_pem.as_bytes(),
            snapshot.key_pem.as_bytes(),
            ca_pem.as_deref(),
        ) {
            Ok(material) => {
                tls.reload_from_config(Arc::new(material.server_config));
                tracing::info!(
                    generation = snapshot.generation,
                    expiry = ?snapshot.expiry,
                    fingerprint = %material.info.fingerprint,
                    "ACME certificate rotated"
                );
            }
            Err(error) => tracing::warn!(
                error = format!("{error:#}"),
                "ACME rotated chain failed to load; keeping the previous certificate"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use http::StatusCode;
    use http_body_util::BodyExt as _;
    use std::convert::Infallible;
    use tower::ServiceExt as _;

    fn config(argv: &[&str]) -> Config {
        let mut full = vec!["stdio2http"];
        full.extend_from_slice(argv);
        Config::parse_from(full)
    }

    /// A stand-in for the rmcp service so router tests need no child process.
    ///
    /// Hand-written rather than `tower::service_fn` because `router_with`
    /// requires a `Send` future, which `service_fn` does not promise for an
    /// unboxed async block.
    #[derive(Clone, Copy)]
    struct StubService;

    impl Service<http::Request<axum::body::Body>> for StubService {
        type Response = axum::response::Response;
        type Error = Infallible;
        type Future = std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
        >;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: http::Request<axum::body::Body>) -> Self::Future {
            Box::pin(async {
                Ok(axum::response::Response::new(axum::body::Body::from(
                    "mcp-ok",
                )))
            })
        }
    }

    fn stub_service() -> StubService {
        StubService
    }

    /// Drive the router without binding a socket.
    async fn call(app: Router, uri: &str) -> (StatusCode, Vec<u8>) {
        let response = app
            .oneshot(
                http::Request::builder()
                    .uri(uri)
                    .body(axum::body::Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("router always responds");
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body collects")
            .to_bytes();
        (status, body.to_vec())
    }

    #[test]
    fn default_config_keeps_loopback_only_host_validation() {
        let server = server_config(&config(&["--command", "s"]));
        assert_eq!(server.allowed_hosts, ["localhost", "127.0.0.1", "::1"]);
    }

    #[test]
    fn allowed_hosts_replace_the_default_list() {
        let cfg = config(&[
            "--command",
            "s",
            "--allowed-host",
            "proxy.internal",
            "--allowed-host",
            "proxy.internal:8080",
        ]);
        assert_eq!(
            server_config(&cfg).allowed_hosts,
            ["proxy.internal", "proxy.internal:8080"]
        );
    }

    #[test]
    fn disabling_allowed_hosts_empties_the_list() {
        let cfg = config(&["--command", "s", "--disable-allowed-hosts"]);
        assert_eq!(server_config(&cfg).allowed_hosts, Vec::<String>::new());
    }

    #[test]
    fn allowed_origins_are_forwarded() {
        let cfg = config(&[
            "--command",
            "s",
            "--allowed-origin",
            "https://app.example.com",
        ]);
        assert_eq!(
            server_config(&cfg).allowed_origins,
            ["https://app.example.com"]
        );
    }

    #[tokio::test]
    async fn health_endpoint_is_not_behind_auth() {
        let cfg = config(&["--command", "s", "--auth-mode", "bearer", "--api-key", "k"]);

        let (status, body) = call(router_with(&cfg, stub_service()), "/healthz").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, HEALTH_BODY.as_bytes());
    }

    #[tokio::test]
    async fn mcp_route_is_mounted_at_the_configured_path() {
        let cfg = config(&["--command", "s", "--mcp-path", "/rpc"]);

        let (status, body) = call(router_with(&cfg, stub_service()), "/rpc").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"mcp-ok");
    }

    #[tokio::test]
    async fn unknown_paths_are_not_routed_to_the_child() {
        let cfg = config(&["--command", "s"]);

        let (status, _) = call(router_with(&cfg, stub_service()), "/nope").await;

        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
