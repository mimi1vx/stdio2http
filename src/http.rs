//! Axum wiring: `/healthz`, the `/mcp` Streamable HTTP mount, graceful shutdown.

use std::sync::Arc;

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
/// # Errors
///
/// Returns an error if the listener cannot be bound or the server fails.
pub async fn serve(cfg: &Config, upstream: &Arc<Upstream>) -> Result<()> {
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
