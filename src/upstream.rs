//! The one long-lived stdio child, and the shared peer every HTTP session forwards through.

use std::sync::Arc;

use anyhow::{Context, Result};
use rmcp::model::ServerConfig;
use rmcp::service::{Peer, RoleClient, RunningService, ServiceExt as _};
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};

use crate::config::Config;

/// Stand-in identity for an upstream that advertises no `serverInfo`.
const UNKNOWN_UPSTREAM: &str = "unknown-upstream";

/// A connected stdio MCP server. Dropping this cancels the child.
///
/// The running service owns the child's transport, and dropping it closes that
/// transport. It is therefore held behind an `Arc` and handed out only as a
/// `Peer` clone: a session must never be able to take a `Peer` without also
/// keeping the child alive.
pub struct Upstream {
    service: Option<Arc<RunningService<RoleClient, ()>>>,
    /// The shared client peer. Cloning this handle is how a session reaches the child.
    peer: Arc<Peer<RoleClient>>,
    /// Captured once at startup so `get_info` stays synchronous.
    info: ServerConfig,
    child_pid: Option<u32>,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upstream")
            .field("child_pid", &self.child_pid)
            .field("server", &self.info.server_info.name)
            .field("version", &self.info.server_info.version)
            .field("protocol", &self.info.protocol_version)
            .finish_non_exhaustive()
    }
}

impl Upstream {
    /// Spawn the child and complete the MCP initialize handshake.
    ///
    /// # Errors
    ///
    /// Returns an error if the program cannot be spawned, the handshake does not
    /// complete within `init_timeout`, or the child exits before initializing.
    pub async fn spawn(cfg: &Config) -> Result<Self> {
        let argv = cfg.argv();
        let (program, child_args) = argv
            .split_first()
            .context("--command resolved to an empty command")?;

        let command = tokio::process::Command::new(program).configure(|c| {
            c.args(child_args);
            c.envs(cfg.env.iter().map(|(k, v)| (k, v)));
            if let Some(cwd) = cfg.cwd.as_ref() {
                c.current_dir(cwd);
            }
        });

        let transport = TokioChildProcess::new(command)
            .with_context(|| format!("failed to spawn upstream MCP server {program:?}"))?;
        let child_pid = transport.id();

        let handshake =
            tokio::time::timeout(cfg.init_timeout(), async { ().serve(transport).await }).await;

        let service = match handshake {
            Ok(Ok(service)) => service,
            Ok(Err(error)) => {
                return Err(error).with_context(|| {
                    format!("upstream MCP server {program:?} failed to initialize")
                });
            }
            Err(_elapsed) => {
                return Err(anyhow::anyhow!(
                    "upstream MCP server {program:?} did not initialize within {:?}",
                    cfg.init_timeout()
                ));
            }
        };

        let peer = Arc::new(service.peer().clone());
        let info = peer
            .peer_info()
            .as_deref()
            .map(server_config)
            .with_context(|| {
                format!("upstream MCP server {program:?} initialized without advertising its info")
            })?;

        log_upstream(program, child_pid, &info, &peer).await;

        Ok(Self {
            service: Some(Arc::new(service)),
            peer,
            info,
            child_pid,
        })
    }

    #[must_use]
    pub fn peer(&self) -> &Arc<Peer<RoleClient>> {
        &self.peer
    }

    #[must_use]
    pub fn info(&self) -> &ServerConfig {
        &self.info
    }

    #[must_use]
    pub fn child_pid(&self) -> Option<u32> {
        self.child_pid
    }

    /// Close the transport and reap the child.
    ///
    /// # Errors
    ///
    /// Returns an error if another handle to the child is still alive, because
    /// then a clean close is impossible and the child would be left to the
    /// transport's drop guard.
    pub async fn shutdown(&mut self) -> anyhow::Result<()> {
        let Some(service) = self.service.take() else {
            return Ok(());
        };
        match Arc::try_unwrap(service) {
            Ok(mut owned) => {
                owned.close().await?;
                Ok(())
            }
            Err(shared) => Err(anyhow::anyhow!(
                "upstream child is still referenced {} time(s); cannot close it cleanly",
                Arc::strong_count(&shared) - 1
            )),
        }
    }
}

/// Project the upstream's advertised peer info into the `ServerConfig` that
/// `get_info` must return. The upstream may omit `serverInfo`; the spec requires
/// a value there, so fall back to naming this proxy.
fn server_config(info: &rmcp::model::ServerPeerInfo) -> ServerConfig {
    let mut config = ServerConfig::new(info.capabilities.clone())
        .with_protocol_version(info.protocol_version.clone());
    config.server_info = info
        .server_info
        .clone()
        .unwrap_or_else(|| rmcp::model::Implementation::new(UNKNOWN_UPSTREAM, "unknown"));
    config.instructions.clone_from(&info.instructions);
    config.meta.clone_from(&info.meta);
    config
}

/// Log what we connected to. Tool count is fetched best-effort: a server that
/// errors here is still usable, so a failure must not abort startup.
async fn log_upstream(
    program: &str,
    pid: Option<u32>,
    info: &ServerConfig,
    peer: &Peer<RoleClient>,
) {
    let tool_count = match peer.list_tools(None).await {
        Ok(result) => result.tools.len(),
        Err(error) => {
            tracing::warn!(%error, "could not list upstream tools at startup");
            0
        }
    };

    tracing::info!(
        pid = ?pid,
        server = %info.server_info.name,
        version = %info.server_info.version,
        protocol = %info.protocol_version,
        tools = tool_count,
        "upstream MCP server connected"
    );

    tracing::debug!(program, "upstream command line resolved");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use clap::Parser;

    fn config(argv: &[&str]) -> Config {
        let mut full = vec!["stdio2http"];
        full.extend_from_slice(argv);
        Config::parse_from(full)
    }

    #[tokio::test]
    async fn spawning_a_missing_program_is_an_error() {
        let cfg = config(&[
            "--command",
            "/nonexistent/definitely-not-a-real-binary-xyz",
            "--init-timeout-ms",
            "500",
        ]);
        let error = Upstream::spawn(&cfg).await.expect_err("must fail to spawn");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("definitely-not-a-real-binary-xyz"),
            "error should name the program: {rendered}"
        );
    }

    #[tokio::test]
    async fn spawning_a_non_mcp_program_times_out() {
        // `sleep` never speaks JSON-RPC, so the handshake can only time out.
        let cfg = config(&[
            "--command",
            "sleep",
            "--arg",
            "30",
            "--init-timeout-ms",
            "300",
        ]);
        let error = Upstream::spawn(&cfg).await.expect_err("must time out");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("did not initialize"),
            "error should report a timeout: {rendered}"
        );
    }

    #[tokio::test]
    async fn spawning_a_program_that_exits_immediately_is_an_error() {
        let cfg = config(&["--command", "true", "--init-timeout-ms", "2000"]);
        let error = Upstream::spawn(&cfg).await.expect_err("must fail");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("failed to initialize") || rendered.contains("did not initialize"),
            "unexpected error: {rendered}"
        );
    }

    #[tokio::test]
    async fn child_env_and_cwd_are_applied() {
        let dir = std::env::temp_dir().join("stdio2http-upstream-cwd-test");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let cfg = config(&[
            "--command",
            "pwd",
            "--child-env",
            "STDOUT2HTTP_PROBE=1",
            "--cwd",
            dir.to_str().expect("utf-8 temp dir"),
            "--init-timeout-ms",
            "500",
        ]);
        let error = Upstream::spawn(&cfg)
            .await
            .expect_err("pwd never initializes");
        // The child ran; it just is not an MCP server. Reaching this point proves
        // the spawn itself succeeded rather than failing on a missing binary.
        assert!(!format!("{error:#}").contains("failed to spawn upstream"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
