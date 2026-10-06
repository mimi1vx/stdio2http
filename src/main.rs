//! stdio2http: re-expose one stdio MCP server over MCP Streamable HTTP.

use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use stdio2http::config::Config;
use stdio2http::http;
use stdio2http::upstream::Upstream;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Render the whole context chain: operators need the program name and
            // the underlying I/O failure, not just the outermost message.
            tracing::error!(error = format!("{error:#}"), "stdio2http failed");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let cfg = Config::parse();
    init_tracing(cfg.log_level);

    cfg.validate().map_err(anyhow::Error::msg)?;

    let upstream = Arc::new(Upstream::spawn(&cfg).await?);
    let served = http::serve(&cfg, &upstream).await;

    tracing::info!("shutting down upstream MCP server");
    match Arc::try_unwrap(upstream) {
        Ok(mut owned) => {
            if let Err(error) = owned.shutdown().await {
                tracing::warn!(%error, "upstream child was not closed cleanly");
            }
        }
        Err(shared) => tracing::warn!(
            pid = ?shared.child_pid(),
            "upstream still referenced after shutdown; dropping it without a clean close"
        ),
    }

    served
}

fn init_tracing(level: stdio2http::config::LogLevel) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level.as_filter()));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}
