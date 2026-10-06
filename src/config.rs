//! Configuration surface: CLI flags plus environment variables, no config file.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};

/// Access control applied to `/mcp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AuthMode {
    /// No authentication.
    None,
    /// Require a matching API key; callers are anonymous to the upstream.
    Bearer,
    /// Require a matching API key and forward the caller's subject upstream.
    IdentityForward,
}

impl AuthMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Bearer => "bearer",
            Self::IdentityForward => "identity-forward",
        }
    }
}

/// Log verbosity, validated against the levels `tracing` understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    #[must_use]
    pub fn as_filter(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

/// Split `KEY=VALUE` into its parts, keeping any `=` in the value.
fn parse_key_value(raw: &str) -> Result<(String, String), String> {
    match raw.split_once('=') {
        Some((key, value)) if !key.is_empty() => Ok((key.to_string(), value.to_string())),
        _ => Err(format!("expected KEY=VALUE, got {raw:?}")),
    }
}

#[derive(Debug, Clone, Parser)]
#[command(
    name = "stdio2http",
    version,
    about = "MCP stdio -> Streamable HTTP proxy",
    disable_help_subcommand = true
)]
pub struct Config {
    /// Program of the stdio MCP server to spawn.
    #[arg(long = "command", env = "STDIO2HTTP_COMMAND", value_name = "PROGRAM")]
    pub command_program: String,

    /// Argument for the stdio MCP server; repeat once per argument. Values may
    /// start with `-`, so upstream flags like `--stdio` pass through intact.
    #[arg(
        long = "arg",
        env = "STDIO2HTTP_ARGS",
        value_name = "ARG",
        allow_hyphen_values = true
    )]
    pub command_args: Vec<String>,

    /// Environment variable for the child, as KEY=VALUE; repeatable.
    #[arg(
        long = "child-env",
        env = "STDIO2HTTP_CHILD_ENV",
        value_name = "KEY=VALUE",
        value_parser = parse_key_value
    )]
    pub env: Vec<(String, String)>,

    /// Working directory for the child process.
    #[arg(long = "cwd", env = "STDIO2HTTP_CWD", value_name = "DIR")]
    pub cwd: Option<PathBuf>,

    /// Address to bind.
    #[arg(long = "host", env = "STDIO2HTTP_HOST", default_value = "127.0.0.1")]
    pub host: IpAddr,

    /// Port to bind.
    #[arg(long = "port", env = "STDIO2HTTP_PORT", default_value_t = 8080)]
    pub port: u16,

    /// Path the Streamable HTTP transport is mounted at.
    #[arg(long = "mcp-path", env = "STDIO2HTTP_MCP_PATH", default_value = "/mcp")]
    pub mcp_path: String,

    /// Host accepted in the Host header; repeatable. Empty keeps rmcp's loopback default.
    #[arg(
        long = "allowed-host",
        env = "STDIO2HTTP_ALLOWED_HOSTS",
        value_delimiter = ','
    )]
    pub allowed_hosts: Vec<String>,

    /// Origin accepted in the Origin header; repeatable.
    #[arg(
        long = "allowed-origin",
        env = "STDIO2HTTP_ALLOWED_ORIGINS",
        value_delimiter = ','
    )]
    pub allowed_origins: Vec<String>,

    /// Authentication mode for /mcp.
    #[arg(
        long = "auth-mode",
        env = "STDIO2HTTP_AUTH_MODE",
        value_enum,
        default_value_t = AuthMode::None
    )]
    pub auth_mode: AuthMode,

    /// Accepted API key, optionally KEY=SUBJECT to name the caller; repeatable.
    #[arg(
        long = "api-key",
        env = "STDIO2HTTP_API_KEYS",
        value_name = "KEY[=SUBJECT]",
        value_delimiter = ','
    )]
    pub api_keys: Vec<String>,

    /// Log verbosity.
    #[arg(
        long = "log-level",
        env = "STDIO2HTTP_LOG_LEVEL",
        value_enum,
        default_value_t = LogLevel::Info
    )]
    pub log_level: LogLevel,

    /// Milliseconds allowed for the upstream spawn and initialize handshake.
    #[arg(
        long = "init-timeout-ms",
        env = "STDIO2HTTP_INIT_TIMEOUT_MS",
        default_value_t = 10_000
    )]
    pub init_timeout_ms: u64,

    /// Accept every Host header. Only for deployments that already trust the network edge.
    #[arg(
        long = "disable-allowed-hosts",
        env = "STDIO2HTTP_DISABLE_ALLOWED_HOSTS",
        action = clap::ArgAction::SetTrue
    )]
    pub disable_allowed_hosts: bool,
}

impl Config {
    /// Program followed by its arguments, in the shape the child spawner wants.
    #[must_use]
    pub fn argv(&self) -> Vec<String> {
        std::iter::once(self.command_program.clone())
            .chain(self.command_args.iter().cloned())
            .collect()
    }

    #[must_use]
    pub fn init_timeout(&self) -> Duration {
        Duration::from_millis(self.init_timeout_ms)
    }

    #[must_use]
    pub fn socket_addr(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(self.host, self.port)
    }

    /// Reject combinations that would silently run unauthenticated or misconfigured.
    ///
    /// # Errors
    ///
    /// Returns a message naming the offending flag when the command, the mount
    /// path, or the authentication mode is unusable.
    pub fn validate(&self) -> Result<(), String> {
        if self.command_program.is_empty() {
            return Err("--command must name a program".to_string());
        }
        if !self.mcp_path.starts_with('/') {
            return Err(format!(
                "--mcp-path must start with '/', got {:?}",
                self.mcp_path
            ));
        }
        match self.auth_mode {
            AuthMode::None => {}
            AuthMode::Bearer | AuthMode::IdentityForward => {
                if self.api_keys.is_empty() {
                    return Err(format!(
                        "--auth-mode {} requires at least one --api-key",
                        self.auth_mode.as_str()
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(flags: &[&str]) -> Result<Config, clap::Error> {
        let mut full = vec!["stdio2http"];
        full.extend_from_slice(flags);
        Config::try_parse_from(full)
    }

    #[test]
    fn clap_definition_is_valid() {
        Config::command().debug_assert();
    }

    #[test]
    fn defaults_are_the_documented_ones() {
        let cfg = parse(&["--command", "server"]).expect("parse");
        assert_eq!(cfg.host.to_string(), "127.0.0.1");
        assert_eq!(cfg.port, 8080);
        assert_eq!(cfg.mcp_path, "/mcp");
        assert_eq!(cfg.auth_mode, AuthMode::None);
        assert_eq!(cfg.log_level, LogLevel::Info);
        assert_eq!(cfg.init_timeout(), Duration::from_millis(10_000));
        assert!(cfg.cwd.is_none());
        let no_strings: Vec<String> = Vec::new();
        assert_eq!(cfg.api_keys, no_strings, "no api keys by default");
        assert_eq!(
            cfg.allowed_hosts, no_strings,
            "rmcp keeps its loopback default"
        );
        assert_eq!(cfg.allowed_origins, no_strings, "origin validation is off");
        assert!(!cfg.disable_allowed_hosts);
        cfg.validate().expect("defaults are valid");
    }

    #[test]
    fn argv_joins_program_and_repeated_args() {
        let cfg = parse(&[
            "--command",
            "node",
            "--arg",
            "dist/server.js",
            "--arg",
            "--stdio",
        ])
        .expect("parse");
        assert_eq!(cfg.argv(), ["node", "dist/server.js", "--stdio"]);
    }

    #[test]
    fn child_env_splits_on_the_first_equals() {
        let cfg = parse(&[
            "--command",
            "server",
            "--child-env",
            "TOKEN=abc",
            "--child-env",
            "MODE=fast=1",
        ])
        .expect("parse");
        assert_eq!(
            cfg.env,
            [
                ("TOKEN".to_string(), "abc".to_string()),
                ("MODE".to_string(), "fast=1".to_string())
            ]
        );
    }

    #[test]
    fn child_env_without_equals_is_a_clap_error() {
        let err = parse(&["--command", "s", "--child-env", "TOKEN"]).expect_err("must reject");
        assert!(err.to_string().contains("KEY=VALUE"), "{err}");
    }

    #[test]
    fn api_keys_may_name_a_subject() {
        let cfg =
            parse(&["--command", "s", "--api-key", "k1=alice", "--api-key", "k2"]).expect("parse");
        assert_eq!(cfg.api_keys, ["k1=alice", "k2"]);
    }

    #[test]
    fn invalid_auth_mode_is_a_clap_error() {
        let err = parse(&["--command", "s", "--auth-mode", "oauth"]).expect_err("must reject");
        assert!(err.to_string().contains("oauth"), "{err}");
    }

    #[test]
    fn invalid_log_level_is_a_clap_error() {
        let err = parse(&["--command", "s", "--log-level", "chatty"]).expect_err("must reject");
        assert!(err.to_string().contains("chatty"), "{err}");
    }

    #[test]
    fn non_numeric_port_is_a_clap_error() {
        let err = parse(&["--command", "s", "--port", "http"]).expect_err("must reject");
        assert!(err.to_string().contains("http"), "{err}");
    }

    #[test]
    fn out_of_range_port_is_a_clap_error() {
        let err = parse(&["--command", "s", "--port", "70000"]).expect_err("must reject");
        assert!(err.to_string().contains("70000"), "{err}");
    }

    #[test]
    fn missing_command_is_a_clap_error() {
        let err = parse(&[]).expect_err("--command is required");
        assert!(err.to_string().contains("--command"), "{err}");
    }

    #[test]
    fn auth_modes_without_keys_are_rejected() {
        for mode in ["bearer", "identity-forward"] {
            let cfg = parse(&["--command", "s", "--auth-mode", mode]).expect("parse");
            let err = cfg.validate().expect_err("no keys configured");
            assert!(err.contains("--api-key"), "{err}");
        }
    }

    #[test]
    fn auth_modes_with_keys_are_accepted() {
        for mode in ["bearer", "identity-forward"] {
            let cfg =
                parse(&["--command", "s", "--auth-mode", mode, "--api-key", "k"]).expect("parse");
            cfg.validate().expect("valid");
        }
    }

    #[test]
    fn mcp_path_must_be_absolute() {
        let cfg = parse(&["--command", "s", "--mcp-path", "mcp"]).expect("parse");
        let err = cfg.validate().expect_err("relative path");
        assert!(err.contains("start with"), "{err}");
    }

    #[test]
    fn empty_program_is_rejected() {
        let cfg = parse(&["--command", ""]).expect("parse");
        let err = cfg.validate().expect_err("empty program");
        assert!(err.contains("--command"), "{err}");
    }

    #[test]
    fn socket_addr_combines_host_and_port() {
        let cfg = parse(&["--command", "s", "--host", "0.0.0.0", "--port", "9000"]).expect("parse");
        assert_eq!(cfg.socket_addr().to_string(), "0.0.0.0:9000");
    }

    #[test]
    fn log_level_maps_to_a_tracing_filter() {
        assert_eq!(LogLevel::Info.as_filter(), "info");
        assert_eq!(LogLevel::Trace.as_filter(), "trace");
    }

    #[test]
    fn auth_mode_renders_the_documented_spelling() {
        assert_eq!(AuthMode::None.as_str(), "none");
        assert_eq!(AuthMode::Bearer.as_str(), "bearer");
        assert_eq!(AuthMode::IdentityForward.as_str(), "identity-forward");
    }

    #[test]
    fn help_lists_every_documented_field() {
        let mut cmd = Config::command();
        let help = cmd.render_long_help().to_string();
        for field in [
            "--command",
            "--arg",
            "--child-env",
            "--cwd",
            "--host",
            "--port",
            "--mcp-path",
            "--allowed-host",
            "--allowed-origin",
            "--auth-mode",
            "--api-key",
            "--log-level",
            "--init-timeout-ms",
            "--disable-allowed-hosts",
        ] {
            assert!(help.contains(field), "help is missing {field}");
        }
    }
}
