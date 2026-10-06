//! Configuration surface: CLI flags plus environment variables, no config file.

use std::fmt;
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

#[derive(Clone, Parser)]
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

    /// Server certificate chain in PEM format, as a file path.
    #[arg(
        long = "tls-cert",
        env = "STDIO2HTTP_TLS_CERT",
        value_name = "CERT_FILE"
    )]
    pub tls_cert: Option<PathBuf>,

    /// Server private key in PEM format, as a file path.
    #[arg(long = "tls-key", env = "STDIO2HTTP_TLS_KEY", value_name = "KEY_FILE")]
    pub tls_key: Option<PathBuf>,

    /// Server certificate chain in PEM format, inline for secret injection.
    #[arg(
        long = "tls-cert-pem",
        env = "STDIO2HTTP_TLS_CERT_PEM",
        value_name = "PEM",
        allow_hyphen_values = true
    )]
    pub tls_cert_pem: Option<String>,

    /// Server private key in PEM format, inline for secret injection.
    #[arg(
        long = "tls-key-pem",
        env = "STDIO2HTTP_TLS_KEY_PEM",
        value_name = "PEM",
        allow_hyphen_values = true
    )]
    pub tls_key_pem: Option<String>,

    /// Client CA bundle in PEM format, as a file path. Enables mTLS.
    #[arg(
        long = "tls-client-ca",
        env = "STDIO2HTTP_TLS_CLIENT_CA",
        value_name = "CA_FILE"
    )]
    pub tls_client_ca: Option<PathBuf>,

    /// Client CA bundle in PEM format, inline for secret injection. Enables mTLS.
    #[arg(
        long = "tls-client-ca-pem",
        env = "STDIO2HTTP_TLS_CLIENT_CA_PEM",
        value_name = "PEM",
        allow_hyphen_values = true
    )]
    pub tls_client_ca_pem: Option<String>,

    /// Contact email for the ACME account.
    #[arg(
        long = "acme-email",
        env = "STDIO2HTTP_ACME_EMAIL",
        value_name = "EMAIL"
    )]
    pub acme_email: Option<String>,

    /// Domain to issue a certificate for; repeatable or comma-separated.
    #[arg(
        long = "acme-domain",
        env = "STDIO2HTTP_ACME_DOMAINS",
        value_name = "DOMAIN",
        value_delimiter = ','
    )]
    pub acme_domains: Vec<String>,

    /// Directory holding the ACME account and certificate cache.
    #[arg(
        long = "acme-cache-dir",
        env = "STDIO2HTTP_ACME_CACHE_DIR",
        value_name = "DIR"
    )]
    pub acme_cache_dir: Option<PathBuf>,

    /// ACME directory URL; defaults to Let's Encrypt production.
    #[arg(
        long = "acme-directory-url",
        env = "STDIO2HTTP_ACME_DIRECTORY_URL",
        value_name = "URL",
        default_value = "https://acme-v02.api.letsencrypt.org/directory"
    )]
    pub acme_directory_url: String,

    /// Port for the ACME HTTP-01 challenge listener.
    #[arg(
        long = "acme-http-port",
        env = "STDIO2HTTP_ACME_HTTP_PORT",
        default_value_t = 80
    )]
    pub acme_http_port: u16,
}

// Hand-written so PEM material and API keys can never reach a log via `{:?}`.
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("command_program", &self.command_program)
            .field("command_args", &self.command_args)
            .field("env", &self.env)
            .field("cwd", &self.cwd)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("mcp_path", &self.mcp_path)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("allowed_origins", &self.allowed_origins)
            .field("auth_mode", &self.auth_mode)
            .field("api_keys", &format!("{} key(s)", self.api_keys.len()))
            .field("log_level", &self.log_level)
            .field("init_timeout_ms", &self.init_timeout_ms)
            .field("disable_allowed_hosts", &self.disable_allowed_hosts)
            .field("tls_cert", &self.tls_cert)
            .field("tls_key", &self.tls_key)
            .field(
                "tls_cert_pem",
                &self.tls_cert_pem.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "tls_key_pem",
                &self.tls_key_pem.as_ref().map(|_| "<redacted>"),
            )
            .field("tls_client_ca", &self.tls_client_ca)
            .field(
                "tls_client_ca_pem",
                &self.tls_client_ca_pem.as_ref().map(|_| "<redacted>"),
            )
            .field("acme_email", &self.acme_email)
            .field("acme_domains", &self.acme_domains)
            .field("acme_cache_dir", &self.acme_cache_dir)
            .field("acme_directory_url", &self.acme_directory_url)
            .field("acme_http_port", &self.acme_http_port)
            .finish()
    }
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

    /// A manually configured server certificate is present (file or inline).
    #[must_use]
    pub fn has_manual_cert(&self) -> bool {
        self.tls_cert.is_some() || self.tls_cert_pem.is_some()
    }

    /// A manually configured server key is present (file or inline).
    #[must_use]
    pub fn has_manual_key(&self) -> bool {
        self.tls_key.is_some() || self.tls_key_pem.is_some()
    }

    /// ACME auto-issuance is requested. The directory URL and challenge port
    /// carry defaults, so only an explicit email, domain, or cache dir counts.
    #[must_use]
    pub fn uses_acme(&self) -> bool {
        self.acme_email.is_some() || !self.acme_domains.is_empty() || self.acme_cache_dir.is_some()
    }

    /// Client-certificate verification is requested.
    #[must_use]
    pub fn uses_mtls(&self) -> bool {
        self.tls_client_ca.is_some() || self.tls_client_ca_pem.is_some()
    }

    /// The listener must speak TLS: a manual cert, ACME, or mTLS implies it.
    #[must_use]
    pub fn tls_enabled(&self) -> bool {
        self.has_manual_cert() || self.has_manual_key() || self.uses_acme() || self.uses_mtls()
    }

    /// Reject combinations that would silently run unauthenticated or misconfigured.
    ///
    /// # Errors
    ///
    /// Returns a message naming the offending flag when the command, the mount
    /// path, the authentication mode, or the TLS/ACME selection is unusable.
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
        if self.tls_cert.is_some() && self.tls_cert_pem.is_some() {
            return Err("--tls-cert and --tls-cert-pem are mutually exclusive".to_string());
        }
        if self.tls_key.is_some() && self.tls_key_pem.is_some() {
            return Err("--tls-key and --tls-key-pem are mutually exclusive".to_string());
        }
        if self.tls_client_ca.is_some() && self.tls_client_ca_pem.is_some() {
            return Err(
                "--tls-client-ca and --tls-client-ca-pem are mutually exclusive".to_string(),
            );
        }
        if self.has_manual_cert() != self.has_manual_key() {
            return Err("--tls-cert and --tls-key must be provided together".to_string());
        }
        let has_manual = self.has_manual_cert() || self.has_manual_key();
        if has_manual && self.uses_acme() {
            return Err("--tls-cert/--tls-key cannot be combined with --acme-*".to_string());
        }
        if self.uses_mtls() && !has_manual && !self.uses_acme() {
            return Err(
                "--tls-client-ca* requires a server certificate (--tls-cert/--tls-key) or ACME (--acme-domain)"
                    .to_string(),
            );
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
        assert!(cfg.tls_cert.is_none());
        assert!(cfg.tls_key.is_none());
        assert!(cfg.tls_cert_pem.is_none());
        assert!(cfg.tls_key_pem.is_none());
        assert!(cfg.tls_client_ca.is_none());
        assert!(cfg.tls_client_ca_pem.is_none());
        assert!(cfg.acme_email.is_none());
        assert_eq!(cfg.acme_domains, Vec::<String>::new());
        assert!(cfg.acme_cache_dir.is_none());
        assert_eq!(
            cfg.acme_directory_url,
            "https://acme-v02.api.letsencrypt.org/directory"
        );
        assert_eq!(cfg.acme_http_port, 80);
        assert!(!cfg.tls_enabled());
        assert!(!cfg.uses_acme());
        assert!(!cfg.uses_mtls());
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
            "--tls-cert",
            "--tls-key",
            "--tls-cert-pem",
            "--tls-key-pem",
            "--tls-client-ca",
            "--tls-client-ca-pem",
            "--acme-email",
            "--acme-domain",
            "--acme-cache-dir",
            "--acme-directory-url",
            "--acme-http-port",
        ] {
            assert!(help.contains(field), "help is missing {field}");
        }
    }

    #[test]
    fn tls_cert_without_key_is_rejected() {
        let cfg = parse(&["--command", "s", "--tls-cert", "/certs/cert.pem"]).expect("parse");
        let err = cfg.validate().expect_err("unpaired cert");
        assert!(
            err.contains("--tls-cert") && err.contains("--tls-key"),
            "{err}"
        );
    }

    #[test]
    fn tls_key_without_cert_is_rejected() {
        let cfg = parse(&["--command", "s", "--tls-key", "/certs/key.pem"]).expect("parse");
        let err = cfg.validate().expect_err("unpaired key");
        assert!(
            err.contains("--tls-cert") && err.contains("--tls-key"),
            "{err}"
        );
    }

    #[test]
    fn tls_file_pair_is_accepted() {
        let cfg = parse(&[
            "--command",
            "s",
            "--tls-cert",
            "/certs/cert.pem",
            "--tls-key",
            "/certs/key.pem",
        ])
        .expect("parse");
        cfg.validate().expect("paired files are valid");
        assert!(cfg.tls_enabled());
    }

    #[test]
    fn tls_inline_pair_is_accepted() {
        let cfg = parse(&[
            "--command",
            "s",
            "--tls-cert-pem",
            "CERT",
            "--tls-key-pem",
            "KEY",
        ])
        .expect("parse");
        cfg.validate().expect("paired inline PEM is valid");
        assert!(cfg.tls_enabled());
    }

    #[test]
    fn tls_inline_pem_accepts_leading_dashes() {
        let cfg = parse(&[
            "--command",
            "s",
            "--tls-cert-pem",
            "-----BEGIN CERTIFICATE-----",
            "--tls-key-pem",
            "-----BEGIN PRIVATE KEY-----",
        ])
        .expect("PEM starting with dashes parses as a value");
        assert_eq!(
            cfg.tls_cert_pem.as_deref(),
            Some("-----BEGIN CERTIFICATE-----")
        );
        assert_eq!(
            cfg.tls_key_pem.as_deref(),
            Some("-----BEGIN PRIVATE KEY-----")
        );
    }

    #[test]
    fn tls_file_and_inline_for_cert_are_mutually_exclusive() {
        let cfg = parse(&[
            "--command",
            "s",
            "--tls-cert",
            "/certs/cert.pem",
            "--tls-cert-pem",
            "CERT",
            "--tls-key",
            "/certs/key.pem",
        ])
        .expect("parse");
        let err = cfg.validate().expect_err("both cert sources");
        assert!(err.contains("--tls-cert"), "{err}");
    }

    #[test]
    fn tls_file_and_inline_for_key_are_mutually_exclusive() {
        let cfg = parse(&[
            "--command",
            "s",
            "--tls-cert",
            "/certs/cert.pem",
            "--tls-key",
            "/certs/key.pem",
            "--tls-key-pem",
            "KEY",
        ])
        .expect("parse");
        let err = cfg.validate().expect_err("both key sources");
        assert!(err.contains("--tls-key"), "{err}");
    }

    #[test]
    fn tls_client_ca_sources_are_mutually_exclusive() {
        let cfg = parse(&[
            "--command",
            "s",
            "--tls-cert",
            "/certs/cert.pem",
            "--tls-key",
            "/certs/key.pem",
            "--tls-client-ca",
            "/certs/ca.pem",
            "--tls-client-ca-pem",
            "CA",
        ])
        .expect("parse");
        let err = cfg.validate().expect_err("both CA sources");
        assert!(err.contains("--tls-client-ca"), "{err}");
    }

    #[test]
    fn manual_cert_and_acme_conflict() {
        let cfg = parse(&[
            "--command",
            "s",
            "--tls-cert",
            "/certs/cert.pem",
            "--tls-key",
            "/certs/key.pem",
            "--acme-domain",
            "example.com",
        ])
        .expect("parse");
        let err = cfg.validate().expect_err("manual plus ACME");
        assert!(err.contains("--acme"), "{err}");
    }

    #[test]
    fn inline_cert_and_acme_conflict() {
        let cfg = parse(&[
            "--command",
            "s",
            "--tls-cert-pem",
            "CERT",
            "--tls-key-pem",
            "KEY",
            "--acme-email",
            "ops@example.com",
        ])
        .expect("parse");
        let err = cfg.validate().expect_err("inline manual plus ACME");
        assert!(err.contains("--acme"), "{err}");
    }

    #[test]
    fn acme_alone_implies_tls() {
        let cfg = parse(&["--command", "s", "--acme-domain", "example.com"]).expect("parse");
        cfg.validate().expect("ACME alone is valid");
        assert!(cfg.uses_acme());
        assert!(cfg.tls_enabled());
    }

    #[test]
    fn acme_domains_accept_repeat_and_comma_forms() {
        let cfg = parse(&[
            "--command",
            "s",
            "--acme-domain",
            "a.example.com,b.example.com",
            "--acme-domain",
            "c.example.com",
        ])
        .expect("parse");
        assert_eq!(
            cfg.acme_domains,
            ["a.example.com", "b.example.com", "c.example.com"]
        );
        cfg.validate().expect("ACME domains are valid");
    }

    #[test]
    fn mtls_alone_is_rejected_without_server_identity() {
        let cfg = parse(&["--command", "s", "--tls-client-ca", "/certs/ca.pem"]).expect("parse");
        assert!(cfg.uses_mtls());
        assert!(cfg.tls_enabled(), "mTLS implies TLS mode");
        let err = cfg.validate().expect_err("mTLS without a server cert");
        assert!(err.contains("--tls-client-ca"), "{err}");
    }

    #[test]
    fn mtls_with_manual_cert_is_accepted() {
        let cfg = parse(&[
            "--command",
            "s",
            "--tls-cert",
            "/certs/cert.pem",
            "--tls-key",
            "/certs/key.pem",
            "--tls-client-ca",
            "/certs/ca.pem",
        ])
        .expect("parse");
        cfg.validate().expect("mTLS with a manual cert is valid");
        assert!(cfg.uses_mtls() && cfg.tls_enabled());
    }

    #[test]
    fn mtls_with_acme_is_accepted() {
        let cfg = parse(&[
            "--command",
            "s",
            "--acme-domain",
            "example.com",
            "--tls-client-ca-pem",
            "CA",
        ])
        .expect("parse");
        cfg.validate().expect("mTLS with ACME is valid");
    }

    #[test]
    fn debug_redacts_key_material() {
        let cfg = parse(&[
            "--command",
            "s",
            "--api-key",
            "s3cr3t",
            "--tls-cert-pem",
            "CERT-BODY",
            "--tls-key-pem",
            "KEY-BODY",
        ])
        .expect("parse");
        let rendered = format!("{cfg:?}");
        for secret in ["s3cr3t", "CERT-BODY", "KEY-BODY"] {
            assert!(!rendered.contains(secret), "leaked {secret:?}: {rendered}");
        }
    }
}
