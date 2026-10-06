#![allow(unexpected_cfgs)] // the `acme` feature lands with the pending Cargo.toml merge
//! ACME HTTP-01 auto-issuance and renewal.
//!
//! The pure logic in this module (validation, JSON cache, renewal math, the
//! challenge router) compiles with the base dependency set so `cargo test`
//! stays offline. Only the network flow that talks to the ACME directory
//! needs `instant-acme` and lives behind the `acme` cargo feature:
//!
//! ```toml
//! # see /tmp/CARGO_DEPS_NOTE.md for the exact snippet
//! features = ["acme"]  # enables instant-acme (rustls 0.23 compatible)
//! ```
//!
//! # Flow
//!
//! 1. [`AcmeConfig::from_config`] derives strict ACME settings from
//!    [`crate::config::Config`] (domains + cache dir required, email optional).
//! 2. [`AcmeManager::load_or_create`] restores the account credentials and the
//!    last certificate from `--acme-cache-dir/acme-cache.json` when present.
//! 3. `ensure_cert` (feature `acme`) creates/reuses the account, places an
//!    order for the domains, serves the HTTP-01 responses via
//!    [`challenge_router`] on `--acme-http-port`, finalizes, and installs the
//!    chain into the [`SharedCert`] handle.
//! 4. `AcmeManager::spawn_renewal_task` (feature `acme`) sleeps until the
//!    installed cert is within [`RENEW_BEFORE`] of expiry (plus jitter) and
//!    re-issues. Restarts reuse the cache, so no re-issue (rate-limit safety).
//!
//! # Integration contract for `http.rs` / `tls.rs`
//!
//! - `tls.rs` builds its first `rustls::ServerConfig` from
//!   [`SharedCert::current`] (`cert_pem` + `key_pem`) via `tls::build`.
//! - The HTTP-01 listener and the issuance flow share one [`ChallengeTokens`]
//!   map: `http.rs` binds the listener, spawns [`serve_challenges`] with the
//!   map, then calls [`AcmeManager::ensure_cert_with`] with the same map so
//!   the CA's fetches hit the responses this order published. `ensure_cert`
//!   (no map) is back-compat only; it issues into a throwaway map no listener
//!   serves, so the serve path must use `ensure_cert_with`.
//! - After each renewal the manager calls [`SharedCert::install`], which bumps
//!   [`CertSnapshot::generation`]. `http.rs` detects rotation by polling
//!   `current().generation` and reloading the acceptor. This module never
//!   touches the acceptor.
//! - `http.rs` spawn order: `load_or_create` → bind the challenge listener →
//!   spawn `serve_challenges` for the process lifetime (renewals need it) →
//!   `ensure_cert_with(&tokens)` → build the acceptor → spawn the renewal
//!   task with the same tokens plus a generation-poll rotation watcher.
//!
//! # Security notes
//!
//! - Key material (account credentials, private key, cert PEM) is never logged:
//!   [`AcmeCache`] and [`CertSnapshot`] have hand-written `Debug` impls that
//!   redact secrets, following the `Config` precedent.
//! - The cache directory is created with `0700` and the cache file with `0600`
//!   on unix. The cache holds a private key: the operator must mount it
//!   read-write for `USER nobody` (or whatever the process user is).
//! - `--acme-directory-url` must be `https://`, except `http://` loopback
//!   hosts (Pebble / local test servers).

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use axum::response::IntoResponse as _;
use serde::{Deserialize, Serialize};

/// Renew when the installed cert has less than this much lifetime left.
pub const RENEW_BEFORE: Duration = Duration::from_secs(30 * 24 * 3600);

/// Upper bound added on top of the renewal sleep to avoid thundering herds.
pub const RENEW_JITTER_MAX: Duration = Duration::from_secs(6 * 3600);

/// Assumed certificate lifetime when the CA does not tell us otherwise.
///
/// Let's Encrypt (prod and staging) issues 90-day certificates; the renewal
/// loop only needs an expiry that is close enough to schedule the next
/// issuance at <30d remaining. Stored in the cache alongside the chain.
pub const ASSUMED_CERT_LIFETIME: Duration = Duration::from_secs(90 * 24 * 3600);

/// File inside `--acme-cache-dir` holding account credentials + cert chain.
pub const CACHE_FILE_NAME: &str = "acme-cache.json";

/// Current schema of [`AcmeCache`]; bump on any incompatible change.
pub const CACHE_VERSION: u32 = 1;

/// Default `--acme-directory-url` values, kept here so tests can reference them.
pub const LETSENCRYPT_PROD_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LETSENCRYPT_STAGING_URL: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// A certificate + key installed for the TLS acceptor to serve.
///
/// `tls.rs` reads this via [`SharedCert::current`]; the ACME renewal task
/// replaces it via [`SharedCert::install`].
#[derive(Clone)]
pub struct CertSnapshot {
    /// PEM-encoded certificate chain, as returned by the ACME server.
    pub cert_pem: String,
    /// PEM-encoded private key generated at finalize time.
    pub key_pem: String,
    /// When the chain stops being valid (approximate, see
    /// [`ASSUMED_CERT_LIFETIME`]).
    pub expiry: SystemTime,
    /// Bumped on every [`SharedCert::install`]; lets `tls.rs` detect rotation
    /// without comparing PEM bytes.
    pub generation: u64,
}

// Hand-written so key material can never reach a log via `{:?}`.
impl fmt::Debug for CertSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertSnapshot")
            .field("cert_pem", &"<redacted>")
            .field("key_pem", &"<redacted>")
            .field("expiry", &self.expiry)
            .field("generation", &self.generation)
            .finish()
    }
}

/// Cheaply cloneable handle to the currently installed certificate.
///
/// Internally `Arc<RwLock<Arc<_>>>`: readers (`tls.rs` accept path) take the
/// read lock only to clone the `Arc`, never across `.await`, so renewal
/// installs never block serving.
#[derive(Clone, Debug, Default)]
pub struct SharedCert {
    inner: Arc<RwLock<Option<Arc<CertSnapshot>>>>,
}

impl SharedCert {
    /// Empty handle: no certificate installed yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The currently installed snapshot, if any.
    #[must_use]
    pub fn current(&self) -> Option<Arc<CertSnapshot>> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Install a new chain, bumping the generation counter.
    pub fn install(&self, cert_pem: String, key_pem: String, expiry: SystemTime) {
        let generation = self.current().map_or(0, |s| s.generation + 1);
        let snapshot = Arc::new(CertSnapshot {
            cert_pem,
            key_pem,
            expiry,
            generation,
        });
        *self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(snapshot);
    }

    /// True once a certificate has been installed.
    #[must_use]
    pub fn is_provisioned(&self) -> bool {
        self.current().is_some()
    }
}

/// True when `expiry` is within [`RENEW_BEFORE`] of `now` (or past it).
///
/// Pure function of its inputs so renewal scheduling is unit-testable.
#[must_use]
pub fn renewal_due(expiry: SystemTime, now: SystemTime) -> bool {
    expiry
        .duration_since(now)
        .map_or(true, |left| left <= RENEW_BEFORE)
}

/// How long to sleep before the next issuance attempt. Zero when due now.
#[must_use]
pub fn time_until_renewal(expiry: SystemTime, now: SystemTime) -> Duration {
    expiry
        .duration_since(now)
        .unwrap_or(Duration::ZERO)
        .checked_sub(RENEW_BEFORE)
        .unwrap_or(Duration::ZERO)
}

/// `base` plus a deterministic jitter in `[0, RENEW_JITTER_MAX)`.
///
/// The jitter spreads renewals of many replicas; it is derived from `seed`
/// (feed e.g. the account id hash) so behavior stays testable without a RNG
/// dependency.
#[must_use]
pub fn renewal_delay_with_jitter(base: Duration, seed: u64) -> Duration {
    // splitmix64: cheap, dependency-free bit mixer, not a security RNG.
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    let mixed = z ^ (z >> 31);
    let jitter = Duration::from_secs(mixed % (RENEW_JITTER_MAX.as_secs() + 1));
    base.checked_add(jitter).unwrap_or(Duration::MAX)
}

/// Reject domains the CA cannot issue for over HTTP-01.
///
/// # Errors
///
/// Returns a message naming the offending domain when the list is empty or a
/// domain is not a plausible public FQDN (wildcards need DNS-01, which is out
/// of scope).
pub fn validate_domains(domains: &[String]) -> std::result::Result<(), String> {
    if domains.is_empty() {
        return Err("--acme-domain requires at least one domain".to_string());
    }
    for domain in domains {
        let domain = domain.trim();
        if domain.is_empty() {
            return Err("--acme-domain must not be empty".to_string());
        }
        if domain.starts_with("*.") {
            return Err(format!(
                "wildcard {domain:?} needs DNS-01, which is out of scope; use HTTP-01 reachable names"
            ));
        }
        if domain.len() > 253 {
            return Err(format!("domain {domain:?} exceeds 253 characters"));
        }
        if !domain.contains('.') {
            return Err(format!(
                "domain {domain:?} is not a fully-qualified name; the CA requires a public FQDN"
            ));
        }
        for label in domain.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(format!("domain {domain:?} has an empty or overlong label"));
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(format!("domain {domain:?} has invalid characters"));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(format!(
                    "domain {domain:?} has a label with a leading or trailing hyphen"
                ));
            }
        }
    }
    Ok(())
}

/// Check an `--acme-email` value loosely: present, one `@`, dot in domain.
///
/// # Errors
///
/// Returns a message when the address is clearly not deliverable.
pub fn validate_email(email: &str) -> std::result::Result<(), String> {
    let email = email.trim();
    match email.split_once('@') {
        Some((local, domain))
            if !local.is_empty() && !domain.is_empty() && domain.contains('.') =>
        {
            Ok(())
        }
        _ => Err(format!("--acme-email {email:?} is not a valid address")),
    }
}

/// Build the ACME `contact` URIs from the optional email flag.
#[must_use]
pub fn mailto_contacts(email: Option<&str>) -> Vec<String> {
    email
        .map(|address| format!("mailto:{}", address.trim()))
        .into_iter()
        .collect()
}

/// The directory URL must be `https://`, except loopback `http://` for Pebble.
///
/// # Errors
///
/// Returns a message when the URL has another scheme or is unparseable.
pub fn validate_directory_url(url: &str) -> std::result::Result<(), String> {
    if url.starts_with("https://") && url.len() > "https://".len() {
        return Ok(());
    }
    for prefix in ["http://localhost", "http://127.0.0.1", "http://[::1]"] {
        if url.starts_with(prefix) {
            return Ok(());
        }
    }
    Err(format!(
        "--acme-directory-url must be https:// (http:// only for loopback test servers), got {url:?}"
    ))
}

/// On-disk ACME state: opaque account credentials plus the last chain.
///
/// Stored as JSON at `<cache-dir>/acme-cache.json`. Restarting with the cache
/// avoids re-creating the account and re-issuing (rate-limit safety).
#[derive(Clone, Serialize, Deserialize)]
pub struct AcmeCache {
    /// Schema marker; see [`CACHE_VERSION`].
    pub version: u32,
    /// Opaque serialized `instant-acme` account credentials (JSON string).
    pub account_credentials: String,
    /// PEM certificate chain of the last issuance.
    pub cert_pem: String,
    /// PEM private key generated at finalize time.
    pub key_pem: String,
    /// Chain expiry as unix seconds; renewal math compares against this.
    pub expiry_unix: u64,
    /// Domains the cached chain covers.
    pub domains: Vec<String>,
    /// Directory the account was created against (prod vs staging must not mix).
    pub directory_url: String,
}

// Hand-written so key material can never reach a log via `{:?}`.
impl fmt::Debug for AcmeCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcmeCache")
            .field("version", &self.version)
            .field("account_credentials", &"<redacted>")
            .field("cert_pem", &"<redacted>")
            .field("key_pem", &"<redacted>")
            .field("expiry_unix", &self.expiry_unix)
            .field("domains", &self.domains)
            .field("directory_url", &self.directory_url)
            .finish()
    }
}

impl AcmeCache {
    /// Expiry as a `SystemTime` (`None` for out-of-range stored values).
    #[must_use]
    pub fn expiry(&self) -> Option<SystemTime> {
        UNIX_EPOCH.checked_add(Duration::from_secs(self.expiry_unix))
    }
}

/// Path of the cache file inside `cache_dir`.
#[must_use]
pub fn cache_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join(CACHE_FILE_NAME)
}

/// Read the cache, or `None` when no cache file exists yet.
///
/// # Errors
///
/// Returns an error when the file exists but cannot be read or parsed, or
/// carries an unsupported schema version. A corrupt cache is loud on purpose:
///
/// silently re-issuing could burn through the CA rate limit.
pub fn load_cache(cache_dir: &Path) -> Result<Option<AcmeCache>> {
    let path = cache_path(cache_dir);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    let cache: AcmeCache = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    if cache.version != CACHE_VERSION {
        anyhow::bail!(
            "unsupported ACME cache version {} in {} (expected {CACHE_VERSION}); delete the file to re-issue",
            cache.version,
            path.display()
        );
    }
    Ok(Some(cache))
}

/// Persist the cache, creating the directory with `0700` and the file with
/// `0600` on unix.
///
/// # Errors
///
/// Returns an error when the directory or file cannot be created or written.
pub fn store_cache(cache_dir: &Path, cache: &AcmeCache) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(cache_dir)
            .with_context(|| format!("failed to create {}", cache_dir.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(cache_dir)
            .with_context(|| format!("failed to create {}", cache_dir.display()))?;
    }
    let path = cache_path(cache_dir);
    let bytes = serde_json::to_vec_pretty(cache).context("failed to serialize ACME cache")?;
    std::fs::write(&path, bytes).with_context(|| format!("failed to write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to chmod {}", path.display()))?;
    }
    Ok(())
}

/// Strict ACME settings derived from [`crate::config::Config`].
#[derive(Clone, Debug)]
pub struct AcmeConfig {
    /// Optional contact email; empty contacts when absent (the CA allows it).
    pub email: Option<String>,
    /// FQDNs to include in one order.
    pub domains: Vec<String>,
    /// Persistent account + cert cache.
    pub cache_dir: PathBuf,
    /// ACME directory URL (prod default, staging override for tests).
    pub directory_url: String,
    /// Port of the HTTP-01 challenge listener.
    pub http_port: u16,
}

impl AcmeConfig {
    /// Derive from the CLI config, enforcing what `Config::validate` leaves lax.
    ///
    /// # Errors
    ///
    /// Returns a message when the cache dir or domains are missing, or any
    /// value fails [`validate_domains`] / [`validate_email`] /
    /// [`validate_directory_url`].
    pub fn from_config(cfg: &crate::config::Config) -> std::result::Result<Self, String> {
        let cache_dir = cfg
            .acme_cache_dir
            .clone()
            .ok_or("--acme-cache-dir is required for ACME".to_string())?;
        let config = Self {
            email: cfg.acme_email.clone(),
            domains: cfg.acme_domains.clone(),
            cache_dir,
            directory_url: cfg.acme_directory_url.clone(),
            http_port: cfg.acme_http_port,
        };
        config.validate()?;
        Ok(config)
    }

    /// Check every field; see [`from_config`](Self::from_config) for the rules.
    ///
    /// # Errors
    ///
    /// Returns a message naming the offending field.
    pub fn validate(&self) -> std::result::Result<(), String> {
        validate_domains(&self.domains)?;
        if let Some(email) = &self.email {
            validate_email(email)?;
        }
        validate_directory_url(&self.directory_url)?;
        if self.http_port == 0 {
            return Err("--acme-http-port must be nonzero; the CA dials it".to_string());
        }
        Ok(())
    }

    /// Contact URIs for the ACME account (`mailto:` or empty).
    #[must_use]
    pub fn contacts(&self) -> Vec<String> {
        mailto_contacts(self.email.as_deref())
    }
}

/// Owns the ACME settings, the shared cert handle, and the renewal lifecycle.
pub struct AcmeManager {
    config: AcmeConfig,
    cert: SharedCert,
}

impl AcmeManager {
    /// Build from validated settings, restoring a cached chain when the
    /// requested domains are covered by it.
    ///
    /// The cache is a small local JSON file read once at startup, so plain
    /// blocking I/O inside this `async fn` is deliberate, not an oversight.
    ///
    /// # Errors
    ///
    /// Returns an error when the settings are invalid or a present cache file
    /// cannot be read or parsed.
    #[allow(
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "async by API contract: callers await alongside network setup"
    )]
    pub async fn load_or_create(config: AcmeConfig) -> Result<Self> {
        config.validate().map_err(anyhow::Error::msg)?;
        let manager = Self {
            config,
            cert: SharedCert::new(),
        };
        if let Some(cached) = load_cache(&manager.config.cache_dir)? {
            manager.restore_cached(&cached);
        }
        Ok(manager)
    }

    /// The validated settings.
    #[must_use]
    pub fn config(&self) -> &AcmeConfig {
        &self.config
    }

    /// Handle `tls.rs` reads the installed chain from.
    #[must_use]
    pub fn cert_handle(&self) -> SharedCert {
        self.cert.clone()
    }

    /// Expiry of the installed chain, if provisioned.
    #[must_use]
    pub fn expiry(&self) -> Option<SystemTime> {
        self.cert.current().map(|s| s.expiry)
    }

    /// True once any chain (cached or freshly issued) is installed.
    #[must_use]
    pub fn is_provisioned(&self) -> bool {
        self.cert.is_provisioned()
    }

    /// True when no chain is installed or the installed one needs renewal.
    #[must_use]
    pub fn renewal_due(&self) -> bool {
        self.expiry()
            .is_none_or(|expiry| renewal_due(expiry, SystemTime::now()))
    }

    /// Install a cached chain when it matches this manager's order.
    ///
    /// A stale (expired) chain is still installed so the listener serves
    /// something until the first renewal succeeds; `renewal_due` stays true.
    fn restore_cached(&self, cached: &AcmeCache) {
        let covers = self
            .config
            .domains
            .iter()
            .all(|want| cached.domains.iter().any(|have| have == want));
        if !covers {
            tracing::info!(
                cached = ?cached.domains,
                wanted = ?self.config.domains,
                "ACME cache covers different domains; ignoring it"
            );
            return;
        }
        if cached.directory_url != self.config.directory_url {
            tracing::info!(
                "ACME cache is for another directory; ignoring it (cached renewal stays valid there)"
            );
            return;
        }
        let Some(expiry) = cached.expiry() else {
            tracing::warn!("ACME cache has an out-of-range expiry; ignoring the chain");
            return;
        };
        tracing::info!(
            domains = ?cached.domains,
            expiry = ?expiry,
            "restored ACME certificate from cache"
        );
        self.cert
            .install(cached.cert_pem.clone(), cached.key_pem.clone(), expiry);
    }

    /// Persist account credentials plus the installed chain.
    ///
    /// # Errors
    ///
    /// Returns an error when nothing is installed yet or the cache cannot be
    /// written.
    pub fn persist(&self, account_credentials: &str) -> Result<()> {
        let Some(snapshot) = self.cert.current() else {
            anyhow::bail!("no certificate installed; nothing to persist");
        };
        let expiry_unix = snapshot
            .expiry
            .duration_since(UNIX_EPOCH)
            .context("certificate expiry is before the unix epoch")?
            .as_secs();
        store_cache(
            &self.config.cache_dir,
            &AcmeCache {
                version: CACHE_VERSION,
                account_credentials: account_credentials.to_string(),
                cert_pem: snapshot.cert_pem.clone(),
                key_pem: snapshot.key_pem.clone(),
                expiry_unix,
                domains: self.config.domains.clone(),
                directory_url: self.config.directory_url.clone(),
            },
        )
    }
}

/// Offline stub: without the `acme` feature there is no network client.
#[cfg(not(feature = "acme"))]
impl AcmeManager {
    /// Would issue or renew the certificate; unavailable in this build.
    ///
    /// # Errors
    ///
    /// Always returns an error telling the operator to rebuild with the feature.
    #[allow(
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "async to match the feature-gated signature"
    )]
    pub async fn ensure_cert(&self) -> Result<()> {
        anyhow::bail!("ACME is not compiled in; rebuild with --features acme")
    }

    /// Shared-map issuance; unavailable in this build.
    ///
    /// # Errors
    ///
    /// Always returns an error telling the operator to rebuild with the feature.
    #[allow(
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "async to match the feature-gated signature"
    )]
    pub async fn ensure_cert_with(&self, _tokens: &ChallengeTokens) -> Result<()> {
        anyhow::bail!("ACME is not compiled in; rebuild with --features acme")
    }
}

/// Token → key-authorization map backing the HTTP-01 challenge listener.
///
/// The values are public by ACME design (the CA fetches them), so no
/// redaction is needed here.
#[derive(Clone, Debug, Default)]
pub struct ChallengeTokens {
    inner: Arc<RwLock<HashMap<String, String>>>,
}

impl ChallengeTokens {
    /// Empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish one challenge response.
    pub fn insert(&self, token: String, authorization: String) {
        self.inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(token, authorization);
    }

    /// Look up the response for `token`.
    #[must_use]
    pub fn proof_for(&self, token: &str) -> Option<String> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(token)
            .cloned()
    }

    /// Drop all responses (after the order finalizes).
    pub fn clear(&self) {
        self.inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }
}

/// Axum router answering `/.well-known/acme-challenge/<token>`.
///
/// Unknown tokens get 404; the CA only ever asks for tokens we published.
pub fn challenge_router(tokens: ChallengeTokens) -> axum::Router {
    axum::Router::new()
        .route(
            "/.well-known/acme-challenge/{token}",
            axum::routing::get(challenge_handler),
        )
        .with_state(tokens)
}

async fn challenge_handler(
    axum::extract::State(tokens): axum::extract::State<ChallengeTokens>,
    axum::extract::Path(token): axum::extract::Path<String>,
) -> impl axum::response::IntoResponse {
    match tokens.proof_for(&token) {
        Some(proof) => (http::StatusCode::OK, proof).into_response(),
        None => (http::StatusCode::NOT_FOUND, "unknown challenge".to_string()).into_response(),
    }
}

/// Serve challenge responses until `shutdown` resolves.
///
/// The caller (`main.rs`) binds the listener on [`AcmeConfig::http_port`];
/// this task runs for the whole process lifetime so renewals keep working.
///
/// # Errors
///
/// Returns an error when the HTTP server itself fails.
pub async fn serve_challenges(
    listener: tokio::net::TcpListener,
    tokens: ChallengeTokens,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    axum::serve(listener, challenge_router(tokens))
        .with_graceful_shutdown(shutdown)
        .await
        .context("ACME challenge server failed")
}

// ---------------------------------------------------------------------------
// Network flow (feature `acme` only). Method names against instant-acme 0.8
// were taken from docs.rs; re-run `cargo check --features acme` after merging
// the deps note, the main session owns that gate.
// ---------------------------------------------------------------------------

/// Account handling + order flow against the ACME directory.
#[cfg(feature = "acme")]
impl AcmeManager {
    /// Issue now when nothing is installed, renew when within [`RENEW_BEFORE`].
    ///
    /// Back-compat wrapper over [`Self::ensure_cert_with`]: issues into a
    /// throwaway token map no challenge listener serves. The serve path must
    /// use `ensure_cert_with` with the listener's shared map instead.
    ///
    /// # Errors
    ///
    /// Returns an error when the account, order, challenge, or finalize
    /// exchange fails; the previously installed chain (if any) keeps serving.
    pub async fn ensure_cert(&self) -> Result<()> {
        self.ensure_cert_with(&ChallengeTokens::new()).await
    }

    /// Issue now (or renew when due) publishing HTTP-01 responses into the
    /// shared `tokens` map the challenge listener serves.
    ///
    /// The caller binds the listener and spawns [`serve_challenges`] with the
    /// same map before awaiting this, and keeps both alive for renewals.
    ///
    /// # Errors
    ///
    /// Returns an error when the account, order, challenge, or finalize
    /// exchange fails; the previously installed chain (if any) keeps serving.
    pub async fn ensure_cert_with(&self, tokens: &ChallengeTokens) -> Result<()> {
        if !self.renewal_due() {
            return Ok(());
        }
        self.issue_once(tokens).await
    }

    /// Spawn the background renewal loop; it never resolves on success.
    ///
    /// `tokens` is the same shared map the challenge listener serves; every
    /// renewal publishes its HTTP-01 responses there. The loop sleeps until
    /// [`time_until_renewal`] plus [`renewal_delay_with_jitter`], then calls
    /// [`Self::ensure_cert_with`]. Failures are logged (never key material)
    /// and retried after one hour so a transient CA outage does not spin.
    #[must_use]
    pub fn spawn_renewal_task(
        manager: &Self,
        tokens: ChallengeTokens,
    ) -> tokio::task::JoinHandle<()> {
        // Clone the shared pieces, not the whole manager: the task must not
        // keep anything else alive.
        let cert = manager.cert.clone();
        let config = manager.config.clone();
        let worker = Self { config, cert };
        tokio::spawn(async move {
            loop {
                let sleep_for = worker.expiry().map_or(Duration::ZERO, |expiry| {
                    let base = time_until_renewal(expiry, SystemTime::now());
                    // Seed from the current generation so consecutive
                    // renewals spread even with identical expiries.
                    let seed = worker
                        .cert
                        .current()
                        .map_or(0, |s| s.generation)
                        .wrapping_add(
                            SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map_or(0, |elapsed| elapsed.as_secs()),
                        );
                    renewal_delay_with_jitter(base, seed)
                });
                tracing::info!(
                    sleep_secs = sleep_for.as_secs(),
                    "ACME renewal task sleeping"
                );
                tokio::time::sleep(sleep_for).await;
                if let Err(error) = worker.ensure_cert_with(&tokens).await {
                    tracing::warn!(error = format!("{error:#}"), "ACME renewal failed");
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                }
            }
        })
    }

    /// Restore the cached account for this directory, or register a new one.
    ///
    /// Returns the account plus its serialized credentials for the cache.
    /// Failures never log key material, only which step failed.
    async fn connect_account(
        &self,
        contact: &[&str],
        directory_url: String,
    ) -> Result<(instant_acme::Account, String)> {
        use instant_acme::{Account, NewAccount};

        // Restore the cached account when it was created against the same
        // directory; prod and staging accounts must not mix.
        let restored: Option<(instant_acme::AccountCredentials, String)> =
            load_cache(&self.config.cache_dir)?.and_then(|cached| {
                if cached.directory_url != directory_url {
                    return None;
                }
                let credentials: instant_acme::AccountCredentials =
                    serde_json::from_str(&cached.account_credentials).ok()?;
                Some((credentials, cached.account_credentials))
            });
        if let Some((credentials, raw)) = restored {
            let account = Account::builder()
                .context("failed to build ACME client")?
                .from_credentials(credentials)
                .await
                .context("cached ACME account was rejected; delete the cache to re-register")?;
            Ok((account, raw))
        } else {
            let (account, credentials) = Account::builder()
                .context("failed to build ACME client")?
                .create(
                    &NewAccount {
                        contact,
                        terms_of_service_agreed: true,
                        only_return_existing: true,
                    },
                    directory_url,
                    None,
                )
                .await
                .context("failed to create ACME account")?;
            let raw = serde_json::to_string(&credentials)
                .context("failed to serialize account credentials")?;
            Ok((account, raw))
        }
    }

    /// Full issuance: restore or create the account, complete every HTTP-01
    /// challenge, finalize, install + persist.
    async fn issue_once(&self, tokens: &ChallengeTokens) -> Result<()> {
        use instant_acme::{AuthorizationStatus, OrderStatus, RetryPolicy};
        use instant_acme::{ChallengeType, Identifier, NewOrder};

        let contacts = self.config.contacts();
        let contact_refs: Vec<&str> = contacts.iter().map(String::as_str).collect();
        let (account, credentials_json) = self
            .connect_account(&contact_refs, self.config.directory_url.clone())
            .await?;

        let identifiers: Vec<Identifier> = self
            .config
            .domains
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .context("failed to create ACME order")?;

        // Publish every HTTP-01 response into the shared map before telling
        // the server we are ready. The challenge listener serves this same
        // map, so the CA's fetches hit the responses published here.
        // Handles borrow the order, so each is completed (set_ready) and
        // dropped inside its own iteration; nothing is held across `.next()`.
        {
            let mut authorizations = order.authorizations();
            while let Some(authorization) = authorizations
                .next()
                .await
                .transpose()
                .context("failed to fetch authorizations")?
            {
                if matches!(authorization.status, AuthorizationStatus::Valid) {
                    continue;
                }
                let mut handle = authorization;
                let Some(mut challenge) = handle.challenge(ChallengeType::Http01) else {
                    anyhow::bail!("CA offered no HTTP-01 challenge for this authorization");
                };
                let token = challenge.token.clone();
                tokens.insert(token, challenge.key_authorization().as_str().to_string());
                challenge
                    .set_ready()
                    .await
                    .context("failed to set challenge ready")?;
            }
        }

        let retry = RetryPolicy::new()
            .timeout(Duration::from_secs(120))
            .initial_delay(Duration::from_secs(2));
        match order
            .poll_ready(&retry)
            .await
            .context("order never became ready")?
        {
            OrderStatus::Ready => {}
            other => anyhow::bail!("ACME order ended in unexpected state: {other:?}"),
        }

        // `finalize` generates the CSR + key via rcgen and returns the key PEM.
        let key_pem = order.finalize().await.context("failed to finalize order")?;
        let chain_pem = order
            .poll_certificate(&retry)
            .await
            .context("failed to fetch certificate")?;
        tokens.clear();

        let expiry = SystemTime::now()
            .checked_add(ASSUMED_CERT_LIFETIME)
            .unwrap_or(SystemTime::now());
        tracing::info!(
            domains = ?self.config.domains,
            expiry = ?expiry,
            "ACME issuance succeeded"
        );
        self.cert.install(chain_pem, key_pem, expiry);
        self.persist(&credentials_json)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;

    fn days(n: u64) -> StdDuration {
        StdDuration::from_secs(n * 24 * 3600)
    }

    fn acme_config(domains: &[&str]) -> AcmeConfig {
        AcmeConfig {
            email: Some("ops@example.com".to_string()),
            domains: domains.iter().map(ToString::to_string).collect(),
            cache_dir: PathBuf::from("/tmp/stdio2http-acme-test-unused"),
            directory_url: LETSENCRYPT_STAGING_URL.to_string(),
            http_port: 80,
        }
    }

    #[test]
    fn renewal_due_only_inside_thirty_days() {
        let now = SystemTime::now();
        assert!(!renewal_due(now + days(90), now), "fresh cert waits");
        assert!(
            !renewal_due(now + days(31), now),
            "just outside the window waits"
        );
        assert!(renewal_due(now + days(30), now), "boundary renews");
        assert!(renewal_due(now + days(7), now), "near expiry renews");
        assert!(
            renewal_due(now.checked_sub(days(1)).unwrap_or(now), now),
            "expired renews"
        );
    }

    #[test]
    fn time_until_renewal_counts_down_to_the_window() {
        let now = SystemTime::now();
        assert_eq!(time_until_renewal(now + days(90), now), days(60));
        assert_eq!(time_until_renewal(now + days(31), now), days(1));
        assert_eq!(time_until_renewal(now + days(7), now), StdDuration::ZERO);
        assert_eq!(
            time_until_renewal(now.checked_sub(days(1)).unwrap_or(now), now),
            StdDuration::ZERO
        );
    }

    #[test]
    fn jitter_stays_bounded_and_deterministic() {
        let base = days(60);
        let first = renewal_delay_with_jitter(base, 42);
        assert_eq!(first, renewal_delay_with_jitter(base, 42));
        assert!(first >= base, "jitter only delays");
        assert!(
            first < base + RENEW_JITTER_MAX + StdDuration::from_secs(1),
            "jitter is bounded"
        );
        // Different seeds spread; at least the mixer does not collapse.
        let distinct: std::collections::HashSet<_> = (0..16)
            .map(|s| renewal_delay_with_jitter(base, s))
            .collect();
        assert!(distinct.len() > 1, "seeds must spread renewals");
    }

    #[test]
    fn domains_accept_plain_fqdns() {
        assert!(validate_domains(&["example.com".to_string()]).is_ok());
        assert!(
            validate_domains(&["a.example.com".to_string(), "b.example.com".to_string()]).is_ok()
        );
        assert!(validate_domains(&["xn--nxasmq6b.example".to_string()]).is_ok());
    }

    #[test]
    fn domains_reject_wildcards_and_non_fqdns() {
        assert!(validate_domains(&[]).is_err(), "empty needs flag usage");
        assert!(validate_domains(&[String::new()]).is_err());
        assert!(
            validate_domains(&["localhost".to_string()]).is_err(),
            "no dot"
        );
        assert!(
            validate_domains(&["*.example.com".to_string()]).is_err(),
            "wildcards need DNS-01"
        );
        assert!(validate_domains(&["bad_domain.example".to_string()]).is_err());
        assert!(validate_domains(&["-lead.example.com".to_string()]).is_err());
        assert!(validate_domains(&["trail-.example.com".to_string()]).is_err());
        assert!(
            validate_domains(&["a..example.com".to_string()]).is_err(),
            "empty label"
        );
    }

    #[test]
    fn email_validation_and_contact_uris() {
        assert!(validate_email("ops@example.com").is_ok());
        assert!(validate_email("not-an-address").is_err());
        assert!(validate_email("missing-tld@host").is_err());
        assert!(validate_email("@example.com").is_err());
        assert_eq!(
            mailto_contacts(Some("ops@example.com")),
            ["mailto:ops@example.com"]
        );
        assert_eq!(mailto_contacts(None), Vec::<String>::new());
    }

    #[test]
    fn directory_url_requires_https_but_allows_loopback_http() {
        assert!(validate_directory_url(LETSENCRYPT_PROD_URL).is_ok());
        assert!(validate_directory_url(LETSENCRYPT_STAGING_URL).is_ok());
        assert!(validate_directory_url("http://localhost:14000/dir").is_ok());
        assert!(validate_directory_url("http://127.0.0.1:14000/dir").is_ok());
        assert!(validate_directory_url("http://acme.example.com/dir").is_err());
        assert!(validate_directory_url("ftp://example.com/dir").is_err());
    }

    #[test]
    fn acme_config_validation_covers_every_field() {
        acme_config(&["example.com"]).validate().expect("valid");
        let no_domains = acme_config(&[]);
        assert!(no_domains.validate().is_err());
        let bad_email = AcmeConfig {
            email: Some("bogus".to_string()),
            ..acme_config(&["example.com"])
        };
        assert!(bad_email.validate().is_err());
        let bad_url = AcmeConfig {
            directory_url: "http://acme.example.com/dir".to_string(),
            ..acme_config(&["example.com"])
        };
        assert!(bad_url.validate().is_err());
        let zero_port = AcmeConfig {
            http_port: 0,
            ..acme_config(&["example.com"])
        };
        assert!(zero_port.validate().is_err());
    }

    fn unique_temp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "stdio2http-acme-test-{}-{tag}-{nanos}",
            std::process::id()
        ));
        dir
    }

    fn sample_cache() -> AcmeCache {
        AcmeCache {
            version: CACHE_VERSION,
            account_credentials: "{\"id\":\"acct-1\"}".to_string(),
            cert_pem: "CERT".to_string(),
            key_pem: "KEY".to_string(),
            expiry_unix: 2_000_000_000,
            domains: vec!["example.com".to_string()],
            directory_url: LETSENCRYPT_STAGING_URL.to_string(),
        }
    }

    #[test]
    fn cache_round_trips_through_json() {
        let dir = unique_temp_dir("roundtrip");
        let cache = AcmeCache {
            version: CACHE_VERSION,
            account_credentials: "{\"id\":\"acct-1\"}".to_string(),
            cert_pem: "CERT".to_string(),
            key_pem: "KEY".to_string(),
            expiry_unix: 2_000_000_000,
            domains: vec!["example.com".to_string(), "www.example.com".to_string()],
            directory_url: LETSENCRYPT_STAGING_URL.to_string(),
        };
        assert!(load_cache(&dir).expect("readable").is_none());
        store_cache(&dir, &cache).expect("writable");
        let back = load_cache(&dir).expect("readable").expect("present");
        assert_eq!(back.version, CACHE_VERSION);
        assert_eq!(back.account_credentials, cache.account_credentials);
        assert_eq!(back.cert_pem, "CERT");
        assert_eq!(back.domains, cache.domains);
        assert_eq!(
            back.expiry(),
            UNIX_EPOCH.checked_add(StdDuration::from_secs(2_000_000_000))
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupt_cache_is_loud() {
        let dir = unique_temp_dir("corrupt");
        std::fs::create_dir_all(&dir).expect("setup");
        std::fs::write(cache_path(&dir), b"{not json").expect("setup");
        assert!(load_cache(&dir).is_err(), "corrupt cache must fail");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wrong_version_cache_is_rejected() {
        let dir = unique_temp_dir("version");
        let mut cache = sample_cache();
        cache.version = CACHE_VERSION + 1;
        store_cache(&dir, &cache).expect("writable");
        assert!(load_cache(&dir).is_err(), "version drift must fail");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn debug_impls_never_leak_key_material() {
        let cache = sample_cache();
        let rendered = format!("{cache:?}");
        for secret in ["acct-1", "CERT", "KEY"] {
            assert!(!rendered.contains(secret), "leaked {secret}: {rendered}");
        }
        let handle = SharedCert::new();
        handle.install(
            "CERT-BODY".to_string(),
            "KEY-BODY".to_string(),
            SystemTime::now() + days(90),
        );
        let snapshot = handle.current().expect("installed");
        let rendered = format!("{snapshot:?} {handle:?}");
        for secret in ["CERT-BODY", "KEY-BODY"] {
            assert!(!rendered.contains(secret), "leaked {secret}: {rendered}");
        }
    }

    #[test]
    fn shared_cert_install_bumps_generation() {
        let handle = SharedCert::new();
        assert!(!handle.is_provisioned());
        handle.install(
            "c1".to_string(),
            "k1".to_string(),
            SystemTime::now() + days(90),
        );
        let first = handle.current().expect("installed");
        assert!(handle.is_provisioned());
        assert_eq!(first.generation, 0);
        handle.install(
            "c2".to_string(),
            "k2".to_string(),
            SystemTime::now() + days(89),
        );
        let second = handle.current().expect("installed");
        assert_eq!(second.generation, 1);
        assert_eq!(second.cert_pem, "c2");
    }

    #[tokio::test]
    async fn challenge_router_serves_published_tokens_only() {
        use http_body_util::BodyExt as _;
        use tower::ServiceExt as _;

        let tokens = ChallengeTokens::new();
        tokens.insert("good-token".to_string(), "good-proof".to_string());

        let response = challenge_router(tokens.clone())
            .oneshot(
                http::Request::builder()
                    .uri("/.well-known/acme-challenge/good-token")
                    .body(axum::body::Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("router responds");
        assert_eq!(response.status(), http::StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body collects")
            .to_bytes();
        assert_eq!(body.as_ref(), b"good-proof");

        let response = challenge_router(tokens)
            .oneshot(
                http::Request::builder()
                    .uri("/.well-known/acme-challenge/nope")
                    .body(axum::body::Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("router responds");
        assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
    }

    // Staging end-to-end: order -> challenge -> issued cert, then
    // `cargo test --features acme -- --ignored` with a reachable ACME server
    // (Pebble locally or Let's Encrypt staging with public DNS) and:
    //   ACME_TEST_DIRECTORY_URL, ACME_TEST_DOMAIN, ACME_TEST_EMAIL,
    //   ACME_TEST_HTTP_PORT set. Excluded from default runs: needs network.
    #[cfg(feature = "acme")]
    #[tokio::test]
    #[ignore = "needs an ACME server plus public DNS; see CARGO_DEPS_NOTE.md"]
    async fn staging_issues_a_served_cert() {
        let dir_url =
            std::env::var("ACME_TEST_DIRECTORY_URL").expect("set ACME_TEST_DIRECTORY_URL");
        let domain = std::env::var("ACME_TEST_DOMAIN").expect("set ACME_TEST_DOMAIN");
        let email = std::env::var("ACME_TEST_EMAIL").expect("set ACME_TEST_EMAIL");
        let http_port: u16 = std::env::var("ACME_TEST_HTTP_PORT")
            .expect("set ACME_TEST_HTTP_PORT")
            .parse()
            .expect("port parses");
        let cache_dir = unique_temp_dir("staging");

        let config = AcmeConfig {
            email: Some(email),
            domains: vec![domain],
            cache_dir: cache_dir.clone(),
            directory_url: dir_url,
            http_port,
        };
        let manager = AcmeManager::load_or_create(config)
            .await
            .expect("manager builds");

        // The challenge listener must be up before the order starts polling,
        // sharing one token map with the issuance flow (the serve-path wiring).
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", http_port))
            .await
            .expect("challenge port binds");
        let tokens = ChallengeTokens::new();
        let (_tx, rx) = tokio::sync::oneshot::channel::<()>();
        let serve = tokio::spawn(serve_challenges(listener, tokens.clone(), async {
            let _ = rx.await;
        }));
        let _ = &serve;
        manager
            .ensure_cert_with(&tokens)
            .await
            .expect("staging issuance works");
        assert!(manager.is_provisioned());

        std::fs::remove_dir_all(&cache_dir).ok();
    }
}
