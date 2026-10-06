//! TLS termination: PEM loading, rustls `ServerConfig` construction, cert summaries.
//!
//! Key material flows through here and is never logged: errors name the
//! failing input (file path or inline flag) but never echo its bytes.
//!
//! mTLS is enforced by rustls at the handshake, before any HTTP routing, so a
//! configured client CA covers every connection on the listener — including
//! `/healthz` probes, which stay open at the HTTP layer. The `/mcp` auth modes
//! still apply unchanged on top at the tower layer.

use std::path::PathBuf;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls::{RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};

use crate::config::Config;

/// What went wrong while loading TLS identity. Variants name the input, never
/// its bytes, so they are safe to log.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// A PEM file could not be read. The path is safe to log; the content never is.
    #[error("tls: cannot read {}: {source}", path.display())]
    UnreadableFile {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Neither `--tls-cert` nor `--tls-cert-pem` was provided.
    #[error("tls: no certificate found; provide --tls-cert or --tls-cert-pem")]
    NoCertificate,
    /// A certificate input held no parseable `CERTIFICATE` block.
    #[error("tls: certificate is not valid PEM holding an X.509 certificate")]
    BadCertificate,
    /// Neither `--tls-key` nor `--tls-key-pem` was provided.
    #[error("tls: no private key found; provide --tls-key or --tls-key-pem")]
    NoPrivateKey,
    /// A key input held no parseable key block.
    #[error("tls: private key is not a valid PKCS#8, PKCS#1, or SEC1 PEM key")]
    BadPrivateKey,
    /// The cert and key parsed but do not form a usable pair.
    #[error("tls: certificate and private key do not form a usable pair")]
    CertKeyMismatch,
    /// mTLS was requested but no client CA material was provided.
    #[error(
        "tls: mTLS requested but no client CA found; provide --tls-client-ca or --tls-client-ca-pem"
    )]
    NoClientCa,
    /// A client CA input held no parseable `CERTIFICATE` block.
    #[error("tls: client CA bundle is not valid PEM holding X.509 certificates")]
    BadClientCa,
    /// rustls rejected an otherwise well-formed input.
    #[error("tls: cannot build TLS configuration")]
    Rustls(#[source] rustls::Error),
    /// The client-CA verifier could not be constructed from a valid store.
    #[error("tls: cannot build client-certificate verifier")]
    Verifier(#[source] rustls::server::VerifierBuilderError),
}

/// Log-safe summary of the loaded server certificate, for the startup line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsInfo {
    /// Certificate subject, e.g. `CN=example.com`.
    pub subject: String,
    /// Certificate expiry in RFC 2822 form, e.g. `Tue, 1 Jul 2025 10:52:37 +0000`.
    pub expiry: String,
    /// SHA-256 fingerprint over the DER bytes, uppercase colon-separated hex.
    pub fingerprint: String,
    /// Whether client certificates are required and verified.
    pub mtls: bool,
}

/// A ready-to-serve rustls config plus its log-safe summary.
pub struct TlsMaterial {
    pub server_config: ServerConfig,
    pub info: TlsInfo,
}

// Hand-written so key material can never reach a log via `{:?}`.
impl std::fmt::Debug for TlsMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsMaterial")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

/// SHA-256 fingerprint over DER bytes, uppercase colon-separated hex.
#[must_use]
pub fn fingerprint_sha256(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Build a client-certificate verifier from a PEM CA bundle.
///
/// The verifier requires and verifies; it is installed at the rustls layer,
/// so verification happens during the handshake for every connection.
///
/// # Errors
///
/// Returns [`TlsError::BadClientCa`] when the bundle holds no parseable
/// certificate, or [`TlsError::Verifier`] when the verifier cannot be built.
pub fn client_verifier(ca_pem: &[u8]) -> Result<Arc<dyn ClientCertVerifier>, TlsError> {
    ensure_default_provider();
    let certs = rustls_pemfile::certs(&mut &*ca_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsError::BadClientCa)?;
    if certs.is_empty() {
        return Err(TlsError::BadClientCa);
    }
    let mut store = RootCertStore::empty();
    for cert in certs {
        store.add(cert).map_err(|_| TlsError::BadClientCa)?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(store))
        .build()
        .map_err(TlsError::Verifier)?;
    Ok(verifier)
}

/// Build a rustls server config from PEM bytes, with no `Config` dependency.
///
/// Pure constructor so ACME-issued chains (held in memory, never in `Config`)
/// load through the same path as manual files. `ca_pem` installs the mTLS
/// verifier when present; `None` means no client authentication.
///
/// Key bytes never appear in errors: failures name the kind of input, never
/// its content.
///
/// # Errors
///
/// Returns a [`TlsError`] when a PEM block is missing or malformed, the
/// cert/key do not pair, or the client CA bundle cannot anchor a verifier.
pub fn build(
    cert_pem: &[u8],
    key_pem: &[u8],
    ca_pem: Option<&[u8]>,
) -> Result<TlsMaterial, TlsError> {
    ensure_default_provider();
    let certs = rustls_pemfile::certs(&mut &*cert_pem)
        .collect::<Result<Vec<CertificateDer<'_>>, _>>()
        .map_err(|_| TlsError::BadCertificate)?;
    if certs.is_empty() {
        return Err(TlsError::BadCertificate);
    }
    // First key wins; multi-key files are a misconfiguration, not a feature.
    let key = rustls_pemfile::private_key(&mut &*key_pem)
        .map_err(|_| TlsError::BadPrivateKey)?
        .ok_or(TlsError::NoPrivateKey)?;
    // `PrivateKeyDer` borrows the PEM buffer; the server config must own its
    // secret, so clone the key into a `'static` value.
    let key: PrivateKeyDer<'static> = key.clone_key();
    let certs: Vec<CertificateDer<'static>> = certs
        .into_iter()
        .map(|cert| CertificateDer::from(cert.as_ref().to_vec()))
        .collect();

    let mtls = ca_pem.is_some();
    let builder = if let Some(ca_pem) = ca_pem {
        // Handshake-level enforcement: rustls demands a verifiable client cert
        // before any HTTP is exchanged, so /healthz requires one too.
        let verifier = client_verifier(ca_pem)?;
        ServerConfig::builder_with_provider(crypto_provider())
            .with_protocol_versions(rustls::ALL_VERSIONS)
            .map_err(TlsError::Rustls)?
            .with_client_cert_verifier(verifier)
    } else {
        ServerConfig::builder_with_provider(crypto_provider())
            .with_protocol_versions(rustls::ALL_VERSIONS)
            .map_err(TlsError::Rustls)?
            .with_no_client_auth()
    };

    // Summarize before the cert moves into the server config; rustls keeps it
    // behind a resolver afterwards.
    let info = summarize_leaf(&certs[0], mtls);

    let mut server_config = builder
        .with_single_cert(certs, key)
        .map_err(|_| TlsError::CertKeyMismatch)?;
    // Same ALPN set axum-server uses for its own PEM helpers.
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(TlsMaterial {
        server_config,
        info,
    })
}

/// Read the configured client-CA bundle, if any.
///
/// `Ok(None)` means no client CA was configured; the caller decides whether
/// that is an error ([`TlsError::NoClientCa`]) or plain non-mTLS serving.
/// File content never appears in errors, only the failing path.
///
/// # Errors
///
/// Returns [`TlsError::UnreadableFile`] when the configured CA file cannot be
/// read.
pub fn client_ca_pem(cfg: &Config) -> Result<Option<Vec<u8>>, TlsError> {
    read_source(cfg.tls_client_ca.as_ref(), cfg.tls_client_ca_pem.as_deref())
}

/// Load the TLS identity from `Config` and build the rustls server config.
///
/// Thin wrapper over [`build`]: reads the cert/key (file or inline PEM per
/// `Config`; file and inline are mutually exclusive, enforced by
/// [`Config::validate`]) plus the client-CA bundle when mTLS is configured,
/// then delegates.
///
/// # Errors
///
/// Returns a [`TlsError`] naming the bad input when files are unreadable,
/// PEM blocks are missing or malformed, the cert/key do not pair, or the
/// client CA bundle cannot anchor a verifier. Key bytes never appear in errors.
pub fn load(cfg: &Config) -> Result<TlsMaterial, TlsError> {
    let cert_pem = read_source(cfg.tls_cert.as_ref(), cfg.tls_cert_pem.as_deref())?
        .ok_or(TlsError::NoCertificate)?;
    let key_pem = read_source(cfg.tls_key.as_ref(), cfg.tls_key_pem.as_deref())?
        .ok_or(TlsError::NoPrivateKey)?;
    let ca_pem = if cfg.uses_mtls() {
        Some(client_ca_pem(cfg)?.ok_or(TlsError::NoClientCa)?)
    } else {
        None
    };

    build(&cert_pem, &key_pem, ca_pem.as_deref())
}

/// Explicit provider so startup never depends on a process-default install.
fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Pin the process-default provider for rustls pieces that resolve it
/// implicitly (client-certificate verification). The server configs built here
/// always carry [`crypto_provider`] explicitly; this only settles which
/// provider implicit lookups use when feature unification enables more than
/// one. Idempotent: a default installed by another subsystem wins and still
/// verifies correctly.
fn ensure_default_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Read a PEM input from file or inline string. `Ok(None)` means neither side
/// was configured; the caller maps that to its own missing-input error.
fn read_source(path: Option<&PathBuf>, inline: Option<&str>) -> Result<Option<Vec<u8>>, TlsError> {
    if let Some(path) = path {
        std::fs::read(path)
            .map(Some)
            .map_err(|source| TlsError::UnreadableFile {
                path: path.clone(),
                source,
            })
    } else {
        Ok(inline.map(|pem| pem.as_bytes().to_vec()))
    }
}

/// Derive the log-safe summary from the leaf certificate.
fn summarize_leaf(leaf: &CertificateDer<'_>, mtls: bool) -> TlsInfo {
    let (subject, expiry) = match x509_parser::parse_x509_certificate(leaf.as_ref()) {
        Ok((_, cert)) => {
            let expiry = cert
                .validity()
                .not_after
                .to_rfc2822()
                .unwrap_or_else(|_| cert.validity().not_after.to_string());
            (cert.subject().to_string(), expiry)
        }
        // rustls already accepted this cert, so a parse miss here must not fail
        // startup; the fingerprint still identifies the served identity.
        Err(_) => (String::from("<unparseable>"), String::from("<unknown>")),
    };
    TlsInfo {
        subject,
        expiry,
        fingerprint: fingerprint_sha256(leaf.as_ref()),
        mtls,
    }
}

/// Unix time for verifier checks in tests.
#[cfg(test)]
fn test_now() -> rustls::pki_types::UnixTime {
    rustls::pki_types::UnixTime::now()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    /// A temp file removed on drop so parallel tests never share state.
    struct TempFile(PathBuf);

    impl TempFile {
        fn write(name: &str, contents: &str) -> Self {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "stdio2http-tls-test-{}-{id}-{name}",
                std::process::id()
            ));
            std::fs::write(&path, contents).expect("test fixture writes");
            Self(path)
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn server_pair() -> (String, String) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("test certificate generates");
        (certified.cert.pem(), certified.signing_key.serialize_pem())
    }

    fn file_config(cert: &std::path::Path, key: &std::path::Path, extra: &[&str]) -> Config {
        let cert = cert.to_str().expect("temp path is UTF-8");
        let key = key.to_str().expect("temp path is UTF-8");
        let mut argv = vec![
            "stdio2http",
            "--command",
            "s",
            "--tls-cert",
            cert,
            "--tls-key",
            key,
        ];
        argv.extend_from_slice(extra);
        let cfg = Config::try_parse_from(argv).expect("test config parses");
        cfg.validate().expect("test config is valid");
        cfg
    }

    /// A CA plus a leaf it issued, as PEM bundle and DER bytes.
    fn ca_and_leaf() -> (String, Vec<u8>) {
        use rcgen::{
            BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        };
        let mut ca_params = CertificateParams::new(vec![]).expect("CA params build");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().expect("CA key generates");
        let ca_cert = ca_params.self_signed(&ca_key).expect("CA self-signs");
        let ca_pem = ca_cert.pem();
        let issuer = Issuer::new(ca_params, ca_key);
        let mut leaf_params =
            CertificateParams::new(vec!["localhost".into()]).expect("leaf params build");
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let leaf_key = KeyPair::generate().expect("leaf key generates");
        let leaf = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("CA signs leaf");
        (ca_pem, leaf.der().to_vec())
    }

    #[test]
    fn file_pair_loads_with_stable_info() {
        let (cert_pem, key_pem) = server_pair();
        let cert = TempFile::write("cert.pem", &cert_pem);
        let key = TempFile::write("key.pem", &key_pem);

        let material = load(&file_config(&cert.0, &key.0, &[])).expect("file pair loads");

        // Subject may be empty for a bare self-signed cert; expiry and the
        // fingerprint must always identify the served identity.
        assert_ne!(material.info.expiry, "");
        assert_ne!(material.info.fingerprint, "");
        assert!(!material.info.mtls);
        // Uppercase colon-separated SHA-256: 32 bytes -> 95 chars.
        assert_eq!(material.info.fingerprint.len(), 95);
        assert!(
            material
                .info
                .fingerprint
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase() || c == ':'),
            "fingerprint is uppercase hex and colons"
        );

        let again = load(&file_config(&cert.0, &key.0, &[])).expect("reloads");
        assert_eq!(material.info.fingerprint, again.info.fingerprint);
    }

    #[test]
    fn inline_pair_matches_file_pair() {
        let (cert_pem, key_pem) = server_pair();
        let cert = TempFile::write("cert.pem", &cert_pem);
        let key = TempFile::write("key.pem", &key_pem);
        let from_files = load(&file_config(&cert.0, &key.0, &[])).expect("file pair loads");

        // `=` form: a space-separated value starting with `-` (as every PEM
        // block does) would parse as a flag. Env vars avoid this too.
        let cfg = Config::try_parse_from([
            "stdio2http",
            "--command",
            "s",
            &format!("--tls-cert-pem={cert_pem}"),
            &format!("--tls-key-pem={key_pem}"),
        ])
        .expect("inline config parses");
        cfg.validate().expect("inline config is valid");
        let from_inline = load(&cfg).expect("inline pair loads");

        assert_eq!(from_files.info.fingerprint, from_inline.info.fingerprint);
    }

    #[test]
    fn garbage_key_is_rejected_without_echo() {
        let (cert_pem, _) = server_pair();
        let cert = TempFile::write("cert.pem", &cert_pem);
        let key = TempFile::write("key.pem", "not a key");

        let error = load(&file_config(&cert.0, &key.0, &[])).expect_err("garbage key fails");

        assert!(format!("{error}").contains("private key"), "{error}");
        assert!(!format!("{error:?}").contains("not a key"));
    }

    #[test]
    fn mismatched_pair_is_rejected() {
        let (cert_pem, _) = server_pair();
        let (_, other_key_pem) = server_pair();
        let cert = TempFile::write("cert.pem", &cert_pem);
        let key = TempFile::write("key.pem", &other_key_pem);

        let error = load(&file_config(&cert.0, &key.0, &[])).expect_err("mismatch fails");

        assert!(matches!(error, TlsError::CertKeyMismatch), "{error}");
    }

    #[test]
    fn garbage_cert_is_rejected() {
        let (_, key_pem) = server_pair();
        let cert = TempFile::write("cert.pem", "not a certificate");
        let key = TempFile::write("key.pem", &key_pem);

        let error = load(&file_config(&cert.0, &key.0, &[])).expect_err("garbage cert fails");

        assert!(format!("{error}").contains("certificate"), "{error}");
    }

    #[test]
    fn missing_identity_is_rejected() {
        let cfg =
            Config::try_parse_from(["stdio2http", "--command", "s"]).expect("plain config parses");
        let error = load(&cfg).expect_err("no identity fails");
        assert!(matches!(error, TlsError::NoCertificate), "{error}");
    }

    #[test]
    fn mtls_config_loads_and_flags_info() {
        let (cert_pem, key_pem) = server_pair();
        let (ca_pem, _) = ca_and_leaf();
        let cert = TempFile::write("cert.pem", &cert_pem);
        let key = TempFile::write("key.pem", &key_pem);
        let ca = TempFile::write("ca.pem", &ca_pem);
        let ca_path = ca.0.to_str().expect("temp path is UTF-8").to_string();

        let cfg = file_config(&cert.0, &key.0, &["--tls-client-ca", &ca_path]);
        let material = load(&cfg).expect("mTLS config loads");
        assert!(material.info.mtls);
    }

    #[test]
    fn client_ca_verifier_accepts_own_leaf_and_rejects_foreign() {
        let (ca_pem, leaf_der) = ca_and_leaf();
        let (_, foreign_der) = ca_and_leaf();

        let verifier = client_verifier(ca_pem.as_bytes()).expect("verifier builds");
        let leaf = CertificateDer::from(leaf_der.as_slice());
        verifier
            .verify_client_cert(&leaf, &[], test_now())
            .expect("own leaf verifies");

        let foreign = CertificateDer::from(foreign_der.as_slice());
        assert!(
            verifier
                .verify_client_cert(&foreign, &[], test_now())
                .is_err(),
            "foreign leaf is rejected"
        );
    }

    #[test]
    fn garbage_client_ca_is_rejected() {
        let error = client_verifier(b"not a CA").expect_err("garbage CA fails");
        assert!(matches!(error, TlsError::BadClientCa), "{error}");
    }
}
