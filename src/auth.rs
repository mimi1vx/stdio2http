//! API-key authentication for the `/mcp` mount.

use std::fmt;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{
    HeaderMap, HeaderName, Request, StatusCode,
    header::{AUTHORIZATION, WWW_AUTHENTICATE},
};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;

use crate::config::AuthMode;

/// Identical for a missing and a wrong key, so the response cannot tell an
/// attacker whether a key exists.
const CHALLENGE: &str = "Bearer realm=\"mcp\"";

const REJECTION_BODY: &str = "unauthorized\n";

const BEARER_PREFIX: &str = "Bearer ";

const API_KEY_HEADER: HeaderName = HeaderName::from_static("x-api-key");

/// Marker extension carrying the authenticated caller's subject.
#[derive(Clone, Debug)]
pub struct Caller(pub String);

/// The authenticated subject of the request, if this layer authenticated one.
#[must_use]
pub fn caller(extensions: &http::Extensions) -> Option<&Caller> {
    extensions.get::<Caller>()
}

/// One configured API key plus the subject it authenticates.
#[derive(Clone)]
pub struct ApiKey {
    secret: String,
    subject: Option<String>,
}

impl ApiKey {
    /// Parse a `KEY` or `KEY=SUBJECT` spec from the config string.
    ///
    /// Returns `None` for a spec with no key part.
    #[must_use]
    pub fn parse(spec: &str) -> Option<Self> {
        let (secret, subject) = spec
            .split_once('=')
            .map_or((spec, None), |(key, subject)| (key, Some(subject)));
        if secret.is_empty() {
            return None;
        }
        Some(Self {
            secret: secret.to_string(),
            subject: subject
                .filter(|value| !value.is_empty())
                .map(str::to_string),
        })
    }

    /// The subject this key authenticates: the configured subject, else the key itself.
    #[must_use]
    pub fn subject(&self) -> &str {
        self.subject.as_deref().unwrap_or(&self.secret)
    }

    fn matches(&self, presented: &str) -> bool {
        // A length mismatch is observable in any case; equality then runs in
        // constant time so no prefix of the secret leaks through timing.
        self.secret.len() == presented.len()
            && bool::from(self.secret.as_bytes().ct_eq(presented.as_bytes()))
    }
}

// Hand-written so that the secret can never reach a log line through `{:?}`.
#[allow(
    clippy::missing_fields_in_debug,
    reason = "the omitted field is the secret"
)]
impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKey")
            .field("subject", &self.subject.as_deref())
            .finish()
    }
}

/// Outcome of authenticating one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Allowed; `subject` is the configured subject for the presented key, if any.
    Allowed { subject: Option<String> },
    /// Rejected. `challenge` is the WWW-Authenticate value to send back.
    Rejected { challenge: String },
}

impl AuthOutcome {
    /// The subject to forward upstream, if this outcome authorizes one.
    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        match self {
            Self::Allowed { subject } => subject.as_deref(),
            Self::Rejected { .. } => None,
        }
    }
}

fn rejected() -> AuthOutcome {
    AuthOutcome::Rejected {
        challenge: CHALLENGE.to_string(),
    }
}

/// Authenticate one request against the configured keys. Pure: no I/O, no logging.
#[must_use]
pub fn authenticate(mode: AuthMode, keys: &[ApiKey], presented: Option<&str>) -> AuthOutcome {
    if mode == AuthMode::None {
        return AuthOutcome::Allowed { subject: None };
    }
    let Some(presented) = presented else {
        return rejected();
    };
    keys.iter()
        .find(|key| key.matches(presented))
        .map_or_else(rejected, |key| AuthOutcome::Allowed {
            subject: Some(key.subject().to_string()),
        })
}

/// Shared state the middleware needs, cloneable and cheap.
#[derive(Clone)]
pub struct AuthState {
    mode: AuthMode,
    keys: Arc<Vec<ApiKey>>,
}

impl AuthState {
    /// Parse each `KEY[=SUBJECT]` spec, dropping the ones that cannot be parsed.
    #[must_use]
    pub fn new(mode: AuthMode, keys: &[String]) -> Self {
        let keys = keys.iter().filter_map(|spec| ApiKey::parse(spec)).collect();
        Self {
            mode,
            keys: Arc::new(keys),
        }
    }

    /// Authenticate `request` and, on success, mark its extensions with the subject.
    pub async fn authorize(&self, mut request: Request<Body>, next: Next) -> Response {
        let presented = presented(request.headers());
        match authenticate(self.mode, &self.keys, presented.as_deref()) {
            AuthOutcome::Rejected { challenge } => {
                tracing::debug!(
                    mode = self.mode.as_str(),
                    "rejecting request without a valid credential"
                );
                (
                    StatusCode::UNAUTHORIZED,
                    [(WWW_AUTHENTICATE, challenge)],
                    REJECTION_BODY,
                )
                    .into_response()
            }
            AuthOutcome::Allowed { subject } => {
                // Only identity-forward hands the child a subject; bearer mode
                // authenticates the caller but leaves the child unable to tell
                // callers apart.
                if self.mode == AuthMode::IdentityForward
                    && let Some(subject) = subject
                {
                    request.extensions_mut().insert(Caller(subject));
                }
                tracing::trace!(mode = self.mode.as_str(), "request authenticated");
                next.run(request).await
            }
        }
    }
}

/// The credential the caller presented: `Authorization: Bearer <key>` first,
/// then `X-API-Key`.
fn presented(headers: &HeaderMap) -> Option<String> {
    let bearer = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix(BEARER_PREFIX));
    bearer
        .or_else(|| {
            headers
                .get(&API_KEY_HEADER)
                .and_then(|value| value.to_str().ok())
        })
        .map(str::to_string)
}

/// Middleware entry point, shaped for [`axum::middleware::from_fn_with_state`].
pub async fn require(
    State(state): State<AuthState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    state.authorize(request, next).await
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, OnceLock};

    use axum::Router;
    use axum::body::Body;
    use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
    use axum::middleware::from_fn_with_state;
    use axum::routing::{any, get};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;

    const SECRET: &str = "s3cr3t-key";

    fn keys(specs: &[&str]) -> Vec<ApiKey> {
        specs
            .iter()
            .map(|spec| ApiKey::parse(spec).expect("parse"))
            .collect()
    }

    fn challenge_of(outcome: &AuthOutcome) -> &str {
        match outcome {
            AuthOutcome::Rejected { challenge } => challenge,
            AuthOutcome::Allowed { .. } => panic!("expected a rejection"),
        }
    }

    #[test]
    fn mode_none_allows_everything() {
        for presented in [None, Some(""), Some("garbage")] {
            assert_eq!(
                authenticate(AuthMode::None, &keys(&[SECRET]), presented),
                AuthOutcome::Allowed { subject: None },
                "{presented:?}"
            );
        }
    }

    #[test]
    fn mode_none_ignores_the_configured_keys() {
        assert_eq!(
            authenticate(AuthMode::None, &[], Some(SECRET)),
            AuthOutcome::Allowed { subject: None }
        );
    }

    #[test]
    fn bearer_rejects_a_missing_key() {
        let outcome = authenticate(AuthMode::Bearer, &keys(&[SECRET]), None);
        assert_eq!(outcome, rejected());
    }

    #[test]
    fn bearer_rejects_a_wrong_key() {
        for wrong in ["nope", "", "s3cr3t-ke", "s3cr3t-keyy"] {
            let outcome = authenticate(AuthMode::Bearer, &keys(&[SECRET]), Some(wrong));
            assert_eq!(outcome, rejected(), "{wrong:?}");
        }
    }

    #[test]
    fn bearer_accepts_a_configured_key_and_names_itself() {
        let outcome = authenticate(AuthMode::Bearer, &keys(&[SECRET]), Some(SECRET));
        assert_eq!(
            outcome,
            AuthOutcome::Allowed {
                subject: Some(SECRET.to_string())
            }
        );
        assert_eq!(outcome.subject(), Some(SECRET));
    }

    #[test]
    fn bearer_forwards_the_configured_subject() {
        let outcome = authenticate(AuthMode::Bearer, &keys(&["k1=alice"]), Some("k1"));
        assert_eq!(outcome.subject(), Some("alice"));
    }

    #[test]
    fn identity_forward_verifies_exactly_like_bearer() {
        for mode in [AuthMode::Bearer, AuthMode::IdentityForward] {
            let configured = keys(&[SECRET]);
            assert_eq!(authenticate(mode, &configured, None), rejected());
            assert_eq!(authenticate(mode, &configured, Some("wrong")), rejected());
            assert_eq!(
                authenticate(mode, &configured, Some(SECRET)),
                AuthOutcome::Allowed {
                    subject: Some(SECRET.to_string())
                }
            );
        }
    }

    #[test]
    fn missing_and_wrong_key_challenge_identically() {
        let keys = keys(&[SECRET]);
        let missing = authenticate(AuthMode::Bearer, &keys, None);
        let wrong = authenticate(AuthMode::Bearer, &keys, Some("wrong"));
        assert_eq!(challenge_of(&missing), challenge_of(&wrong));
        assert_eq!(challenge_of(&missing), "Bearer realm=\"mcp\"");
    }

    #[test]
    fn a_rejection_authorizes_no_subject() {
        assert_eq!(challenge_of(&rejected()).len() + 1, 19);
        assert!(rejected().subject().is_none());
    }

    #[test]
    fn api_key_parse_covers_the_spec_edges() {
        let subject = |spec: &str| ApiKey::parse(spec).map(|key| key.subject().to_string());
        assert_eq!(subject("k"), Some("k".to_string()));
        assert_eq!(subject("k=alice"), Some("alice".to_string()));
        assert_eq!(subject("k="), Some("k".to_string()));
        assert_eq!(subject("=x"), None);
        assert_eq!(subject(""), None);
        assert_eq!(subject("k=a=b"), Some("a=b".to_string()));
    }

    #[test]
    fn api_key_debug_never_prints_the_secret() {
        let named = ApiKey::parse("s3cr3t=alice").expect("parse");
        let anonymous = ApiKey::parse("s3cr3t").expect("parse");
        assert!(!format!("{named:?}").contains("s3cr3t"), "{named:?}");
        assert!(
            !format!("{anonymous:?}").contains("s3cr3t"),
            "{anonymous:?}"
        );
        assert!(format!("{named:?}").contains("alice"), "{named:?}");
    }

    #[test]
    fn state_drops_unparsable_specs_without_panicking() {
        let specs = vec![
            String::new(),
            "=alice".to_string(),
            "=x".to_string(),
            SECRET.to_string(),
            "k1=alice".to_string(),
        ];
        let state = AuthState::new(AuthMode::Bearer, &specs);
        assert_eq!(
            authenticate(AuthMode::Bearer, &state.keys, Some(SECRET)),
            AuthOutcome::Allowed {
                subject: Some(SECRET.to_string())
            }
        );
        assert_eq!(
            authenticate(AuthMode::Bearer, &state.keys, Some("k1")).subject(),
            Some("alice")
        );
        assert_eq!(
            authenticate(AuthMode::Bearer, &state.keys, Some("")),
            rejected()
        );
    }

    async fn echo_subject(State(_state): State<AuthState>, request: Request<Body>) -> String {
        caller(request.extensions()).map_or_else(|| "anonymous".into(), |caller| caller.0.clone())
    }

    fn protected_router(mode: AuthMode, specs: &[&str]) -> Router {
        let specs: Vec<String> = specs.iter().map(|spec| (*spec).to_string()).collect();
        let state = AuthState::new(mode, &specs);
        Router::new()
            .route(
                "/mcp",
                any(echo_subject).layer(from_fn_with_state(state.clone(), require)),
            )
            .route("/healthz", get(|| async { "ok" }))
            .with_state(state)
    }

    async fn call(app: Router, request: Request<Body>) -> Response {
        app.oneshot(request).await.expect("router is a service")
    }

    fn request(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request")
    }

    async fn body_of(response: Response) -> String {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn unauthenticated_request_is_challenged() {
        let app = protected_router(AuthMode::Bearer, &[SECRET]);
        let response = call(app, request("/mcp")).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let challenge = response
            .headers()
            .get(WWW_AUTHENTICATE)
            .expect("challenge header")
            .to_str()
            .expect("challenge is ascii");
        assert_eq!(challenge, CHALLENGE);
        assert_eq!(body_of(response).await, REJECTION_BODY);
    }

    #[tokio::test]
    async fn a_wrong_key_gets_the_same_challenge_as_a_missing_one() {
        let missing = call(
            protected_router(AuthMode::Bearer, &[SECRET]),
            request("/mcp"),
        )
        .await;
        let wrong = call(
            protected_router(AuthMode::Bearer, &[SECRET]),
            Request::builder()
                .uri("/mcp")
                .header(AUTHORIZATION, "Bearer nope")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(missing.status(), wrong.status());
        assert_eq!(
            missing.headers().get(WWW_AUTHENTICATE),
            wrong.headers().get(WWW_AUTHENTICATE)
        );
    }

    #[tokio::test]
    async fn a_valid_key_reaches_the_handler() {
        let app = protected_router(AuthMode::Bearer, &[SECRET]);
        let response = call(
            app,
            Request::builder()
                .uri("/mcp")
                .header(AUTHORIZATION, format!("Bearer {SECRET}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        // Bearer mode authenticates but does not attach a subject, so the
        // handler sees no `Caller` extension.
        assert_eq!(body_of(response).await, "anonymous");
    }

    #[tokio::test]
    async fn identity_forward_attaches_the_configured_subject() {
        let app = protected_router(AuthMode::IdentityForward, &[&format!("{SECRET}=alice")]);
        let response = call(
            app,
            Request::builder()
                .uri("/mcp")
                .header(AUTHORIZATION, format!("Bearer {SECRET}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_of(response).await, "alice");
    }

    #[tokio::test]
    async fn identity_forward_falls_back_to_the_key_itself() {
        let app = protected_router(AuthMode::IdentityForward, &[SECRET]);
        let response = call(
            app,
            Request::builder()
                .uri("/mcp")
                .header("x-api-key", SECRET)
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_of(response).await, SECRET);
    }

    #[tokio::test]
    async fn the_api_key_header_is_accepted_too() {
        let app = protected_router(AuthMode::Bearer, &[SECRET]);
        let response = call(
            app,
            Request::builder()
                .uri("/mcp")
                .header("x-api-key", SECRET)
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn mode_none_needs_no_credential() {
        for headers in [
            HeaderMap::new(),
            HeaderMap::from_iter([(AUTHORIZATION, HeaderValue::from_static("Bearer garbage"))]),
        ] {
            let response = call(protected_router(AuthMode::None, &[]), {
                let mut request = request("/mcp");
                *request.headers_mut() = headers;
                request
            })
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(body_of(response).await, "anonymous");
        }
    }

    #[tokio::test]
    async fn an_unprotected_route_is_not_behind_the_layer() {
        let response = call(
            protected_router(AuthMode::Bearer, &[SECRET]),
            request("/healthz"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_of(response).await, "ok");
    }

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .map_or(Ok(0), |mut sink| sink.write_all(buf).map(|()| buf.len()))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = CaptureWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CaptureWriter(Arc::clone(&self.0))
        }
    }

    fn install_capture(sink: &Arc<Mutex<Vec<u8>>>) {
        static ONCE: OnceLock<()> = OnceLock::new();
        ONCE.get_or_init(|| {
            let capture = Capture(Arc::clone(sink));
            let _already_set = tracing_subscriber::fmt()
                .with_writer(capture)
                .with_max_level(tracing::Level::TRACE)
                .with_ansi(false)
                .try_init();
        });
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn neither_the_configured_nor_the_presented_key_is_logged() {
        let presented = "presented-key";
        let sink: Arc<Mutex<Vec<u8>>> = Arc::default();
        install_capture(&sink);

        let accepted = call(
            protected_router(AuthMode::Bearer, &[SECRET]),
            Request::builder()
                .uri("/mcp")
                .header(AUTHORIZATION, format!("Bearer {SECRET}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(accepted.status(), StatusCode::OK);

        let refused = call(
            protected_router(AuthMode::IdentityForward, &["k1=alice"]),
            Request::builder()
                .uri("/mcp")
                .header(AUTHORIZATION, format!("Bearer {presented}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);

        let logged = String::from_utf8_lossy(&sink.lock().expect("lock")).into_owned();
        assert!(
            logged.contains("request authenticated") && logged.contains("rejecting request"),
            "expected the layer to log both paths, got: {logged}"
        );
        assert!(!logged.contains(SECRET), "configured key leaked: {logged}");
        assert!(
            !logged.contains(presented),
            "presented key leaked: {logged}"
        );
    }
}
