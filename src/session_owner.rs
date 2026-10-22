//! Bind MCP sessions to the key that created them.
//!
//! In bearer/identity-forward mode every session id is owned by the
//! authenticating key's index. A request carrying a session id owned by
//! another key gets `404 Not Found: Session not found`, matching rmcp.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::auth::Principal;

/// Owner map from session id to the principal that created it.
#[derive(Clone, Default, Debug)]
pub struct SessionOwners(Arc<Mutex<HashMap<String, Principal>>>);

impl SessionOwners {
    /// Record `id` as owned by `principal`.
    pub fn claim(&self, id: String, principal: Principal) {
        if let Ok(mut owners) = self.0.lock() {
            owners.insert(id, principal);
        }
    }

    /// True when `id` is unknown or owned by `principal`; deny by default.
    #[must_use]
    pub fn check(&self, id: &str, principal: Principal) -> bool {
        self.0
            .lock()
            .is_ok_and(|owners| owners.get(id).is_none_or(|owner| *owner == principal))
    }

    /// Forget `id`, e.g. after its owner deleted it or rmcp reported it gone.
    pub fn release(&self, id: &str) {
        if let Ok(mut owners) = self.0.lock() {
            owners.remove(id);
        }
    }
}

/// Reject a request carrying a session owned by another key.
///
/// Placed inside the auth layer so [`Principal`] is already set. Without a
/// principal (auth none) the request passes through unchanged.
pub async fn enforce(
    axum::extract::State(owners): axum::extract::State<SessionOwners>,
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;

    const SESSION_HEADER: &str = "mcp-session-id";
    const NOT_FOUND_BODY: &str = "Not Found: Session not found";

    let Some(principal) = crate::auth::principal(request.extensions()) else {
        return next.run(request).await;
    };
    if let Some(id) = request
        .headers()
        .get(SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        && !owners.check(id, principal)
    {
        return (axum::http::StatusCode::NOT_FOUND, NOT_FOUND_BODY).into_response();
    }
    // A present-but-undecodable session id cannot be checked; deny it the
    // same way rather than passing an unaudited id to rmcp.
    if request.headers().contains_key(SESSION_HEADER)
        && request
            .headers()
            .get(SESSION_HEADER)
            .and_then(|value| value.to_str().ok())
            .is_none()
    {
        return (axum::http::StatusCode::NOT_FOUND, NOT_FOUND_BODY).into_response();
    }

    let method = request.method().clone();
    let incoming = request
        .headers()
        .get(SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    let response = next.run(request).await;

    if let Some(new_id) = response
        .headers()
        .get(SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        && incoming.is_none()
    {
        owners.claim(new_id, principal);
    }
    // Entries for sessions expired by rmcp (300s idle) are removed only when that id is used again.
    if let Some(id) = incoming
        && ((method == axum::http::Method::DELETE && response.status().is_success())
            || response.status() == axum::http::StatusCode::NOT_FOUND)
    {
        owners.release(&id);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_session_is_allowed() {
        let owners = SessionOwners::default();
        assert!(owners.check("new-id", Principal(0)));
    }

    #[test]
    fn owner_may_reuse_its_session() {
        let owners = SessionOwners::default();
        owners.claim("sess".to_string(), Principal(1));
        assert!(owners.check("sess", Principal(1)));
    }

    #[test]
    fn another_key_is_denied() {
        let owners = SessionOwners::default();
        owners.claim("sess".to_string(), Principal(0));
        assert!(!owners.check("sess", Principal(1)));
    }

    #[test]
    fn release_forgets_the_owner() {
        let owners = SessionOwners::default();
        owners.claim("sess".to_string(), Principal(0));
        owners.release("sess");
        assert!(owners.check("sess", Principal(1)));
    }
}
