//! The downstream `ServerHandler`. Every method is a pass-through to the shared
//! upstream peer; rmcp owns sessions, framing, and negotiation around it.

use std::sync::Arc;

use rmcp::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CompleteRequestParams, CompleteResult, ErrorCode,
    ErrorData, GetPromptRequestParams, GetPromptResponse, ListPromptsResult,
    ListResourceTemplatesResult, ListResourcesResult, ListToolsResult, PaginatedRequestParams,
    ProtocolVersion, ReadResourceRequestParams, ReadResourceResponse, RequestMetaObject,
    RequestParamsMeta, ServerConfig,
};
use rmcp::service::{Peer, RequestContext, RoleClient, RoleServer, ServiceError};

/// `_meta` key carrying the authenticated caller's subject to the upstream.
pub const CALLER_META_KEY: &str = "io.stdio2http/caller";

/// Forwards MCP requests from HTTP sessions to the one shared stdio child.
#[derive(Clone, Debug)]
pub struct ProxyHandler {
    peer: Arc<Peer<RoleClient>>,
    info: Arc<ServerConfig>,
}

impl ProxyHandler {
    #[must_use]
    pub fn new(peer: Arc<Peer<RoleClient>>, info: Arc<ServerConfig>) -> Self {
        Self { peer, info }
    }

    #[must_use]
    pub fn peer(&self) -> &Arc<Peer<RoleClient>> {
        &self.peer
    }
}

/// Collapse an upstream failure into an opaque protocol error. The child's stderr
/// and the proxy's environment must never reach the HTTP caller.
fn upstream_error(error: &ServiceError) -> ErrorData {
    tracing::error!(%error, "upstream MCP call failed");
    ErrorData::internal_error("upstream MCP server call failed", None)
}

/// The caller's subject for this request, if the auth layer authenticated one.
fn caller_of(context: &RequestContext<RoleServer>) -> Option<String> {
    let parts = context.extensions.get::<http::request::Parts>()?;
    let caller = crate::auth::caller(&parts.extensions)?;
    Some(caller.0.clone())
}

/// Merge the client's wire `_meta` (surfaced by rmcp in `context.meta`) with
/// the proxy's own caller stamp for one outgoing upstream request.
///
/// The client's custom keys pass through untouched, but two keys never do:
/// `io.stdio2http/caller` is set by the proxy alone, so a client-sent value
/// is spoofing and is always dropped; `progressToken` belongs to the HTTP
/// session's progress subscription and rmcp mints a fresh one for the
/// upstream leg. Returns `None` when nothing remains to forward.
fn merged_meta(client: &RequestMetaObject, subject: Option<&str>) -> Option<RequestMetaObject> {
    let mut merged = client.clone();
    let _ = merged.remove(CALLER_META_KEY);
    let _ = merged.remove("progressToken");
    if let Some(subject) = subject {
        merged.insert(
            CALLER_META_KEY.to_string(),
            serde_json::Value::String(subject.to_string()),
        );
    }
    if merged.is_empty() {
        None
    } else {
        Some(merged)
    }
}

/// Stamp the merged client `_meta` plus caller onto an outgoing request.
/// Typed `params.meta` is always empty on the server path (rmcp moves the
/// wire `_meta` into `context.meta`), so overwrite it outright.
fn stamp_caller<T: rmcp::model::RequestParamsMeta>(
    params: &mut T,
    context: &RequestContext<RoleServer>,
) {
    *params.meta_mut() = merged_meta(&context.meta, caller_of(context).as_deref());
}

/// Set paginated params meta from pre-merged meta, creating `params` only
/// when there is something to forward so a bare cursor still round-trips.
fn set_paginated_meta(
    request: &mut Option<PaginatedRequestParams>,
    merged: Option<RequestMetaObject>,
) {
    match merged {
        Some(meta) => request
            .get_or_insert_with(PaginatedRequestParams::default)
            .set_meta(meta),
        None => {
            if let Some(params) = request {
                *params.meta_mut() = None;
            }
        }
    }
}

/// List requests may omit `params`; create them only when merged meta is non-empty.
fn stamp_caller_paginated(
    request: &mut Option<PaginatedRequestParams>,
    context: &RequestContext<RoleServer>,
) {
    set_paginated_meta(
        request,
        merged_meta(&context.meta, caller_of(context).as_deref()),
    );
}

impl ServerHandler for ProxyHandler {
    fn get_info(&self) -> ServerConfig {
        self.info.as_ref().clone()
    }

    fn supported_protocol_versions(&self) -> std::borrow::Cow<'static, [ProtocolVersion]> {
        // Advertise exactly what the upstream negotiated, so the HTTP client and
        // the child never disagree about the dialect in use.
        std::borrow::Cow::Owned(vec![self.info.protocol_version.clone()])
    }

    async fn list_tools(
        &self,
        mut request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        stamp_caller_paginated(&mut request, &context);
        self.peer
            .list_tools(request)
            .await
            .map_err(|e| upstream_error(&e))
    }

    async fn call_tool(
        &self,
        mut request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        stamp_caller(&mut request, &context);
        self.peer
            .call_tool_once(request)
            .await
            .map_err(|e| upstream_error(&e))
    }

    async fn list_resources(
        &self,
        mut request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        stamp_caller_paginated(&mut request, &context);
        self.peer
            .list_resources(request)
            .await
            .map_err(|e| upstream_error(&e))
    }

    async fn list_resource_templates(
        &self,
        mut request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        stamp_caller_paginated(&mut request, &context);
        self.peer
            .list_resource_templates(request)
            .await
            .map_err(|e| upstream_error(&e))
    }

    async fn read_resource(
        &self,
        mut request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        stamp_caller(&mut request, &context);
        self.peer
            .read_resource_once(request)
            .await
            .map_err(|e| upstream_error(&e))
    }

    async fn list_prompts(
        &self,
        mut request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        stamp_caller_paginated(&mut request, &context);
        self.peer
            .list_prompts(request)
            .await
            .map_err(|e| upstream_error(&e))
    }

    async fn get_prompt(
        &self,
        mut request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, ErrorData> {
        stamp_caller(&mut request, &context);
        self.peer
            .get_prompt_once(request)
            .await
            .map_err(|e| upstream_error(&e))
    }

    async fn complete(
        &self,
        mut request: CompleteRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CompleteResult, ErrorData> {
        stamp_caller(&mut request, &context);
        self.peer
            .complete(request)
            .await
            .map_err(|e| upstream_error(&e))
    }

    /// Deprecated by SEP-2577, but still implemented by legacy upstreams.
    #[allow(deprecated, reason = "forward logging/setLevel for legacy upstreams")]
    async fn set_level(
        &self,
        mut request: rmcp::model::SetLevelRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        stamp_caller(&mut request, &context);
        #[allow(deprecated, reason = "matches the deprecated request type")]
        self.peer
            .set_level(request)
            .await
            .map_err(|e| upstream_error(&e))
    }

    /// Not implemented: a subscription is a long-lived server-initiated stream and
    /// this proxy only forwards request/response pairs.
    fn accepted_subscription_filter(
        &self,
        _requested: &rmcp::model::SubscriptionFilter,
    ) -> Option<rmcp::model::SubscriptionFilter> {
        None
    }

    fn on_custom_request(
        &self,
        request: rmcp::model::CustomRequest,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<rmcp::model::CustomResult, ErrorData>> + '_ {
        std::future::ready(Err(ErrorData::new(
            ErrorCode::METHOD_NOT_FOUND,
            request.method,
            None,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::RequestParamsMeta;
    use serde_json::json;

    fn meta_of(pairs: &[(&str, serde_json::Value)]) -> RequestMetaObject {
        let mut meta = RequestMetaObject::new();
        for (key, value) in pairs {
            meta.insert((*key).to_owned(), value.clone());
        }
        meta
    }

    #[test]
    fn custom_keys_pass_through_without_subject() {
        let client = meta_of(&[("custom", json!("keep-me"))]);
        let merged = merged_meta(&client, None).expect("custom keys survive");
        assert_eq!(merged.get("custom"), Some(&json!("keep-me")));
        assert!(!merged.contains_key(CALLER_META_KEY));
    }

    #[test]
    fn spoofed_caller_is_stripped_without_subject() {
        let client = meta_of(&[(CALLER_META_KEY, json!("mallory"))]);
        assert!(merged_meta(&client, None).is_none());
    }

    #[test]
    fn subject_replaces_spoofed_caller() {
        let client = meta_of(&[
            (CALLER_META_KEY, json!("mallory")),
            ("custom", json!("keep-me")),
        ]);
        let merged = merged_meta(&client, Some("alice")).expect("caller stamp survives");
        assert_eq!(merged.get(CALLER_META_KEY), Some(&json!("alice")));
        assert_eq!(merged.get("custom"), Some(&json!("keep-me")));
    }

    #[test]
    fn empty_meta_without_subject_yields_none() {
        assert!(merged_meta(&RequestMetaObject::new(), None).is_none());
    }

    #[test]
    fn progress_token_is_not_forwarded() {
        let client = meta_of(&[
            ("progressToken", json!("tok-1")),
            ("custom", json!("keep-me")),
        ]);
        let merged = merged_meta(&client, None).expect("custom keys survive");
        assert!(!merged.contains_key("progressToken"));
        assert_eq!(merged.get("custom"), Some(&json!("keep-me")));
    }

    #[test]
    fn paginated_none_without_meta_stays_none() {
        let mut request = None;
        set_paginated_meta(&mut request, None);
        assert!(request.is_none());
    }

    #[test]
    fn paginated_none_with_meta_gets_meta() {
        let mut request = None;
        set_paginated_meta(
            &mut request,
            merged_meta(&meta_of(&[("custom", json!("keep-me"))]), Some("alice")),
        );
        let params = request.as_ref().expect("params are created");
        assert_eq!(
            params.meta.as_ref().and_then(|meta| meta.get("custom")),
            Some(&json!("keep-me"))
        );
        assert_eq!(
            params
                .meta
                .as_ref()
                .and_then(|meta| meta.get(CALLER_META_KEY)),
            Some(&json!("alice"))
        );
    }

    #[test]
    fn paginated_existing_cursor_is_kept() {
        let mut request =
            Some(PaginatedRequestParams::default().with_cursor(Some("next".to_owned())));
        set_paginated_meta(
            &mut request,
            merged_meta(&RequestMetaObject::new(), Some("alice")),
        );
        let params = request.as_ref().expect("still present");
        assert_eq!(params.cursor.as_deref(), Some("next"));
        assert_eq!(
            params
                .meta
                .as_ref()
                .and_then(|meta| meta.get(CALLER_META_KEY)),
            Some(&json!("alice"))
        );
    }

    #[test]
    fn paginated_some_without_meta_clears_spoofed_typed_meta() {
        let mut params = PaginatedRequestParams::default();
        params.meta_or_default().insert(
            CALLER_META_KEY.to_owned(),
            serde_json::Value::String("mallory".to_owned()),
        );
        let mut request = Some(params);
        set_paginated_meta(&mut request, None);
        assert!(request.as_ref().expect("still present").meta.is_none());
    }
}
