//! The downstream `ServerHandler`. Every method is a pass-through to the shared
//! upstream peer; rmcp owns sessions, framing, and negotiation around it.

use std::sync::Arc;

use rmcp::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CompleteRequestParams, CompleteResult, ErrorCode,
    ErrorData, GetPromptRequestParams, GetPromptResponse, ListPromptsResult,
    ListResourceTemplatesResult, ListResourcesResult, ListToolsResult, PaginatedRequestParams,
    ProtocolVersion, ReadResourceRequestParams, ReadResourceResponse, ServerConfig,
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

/// Stamp the caller into the outgoing `_meta`. The child's env is fixed at spawn,
/// so this per-request channel is the only way identity can reach it.
fn stamp_caller<T: rmcp::model::RequestParamsMeta>(
    params: &mut T,
    context: &RequestContext<RoleServer>,
) {
    if let Some(subject) = caller_of(context) {
        params.meta_or_default().insert(
            CALLER_META_KEY.to_string(),
            serde_json::Value::String(subject),
        );
    }
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
        if let Some(params) = request.as_mut() {
            stamp_caller(params, &context);
        }
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
        if let Some(params) = request.as_mut() {
            stamp_caller(params, &context);
        }
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
        if let Some(params) = request.as_mut() {
            stamp_caller(params, &context);
        }
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
        if let Some(params) = request.as_mut() {
            stamp_caller(params, &context);
        }
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
