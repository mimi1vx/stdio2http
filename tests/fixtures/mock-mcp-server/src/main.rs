//! Deterministic stdio MCP server used as the upstream child process in the
//! stdio2http integration tests.
//!
//! Exposes exactly two tools (`echo`, `whoami`) so assertions on tool names,
//! schemas and text output are stable.

// The `#[tool]`/`#[tool_handler]` macros fix the shape of the generated items:
// a `&self` receiver, extractor-owned arguments, and an `async fn` with no await
// in `list_tools`. The pedantic lints below do not apply to those shapes.
#![allow(
    clippy::needless_pass_by_value,
    clippy::ref_option,
    clippy::unused_async_trait_impl,
    clippy::unused_self
)]

use std::time::Duration;

use rmcp::{
    ServerHandler,
    handler::server::router::tool::ToolRouter,
    model::{
        CallToolResult, ContentBlock, Implementation, JsonObject, RequestMetaObject,
        ServerCapabilities, ServerConfig,
    },
    tool, tool_handler, tool_router,
};
use serde_json::{Value, json};

const SERVER_NAME: &str = "mock-mcp-server";
const SERVER_VERSION: &str = "0.1.0";

const CALLER_META_KEY: &str = "io.stdio2http/caller";
const NO_CALLER: &str = "<none>";

const DEBUG_ENV: &str = "MOCK_MCP_SERVER_DEBUG";
const EXIT_AFTER_ENV: &str = "MOCK_MCP_SERVER_EXIT_AFTER_MS";

struct Handler {
    tools: ToolRouter<Handler>,
}

#[tool_router]
impl Handler {
    fn new() -> Self {
        Self {
            tools: Self::tool_router(),
        }
    }

    /// Return the `message` argument unchanged.
    #[tool(name = "echo", input_schema = echo_input_schema())]
    fn echo(&self, args: JsonObject) -> CallToolResult {
        // Both arms are tool-level results (`isError`), never a JSON-RPC error.
        match echo_text(&Some(args)) {
            Ok(text) => CallToolResult::success(vec![ContentBlock::text(text)]),
            Err(message) => CallToolResult::error(vec![ContentBlock::text(message)]),
        }
    }

    /// Report the caller identity the proxy attached to this request.
    #[tool(name = "whoami")]
    fn whoami(&self, meta: RequestMetaObject) -> String {
        // Read from the extracted `meta`, not from `CallToolRequestParams::meta`:
        // rmcp deserialization strips the wire `params._meta` into the message
        // `Extensions`, and the service loop moves it into `RequestContext::meta`
        // before dispatch, so the typed params field is always empty.
        caller_from(&meta)
    }
}

#[tool_handler(router = self.tools)]
impl ServerHandler for Handler {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(SERVER_NAME, SERVER_VERSION))
    }
}

fn echo_input_schema() -> JsonObject {
    rmcp::model::object(json!({
        "type": "object",
        "properties": {
            "message": { "type": "string" }
        },
        "required": ["message"]
    }))
}

fn echo_text(args: &Option<JsonObject>) -> Result<String, String> {
    let message = args
        .as_ref()
        .and_then(|args| args.get("message"))
        .ok_or_else(|| "missing required argument `message`".to_owned())?;
    message
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| "argument `message` must be a string".to_owned())
}

fn caller_from(meta: &RequestMetaObject) -> String {
    meta.get(CALLER_META_KEY)
        .and_then(Value::as_str)
        .unwrap_or(NO_CALLER)
        .to_owned()
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{SERVER_NAME}: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    init_tracing();
    spawn_exit_timer();
    let service = rmcp::serve_server(Handler::new(), rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}

fn init_tracing() {
    // stdout carries the JSON-RPC stream, so every log line must go to stderr.
    let level = if std::env::var(DEBUG_ENV).as_deref() == Ok("1") {
        tracing::Level::DEBUG
    } else {
        tracing::Level::WARN
    };
    if let Err(error) = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(level)
        .try_init()
    {
        eprintln!("{SERVER_NAME}: tracing init failed: {error}");
    }
}

fn spawn_exit_timer() {
    // Lets the integration test prove the proxy treats a dead upstream child as
    // fatal instead of hanging on a request nobody will ever answer.
    if let Some(ms) = std::env::var(EXIT_AFTER_ENV)
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
    {
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(ms)).await;
            std::process::exit(0);
        });
    }
}

#[cfg(test)]
mod tests {
    use rmcp::RoleServer;

    use super::*;

    fn args(value: Value) -> Option<JsonObject> {
        value.as_object().cloned()
    }

    #[test]
    fn echo_text_reads_the_message_argument() {
        assert_eq!(
            echo_text(&args(json!({"message": "hi"}))).as_deref(),
            Ok("hi")
        );
    }

    #[test]
    fn echo_text_rejects_missing_and_mistyped_messages() {
        assert!(echo_text(&None).is_err());
        assert!(echo_text(&args(json!({}))).is_err());
        assert!(echo_text(&args(json!({"message": 7}))).is_err());
        assert!(
            echo_text(&args(json!({})))
                .expect_err("missing message must fail")
                .contains("message")
        );
    }

    #[test]
    fn caller_from_reads_the_meta_key_or_reports_none() {
        assert_eq!(caller_from(&RequestMetaObject::new()), NO_CALLER);

        let mut meta = RequestMetaObject::new();
        let previous = meta.insert(CALLER_META_KEY.to_owned(), json!("alice"));
        assert!(previous.is_none());
        assert_eq!(caller_from(&meta), "alice");
    }

    #[test]
    fn tool_catalog_is_exactly_echo_and_whoami() {
        let names: Vec<String> = Handler::new()
            .tools
            .list_all()
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();
        assert_eq!(names, ["echo", "whoami"]);
    }

    #[test]
    fn echo_schema_requires_a_string_message() {
        let schema = Handler::echo_tool_attr().input_schema;
        assert_eq!(schema.get("type"), Some(&json!("object")));
        assert_eq!(schema.get("required"), Some(&json!(["message"])));
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("input schema must declare properties");
        assert_eq!(
            properties.get("message").and_then(|p| p.get("type")),
            Some(&json!("string"))
        );
    }

    #[test]
    fn whoami_schema_declares_no_properties() {
        let schema = Handler::whoami_tool_attr().input_schema;
        assert_eq!(
            schema.get("properties").and_then(Value::as_object),
            Some(&JsonObject::new())
        );
    }

    #[test]
    fn server_identity_is_fixed() {
        let info = Handler::new().get_info();
        assert_eq!(info.server_info.name, SERVER_NAME);
        assert_eq!(info.server_info.version, SERVER_VERSION);
        assert!(info.capabilities.tools.is_some());
    }

    #[test]
    fn handler_is_a_role_server_service() {
        fn assert_service<S: rmcp::Service<RoleServer>>(_service: &S) {}
        assert_service(&Handler::new());
    }
}
