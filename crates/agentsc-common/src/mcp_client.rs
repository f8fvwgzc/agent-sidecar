//! An MCP client (protocol 2026-07-28, Streamable HTTP) for `type: mcp` tools: the sidecar calls
//! tools with it, and `agentsc mcp` reads servers' definitions with it (docs/design/mcp-tools.md).
//! The revision has no sessions: every request is one POST carrying its protocol version in
//! `_meta` and in headers, and the answer is a JSON object or an SSE stream scoped to that
//! request. Pins, `x-mcp-header`s and header encoding are in `agentsc_charter::mcp`.
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use agentsc_charter::ToolSpec;
use agentsc_charter::mcp::{self as spec, PROTOCOL_VERSION, ParamHeader};
use serde_json::{Value, json};

/// The tool is not in the server's `tools/list`, or its definition breaks MCP's `x-mcp-header`
/// rules (so a client must treat it as not listed).
pub const RULE_TOOL_MISSING: &str = "mcp.tool_missing";
/// The server's definition of the tool is not the one the charter pinned.
pub const RULE_PIN_MISMATCH: &str = "mcp.pin_mismatch";
/// The server does not speak MCP 2026-07-28.
pub const RULE_UNSUPPORTED_VERSION: &str = "mcp.unsupported_version";
/// The server answered `input_required` (an elicitation or sampling request), which the
/// sidecar does not answer: a tool error the model sees.
pub const RULE_INPUT_REQUIRED: &str = "mcp.input_required";
/// A JSON-RPC error, a transport error, or an answer that is not MCP.
pub const RULE_ERROR: &str = "mcp.error";
/// The tool's `credential` file could not be read.
pub const RULE_CREDENTIAL: &str = "mcp.credential_unavailable";
/// An answer longer than the reader takes (the sidecar's `--max-response-bytes`).
pub const RULE_RESPONSE_TOO_LARGE: &str = "http.response_too_large";

/// `UnsupportedProtocolVersionError` (MCP 2026-07-28).
const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;
/// How long a `tools/list` is kept without a `ttlMs`, and at most with one.
pub const DEFAULT_TTL: Duration = Duration::from_secs(300);
pub const MAX_TTL: Duration = Duration::from_secs(600);
/// `tools/list` pages followed at most.
pub const MAX_PAGES: usize = 20;
/// Longest server message quoted in a reason.
const MAX_QUOTE: usize = 500;

/// Why a request to a remote server (MCP, A2A) failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteError {
    pub rule: &'static str,
    pub reason: String,
    /// The reason quotes text the server wrote, which the model sees: it taints the run like an
    /// answer would.
    pub from_server: bool,
}

/// The MCP client's name for [`RemoteError`].
pub type McpError = RemoteError;

impl RemoteError {
    pub fn ours(rule: &'static str, reason: impl Into<String>) -> Self {
        Self {
            rule,
            reason: reason.into(),
            from_server: false,
        }
    }

    pub fn theirs(rule: &'static str, reason: impl Into<String>) -> Self {
        Self {
            rule,
            reason: reason.into(),
            from_server: true,
        }
    }
}

/// One MCP request: everything but the body's `jsonrpc`, `id` and `_meta`, which [`post`] adds.
pub struct Request<'a> {
    pub url: &'a str,
    /// `tools/list` or `tools/call` (also `Mcp-Method`).
    pub method: &'a str,
    /// `Mcp-Name` (`params.name` of a `tools/call`).
    pub name: Option<&'a str>,
    /// `params` without `_meta`: a JSON object.
    pub params: Value,
    /// `Mcp-Param-*` headers, values already encoded.
    pub param_headers: Vec<(String, String)>,
    pub bearer: Option<&'a str>,
    /// The span this request belongs to: the `traceparent` header and `_meta.traceparent`.
    pub traceparent: Option<String>,
    pub request_id: Option<&'a str>,
    /// The whole request, the answer read to its end included.
    pub timeout: Duration,
    /// The most read of the answer, JSON or SSE (the sidecar's `--max-response-bytes`).
    pub max_bytes: usize,
}

/// Send `r` and return the JSON-RPC `result` of its response.
pub async fn post(client: &reqwest::Client, r: Request<'_>) -> Result<Value, McpError> {
    let id = uuid::Uuid::new_v4().to_string();
    let mut params = match r.params {
        Value::Object(m) => m,
        _ => serde_json::Map::new(),
    };
    let mut meta = json!({
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": {"name": "agentscd", "version": env!("CARGO_PKG_VERSION")},
        "io.modelcontextprotocol/clientCapabilities": {},
    });
    if let Some(tp) = &r.traceparent {
        meta["traceparent"] = json!(tp);
    }
    params.insert("_meta".into(), meta);
    let body = json!({"jsonrpc": "2.0", "id": id, "method": r.method, "params": params});

    let mut req = client
        .post(r.url)
        .timeout(r.timeout)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", PROTOCOL_VERSION)
        .header("mcp-method", r.method);
    if let Some(name) = r.name {
        req = req.header("mcp-name", spec::encode_header_value(name));
    }
    for (k, v) in &r.param_headers {
        req = req.header(k.as_str(), v.as_str());
    }
    if let Some(token) = r.bearer {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    if let Some(tp) = &r.traceparent {
        req = req.header("traceparent", tp);
    }
    if let Some(rid) = r.request_id {
        req = req.header("x-agentsc-request-id", rid);
    }
    let resp = req
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| McpError::ours(RULE_ERROR, format!("{} {}: {e}", r.method, r.url)))?;
    let status = resp.status();
    let ctype = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if status.is_success() && ctype.starts_with("text/event-stream") {
        return read_sse(resp, &id, r.max_bytes).await;
    }
    let body = read_capped(resp, r.max_bytes).await?;
    let msg: Option<Value> = serde_json::from_slice(&body).ok();
    if !status.is_success() {
        return Err(http_error(status.as_u16(), msg.as_ref(), &body));
    }
    match msg {
        Some(m) => match response_of(&m, &id) {
            Some(r) => r,
            None => Err(McpError::ours(
                RULE_ERROR,
                "the server's JSON answer is not the response to this request",
            )),
        },
        None => Err(McpError::ours(
            RULE_ERROR,
            format!("the server answered HTTP {status} with {ctype:?}, not a JSON-RPC response"),
        )),
    }
}

/// A JSON answer, chunk by chunk, refused past `max` bytes.
pub(crate) async fn read_capped(
    mut resp: reqwest::Response,
    max: usize,
) -> Result<Vec<u8>, McpError> {
    let too_large = || {
        McpError::ours(
            RULE_RESPONSE_TOO_LARGE,
            format!("the answer is longer than the {max} bytes read"),
        )
    };
    if resp.content_length().is_some_and(|n| n > max as u64) {
        return Err(too_large());
    }
    let mut body = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > max {
                    return Err(too_large());
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok(body),
            Err(e) => {
                return Err(McpError::ours(
                    RULE_ERROR,
                    format!("the answer broke off: {e}"),
                ));
            }
        }
    }
}

/// A non-2xx answer. A modern server says why in a JSON-RPC error; a 400, 404 or 405 without one
/// is a server of an older revision (MCP, Streamable HTTP: Backward Compatibility).
fn http_error(status: u16, msg: Option<&Value>, body: &[u8]) -> McpError {
    if let Some(err) = msg.and_then(|m| m.get("error")) {
        return rpc_error(err, Some(status));
    }
    if matches!(status, 400 | 404 | 405) {
        return McpError::ours(
            RULE_UNSUPPORTED_VERSION,
            format!(
                "the server answered HTTP {status} without an MCP error: it does not speak MCP {PROTOCOL_VERSION} (older revisions, with sessions, are not supported)"
            ),
        );
    }
    let text = quote(&String::from_utf8_lossy(body));
    if text.is_empty() {
        McpError::ours(RULE_ERROR, format!("the server answered HTTP {status}"))
    } else {
        McpError::theirs(
            RULE_ERROR,
            format!("the server answered HTTP {status}: {text}"),
        )
    }
}

/// A JSON-RPC `error` object as an [`McpError`].
fn rpc_error(err: &Value, status: Option<u16>) -> McpError {
    let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
    let message = quote(err.get("message").and_then(Value::as_str).unwrap_or(""));
    if code == UNSUPPORTED_PROTOCOL_VERSION {
        let supported = err
            .pointer("/data/supported")
            .map(Value::to_string)
            .unwrap_or_else(|| "[]".into());
        return McpError::theirs(
            RULE_UNSUPPORTED_VERSION,
            format!(
                "the server does not support MCP {PROTOCOL_VERSION} (it supports {supported}): {message}"
            ),
        );
    }
    let http = status.map(|s| format!("HTTP {s}, ")).unwrap_or_default();
    McpError::theirs(
        RULE_ERROR,
        format!("{http}JSON-RPC error {code}: {message}"),
    )
}

/// `Some` when `m` is the response with this id: its `result`, or its `error`.
fn response_of(m: &Value, id: &str) -> Option<Result<Value, McpError>> {
    if m.get("id").and_then(Value::as_str) != Some(id) {
        return None;
    }
    if let Some(err) = m.get("error") {
        return Some(Err(rpc_error(err, None)));
    }
    Some(
        m.get("result")
            .cloned()
            .ok_or_else(|| McpError::ours(RULE_ERROR, "the response has neither result nor error")),
    )
}

/// Read an SSE stream up to the response with this id, skipping notifications and comments, at
/// most `max` bytes in all. Dropping the stream after it (or on error) closes it, which MCP
/// treats as cancellation.
async fn read_sse(mut resp: reqwest::Response, id: &str, max: usize) -> Result<Value, McpError> {
    let too_large = || {
        McpError::ours(
            RULE_RESPONSE_TOO_LARGE,
            format!("the SSE stream is longer than the {max} bytes read"),
        )
    };
    let mut pending: Vec<u8> = Vec::new();
    let mut data = String::new();
    let mut total = 0usize;
    loop {
        let chunk = match resp.chunk().await {
            Ok(Some(c)) => c,
            Ok(None) => break,
            Err(e) => {
                return Err(McpError::ours(
                    RULE_ERROR,
                    format!("the SSE stream broke off: {e}"),
                ));
            }
        };
        total += chunk.len();
        if total > max {
            return Err(too_large());
        }
        pending.extend_from_slice(&chunk);
        while let Some(end) = pending.iter().position(|&b| b == b'\n') {
            let mut raw: Vec<u8> = pending.drain(..=end).collect();
            raw.pop();
            if raw.last() == Some(&b'\r') {
                raw.pop();
            }
            let line = String::from_utf8_lossy(&raw);
            if line.is_empty() {
                if let Some(r) = dispatch(&data, id) {
                    return r;
                }
                data.clear();
            } else if !line.starts_with(':') {
                let (field, value) = match line.split_once(':') {
                    Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
                    None => (line.as_ref(), ""),
                };
                if field == "data" {
                    if !data.is_empty() {
                        data.push('\n');
                    }
                    data.push_str(value);
                }
            }
        }
    }
    if let Some(r) = dispatch(&data, id) {
        return r;
    }
    Err(McpError::ours(
        RULE_ERROR,
        "the SSE stream ended without the response",
    ))
}

/// One SSE event's data: `Some` when it is the response to this request.
fn dispatch(data: &str, id: &str) -> Option<Result<Value, McpError>> {
    if data.is_empty() {
        return None;
    }
    let m: Value = serde_json::from_str(data).ok()?;
    response_of(&m, id)
}

pub(crate) fn quote(s: &str) -> String {
    let s = s.trim();
    if s.len() <= MAX_QUOTE {
        return s.to_string();
    }
    let mut end = MAX_QUOTE;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// What a `tools/call` came back with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// `resultType: complete` (or none): the content as text, and the server's `isError`.
    Complete { text: String, is_error: bool },
    /// `resultType: input_required`: what the server asked for, as text.
    InputRequired { text: String },
}

/// The outcome of a `tools/call` result.
pub fn outcome(result: &Value) -> Result<Outcome, McpError> {
    match result.get("resultType").and_then(Value::as_str) {
        None | Some("complete") => Ok(Outcome::Complete {
            text: render(result),
            is_error: result.get("isError").and_then(Value::as_bool) == Some(true),
        }),
        Some("input_required") => Ok(Outcome::InputRequired {
            text: input_required_text(result),
        }),
        Some(other) => Err(McpError::theirs(
            RULE_ERROR,
            format!(
                "the server answered resultType {:?}, which the sidecar does not handle",
                quote(other)
            ),
        )),
    }
}

/// A tool result's content as text: text blocks as they are, an embedded text resource's text,
/// a one-line placeholder for media and blobs, a resource link's name and URI; the
/// `structuredContent` as JSON when no block carried text.
pub fn render(result: &Value) -> String {
    let mut parts = Vec::new();
    let mut has_text = false;
    for block in result
        .get("content")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let s = |k: &str| block.get(k).and_then(Value::as_str).unwrap_or("");
        match s("type") {
            "text" => {
                has_text = true;
                parts.push(s("text").to_string());
            }
            kind @ ("image" | "audio") => {
                parts.push(format!(
                    "[{kind} {}, {}, not shown]",
                    s("mimeType"),
                    size(s("data"))
                ));
            }
            "resource_link" => {
                let name = if s("name").is_empty() {
                    s("uri")
                } else {
                    s("name")
                };
                parts.push(format!("[resource {name}: {}]", s("uri")));
            }
            "resource" => {
                let r = block.get("resource").cloned().unwrap_or(Value::Null);
                let rs = |k: &str| r.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                match r.get("text").and_then(Value::as_str) {
                    Some(text) => {
                        has_text = true;
                        parts.push(format!("[resource {}]\n{text}", rs("uri")));
                    }
                    None => parts.push(format!(
                        "[resource {} {}, {}, not shown]",
                        rs("uri"),
                        rs("mimeType"),
                        size(&rs("blob"))
                    )),
                }
            }
            other => parts.push(format!("[{} content, not shown]", quote(other))),
        }
    }
    if !has_text && let Some(sc) = result.get("structuredContent") {
        parts.insert(0, sc.to_string());
    }
    if parts.is_empty() {
        return "(no content)".into();
    }
    parts.join("\n")
}

/// The decoded size of base64 `data`, roughly, for a placeholder.
fn size(data: &str) -> String {
    let bytes = data.len() / 4 * 3;
    if bytes >= 1024 {
        format!("{} KB", bytes.div_ceil(1024))
    } else {
        format!("{bytes} B")
    }
}

/// What an `input_required` result asked for.
fn input_required_text(result: &Value) -> String {
    let mut asks = Vec::new();
    if let Some(reqs) = result.get("inputRequests").and_then(Value::as_object) {
        for r in reqs.values() {
            let method = r.get("method").and_then(Value::as_str).unwrap_or("?");
            let message = r
                .pointer("/params/message")
                .and_then(Value::as_str)
                .map(quote)
                .unwrap_or_default();
            asks.push(if message.is_empty() {
                method.to_string()
            } else {
                format!("{method}: {message}")
            });
        }
    }
    let asked = if asks.is_empty() {
        String::new()
    } else {
        format!(" It asked for: {}.", asks.join("; "))
    };
    format!(
        "The MCP server needs more input to run this tool, which this sidecar does not provide ({RULE_INPUT_REQUIRED}).{asked} Ask your caller if you need it."
    )
}

/// What each `tools/list` request carries.
pub struct ListOptions<'a> {
    pub bearer: Option<&'a str>,
    pub traceparent: Option<&'a str>,
    pub request_id: Option<&'a str>,
    /// The timeout of each page's request, asked before it is sent (a deadline shrinks it).
    pub timeout: &'a (dyn Fn() -> Duration + Send + Sync),
    pub max_bytes: usize,
}

/// The server's tools at `url` (at most [`MAX_PAGES`] pages; the first definition of a name
/// wins), and how long to keep them: `ttlMs`, at most [`MAX_TTL`], else [`DEFAULT_TTL`].
pub async fn list_tools(
    client: &reqwest::Client,
    url: &str,
    c: &ListOptions<'_>,
) -> Result<(HashMap<String, Value>, Duration), McpError> {
    let mut tools = HashMap::new();
    let mut cursor: Option<String> = None;
    let mut ttl = None;
    for _ in 0..MAX_PAGES {
        let params = match &cursor {
            Some(cur) => json!({ "cursor": cur }),
            None => json!({}),
        };
        let result = post(
            client,
            Request {
                url,
                method: "tools/list",
                name: None,
                params,
                param_headers: Vec::new(),
                bearer: c.bearer,
                traceparent: c.traceparent.map(str::to_string),
                request_id: c.request_id,
                timeout: (c.timeout)(),
                max_bytes: c.max_bytes,
            },
        )
        .await?;
        if ttl.is_none() {
            ttl = result
                .get("ttlMs")
                .and_then(Value::as_u64)
                .map(Duration::from_millis);
        }
        for t in result
            .get("tools")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(name) = t.get("name").and_then(Value::as_str) {
                tools.entry(name.to_string()).or_insert_with(|| t.clone());
            }
        }
        match result.get("nextCursor").and_then(Value::as_str) {
            Some(next) if !next.is_empty() => cursor = Some(next.to_string()),
            _ => break,
        }
    }
    Ok((tools, ttl.map_or(DEFAULT_TTL, |t| t.min(MAX_TTL))))
}

/// The pin check of one listed definition (decisions 6 and 8): the `x-mcp-header`s it declares,
/// or the refusal.
pub fn check(
    tool: &ToolSpec,
    def: Option<&Value>,
) -> Result<Vec<ParamHeader>, (&'static str, String)> {
    let name = tool.mcp_tool_name();
    let url = tool.url.as_deref().unwrap_or("");
    let Some(def) = def else {
        return Err((
            RULE_TOOL_MISSING,
            format!("the MCP server at {url} lists no tool {name:?}"),
        ));
    };
    let headers = match def.get("inputSchema") {
        Some(s @ Value::Object(_)) => spec::param_headers(s),
        _ => Err("it has no inputSchema object".to_string()),
    }
    .map_err(|e| {
        (
            RULE_TOOL_MISSING,
            format!("the MCP server's definition of {name:?} is invalid, so it counts as not listed: {e}"),
        )
    })?;
    let got = spec::definition_pin(def);
    if Some(got.as_str()) != tool.pin.as_deref() {
        return Err((
            RULE_PIN_MISMATCH,
            format!(
                "the MCP server's definition of {name:?} changed: it is {got}, the charter pins {}; review it (agentsc mcp check) and pin it again",
                tool.pin.as_deref().unwrap_or("nothing")
            ),
        ));
    }
    Ok(headers)
}

/// The bearer token of a `credential: {secret}`: the file `<dir>/<secret>`, trimmed. The name is
/// a DNS-1123 label (the charter's rule, checked again here), so it is never a path.
pub async fn read_credential(dir: &Path, secret: &str) -> Result<String, String> {
    if !agentsc_charter::is_dns_label(secret) {
        return Err(format!("credential {secret:?} is not a DNS-1123 label"));
    }
    let text = tokio::fs::read_to_string(dir.join(secret))
        .await
        .map_err(|e| {
            format!(
                "credential {secret}: cannot read it from {}: {e}",
                dir.display()
            )
        })?;
    let token = text.trim();
    if token.is_empty() || token.chars().any(char::is_control) {
        return Err(format!(
            "credential {secret}: the file is empty or not a single-line token"
        ));
    }
    Ok(token.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn results_render_as_the_text_the_model_sees() {
        let r = json!({"resultType": "complete", "content": [
            {"type": "text", "text": "two issues"},
            {"type": "image", "mimeType": "image/png", "data": "A".repeat(4096)},
            {"type": "resource_link", "uri": "file:///a.rs", "name": "a.rs"},
            {"type": "resource", "resource": {"uri": "file:///b.txt", "text": "hello"}},
            {"type": "resource", "resource": {"uri": "file:///c.bin", "mimeType": "application/zip", "blob": "AAAA"}},
            {"type": "hologram"}
        ], "structuredContent": {"count": 2}});
        assert_eq!(
            render(&r),
            "two issues\n[image image/png, 3 KB, not shown]\n[resource a.rs: file:///a.rs]\n[resource file:///b.txt]\nhello\n[resource file:///c.bin application/zip, 3 B, not shown]\n[hologram content, not shown]"
        );
        assert_eq!(
            outcome(&r).unwrap(),
            Outcome::Complete {
                text: render(&r),
                is_error: false
            }
        );
        // structured content only when no block carried text
        let r = json!({"content": [], "structuredContent": {"count": 2}, "isError": true});
        assert_eq!(
            outcome(&r).unwrap(),
            Outcome::Complete {
                text: r#"{"count":2}"#.into(),
                is_error: true
            }
        );
        assert_eq!(render(&json!({"resultType": "complete"})), "(no content)");
        let r = json!({"resultType": "input_required", "inputRequests": {"login": {
            "method": "elicitation/create", "params": {"mode": "form", "message": "Your GitHub username?"}}},
            "requestState": "abc"});
        let Outcome::InputRequired { text } = outcome(&r).unwrap() else {
            panic!()
        };
        assert!(
            text.contains("elicitation/create: Your GitHub username?"),
            "{text}"
        );
        assert!(text.contains(RULE_INPUT_REQUIRED), "{text}");
        assert_eq!(
            outcome(&json!({"resultType": "task"})).unwrap_err().rule,
            RULE_ERROR
        );
    }

    #[test]
    fn errors_name_the_rule() {
        let e = http_error(
            400,
            Some(&json!({"jsonrpc": "2.0", "id": "1", "error": {
            "code": -32022, "message": "Unsupported protocol version", "data": {"supported": ["2025-11-25"]}}})),
            b"",
        );
        assert_eq!(e.rule, RULE_UNSUPPORTED_VERSION);
        assert!(e.reason.contains("2025-11-25"), "{}", e.reason);
        let e = http_error(400, None, b"Bad Request: No valid session ID provided");
        assert_eq!(e.rule, RULE_UNSUPPORTED_VERSION);
        assert!(!e.from_server);
        let e = http_error(
            400,
            Some(&json!({"error": {"code": -32020, "message": "Header mismatch"}})),
            b"",
        );
        assert_eq!((e.rule, e.from_server), (RULE_ERROR, true));
        assert!(e.reason.contains("-32020"), "{}", e.reason);
        let e = http_error(502, None, b"");
        assert_eq!(e.reason, "the server answered HTTP 502");
        assert_eq!(
            response_of(&json!({"id": "x", "result": {}}), "y"),
            None,
            "another request's response is not ours"
        );
    }
}
