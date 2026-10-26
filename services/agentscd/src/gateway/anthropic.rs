//! The Anthropic Messages API adapter of the model gateway (`POST /v1/messages`).
//!
//! The request may carry only the fields the runtime sends (an allow-list, so a new field that
//! bills differently, like `speed`, never gets through unseen) and only custom tools: a server
//! tool (`type: web_search_…`, `code_execution_…`) bills per use, outside the token price. The
//! key is the sidecar's (`x-api-key`); the runtime's `x-api-key`, `authorization` and
//! `anthropic-beta` are never forwarded.
//!
//! The meter reads the SSE stream as it passes: `message_start` carries the input and cache
//! counts, `message_delta` the output count so far (cumulative; newer API versions repeat the
//! input counts there too, so each count keeps the largest value seen), `content_block_*` the
//! content, and an `error` event the provider's mid-stream error. A stream that breaks keeps the
//! counts it had: the provider bills what it reported.
use axum::http::{HeaderMap, StatusCode};
use serde_json::{Map, Value, json};

use super::{Checked, Ended, Meter, Metered, Provider, Wire};
use agentsc_common::llm_contract::SecretSource;
use agentsc_common::pricing::Usage;

pub const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
/// Sent when the runtime names no version.
pub const DEFAULT_VERSION: &str = "2023-06-01";
/// The request fields that may reach the API.
pub const ALLOWED_FIELDS: &[&str] = &[
    "model",
    "max_tokens",
    "messages",
    "system",
    "tools",
    "tool_choice",
    "stream",
    "stop_sequences",
    "metadata",
    "thinking",
    "output_config",
    // sampling: no effect on the price
    "temperature",
    "top_p",
    "top_k",
];
/// A non-streamed answer is read up to this size for its usage.
const MAX_BODY_METERED: usize = 16 * 1024 * 1024;

pub struct Anthropic {
    key: SecretSource,
    base_url: String,
}

impl Anthropic {
    pub fn new(key: String, base_url: &str) -> Self {
        Self::with_key(SecretSource::Text(key), base_url)
    }

    /// The key from `key`, read again for every request (a key file's rotation applies to the
    /// next call).
    pub fn with_key(key: SecretSource, base_url: &str) -> Self {
        Self {
            key,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }
}

/// The `anthropic-version` of an incoming request, if it is a plain version name.
pub(crate) fn version(incoming: &HeaderMap) -> &str {
    incoming
        .get("anthropic-version")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty() && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        .unwrap_or(DEFAULT_VERSION)
}

impl Provider for Anthropic {
    fn name(&self) -> &'static str {
        "anthropic"
    }

    fn wire(&self) -> Wire {
        Wire::Messages
    }

    fn request(
        &self,
        client: &reqwest::Client,
        body: Vec<u8>,
        incoming: &HeaderMap,
    ) -> Result<reqwest::RequestBuilder, String> {
        let key = self.key.read()?;
        Ok(client
            .post(format!("{}/v1/messages", self.base_url))
            .header("x-api-key", key)
            .header("anthropic-version", version(incoming))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(body))
    }
}

/// Check a Messages request body; `Err` is the reason it is refused (`model.request_invalid`).
pub fn check(body: &Map<String, Value>) -> Result<Checked, String> {
    if body.contains_key("fallbacks") {
        return Err(
            "request field \"fallbacks\" may answer with another model than the request names, \
             at that model's price: turn it off (onto-intelli: llm.fallbacks = false)"
                .into(),
        );
    }
    if let Some(f) = body.keys().find(|k| !ALLOWED_FIELDS.contains(&k.as_str())) {
        return Err(format!(
            "request field {f:?} is not one the gateway forwards"
        ));
    }
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .filter(|m| !m.is_empty())
        .ok_or("the request names no model")?
        .to_string();
    let max_tokens = body
        .get("max_tokens")
        .and_then(Value::as_u64)
        .ok_or("max_tokens must be a non-negative integer")?;
    let stream = match body.get("stream") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err("stream must be a boolean".into()),
    };
    for t in body
        .get("tools")
        .map(|t| t.as_array().ok_or("tools must be an array"))
        .transpose()?
        .into_iter()
        .flatten()
    {
        match t.get("type").and_then(Value::as_str) {
            None | Some("custom") => {}
            Some(other) => {
                return Err(format!(
                    "tool type {other:?} is a server tool, billed outside the token price"
                ));
            }
        }
        if t.get("name").and_then(Value::as_str).is_none() {
            return Err("every tool needs a name".into());
        }
    }
    let messages = body
        .get("messages")
        .and_then(Value::as_array)
        .ok_or("messages must be an array")?;
    let mut has_media = false;
    for part in [body.get("messages"), body.get("system")]
        .into_iter()
        .flatten()
    {
        scan_media(part, &mut has_media)?;
    }
    let assistant_turns = messages
        .iter()
        .filter(|m| m.get("role").and_then(Value::as_str) == Some("assistant"))
        .count();
    Ok(Checked {
        model,
        max_tokens: Some(max_tokens),
        stream,
        assistant_turns: u32::try_from(assistant_turns).unwrap_or(u32::MAX),
        has_media,
        stored_state: false,
    })
}

/// A meter for one Messages answer.
pub fn meter(stream: bool) -> Box<dyn Meter> {
    Box::new(SseMeter {
        stream,
        ..SseMeter::default()
    })
}

/// Content blocks whose tokens their bytes do not bound (a page of a PDF bills its text and an
/// image of it; an image bills by its pixels).
const MEDIA_BLOCKS: &[&str] = &["image", "document", "search_result", "container_upload"];

/// Find media blocks anywhere in `v` (tool results nest them too), and refuse a `source` the
/// provider would fetch from a URL: that is egress outside the sidecar's tool policy, and its
/// size, so its cost, is unknown until the provider has fetched it.
fn scan_media(v: &Value, found: &mut bool) -> Result<(), String> {
    match v {
        Value::Object(m) => {
            if m.get("source")
                .and_then(|s| s.get("type"))
                .and_then(Value::as_str)
                == Some("url")
            {
                return Err(
                    "a content block's source is a URL, which the provider would fetch outside the sidecar's tool policy"
                        .into(),
                );
            }
            if m.get("type")
                .and_then(Value::as_str)
                .is_some_and(|t| MEDIA_BLOCKS.contains(&t))
            {
                *found = true;
            }
            for x in m.values() {
                scan_media(x, found)?;
            }
        }
        Value::Array(a) => {
            for x in a {
                scan_media(x, found)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Reads one answer: SSE events when `stream`, else the JSON body.
#[derive(Default)]
pub struct SseMeter {
    stream: bool,
    buf: Vec<u8>,
    usage: Usage,
    blocks: Vec<Value>,
    /// The `partial_json` of each tool_use block, by index.
    partial: Vec<String>,
    stop_reason: Option<String>,
    error: Option<String>,
    /// `message_stop` arrived: the stream ended as the provider meant it to.
    stopped: bool,
}

fn n(v: &Value, key: &str) -> u64 {
    v.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn error_text(v: &Value) -> Option<String> {
    let e = v.get("error")?;
    let kind = e.get("type").and_then(Value::as_str).unwrap_or("error");
    let msg = e.get("message").and_then(Value::as_str).unwrap_or("");
    Some(format!("{kind}: {msg}"))
}

impl SseMeter {
    fn usage(&mut self, u: &Value) {
        let m = &mut self.usage;
        m.input = m.input.max(n(u, "input_tokens"));
        m.output = m.output.max(n(u, "output_tokens"));
        m.cache_read = m.cache_read.max(n(u, "cache_read_input_tokens"));
        let total_write = n(u, "cache_creation_input_tokens");
        match u.get("cache_creation") {
            Some(by_ttl) if by_ttl.is_object() => {
                m.cache_write_5m = m.cache_write_5m.max(n(by_ttl, "ephemeral_5m_input_tokens"));
                m.cache_write_1h = m.cache_write_1h.max(n(by_ttl, "ephemeral_1h_input_tokens"));
                let known = m.cache_write_5m + m.cache_write_1h;
                m.cache_write_unknown =
                    m.cache_write_unknown.max(total_write.saturating_sub(known));
            }
            _ => {
                let known = m.cache_write_5m + m.cache_write_1h;
                m.cache_write_unknown =
                    m.cache_write_unknown.max(total_write.saturating_sub(known));
            }
        }
    }

    fn block(&mut self, index: usize) -> Option<&mut Value> {
        self.blocks.get_mut(index)
    }

    fn event(&mut self, data: &Value) {
        let index = data
            .get("index")
            .and_then(Value::as_u64)
            .map(|i| i as usize);
        match data.get("type").and_then(Value::as_str).unwrap_or("") {
            "message_start" => {
                if let Some(u) = data.get("message").and_then(|m| m.get("usage")) {
                    self.usage(&u.clone());
                }
            }
            "content_block_start" => {
                if let (Some(i), Some(b)) = (index, data.get("content_block")) {
                    if self.blocks.len() <= i {
                        self.blocks.resize(i + 1, Value::Null);
                        self.partial.resize(i + 1, String::new());
                    }
                    self.blocks[i] = b.clone();
                }
            }
            "content_block_delta" => {
                let (Some(i), Some(d)) = (index, data.get("delta")) else {
                    return;
                };
                let d = d.clone();
                match d.get("type").and_then(Value::as_str).unwrap_or("") {
                    "text_delta" => append(self.block(i), "text", &d),
                    "thinking_delta" => append(self.block(i), "thinking", &d),
                    "signature_delta" => {
                        if let Some(b) = self.block(i).and_then(Value::as_object_mut) {
                            b.insert(
                                "signature".into(),
                                d.get("signature").cloned().unwrap_or_default(),
                            );
                        }
                    }
                    "input_json_delta" => {
                        if let Some(p) = self.partial.get_mut(i) {
                            p.push_str(d.get("partial_json").and_then(Value::as_str).unwrap_or(""));
                        }
                    }
                    "citations_delta" => {
                        if let (Some(b), Some(c)) = (
                            self.block(i).and_then(Value::as_object_mut),
                            d.get("citation"),
                        ) {
                            let list = b.entry("citations").or_insert_with(|| json!([]));
                            if let Some(a) = list.as_array_mut() {
                                a.push(c.clone());
                            }
                        }
                    }
                    _ => {}
                }
            }
            "content_block_stop" => {
                let Some(i) = index else { return };
                let partial = self.partial.get(i).cloned().unwrap_or_default();
                if let Some(b) = self.block(i).and_then(Value::as_object_mut)
                    && b.get("type").and_then(Value::as_str) == Some("tool_use")
                    && !partial.is_empty()
                {
                    let input = serde_json::from_str(&partial).unwrap_or(Value::String(partial));
                    b.insert("input".into(), input);
                }
            }
            "message_delta" => {
                if let Some(r) = data
                    .get("delta")
                    .and_then(|d| d.get("stop_reason"))
                    .and_then(Value::as_str)
                {
                    self.stop_reason = Some(r.to_string());
                }
                if let Some(u) = data.get("usage") {
                    self.usage(&u.clone());
                }
            }
            "error" => self.error = error_text(data),
            "message_stop" => self.stopped = true,
            _ => {}
        }
    }

    fn drain_events(&mut self) {
        while let Some(end) = find_event_end(&self.buf) {
            let raw: Vec<u8> = self.buf.drain(..end).collect();
            let text = String::from_utf8_lossy(&raw);
            let data: String = text
                .lines()
                .filter_map(|l| l.trim_end_matches('\r').strip_prefix("data:"))
                .map(str::trim_start)
                .collect::<Vec<_>>()
                .join("\n");
            if let Ok(v) = serde_json::from_str::<Value>(&data) {
                self.event(&v);
            }
        }
    }
}

/// The end (exclusive, past the blank line) of the first complete SSE event in `buf`.
pub(crate) fn find_event_end(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len() {
        if buf[i..].starts_with(b"\n\n") {
            return Some(i + 2);
        }
        if buf[i..].starts_with(b"\r\n\r\n") {
            return Some(i + 4);
        }
    }
    None
}

fn append(block: Option<&mut Value>, field: &str, delta: &Value) {
    let Some(b) = block.and_then(Value::as_object_mut) else {
        return;
    };
    let add = delta.get(field).and_then(Value::as_str).unwrap_or("");
    let cur = b
        .entry(field)
        .or_insert_with(|| Value::String(String::new()));
    if let Value::String(s) = cur {
        s.push_str(add);
    }
}

impl Meter for SseMeter {
    fn feed(&mut self, chunk: &[u8]) {
        if !self.stream {
            if self.buf.len() < MAX_BODY_METERED {
                self.buf.extend_from_slice(chunk);
            }
            return;
        }
        self.buf.extend_from_slice(chunk);
        self.drain_events();
    }

    fn finish(mut self: Box<Self>, status: StatusCode) -> Metered {
        let mut ended = Ended::Cut;
        if !status.is_success() {
            // the provider answered with an error: it generated nothing
            ended = Ended::Refused;
        }
        if self.stream {
            self.buf.extend_from_slice(b"\n\n");
            self.drain_events();
            if self.stopped && self.error.is_none() {
                ended = Ended::Completed;
            }
        } else if let Ok(v) = serde_json::from_slice::<Value>(&self.buf) {
            if status.is_success() {
                if v.get("usage").is_some() {
                    ended = Ended::Completed;
                }
                if let Some(u) = v.get("usage") {
                    self.usage(&u.clone());
                }
                self.blocks = v
                    .get("content")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                self.stop_reason = v
                    .get("stop_reason")
                    .and_then(Value::as_str)
                    .map(str::to_string);
            } else {
                self.error = error_text(&v);
            }
        }
        let content = if self.blocks.is_empty() {
            Value::Null
        } else {
            Value::Array(self.blocks.into_iter().filter(|b| !b.is_null()).collect())
        };
        Metered {
            usage: self.usage,
            ended,
            content,
            stop_reason: self.stop_reason,
            error: self.error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sse(events: &[Value]) -> Vec<u8> {
        events
            .iter()
            .map(|e| format!("event: {}\ndata: {e}\n\n", e["type"].as_str().unwrap()))
            .collect::<String>()
            .into_bytes()
    }

    fn body(v: Value) -> Map<String, Value> {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn requests_keep_to_the_allowed_fields_and_custom_tools() {
        let a = Anthropic::new("k".into(), DEFAULT_BASE_URL);
        let ok = a
            .check(&body(json!({
                "model": "claude-opus-5-5", "max_tokens": 64, "stream": true,
                "messages": [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "x"},
                             {"role": "user", "content": "y"}],
                "tools": [{"name": "lookup", "input_schema": {}}],
                "output_config": {"effort": "low"}
            })))
            .unwrap();
        assert_eq!(
            ok,
            Checked {
                model: "claude-opus-5-5".into(),
                max_tokens: Some(64),
                stream: true,
                assistant_turns: 1,
                has_media: false,
                stored_state: false
            }
        );
        for (bad, why) in [
            (
                json!({"model": "m", "max_tokens": 1, "messages": [], "speed": "fast"}),
                "speed",
            ),
            (
                json!({"model": "m", "max_tokens": 1, "messages": [],
                    "tools": [{"type": "web_search_20260209", "name": "web_search"}]}),
                "server tool",
            ),
            (json!({"model": "m", "messages": []}), "max_tokens"),
            (json!({"max_tokens": 1, "messages": []}), "no model"),
            (
                json!({"model": "m", "max_tokens": -1, "messages": []}),
                "negative",
            ),
        ] {
            assert!(a.check(&body(bad)).is_err(), "{why}");
        }
    }

    /// The review finding: gateway-mode clients were refused for fields they send by default.
    /// These are the bodies texc-symphony (symphony-agents api/anthropic.rs) and onto-intelli
    /// (llm/anthropic.rs) build.
    #[test]
    fn the_platform_clients_bodies_pass() {
        let texc = json!({
            "model": "claude-opus-5-5", "max_tokens": 4096, "system": "You are a coding agent.",
            "messages": [
                {"role": "user", "content": "fix the test"},
                {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "read", "input": {"path": "a.rs"}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "fn a() {}", "is_error": false}]}
            ],
            "tools": [{"name": "read", "description": "read a file", "input_schema": {"type": "object"}}],
            "temperature": 0.5, "stream": true
        });
        assert_eq!(check(&body(texc)).unwrap().assistant_turns, 1);
        let mut onto = json!({
            "model": "claude-opus-5-5", "max_tokens": 2048,
            "system": [{"type": "text", "text": "Answer from the ontology.", "cache_control": {"type": "ephemeral"}}],
            "messages": [{"role": "user", "content": "what depends on orders?"}],
            "output_config": {"effort": "low"}, "stream": true
        });
        assert!(check(&body(onto.clone())).is_ok(), "llm.fallbacks = false");
        onto["fallbacks"] = json!("default");
        let e = check(&body(onto)).unwrap_err();
        assert!(e.contains("llm.fallbacks = false"), "{e}");
        assert!(
            check(&body(
                json!({"model": "m", "max_tokens": 8, "messages": [], "top_p": 0.9, "top_k": 40})
            ))
            .is_ok()
        );
    }

    #[test]
    fn media_is_flagged_and_url_sources_are_refused() {
        let a = Anthropic::new("k".into(), DEFAULT_BASE_URL);
        let with = |content: Value| {
            a.check(&body(json!({
                "model": "m", "max_tokens": 8,
                "messages": [{"role": "user", "content": content}]
            })))
        };
        assert!(!with(json!("plain text")).unwrap().has_media);
        let image = json!([{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AA=="}}]);
        assert!(with(image).unwrap().has_media);
        // nested in a tool result too
        let nested = json!([{"type": "tool_result", "tool_use_id": "t", "content": [
            {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": "AA=="}}]}]);
        assert!(with(nested).unwrap().has_media);
        for url in [
            json!([{"type": "document", "source": {"type": "url", "url": "https://example.com/big.pdf"}}]),
            json!([{"type": "tool_result", "tool_use_id": "t", "content": [
                {"type": "image", "source": {"type": "url", "url": "https://example.com/a.png"}}]}]),
        ] {
            assert!(with(url).unwrap_err().contains("URL"));
        }
    }

    #[test]
    fn only_a_whole_answer_is_completed() {
        let a = Anthropic::new("k".into(), DEFAULT_BASE_URL);
        let start = json!({"type": "message_start", "message": {"usage": {"input_tokens": 9, "output_tokens": 1}}});
        let delta = json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 4}});
        let ended = |stream: bool, status: StatusCode, bytes: Vec<u8>| {
            let mut m = a.meter(stream);
            m.feed(&bytes);
            m.finish(status).ended
        };
        let whole = sse(&[
            start.clone(),
            delta.clone(),
            json!({"type": "message_stop"}),
        ]);
        assert_eq!(ended(true, StatusCode::OK, whole), Ended::Completed);
        // no message_stop: cut (the final usage may never have arrived)
        assert_eq!(
            ended(true, StatusCode::OK, sse(std::slice::from_ref(&start))),
            Ended::Cut
        );
        let errored = sse(&[
            start,
            json!({"type": "error", "error": {"type": "overloaded_error", "message": "o"}}),
            json!({"type": "message_stop"}),
        ]);
        assert_eq!(ended(true, StatusCode::OK, errored), Ended::Cut);
        assert_eq!(
            ended(
                false,
                StatusCode::OK,
                br#"{"usage":{"input_tokens":5,"output_tokens":2},"content":[]}"#.to_vec()
            ),
            Ended::Completed
        );
        assert_eq!(
            ended(
                false,
                StatusCode::OK,
                br#"{"content":[{"type":"te"#.to_vec()
            ),
            Ended::Cut
        );
        assert_eq!(ended(false, StatusCode::OK, Vec::new()), Ended::Cut);
        assert_eq!(
            ended(
                false,
                StatusCode::TOO_MANY_REQUESTS,
                br#"{"type":"error","error":{"type":"rate_limit_error","message":"s"}}"#.to_vec()
            ),
            Ended::Refused
        );
    }

    #[test]
    fn the_meter_reads_usage_and_content_from_the_stream() {
        let events = sse(&[
            json!({"type": "message_start", "message": {"model": "claude-opus-5-5", "usage": {
                "input_tokens": 1200, "output_tokens": 1, "cache_read_input_tokens": 300,
                "cache_creation_input_tokens": 100,
                "cache_creation": {"ephemeral_5m_input_tokens": 100, "ephemeral_1h_input_tokens": 0}}}}),
            json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Look"}}),
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "ing up"}}),
            json!({"type": "content_block_stop", "index": 0}),
            json!({"type": "ping"}),
            json!({"type": "content_block_start", "index": 1, "content_block":
                {"type": "tool_use", "id": "toolu_1", "name": "lookup_order", "input": {}}}),
            json!({"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "{\"id\": "}}),
            json!({"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "\"1001\"}"}}),
            json!({"type": "content_block_stop", "index": 1}),
            json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 345}}),
            json!({"type": "message_stop"}),
        ]);
        let mut m = Anthropic::new("k".into(), DEFAULT_BASE_URL).meter(true);
        // in odd pieces, as the network delivers it
        for piece in events.chunks(7) {
            m.feed(piece);
        }
        let got = m.finish(StatusCode::OK);
        assert_eq!(
            got.usage,
            Usage {
                input: 1200,
                output: 345,
                cache_read: 300,
                cache_write_5m: 100,
                ..Usage::default()
            }
        );
        assert_eq!(got.stop_reason.as_deref(), Some("tool_use"));
        assert_eq!(
            got.content,
            json!([{"type": "text", "text": "Looking up"},
                   {"type": "tool_use", "id": "toolu_1", "name": "lookup_order", "input": {"id": "1001"}}])
        );
        assert_eq!(got.error, None);
    }

    #[test]
    fn a_broken_stream_keeps_the_usage_reported_before_the_error() {
        let mut m = Anthropic::new("k".into(), DEFAULT_BASE_URL).meter(true);
        m.feed(&sse(&[
            json!({"type": "message_start", "message": {"usage": {"input_tokens": 900, "output_tokens": 1}}}),
            json!({"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}}),
        ]));
        let got = m.finish(StatusCode::OK);
        assert_eq!((got.usage.input, got.usage.output), (900, 1));
        assert_eq!(got.error.as_deref(), Some("overloaded_error: Overloaded"));

        let mut m = Anthropic::new("k".into(), DEFAULT_BASE_URL).meter(false);
        m.feed(br#"{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}"#);
        let got = m.finish(StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(got.usage, Usage::default());
        assert_eq!(got.error.as_deref(), Some("rate_limit_error: slow down"));

        let mut m = Anthropic::new("k".into(), DEFAULT_BASE_URL).meter(false);
        m.feed(br#"{"content":[{"type":"text","text":"no"}],"stop_reason":"refusal","usage":{"input_tokens":5,"output_tokens":2}}"#);
        let got = m.finish(StatusCode::OK);
        assert_eq!((got.usage.input, got.usage.output), (5, 2));
        assert_eq!(got.stop_reason.as_deref(), Some("refusal"));
    }
}
