//! OpenAI's wire formats: Chat Completions (`POST /v1/chat/completions`) and Responses
//! (`POST /v1/responses`), for OpenAI itself (`openai`) and for anything that speaks Chat
//! Completions at its own base URL (`openai-compatible`: Ollama, vLLM, LM Studio, OpenRouter,
//! Groq, Together, Gemini's OpenAI endpoint, Azure OpenAI).
//!
//! As for Messages (anthropic.rs), a request carries only allowed fields, and tools only of the
//! kinds the caller runs itself: a hosted tool (`web_search`, `file_search`, `code_interpreter`,
//! `image_generation`, `mcp`, ...) bills per use, outside the token price, and acts outside the
//! platform's tool policy. Fields that bill differently (`service_tier`, `audio`, `prediction`,
//! `background`) are refused for the same reason, and so is more than one choice (`n`). A media
//! part the provider would fetch from a URL is refused (egress outside the tool policy, of an
//! unknown size); inline data is allowed and marks the request as one whose input its bytes do
//! not bound, like a `previous_response_id`.
//!
//! A streamed Chat Completions request gets `stream_options.include_usage: true`, so its last
//! chunk carries the usage. Both meters count `usage` as the provider reported it: prompt
//! (`prompt_tokens` / `input_tokens`, cached ones included, at the input rate: the conservative
//! reading) and output tokens. An answer that ended without a reported usage is counted at its
//! reservation (`Ended::Cut`), so a server that does not report usage cannot run a budget open.
use agentsc_common::llm_contract::{ProviderKind, SecretSource};
use agentsc_common::pricing::Usage;
use axum::http::{HeaderMap, StatusCode};
use serde_json::{Map, Value, json};

use super::anthropic::find_event_end;
use super::{Checked, Ended, Meter, Metered, Provider, Wire};

/// The Chat Completions request fields that may reach the provider.
pub const CHAT_FIELDS: &[&str] = &[
    "model",
    "messages",
    "max_tokens",
    "max_completion_tokens",
    "stream",
    "stream_options",
    "temperature",
    "top_p",
    "stop",
    "tools",
    "tool_choice",
    "parallel_tool_calls",
    "response_format",
    "seed",
    "user",
    "frequency_penalty",
    "presence_penalty",
    "logprobs",
    "top_logprobs",
    "logit_bias",
    "reasoning_effort",
    "metadata",
    "n",
];
/// The Responses request fields that may reach the provider.
pub const RESPONSES_FIELDS: &[&str] = &[
    "model",
    "input",
    "instructions",
    "max_output_tokens",
    "stream",
    "temperature",
    "top_p",
    "tools",
    "tool_choice",
    "parallel_tool_calls",
    "text",
    "reasoning",
    "metadata",
    "previous_response_id",
    "store",
    "include",
    "truncation",
    "user",
    "prompt_cache_key",
    "safety_identifier",
    "top_logprobs",
];
/// Tools the caller runs itself (a function call comes back to it): the only ones forwarded.
const CHAT_TOOL_TYPES: &[&str] = &["function"];
const RESPONSES_TOOL_TYPES: &[&str] = &["function", "custom", "local_shell"];
/// A non-streamed answer is read up to this size for its usage.
const MAX_BODY_METERED: usize = 16 * 1024 * 1024;

/// One OpenAI-shaped upstream, in one wire format.
pub struct OpenAi {
    name: &'static str,
    wire: Wire,
    /// Up to and including `/v1` (`https://api.openai.com/v1`).
    base_url: String,
    key: Option<SecretSource>,
}

impl OpenAi {
    /// `kind` is `openai` or `openai-compatible`; `wire` is Chat Completions or Responses.
    pub fn new(kind: ProviderKind, wire: Wire, base_url: &str, key: Option<SecretSource>) -> Self {
        Self {
            name: match kind {
                ProviderKind::OpenAiCompatible => "openai-compatible",
                _ => "openai",
            },
            wire,
            base_url: base_url.trim_end_matches('/').to_string(),
            key,
        }
    }
}

impl Provider for OpenAi {
    fn name(&self) -> &'static str {
        self.name
    }

    fn wire(&self) -> Wire {
        self.wire
    }

    fn request(
        &self,
        client: &reqwest::Client,
        body: Vec<u8>,
        _incoming: &HeaderMap,
    ) -> Result<reqwest::RequestBuilder, String> {
        let path = match self.wire {
            Wire::Responses => "/responses",
            _ => "/chat/completions",
        };
        let mut req = client
            .post(format!("{}{path}", self.base_url))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(body);
        if let Some(key) = &self.key {
            req = req.bearer_auth(key.read()?);
        }
        Ok(req)
    }
}

fn model(body: &Map<String, Value>) -> Result<String, String> {
    Ok(body
        .get("model")
        .and_then(Value::as_str)
        .filter(|m| !m.is_empty())
        .ok_or("the request names no model")?
        .to_string())
}

fn stream(body: &Map<String, Value>) -> Result<bool, String> {
    match body.get("stream") {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err("stream must be a boolean".into()),
    }
}

fn limit(body: &Map<String, Value>, key: &str) -> Result<Option<u64>, String> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("{key} must be a non-negative integer")),
    }
}

fn only_fields(body: &Map<String, Value>, allowed: &[&str]) -> Result<(), String> {
    match body.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(f) => Err(format!(
            "request field {f:?} is not one the gateway forwards"
        )),
        None => Ok(()),
    }
}

fn tools(body: &Map<String, Value>, allowed: &[&str]) -> Result<(), String> {
    for t in body
        .get("tools")
        .map(|t| t.as_array().ok_or("tools must be an array"))
        .transpose()?
        .into_iter()
        .flatten()
    {
        let kind = t.get("type").and_then(Value::as_str).unwrap_or("");
        if !allowed.contains(&kind) {
            return Err(format!(
                "tool type {kind:?} is a hosted tool, billed outside the token price"
            ));
        }
    }
    Ok(())
}

/// Find media anywhere in `v`, and refuse a part the provider would fetch from a URL.
fn scan_media(v: &Value, found: &mut bool) -> Result<(), String> {
    match v {
        Value::Object(m) => {
            let url = |field: &str| -> Option<&str> {
                match m.get(field) {
                    Some(Value::String(u)) => Some(u.as_str()),
                    Some(Value::Object(o)) => o.get("url").and_then(Value::as_str),
                    _ => None,
                }
            };
            match m.get("type").and_then(Value::as_str) {
                Some("image_url" | "input_image") => {
                    *found = true;
                    if let Some(u) = url("image_url")
                        && !u.starts_with("data:")
                    {
                        return Err(
                            "an image is a URL, which the provider would fetch outside the platform's tool policy"
                                .into(),
                        );
                    }
                }
                Some("input_file" | "file") => {
                    *found = true;
                    if url("file_url").is_some() {
                        return Err(
                            "a file is a URL, which the provider would fetch outside the platform's tool policy"
                                .into(),
                        );
                    }
                }
                Some("input_audio") => *found = true,
                _ => {}
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

fn assistant_turns(items: &[Value]) -> u32 {
    let n = items
        .iter()
        .filter(|m| m.get("role").and_then(Value::as_str) == Some("assistant"))
        .count();
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Check a Chat Completions request body.
pub fn check_chat(body: &Map<String, Value>) -> Result<Checked, String> {
    only_fields(body, CHAT_FIELDS)?;
    let model = model(body)?;
    let max_tokens = match limit(body, "max_completion_tokens")? {
        Some(n) => Some(n),
        None => limit(body, "max_tokens")?,
    };
    if !matches!(body.get("n"), None | Some(Value::Null)) && body.get("n") != Some(&json!(1)) {
        return Err("n must be 1: more choices bill more output".into());
    }
    let stream = stream(body)?;
    tools(body, CHAT_TOOL_TYPES)?;
    let messages = body
        .get("messages")
        .and_then(Value::as_array)
        .ok_or("messages must be an array")?;
    let mut has_media = false;
    scan_media(&Value::Array(messages.clone()), &mut has_media)?;
    Ok(Checked {
        model,
        max_tokens,
        stream,
        assistant_turns: assistant_turns(messages),
        has_media,
        stored_state: false,
    })
}

/// A streamed Chat Completions request asks for the usage in its last chunk.
pub fn rewrite_chat(body: &mut Map<String, Value>) -> bool {
    if body.get("stream") != Some(&Value::Bool(true)) {
        return false;
    }
    let options = body.entry("stream_options").or_insert_with(|| json!({}));
    match options.as_object_mut() {
        Some(o) if o.get("include_usage") != Some(&Value::Bool(true)) => {
            o.insert("include_usage".into(), Value::Bool(true));
            true
        }
        Some(_) => false,
        None => {
            *options = json!({"include_usage": true});
            true
        }
    }
}

/// Check a Responses request body.
pub fn check_responses(body: &Map<String, Value>) -> Result<Checked, String> {
    only_fields(body, RESPONSES_FIELDS)?;
    let model = model(body)?;
    let max_tokens = limit(body, "max_output_tokens")?;
    let stream = stream(body)?;
    tools(body, RESPONSES_TOOL_TYPES)?;
    let input = match body.get("input") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(_)) => Vec::new(),
        Some(Value::Array(items)) => items.clone(),
        Some(_) => return Err("input must be a string or an array".into()),
    };
    let mut has_media = false;
    scan_media(&Value::Array(input.clone()), &mut has_media)?;
    // the earlier turns, or an item, are the provider's: their size is not in this request
    let stored_state = body
        .get("previous_response_id")
        .is_some_and(|v| !v.is_null())
        || refers_to_stored_items(&Value::Array(input.clone()));
    Ok(Checked {
        model,
        max_tokens,
        stream,
        assistant_turns: assistant_turns(&input),
        has_media: has_media || stored_state,
        stored_state,
    })
}

/// An `item_reference` anywhere in `v`: an item the provider stored, pulled into the prompt.
fn refers_to_stored_items(v: &Value) -> bool {
    match v {
        Value::Object(m) => {
            m.get("type").and_then(Value::as_str) == Some("item_reference")
                || m.values().any(refers_to_stored_items)
        }
        Value::Array(a) => a.iter().any(refers_to_stored_items),
        _ => false,
    }
}

fn n(v: &Value, key: &str) -> u64 {
    v.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn error_text(v: &Value) -> Option<String> {
    let e = v.get("error").filter(|e| !e.is_null())?;
    let kind = e
        .get("type")
        .or_else(|| e.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("error");
    let msg = e.get("message").and_then(Value::as_str).unwrap_or("");
    Some(format!("{kind}: {msg}"))
}

/// The `data:` payload of each complete SSE event in `buf`, which keeps the rest.
fn drain_data(buf: &mut Vec<u8>) -> Vec<String> {
    let mut out = Vec::new();
    while let Some(end) = find_event_end(buf) {
        let raw: Vec<u8> = buf.drain(..end).collect();
        let text = String::from_utf8_lossy(&raw);
        let data: Vec<&str> = text
            .lines()
            .filter_map(|l| l.trim_end_matches('\r').strip_prefix("data:"))
            .map(str::trim_start)
            .collect();
        if !data.is_empty() {
            out.push(data.join("\n"));
        }
    }
    out
}

/// A meter for one Chat Completions answer.
pub fn chat_meter(stream: bool) -> Box<dyn Meter> {
    Box::new(ChatMeter {
        stream,
        ..ChatMeter::default()
    })
}

#[derive(Default)]
struct ChatMeter {
    stream: bool,
    buf: Vec<u8>,
    usage: Option<Usage>,
    text: String,
    tool_calls: Vec<Value>,
    finish_reason: Option<String>,
    error: Option<String>,
    /// `data: [DONE]` arrived.
    done: bool,
}

fn chat_usage(u: &Value) -> Usage {
    Usage {
        input: n(u, "prompt_tokens"),
        output: n(u, "completion_tokens"),
        ..Usage::default()
    }
}

impl ChatMeter {
    fn chunk(&mut self, v: &Value) {
        if let Some(e) = error_text(v) {
            self.error = Some(e);
        }
        if let Some(u) = v.get("usage").filter(|u| u.is_object()) {
            self.usage = Some(chat_usage(u));
        }
        let Some(choice) = v.get("choices").and_then(|c| c.get(0)) else {
            return;
        };
        if let Some(r) = choice.get("finish_reason").and_then(Value::as_str) {
            self.finish_reason = Some(r.to_string());
        }
        let Some(delta) = choice.get("delta") else {
            return;
        };
        if let Some(t) = delta.get("content").and_then(Value::as_str) {
            self.text.push_str(t);
        }
        for call in delta
            .get("tool_calls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let i = call.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
            if self.tool_calls.len() <= i {
                self.tool_calls.resize(
                    i + 1,
                    json!({"type": "function", "function": {"name": "", "arguments": ""}}),
                );
            }
            let slot = &mut self.tool_calls[i];
            if let Some(id) = call.get("id") {
                slot["id"] = id.clone();
            }
            if let Some(f) = call.get("function") {
                for key in ["name", "arguments"] {
                    if let Some(part) = f.get(key).and_then(Value::as_str) {
                        let cur = slot["function"][key].as_str().unwrap_or("").to_string();
                        slot["function"][key] = Value::String(cur + part);
                    }
                }
            }
        }
    }
}

impl Meter for ChatMeter {
    fn feed(&mut self, chunk: &[u8]) {
        if !self.stream {
            if self.buf.len() < MAX_BODY_METERED {
                self.buf.extend_from_slice(chunk);
            }
            return;
        }
        self.buf.extend_from_slice(chunk);
        for data in drain_data(&mut self.buf) {
            if data.trim() == "[DONE]" {
                self.done = true;
            } else if let Ok(v) = serde_json::from_str::<Value>(&data) {
                self.chunk(&v);
            }
        }
    }

    fn finish(mut self: Box<Self>, status: StatusCode) -> Metered {
        let mut content = Value::Null;
        if self.stream {
            self.feed(b"\n\n");
            if !self.text.is_empty() || !self.tool_calls.is_empty() {
                content = json!({"role": "assistant", "content": self.text});
                if !self.tool_calls.is_empty() {
                    content["tool_calls"] = Value::Array(self.tool_calls.clone());
                }
            }
        } else if let Ok(v) = serde_json::from_slice::<Value>(&self.buf) {
            if status.is_success() {
                self.chunk(&json!({"usage": v.get("usage")}));
                let choice = v.get("choices").and_then(|c| c.get(0));
                content = choice
                    .and_then(|c| c.get("message"))
                    .cloned()
                    .unwrap_or(Value::Null);
                self.finish_reason = choice
                    .and_then(|c| c.get("finish_reason"))
                    .and_then(Value::as_str)
                    .map(str::to_string);
                self.done = true;
            } else {
                self.error = error_text(&v);
            }
        }
        let ended = if !status.is_success() {
            Ended::Refused
        } else if self.done && self.error.is_none() && self.usage.is_some() {
            Ended::Completed
        } else {
            Ended::Cut
        };
        if ended == Ended::Cut && self.usage.is_none() && self.error.is_none() && self.done {
            self.error = Some("the provider reported no usage".into());
        }
        Metered {
            usage: self.usage.unwrap_or_default(),
            ended,
            content,
            stop_reason: self.finish_reason,
            error: self.error,
        }
    }
}

/// A meter for one Responses answer.
pub fn responses_meter(stream: bool) -> Box<dyn Meter> {
    Box::new(ResponsesMeter {
        stream,
        ..ResponsesMeter::default()
    })
}

#[derive(Default)]
struct ResponsesMeter {
    stream: bool,
    buf: Vec<u8>,
    usage: Option<Usage>,
    output: Value,
    status: Option<String>,
    error: Option<String>,
}

impl ResponsesMeter {
    /// A whole response object (the body, or a `response.*` event's `response`).
    fn response(&mut self, r: &Value) {
        if let Some(u) = r.get("usage").filter(|u| u.is_object()) {
            self.usage = Some(Usage {
                input: n(u, "input_tokens"),
                output: n(u, "output_tokens"),
                ..Usage::default()
            });
        }
        if let Some(s) = r.get("status").and_then(Value::as_str) {
            self.status = Some(s.to_string());
        }
        if let Some(o) = r.get("output").filter(|o| o.is_array()) {
            self.output = o.clone();
        }
        if let Some(e) = error_text(r) {
            self.error = Some(e);
        }
    }

    fn event(&mut self, v: &Value) {
        match v.get("type").and_then(Value::as_str).unwrap_or("") {
            "response.completed" | "response.incomplete" | "response.failed" => {
                if let Some(r) = v.get("response") {
                    self.response(&r.clone());
                }
            }
            "error" => {
                self.error = Some(format!(
                    "{}: {}",
                    v.get("code").and_then(Value::as_str).unwrap_or("error"),
                    v.get("message").and_then(Value::as_str).unwrap_or("")
                ));
            }
            _ => {}
        }
    }

    /// The response ended as the provider meant it to (`incomplete`: at its token limit).
    fn finished(&self) -> bool {
        matches!(self.status.as_deref(), Some("completed" | "incomplete"))
    }
}

impl Meter for ResponsesMeter {
    fn feed(&mut self, chunk: &[u8]) {
        if !self.stream {
            if self.buf.len() < MAX_BODY_METERED {
                self.buf.extend_from_slice(chunk);
            }
            return;
        }
        self.buf.extend_from_slice(chunk);
        for data in drain_data(&mut self.buf) {
            if let Ok(v) = serde_json::from_str::<Value>(&data) {
                self.event(&v);
            }
        }
    }

    fn finish(mut self: Box<Self>, status: StatusCode) -> Metered {
        if self.stream {
            self.feed(b"\n\n");
        } else if let Ok(v) = serde_json::from_slice::<Value>(&self.buf) {
            if status.is_success() {
                self.response(&v);
            } else {
                self.error = error_text(&v);
            }
        }
        let ended = if !status.is_success() {
            Ended::Refused
        } else if self.finished() && self.error.is_none() && self.usage.is_some() {
            Ended::Completed
        } else {
            Ended::Cut
        };
        Metered {
            usage: self.usage.unwrap_or_default(),
            ended,
            content: self.output,
            stop_reason: self.status,
            error: self.error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(v: Value) -> Map<String, Value> {
        serde_json::from_value(v).unwrap()
    }

    fn sse(events: &[Value]) -> Vec<u8> {
        events
            .iter()
            .map(|e| format!("data: {e}\n\n"))
            .collect::<String>()
            .into_bytes()
    }

    #[test]
    fn chat_requests_keep_to_the_allowed_fields_and_function_tools() {
        let ok = check_chat(&body(json!({
            "model": "gpt-5", "max_completion_tokens": 256, "stream": true,
            "messages": [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "x"}],
            "tools": [{"type": "function", "function": {"name": "lookup", "parameters": {}}}],
        })))
        .unwrap();
        assert_eq!(
            ok,
            Checked {
                model: "gpt-5".into(),
                max_tokens: Some(256),
                stream: true,
                assistant_turns: 1,
                has_media: false,
                stored_state: false
            }
        );
        let no_limit = check_chat(&body(json!({"model": "m", "messages": []}))).unwrap();
        assert_eq!(
            no_limit.max_tokens, None,
            "OpenAI lets a request name no limit"
        );
        for (bad, why) in [
            (
                json!({"model": "m", "messages": [], "service_tier": "priority"}),
                "service_tier",
            ),
            (json!({"model": "m", "messages": [], "n": 3}), "n"),
            (
                json!({"model": "m", "messages": [], "tools": [{"type": "web_search"}]}),
                "hosted tool",
            ),
            (json!({"messages": []}), "no model"),
            (
                json!({"model": "m", "messages": [], "max_tokens": -1}),
                "negative",
            ),
            (
                json!({"model": "m", "messages": [{"role": "user", "content": [
                    {"type": "image_url", "image_url": {"url": "https://example.com/cat.png"}}]}]}),
                "an image URL",
            ),
        ] {
            assert!(check_chat(&body(bad)).is_err(), "{why}");
        }
        let inline = check_chat(&body(
            json!({"model": "m", "messages": [{"role": "user", "content": [
            {"type": "image_url", "image_url": {"url": "data:image/png;base64,AA=="}}]}]}),
        ))
        .unwrap();
        assert!(inline.has_media);
    }

    #[test]
    fn a_streamed_chat_request_asks_for_its_usage() {
        let mut b = body(json!({"model": "m", "messages": [], "stream": true}));
        assert!(rewrite_chat(&mut b));
        assert_eq!(b["stream_options"], json!({"include_usage": true}));
        assert!(!rewrite_chat(&mut b), "once");
        let mut b = body(json!({"model": "m", "messages": [], "stream": true,
            "stream_options": {"include_usage": false}}));
        assert!(rewrite_chat(&mut b));
        assert_eq!(b["stream_options"]["include_usage"], true);
        let mut b = body(json!({"model": "m", "messages": []}));
        assert!(!rewrite_chat(&mut b) && !b.contains_key("stream_options"));
    }

    #[test]
    fn responses_requests_keep_to_caller_run_tools_and_bound_their_input() {
        let ok = check_responses(&body(json!({
            "model": "gpt-5", "instructions": "be brief", "stream": true,
            "input": [{"role": "user", "content": [{"type": "input_text", "text": "hi"}]}],
            "tools": [{"type": "function", "name": "shell", "parameters": {}},
                      {"type": "custom", "name": "apply_patch"}],
            "reasoning": {"effort": "low"}, "store": false, "include": ["reasoning.encrypted_content"],
            "prompt_cache_key": "k"
        })))
        .unwrap();
        assert_eq!(
            (ok.model.as_str(), ok.max_tokens, ok.stream, ok.has_media),
            ("gpt-5", None, true, false)
        );
        assert!(
            check_responses(&body(
                json!({"model": "m", "input": "x", "previous_response_id": "resp_1"})
            ))
            .unwrap()
            .has_media,
            "earlier turns are not in the request's bytes"
        );
        // the review finding: an item_reference pulls a stored item in, whatever its size
        let referenced = check_responses(&body(json!({"model": "m", "input": [
            {"type": "item_reference", "id": "msg_1"},
            {"role": "user", "content": [{"type": "input_text", "text": "and now?"}]}]})))
        .unwrap();
        assert!(referenced.has_media && referenced.stored_state);
        let plain = check_responses(&body(json!({"model": "m", "input": "hi"}))).unwrap();
        assert!(!plain.has_media && !plain.stored_state);
        for (bad, why) in [
            (
                json!({"model": "m", "input": "x", "tools": [{"type": "web_search"}]}),
                "hosted tool",
            ),
            (
                json!({"model": "m", "input": "x", "background": true}),
                "background",
            ),
            (json!({"model": "m", "input": 3}), "input"),
            (
                json!({"model": "m", "input": [{"role": "user", "content": [
                    {"type": "input_file", "file_url": "https://example.com/a.pdf"}]}]}),
                "a file URL",
            ),
        ] {
            assert!(check_responses(&body(bad)).is_err(), "{why}");
        }
    }

    #[test]
    fn the_chat_meter_reads_the_usage_chunk_and_the_content() {
        let mut m = chat_meter(true);
        let stream = sse(&[
            json!({"choices": [{"index": 0, "delta": {"role": "assistant", "content": "Hel"}}]}),
            json!({"choices": [{"index": 0, "delta": {"content": "lo", "tool_calls": [
                {"index": 0, "id": "call_1", "function": {"name": "look", "arguments": "{\"a\""}}]}}]}),
            json!({"choices": [{"index": 0, "delta": {"tool_calls": [
                {"index": 0, "function": {"name": "up", "arguments": ":1}"}}]}, "finish_reason": "tool_calls"}]}),
            json!({"choices": [], "usage": {"prompt_tokens": 120, "completion_tokens": 30}}),
        ]);
        let (a, b) = stream.split_at(37);
        m.feed(a);
        m.feed(b);
        m.feed(b"data: [DONE]\n\n");
        let got = m.finish(StatusCode::OK);
        assert_eq!(got.ended, Ended::Completed);
        assert_eq!((got.usage.input, got.usage.output), (120, 30));
        assert_eq!(got.content["content"], "Hello");
        assert_eq!(got.content["tool_calls"][0]["function"]["name"], "lookup");
        assert_eq!(
            got.content["tool_calls"][0]["function"]["arguments"],
            "{\"a\":1}"
        );
        assert_eq!(got.stop_reason.as_deref(), Some("tool_calls"));

        // a server that reports no usage, or a stream that broke: counted at the reservation
        let mut m = chat_meter(true);
        m.feed(&sse(&[
            json!({"choices": [{"delta": {"content": "x"}, "finish_reason": "stop"}]}),
        ]));
        m.feed(b"data: [DONE]\n\n");
        let got = m.finish(StatusCode::OK);
        assert_eq!(got.ended, Ended::Cut);
        assert_eq!(got.error.as_deref(), Some("the provider reported no usage"));
        let mut m = chat_meter(true);
        m.feed(&sse(&[json!({"choices": [{"delta": {"content": "x"}}]})]));
        assert_eq!(m.finish(StatusCode::OK).ended, Ended::Cut);

        let mut m = chat_meter(false);
        m.feed(json!({"choices": [{"message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
                      "usage": {"prompt_tokens": 9, "completion_tokens": 2}}).to_string().as_bytes());
        let got = m.finish(StatusCode::OK);
        assert_eq!(
            (got.ended, got.usage.input, got.usage.output),
            (Ended::Completed, 9, 2)
        );
        let mut m = chat_meter(false);
        m.feed(br#"{"error": {"type": "invalid_request_error", "message": "bad"}}"#);
        let got = m.finish(StatusCode::BAD_REQUEST);
        assert_eq!(
            (got.ended, got.error.as_deref()),
            (Ended::Refused, Some("invalid_request_error: bad"))
        );
    }

    #[test]
    fn the_responses_meter_reads_the_final_event() {
        let ev = |t: &str, extra: Value| {
            let mut v = json!({"type": t});
            v.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            format!("event: {t}\ndata: {v}\n\n")
        };
        let mut m = responses_meter(true);
        m.feed(
            ev(
                "response.created",
                json!({"response": {"status": "in_progress"}}),
            )
            .as_bytes(),
        );
        m.feed(ev("response.output_text.delta", json!({"delta": "hi"})).as_bytes());
        m.feed(
            ev(
                "response.completed",
                json!({"response": {"status": "completed",
                    "output": [{"type": "message", "content": [{"type": "output_text", "text": "hi"}]}],
                    "usage": {"input_tokens": 300, "output_tokens": 40, "input_tokens_details": {"cached_tokens": 100}}}}),
            )
            .as_bytes(),
        );
        let got = m.finish(StatusCode::OK);
        assert_eq!(got.ended, Ended::Completed);
        assert_eq!(
            (got.usage.input, got.usage.output),
            (300, 40),
            "cached tokens at the input rate"
        );
        assert_eq!(got.content[0]["type"], "message");
        assert_eq!(got.stop_reason.as_deref(), Some("completed"));

        let mut m = responses_meter(true);
        m.feed(
            ev(
                "response.failed",
                json!({"response": {"status": "failed",
            "error": {"code": "server_error", "message": "boom"},
            "usage": {"input_tokens": 10, "output_tokens": 1}}}),
            )
            .as_bytes(),
        );
        let got = m.finish(StatusCode::OK);
        assert_eq!(
            (got.ended, got.error.as_deref()),
            (Ended::Cut, Some("server_error: boom"))
        );

        let mut m = responses_meter(false);
        m.feed(json!({"status": "incomplete", "output": [], "usage": {"input_tokens": 5, "output_tokens": 64}})
            .to_string()
            .as_bytes());
        assert_eq!(
            m.finish(StatusCode::OK).ended,
            Ended::Completed,
            "incomplete: at its limit"
        );
    }
}
