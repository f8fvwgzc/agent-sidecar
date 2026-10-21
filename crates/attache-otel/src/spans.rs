//! Audit record → span (design §9, the stateless span rule).
//!
//! `agent_invocation`, `agent_call`, `model_call`, `tool_call`, `service_call` and `http_call`
//! records are hops: their span keeps the record's `span_id` and `parent_span_id`. Every other
//! kind (`guardrail`, `budget`, `authz`, `config`, `learning`) is an event inside a hop and
//! becomes its own child span of the record's `span_id`, with a derived id:
//! the first 8 bytes of SHA-256(`span_id ‖ kind ‖ rule ‖ ts ‖ seq`), where `seq` is a
//! per-process sequence number (8 bytes, big-endian; it is last and fixed-width, so two records
//! with different sequence numbers never hash the same input). No state is kept between records.
use crate::otlp::{
    KeyValue, SPAN_KIND_CLIENT, SPAN_KIND_INTERNAL, SPAN_KIND_SERVER, STATUS_CODE_ERROR, Span,
    Status,
};
use attache_common::audit::{AuditRecord, Direction, Kind};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// The next per-process sequence number (unique across every exporter in the process).
pub fn next_sequence() -> u64 {
    SEQUENCE.fetch_add(1, Ordering::Relaxed)
}

/// Whether a record of this kind keeps its own `span_id` (a hop) or gets a derived child span.
pub fn keeps_span_id(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::AgentInvocation
            | Kind::AgentCall
            | Kind::ModelCall
            | Kind::ToolCall
            | Kind::ServiceCall
            | Kind::HttpCall
    )
}

fn digest(parts: &[&[u8]], seq: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.update(seq.to_be_bytes());
    h.finalize().into()
}

/// 16 hex characters: the first 8 bytes of SHA-256(`span_id ‖ kind ‖ rule ‖ ts ‖ seq`), with
/// `rule` empty when the record has none and `seq` as 8 big-endian bytes.
pub fn derived_span_id(span_id: &str, kind: &str, rule: &str, ts: &str, seq: u64) -> String {
    let d = digest(
        &[
            span_id.as_bytes(),
            kind.as_bytes(),
            rule.as_bytes(),
            ts.as_bytes(),
        ],
        seq,
    );
    nonzero_hex(&d[..8])
}

/// 32 hex characters for a record whose `trace_id` is not a valid W3C trace id: the first 16
/// bytes of SHA-256(`"trace" ‖ span_id ‖ kind ‖ rule ‖ ts ‖ seq`). The span becomes the root of
/// its own trace (no parent) instead of being lost.
pub fn derived_trace_id(span_id: &str, kind: &str, rule: &str, ts: &str, seq: u64) -> String {
    let d = digest(
        &[
            b"trace",
            span_id.as_bytes(),
            kind.as_bytes(),
            rule.as_bytes(),
            ts.as_bytes(),
        ],
        seq,
    );
    nonzero_hex(&d[..16])
}

/// Lowercase hex; an all-zero id (invalid in W3C and OTLP) gets its last byte set to 1.
fn nonzero_hex(bytes: &[u8]) -> String {
    let mut b = bytes.to_vec();
    if b.iter().all(|&x| x == 0)
        && let Some(last) = b.last_mut()
    {
        *last = 1;
    }
    hex::encode(b)
}

/// `Some(lowercase id)` when `id` is `len` hex characters and not all zero.
fn valid_id(id: &str, len: usize) -> Option<String> {
    (id.len() == len && id.bytes().all(|b| b.is_ascii_hexdigit()) && id.bytes().any(|b| b != b'0'))
        .then(|| id.to_ascii_lowercase())
}

/// The record's `ts` (its end) as Unix nanoseconds; a record whose `ts` does not parse is
/// stamped with the current time.
pub fn end_unix_nanos(ts: &str) -> u64 {
    chrono::DateTime::parse_from_rfc3339(ts)
        .ok()
        .and_then(|t| t.timestamp_nanos_opt())
        .map_or_else(now_unix_nanos, |n| u64::try_from(n).unwrap_or(0))
}

pub fn now_unix_nanos() -> u64 {
    chrono::Utc::now()
        .timestamp_nanos_opt()
        .and_then(|n| u64::try_from(n).ok())
        .unwrap_or(0)
}

/// `(provider, model)` from a `model_call` callee: `anthropic:<model>` → (`anthropic`, model),
/// `mock` → (`mock`, `mock`).
pub fn model_of(callee: &str) -> (&str, &str) {
    match callee.split_once(':') {
        Some((provider, model)) if !provider.is_empty() && !model.is_empty() => (provider, model),
        _ => (callee, callee),
    }
}

/// The tool of a `tool_call` callee; `load_skill:<skill>` is the tool `load_skill`.
fn tool_of(callee: &str) -> &str {
    callee.split_once(':').map_or(callee, |(tool, _)| tool)
}

/// `(service, METHOD, path)` of a `service_call` callee (`<service> <METHOD> <path>`).
fn service_call_parts(callee: &str) -> Option<(&str, &str, &str)> {
    let mut it = callee.splitn(3, ' ');
    let service = it.next().filter(|s| !s.is_empty())?;
    let method = it.next().filter(|s| !s.is_empty())?;
    let path = it.next().unwrap_or("");
    Some((service, method, path))
}

/// The URL of an `http_call` callee (`<METHOD> <url>`, or a bare URL).
fn http_call_url(callee: &str) -> &str {
    match callee.split_once(' ') {
        Some((_, url)) => url,
        None => callee,
    }
}

/// The low-cardinality span name (design §9).
pub fn span_name(rec: &AuditRecord) -> String {
    let kind = rec.kind.as_str();
    let agent = rec.agent.as_deref();
    match rec.kind {
        Kind::ModelCall => format!("model_call {}", model_of(&rec.callee).1),
        Kind::ToolCall => {
            let tool = tool_of(&rec.callee);
            match agent {
                Some(a) => format!("tool_call {a}.{tool}"),
                None => format!("tool_call {tool}"),
            }
        }
        Kind::ServiceCall => match service_call_parts(&rec.callee) {
            Some((service, method, _)) => {
                format!("service_call {service} {}", method.to_ascii_uppercase())
            }
            None => "service_call".to_string(),
        },
        Kind::HttpCall => match url::Url::parse(http_call_url(&rec.callee))
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
        {
            Some(host) => format!("http_call {host}"),
            None => "http_call".to_string(),
        },
        _ => match agent {
            Some(a) => format!("{kind} {a}"),
            None => kind.to_string(),
        },
    }
}

fn span_kind(direction: Direction) -> i32 {
    match direction {
        Direction::Inbound => SPAN_KIND_SERVER,
        Direction::Outbound => SPAN_KIND_CLIENT,
        Direction::Internal => SPAN_KIND_INTERNAL,
    }
}

/// A payload as an attribute value: strings as they are, other JSON compact; `None` for null.
fn payload_text(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        other => serde_json::to_string(other).ok(),
    }
}

fn attributes(rec: &AuditRecord, export_payloads: bool) -> Vec<KeyValue> {
    let mut a = vec![
        KeyValue::string("attache.kind", rec.kind.as_str()),
        KeyValue::string("attache.decision", rec.decision.as_str()),
    ];
    if let Some(rule) = &rec.rule {
        a.push(KeyValue::string("attache.rule", rule.as_str()));
    }
    a.push(KeyValue::string("attache.caller", rec.caller.as_str()));
    if let Some(ca) = &rec.caller_agent {
        a.push(KeyValue::string("attache.caller_agent", ca.as_str()));
    }
    if let Some(agent) = &rec.agent {
        a.push(KeyValue::string("attache.agent", agent.as_str()));
    }
    if !rec.request_id.is_empty() {
        a.push(KeyValue::string(
            "attache.request_id",
            rec.request_id.as_str(),
        ));
    }
    if rec.kind == Kind::ModelCall {
        let (provider, model) = model_of(&rec.callee);
        a.push(KeyValue::string("gen_ai.system", provider));
        a.push(KeyValue::string("gen_ai.operation.name", "chat"));
        a.push(KeyValue::string("gen_ai.request.model", model));
        if let Some(t) = rec.tokens {
            a.push(KeyValue::int(
                "gen_ai.usage.input_tokens",
                i64::from(t.input),
            ));
            a.push(KeyValue::int(
                "gen_ai.usage.output_tokens",
                i64::from(t.output),
            ));
        }
    }
    if export_payloads {
        match rec.kind {
            Kind::HttpCall => {
                let full = http_call_url(&rec.callee);
                if !full.is_empty() {
                    a.push(KeyValue::string("url.full", full));
                }
                if let Ok(u) = url::Url::parse(full) {
                    a.push(KeyValue::string("url.path", u.path()));
                }
            }
            Kind::ServiceCall => {
                if let Some((_, _, path)) = service_call_parts(&rec.callee) {
                    let path = path.split(['?', '#']).next().unwrap_or("");
                    if !path.is_empty() {
                        a.push(KeyValue::string("url.path", path));
                    }
                }
            }
            _ => {}
        }
        if let Some(input) = payload_text(&rec.input) {
            a.push(KeyValue::string("attache.input", input));
        }
        if let Some(output) = payload_text(&rec.output) {
            a.push(KeyValue::string("attache.output", output));
        }
    }
    a
}

/// ERROR when the decision is `deny` or `error` is set; the message is the error, else the
/// reason, else the rule.
fn status(rec: &AuditRecord) -> Option<Status> {
    if rec.decision != "deny" && rec.error.is_none() {
        return None;
    }
    let message = rec
        .error
        .clone()
        .or_else(|| rec.reason.clone())
        .or_else(|| rec.rule.clone())
        .unwrap_or_default();
    Some(Status {
        message,
        code: STATUS_CODE_ERROR,
    })
}

/// The span for one record. `seq` is a per-process sequence number ([`next_sequence`]); it only
/// matters for records that get a derived id. Start = `ts − latency_ms`, end = `ts`.
pub fn span_from_record(rec: &AuditRecord, seq: u64, export_payloads: bool) -> Span {
    let kind = rec.kind.as_str();
    let rule = rec.rule.as_deref().unwrap_or("");
    let own = valid_id(&rec.span_id, 16);
    let (span_id, parent_span_id) = if keeps_span_id(rec.kind) {
        let parent = rec.parent_span_id.as_deref().and_then(|p| valid_id(p, 16));
        let id = own.unwrap_or_else(|| derived_span_id(&rec.span_id, kind, rule, &rec.ts, seq));
        (id, parent)
    } else {
        (derived_span_id(&rec.span_id, kind, rule, &rec.ts, seq), own)
    };
    // Without a valid trace id the span starts a trace of its own, so it has no parent.
    let (trace_id, parent_span_id) = match valid_id(&rec.trace_id, 32) {
        Some(t) => (t, parent_span_id),
        None => (
            derived_trace_id(&rec.span_id, kind, rule, &rec.ts, seq),
            None,
        ),
    };
    let end = end_unix_nanos(&rec.ts);
    let start = end.saturating_sub(rec.latency_ms.saturating_mul(1_000_000));
    Span {
        trace_id,
        span_id,
        parent_span_id,
        name: span_name(rec),
        kind: span_kind(rec.direction),
        start_time_unix_nano: start.to_string(),
        end_time_unix_nano: end.to_string(),
        attributes: attributes(rec, export_payloads),
        status: status(rec),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_ids_are_deterministic_and_distinct() {
        let a = derived_span_id(
            "00f067aa0ba902b7",
            "guardrail",
            "r",
            "2026-10-21T10:00:00.000Z",
            7,
        );
        let b = derived_span_id(
            "00f067aa0ba902b7",
            "guardrail",
            "r",
            "2026-10-21T10:00:00.000Z",
            7,
        );
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        let c = derived_span_id(
            "00f067aa0ba902b7",
            "guardrail",
            "r",
            "2026-10-21T10:00:00.000Z",
            8,
        );
        assert_ne!(a, c);
        assert_eq!(
            derived_trace_id("", "config", "", "2026-10-21T10:00:00.000Z", 1).len(),
            32
        );
    }

    #[test]
    fn derived_id_matches_its_definition() {
        let mut h = Sha256::new();
        h.update(b"00f067aa0ba902b7budgetbudget.max_calls2026-10-21T10:00:00.000Z");
        h.update(42u64.to_be_bytes());
        let d = h.finalize();
        assert_eq!(
            derived_span_id(
                "00f067aa0ba902b7",
                "budget",
                "budget.max_calls",
                "2026-10-21T10:00:00.000Z",
                42
            ),
            hex::encode(&d[..8])
        );
    }

    #[test]
    fn ids_are_validated() {
        assert_eq!(
            valid_id("00F067AA0BA902B7", 16).as_deref(),
            Some("00f067aa0ba902b7")
        );
        assert_eq!(valid_id("0000000000000000", 16), None);
        assert_eq!(valid_id("00f067aa0ba902b", 16), None);
        assert_eq!(valid_id("00f067aa0ba902bz", 16), None);
        assert_eq!(valid_id("", 16), None);
        assert_eq!(nonzero_hex(&[0, 0]), "0001");
    }

    #[test]
    fn callee_parsing() {
        assert_eq!(
            model_of("anthropic:claude-opus-5-5"),
            ("anthropic", "claude-opus-5-5")
        );
        assert_eq!(model_of("mock"), ("mock", "mock"));
        assert_eq!(model_of(":x"), (":x", ":x"));
        assert_eq!(tool_of("load_skill:refund-policy"), "load_skill");
        assert_eq!(tool_of("get_stock"), "get_stock");
        assert_eq!(
            service_call_parts("inventory GET /stock/W 1"),
            Some(("inventory", "GET", "/stock/W 1"))
        );
        assert_eq!(service_call_parts("inventory"), None);
        assert_eq!(
            http_call_url("GET https://x.example/a"),
            "https://x.example/a"
        );
        assert_eq!(http_call_url("https://x.example/a"), "https://x.example/a");
    }

    #[test]
    fn time_parsing() {
        assert_eq!(
            end_unix_nanos("2026-10-21T10:00:00.250Z"),
            1_792_576_800_250_000_000
        );
        assert_eq!(end_unix_nanos("1960-01-01T00:00:00Z"), 0);
        let now = now_unix_nanos();
        assert!(end_unix_nanos("not a time") >= now);
    }
}
