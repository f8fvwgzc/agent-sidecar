//! The stateless span rule: derived ids are deterministic for the same input and unique across
//! records, hop records keep their ids, and payloads stay out unless `export_payloads`.
mod common;

use agentsc_common::audit::{Direction, Kind};
use agentsc_otel::otlp::{AnyValue, Span};
use agentsc_otel::spans::{derived_span_id, next_sequence, span_from_record};
use common::*;
use std::collections::HashSet;

fn attr<'a>(span: &'a Span, key: &str) -> Option<&'a AnyValue> {
    span.attributes
        .iter()
        .find(|kv| kv.key == key)
        .map(|kv| &kv.value)
}

#[test]
fn the_same_record_and_sequence_give_the_same_span() {
    for (_, rec) in one_of_every_kind() {
        assert_eq!(
            span_from_record(&rec, 9, true),
            span_from_record(&rec, 9, true)
        );
    }
}

#[test]
fn derived_ids_are_unique_even_for_identical_records() {
    // Same span, kind, rule and ts: only the per-process sequence tells them apart.
    let mut rec = base(Kind::Guardrail, Direction::Internal);
    rec.rule = Some("guardrail.pii_redact".into());
    let mut seen = HashSet::new();
    for _ in 0..20_000 {
        let span = span_from_record(&rec, next_sequence(), false);
        assert_eq!(span.parent_span_id.as_deref(), Some(INVOCATION_SPAN));
        assert_eq!(span.span_id.len(), 16);
        assert_ne!(span.span_id, INVOCATION_SPAN);
        assert!(seen.insert(span.span_id), "duplicate derived span id");
    }
}

#[test]
fn derived_ids_depend_on_every_input() {
    let ts = "2026-10-21T10:00:00.000Z";
    let a = derived_span_id(INVOCATION_SPAN, "budget", "budget.x", ts, 1);
    let others = [
        derived_span_id("1111111111111111", "budget", "budget.x", ts, 1),
        derived_span_id(INVOCATION_SPAN, "authz", "budget.x", ts, 1),
        derived_span_id(INVOCATION_SPAN, "budget", "budget.y", ts, 1),
        derived_span_id(
            INVOCATION_SPAN,
            "budget",
            "budget.x",
            "2026-10-21T10:00:00.001Z",
            1,
        ),
        derived_span_id(INVOCATION_SPAN, "budget", "budget.x", ts, 2),
    ];
    for o in others {
        assert_ne!(a, o);
    }
}

#[test]
fn the_sequence_is_process_wide_and_increasing() {
    let a = next_sequence();
    let b = next_sequence();
    assert!(b > a);
}

#[test]
fn hop_records_keep_their_ids_and_events_nest_under_them() {
    for kind in [
        Kind::AgentInvocation,
        Kind::AgentCall,
        Kind::ModelCall,
        Kind::ToolCall,
        Kind::ServiceCall,
        Kind::HttpCall,
    ] {
        let span = span_from_record(&base(kind, Direction::Outbound), 1, false);
        assert_eq!(span.span_id, INVOCATION_SPAN, "{kind}");
        assert_eq!(span.parent_span_id.as_deref(), Some(PARENT_SPAN), "{kind}");
    }
    for kind in [
        Kind::Guardrail,
        Kind::Budget,
        Kind::Authz,
        Kind::Config,
        Kind::Learning,
    ] {
        let span = span_from_record(&base(kind, Direction::Internal), 1, false);
        assert_ne!(span.span_id, INVOCATION_SPAN, "{kind}");
        assert_eq!(
            span.parent_span_id.as_deref(),
            Some(INVOCATION_SPAN),
            "{kind}"
        );
    }
}

#[test]
fn an_event_without_a_span_id_has_no_parent() {
    let mut rec = base(Kind::Authz, Direction::Inbound);
    rec.span_id = String::new();
    let span = span_from_record(&rec, 1, false);
    assert_eq!(span.parent_span_id, None);
    assert_eq!(span.trace_id, TRACE);
}

#[test]
fn a_record_without_a_valid_trace_id_starts_its_own_trace() {
    for kind in [Kind::Guardrail, Kind::ToolCall] {
        let mut rec = base(kind, Direction::Internal);
        rec.trace_id = String::new();
        let span = span_from_record(&rec, 3, false);
        assert_ne!(span.trace_id, TRACE, "{kind}");
        assert_eq!(span.trace_id.len(), 32, "{kind}");
        assert_eq!(
            span.parent_span_id, None,
            "{kind}: a parent in another trace"
        );
        assert_eq!(span_from_record(&rec, 3, false).trace_id, span.trace_id);
        assert_ne!(span_from_record(&rec, 4, false).trace_id, span.trace_id);
    }
}

#[test]
fn malformed_ids_are_never_exported_as_is() {
    let mut rec = base(Kind::ModelCall, Direction::Outbound);
    rec.trace_id = "not-a-trace".into();
    rec.span_id = "0000000000000000".into();
    rec.parent_span_id = Some("xyz".into());
    let span = span_from_record(&rec, 5, false);
    assert_eq!(span.trace_id.len(), 32);
    assert!(span.trace_id.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_ne!(span.span_id, "0000000000000000");
    assert_eq!(span.span_id.len(), 16);
    assert_eq!(span.parent_span_id, None);
    // upper-case ids are normalized
    let mut rec = base(Kind::AgentInvocation, Direction::Inbound);
    rec.trace_id = TRACE.to_uppercase();
    rec.span_id = INVOCATION_SPAN.to_uppercase();
    let span = span_from_record(&rec, 5, false);
    assert_eq!(span.trace_id, TRACE);
    assert_eq!(span.span_id, INVOCATION_SPAN);
}

#[test]
fn span_kind_follows_direction() {
    for (dir, kind) in [
        (Direction::Inbound, 2),
        (Direction::Outbound, 3),
        (Direction::Internal, 1),
    ] {
        assert_eq!(
            span_from_record(&base(Kind::ToolCall, dir), 1, false).kind,
            kind
        );
        assert_eq!(
            span_from_record(&base(Kind::Budget, dir), 1, false).kind,
            kind
        );
    }
}

#[test]
fn names_are_low_cardinality() {
    let mut rec = base(Kind::ServiceCall, Direction::Outbound);
    rec.callee = "inventory get /stock/WIDGET-1?full=1".into();
    assert_eq!(
        span_from_record(&rec, 1, false).name,
        "service_call inventory GET"
    );
    let mut rec = base(Kind::HttpCall, Direction::Outbound);
    rec.callee = "POST https://api.partner.example:8443/v1/orders/123".into();
    assert_eq!(
        span_from_record(&rec, 1, false).name,
        "http_call api.partner.example"
    );
    rec.callee = "garbage".into();
    assert_eq!(span_from_record(&rec, 1, false).name, "http_call");
    let mut rec = base(Kind::ModelCall, Direction::Outbound);
    rec.callee = "mock".into();
    let span = span_from_record(&rec, 1, false);
    assert_eq!(span.name, "model_call mock");
    assert_eq!(
        attr(&span, "gen_ai.system"),
        Some(&AnyValue::StringValue("mock".into()))
    );
    let mut rec = base(Kind::ToolCall, Direction::Internal);
    rec.callee = "get_stock".into();
    rec.agent = None;
    assert_eq!(span_from_record(&rec, 1, false).name, "tool_call get_stock");
    let mut rec = base(Kind::Config, Direction::Internal);
    rec.agent = None;
    assert_eq!(span_from_record(&rec, 1, false).name, "config");
}

#[test]
fn payload_attributes_only_with_export_payloads() {
    for (name, rec) in one_of_every_kind() {
        let off = span_from_record(&rec, 1, false);
        for key in ["url.full", "url.path", "agentsc.input", "agentsc.output"] {
            assert!(attr(&off, key).is_none(), "{name}: {key}");
        }
        let on = span_from_record(&rec, 1, true);
        assert_eq!(
            attr(&on, "agentsc.input").is_some(),
            !rec.input.is_null(),
            "{name}"
        );
        assert_eq!(
            attr(&on, "agentsc.output").is_some(),
            !rec.output.is_null(),
            "{name}"
        );
    }
}

#[test]
fn status_is_error_for_denials_and_errors_only() {
    let ok = span_from_record(&base(Kind::ToolCall, Direction::Internal), 1, false);
    assert_eq!(ok.status, None);
    let mut denied = base(Kind::ToolCall, Direction::Internal);
    denied.decision = "deny".into();
    denied.rule = Some("guardrail.allowed_tools".into());
    let s = span_from_record(&denied, 1, false)
        .status
        .expect("error status");
    assert_eq!((s.code, s.message.as_str()), (2, "guardrail.allowed_tools"));
    let mut errored = base(Kind::ModelCall, Direction::Outbound);
    errored.error = Some("overloaded".into());
    errored.reason = Some("ignored when error is set".into());
    let s = span_from_record(&errored, 1, true)
        .status
        .expect("error status");
    assert_eq!((s.code, s.message.as_str()), (2, "overloaded"));
    // without payloads only the rule (here none) is the message
    let s = span_from_record(&errored, 1, false)
        .status
        .expect("error status");
    assert_eq!((s.code, s.message.as_str()), (2, ""));
}

/// The texts the sidecar writes into `reason` and `error` quote paths and URLs (authz deny
/// reasons, the http tool's mismatch, reqwest's "error sending request for url (…)").
fn records_quoting_the_request() -> Vec<(&'static str, agentsc_common::audit::AuditRecord)> {
    let mut out = Vec::new();

    let mut r = base(Kind::Authz, Direction::Inbound);
    r.decision = "deny".into();
    r.rule = Some("authz.services.deny-admin".into());
    r.reason =
        Some("POST /admin/reset?token=s3cr3t on inventory matches deny pattern /admin/*".into());
    out.push(("authz deny with a rule", r));

    let mut r = base(Kind::ServiceCall, Direction::Inbound);
    r.callee = "orders GET /customers/42/cards?full=1".into();
    r.decision = "deny".into();
    r.rule = None;
    r.reason = Some("no rule allows GET /customers/42/cards?full=1 for inventory".into());
    out.push(("service_call deny without a rule", r));

    let mut r = base(Kind::ToolCall, Direction::Internal);
    r.callee = "get_rates".into();
    r.decision = "deny".into();
    r.rule = Some("tools.http.mismatch".into());
    r.reason = Some(
        "GET https://api.partner.example/v1/rates?key=s3cr3t does not match tool get_rates".into(),
    );
    out.push(("http tool mismatch", r));

    let mut r = base(Kind::HttpCall, Direction::Outbound);
    r.callee = "GET https://api.partner.example/v1/rates?key=s3cr3t".into();
    r.error = Some(
        "error sending request for url (https://api.partner.example/v1/rates?key=s3cr3t)".into(),
    );
    out.push(("http_call transport error", r));

    let mut r = base(Kind::ToolCall, Direction::Internal);
    r.callee = "get_rates".into();
    r.rule = Some("tools.http.error".into());
    r.error = Some(
        "error sending request for url (https://api.partner.example/v1/rates?key=s3cr3t)".into(),
    );
    r.reason = Some("GET /v1/rates?key=s3cr3t".into());
    out.push(("tool_call error with a rule", r));

    out
}

#[test]
fn the_status_message_carries_no_request_text_without_export_payloads() {
    let mut cases = records_quoting_the_request();
    cases.extend(one_of_every_kind());
    for (name, rec) in cases {
        let error = rec.decision == "deny" || rec.error.is_some();
        let off = span_from_record(&rec, 1, false);
        assert_eq!(off.status.is_some(), error, "{name}");
        if let Some(s) = &off.status {
            assert_eq!(s.code, 2, "{name}");
            assert_eq!(
                s.message,
                rec.rule.clone().unwrap_or_default(),
                "{name}: only the rule"
            );
            for leak in ["/", "s3cr3t", "?"] {
                assert!(!s.message.contains(leak), "{name}: {leak:?} in {s:?}");
            }
        }
        // the whole span, serialized, quotes none of it
        let json = serde_json::to_string(&off).expect("json");
        assert!(!json.contains("s3cr3t"), "{name}: {json}");
        assert!(!json.contains("/admin/reset"), "{name}: {json}");
        assert!(!json.contains("/customers/42"), "{name}: {json}");
        // with payloads the full text is there to debug with
        let on = span_from_record(&rec, 1, true);
        if let Some(s) = &on.status {
            let full = rec
                .error
                .clone()
                .or_else(|| rec.reason.clone())
                .or_else(|| rec.rule.clone())
                .unwrap_or_default();
            assert_eq!(s.message, full, "{name}");
        }
    }
}

#[test]
fn start_is_ts_minus_latency() {
    let mut rec = base(Kind::AgentInvocation, Direction::Inbound);
    rec.ts = "2026-10-21T10:00:01.180Z".into();
    rec.latency_ms = 1180;
    let span = span_from_record(&rec, 1, false);
    assert_eq!(span.end_time_unix_nano, "1792576801180000000");
    assert_eq!(span.start_time_unix_nano, "1792576800000000000");
    rec.latency_ms = u64::MAX;
    assert_eq!(span_from_record(&rec, 1, false).start_time_unix_nano, "0");
}
