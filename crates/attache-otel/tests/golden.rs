//! Golden OTLP/HTTP JSON for one record of every kind, with and without payloads, and for the
//! metrics they aggregate to. Regenerate with `ATTACHE_UPDATE_GOLDEN=1 cargo test -p attache-otel`
//! and review the diff.
mod common;

use attache_common::audit::Kind;
use attache_otel::metrics::MetricsState;
use attache_otel::otlp::{ExportMetricsServiceRequest, ExportTraceServiceRequest};
use attache_otel::spans::{derived_span_id, keeps_span_id, span_from_record};
use common::*;
use serde_json::{Value, json};

/// The sequence number the golden spans are derived with.
const SEQ: u64 = 41;

fn traces_json(records: &[attache_common::audit::AuditRecord], payloads: bool) -> Value {
    let spans = records
        .iter()
        .map(|r| span_from_record(r, SEQ, payloads))
        .collect();
    serde_json::to_value(ExportTraceServiceRequest::new(&resource(), spans)).expect("json")
}

#[test]
fn every_kind_has_a_golden_trace() {
    let records = one_of_every_kind();
    let kinds: Vec<Kind> = records.iter().map(|(_, r)| r.kind).collect();
    assert_eq!(
        kinds,
        [
            Kind::AgentInvocation,
            Kind::ModelCall,
            Kind::ToolCall,
            Kind::AgentCall,
            Kind::ServiceCall,
            Kind::HttpCall,
            Kind::Authz,
            Kind::Guardrail,
            Kind::Budget,
            Kind::Config,
            Kind::Learning,
        ]
    );
    for (name, rec) in &records {
        assert_golden(
            &format!("traces/{name}.json"),
            &traces_json(std::slice::from_ref(rec), false),
        );
    }
}

#[test]
fn golden_traces_with_payloads() {
    let records: Vec<_> = one_of_every_kind().into_iter().map(|(_, r)| r).collect();
    assert_golden("traces_with_payloads.json", &traces_json(&records, true));
}

#[test]
fn golden_trace_without_a_trace_context() {
    assert_golden(
        "traces/config_without_trace.json",
        &traces_json(&[config_without_trace()], false),
    );
}

#[test]
fn golden_metrics() {
    let mut m = MetricsState::new();
    for (_, rec) in one_of_every_kind() {
        m.record(&rec);
    }
    // a second invocation of the same agent, denied
    let mut denied = base(
        Kind::AgentInvocation,
        attache_common::audit::Direction::Inbound,
    );
    denied.decision = "deny".into();
    denied.rule = Some("guardrail.input_deny.no-secrets".into());
    denied.latency_ms = 2;
    m.record(&denied);
    let start = 1_792_576_700_000_000_000;
    let now = 1_792_576_815_000_000_000;
    let req = ExportMetricsServiceRequest::new(&resource(), m.to_metrics(start, now, 3));
    assert_golden("metrics.json", &serde_json::to_value(req).expect("json"));
}

/// The goldens are not just self-consistent: spot-check the rules they encode.
#[test]
fn goldens_follow_the_span_rules() {
    for (name, rec) in one_of_every_kind() {
        let v = traces_json(std::slice::from_ref(&rec), false);
        let span = &v["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert_eq!(span["traceId"], json!(rec.trace_id), "{name}");
        if keeps_span_id(rec.kind) {
            assert_eq!(span["spanId"], json!(rec.span_id), "{name}");
            assert_eq!(
                span.get("parentSpanId").cloned(),
                rec.parent_span_id.clone().map(Value::String),
                "{name}"
            );
        } else {
            let derived = derived_span_id(
                &rec.span_id,
                rec.kind.as_str(),
                rec.rule.as_deref().unwrap_or(""),
                &rec.ts,
                SEQ,
            );
            assert_eq!(span["spanId"], json!(derived), "{name}");
            assert_eq!(span["parentSpanId"], json!(rec.span_id), "{name}");
        }
        let attrs = span["attributes"].as_array().cloned().unwrap_or_default();
        for a in &attrs {
            let key = a["key"].as_str().unwrap_or("");
            assert!(
                !key.starts_with("url.") && key != "attache.input" && key != "attache.output",
                "{name}: payload attribute {key} without export_payloads"
            );
        }
        let error = rec.decision == "deny" || rec.error.is_some();
        assert_eq!(span["status"]["code"] == json!(2), error, "{name}");
        // without export_payloads the status message is the rule or nothing, never the free
        // text of `reason` or `error`
        assert_eq!(
            span["status"].get("message").cloned(),
            rec.rule.clone().filter(|_| error).map(Value::String),
            "{name}"
        );
        let end: u64 = span["endTimeUnixNano"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let start: u64 = span["startTimeUnixNano"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        assert_eq!(end - start, rec.latency_ms * 1_000_000, "{name}");
    }
}
