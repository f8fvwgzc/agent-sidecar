//! Records and helpers shared by the integration tests.
#![allow(dead_code)]

use agentsc_common::audit::{AuditRecord, Direction, Kind, Tokens};
use serde_json::{Value, json};
use std::path::PathBuf;

pub const TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
pub const INVOCATION_SPAN: &str = "00f067aa0ba902b7";
pub const PARENT_SPAN: &str = "b7ad6b7169203331";
pub const REQUEST: &str = "0c4a3f8e-6b1d-4f7e-9c11-2a5d3e4f5a6b";

pub fn resource() -> Vec<(String, String)> {
    [
        ("service.name", "orders"),
        ("service.namespace", "shop"),
        ("service.version", "0.2.0"),
        ("agentsc.identity", "spiffe://agentsc/ns/shop/svc/orders"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

/// A plain allowed record of `kind` in the demo trace; tests adjust the fields they need.
pub fn base(kind: Kind, direction: Direction) -> AuditRecord {
    AuditRecord {
        ts: "2026-10-21T10:00:01.180Z".into(),
        kind,
        request_id: REQUEST.into(),
        trace_id: TRACE.into(),
        span_id: INVOCATION_SPAN.into(),
        parent_span_id: Some(PARENT_SPAN.into()),
        service: "orders".into(),
        namespace: "shop".into(),
        agent: Some("ops-assistant".into()),
        agent_id: None,
        caller: "local".into(),
        caller_agent: None,
        callee: "ops-assistant".into(),
        direction,
        input: Value::Null,
        output: Value::Null,
        input_sha256: None,
        output_sha256: None,
        tokens: None,
        cost_usd: None,
        latency_ms: 0,
        decision: "allow".into(),
        rule: None,
        reason: None,
        error: None,
    }
}

/// One record of every kind, in the order of `Kind`, with the file stem of its golden.
pub fn one_of_every_kind() -> Vec<(&'static str, AuditRecord)> {
    let mut out = Vec::new();

    let mut r = base(Kind::AgentInvocation, Direction::Inbound);
    r.input = json!({"message": "How many WIDGET-1 are left?"});
    r.output = json!("12 in stock.");
    r.input_sha256 = Some("a".repeat(64));
    r.output_sha256 = Some("b".repeat(64));
    r.tokens = Some(Tokens {
        input: 1624,
        output: 192,
    });
    r.cost_usd = Some(0.0104);
    r.latency_ms = 1180;
    out.push(("agent_invocation", r));

    let mut r = base(Kind::ModelCall, Direction::Outbound);
    r.ts = "2026-10-21T10:00:00.950Z".into();
    r.span_id = "1111111111111111".into();
    r.parent_span_id = Some(INVOCATION_SPAN.into());
    r.callee = "anthropic:claude-opus-5-5".into();
    r.input = json!({"messages": [{"role": "user", "content": "How many WIDGET-1 are left?"}]});
    r.output = json!({"content": "12 in stock."});
    r.tokens = Some(Tokens {
        input: 812,
        output: 96,
    });
    r.cost_usd = Some(0.0052);
    r.latency_ms = 900;
    out.push(("model_call", r));

    let mut r = base(Kind::ToolCall, Direction::Internal);
    r.ts = "2026-10-21T10:00:00.400Z".into();
    r.span_id = "2222222222222222".into();
    r.parent_span_id = Some(INVOCATION_SPAN.into());
    r.callee = "load_skill:refund-policy".into();
    r.input = json!({"name": "refund-policy"});
    r.output = json!("Look up the order first.");
    r.latency_ms = 3;
    out.push(("tool_call", r));

    let mut r = base(Kind::AgentCall, Direction::Outbound);
    r.ts = "2026-10-21T10:00:00.800Z".into();
    r.span_id = "3333333333333333".into();
    r.parent_span_id = Some(INVOCATION_SPAN.into());
    r.callee = "inventory/stock-analyst".into();
    r.input = json!({"message": "stock for WIDGET-1"});
    r.output = json!("12");
    r.tokens = Some(Tokens {
        input: 400,
        output: 20,
    });
    r.cost_usd = Some(0.002);
    r.latency_ms = 380;
    out.push(("agent_call", r));

    let mut r = base(Kind::ServiceCall, Direction::Inbound);
    r.ts = "2026-10-21T10:00:00.500Z".into();
    r.span_id = "4444444444444444".into();
    r.parent_span_id = Some("3333333333333333".into());
    r.agent = Some("stock-analyst".into());
    r.caller = "spiffe://agentsc/ns/shop/svc/inventory".into();
    r.caller_agent = Some("stock-analyst".into());
    r.callee = "orders POST /admin/reset?force=1".into();
    r.input = json!({"confirm": true});
    r.decision = "deny".into();
    r.rule = Some("authz.services.deny-admin".into());
    r.reason = Some("POST /admin/reset is denied for inventory".into());
    r.latency_ms = 1;
    out.push(("service_call", r));

    let mut r = base(Kind::HttpCall, Direction::Outbound);
    r.ts = "2026-10-21T10:00:00.700Z".into();
    r.span_id = "5555555555555555".into();
    r.parent_span_id = Some(INVOCATION_SPAN.into());
    r.callee = "GET https://api.partner.example/v1/rates?ccy=EUR".into();
    r.input = json!({"ccy": "EUR"});
    r.error = Some("timed out after 10s".into());
    r.latency_ms = 10000;
    out.push(("http_call", r));

    let mut r = base(Kind::Authz, Direction::Inbound);
    r.ts = "2026-10-21T10:00:00.010Z".into();
    r.span_id = "6666666666666666".into();
    r.parent_span_id = Some("7777777777777777".into());
    r.agent = None;
    r.caller = "unknown".into();
    r.callee = "ops-assistant".into();
    r.decision = "deny".into();
    r.rule = Some("authz.identity.invalid".into());
    r.reason = Some("client certificate has no SPIFFE id".into());
    out.push(("authz", r));

    let mut r = base(Kind::Guardrail, Direction::Internal);
    r.ts = "2026-10-21T10:00:01.170Z".into();
    r.rule = Some("guardrail.pii_redact".into());
    r.reason = Some("1 redaction(s)".into());
    r.output = json!("[redacted:email]");
    out.push(("guardrail", r));

    let mut r = base(Kind::Budget, Direction::Internal);
    r.ts = "2026-10-21T10:00:00.020Z".into();
    r.decision = "deny".into();
    r.rule = Some("budget.max_calls_per_minute".into());
    r.reason = Some("60 calls in the last minute".into());
    out.push(("budget", r));

    let mut r = base(Kind::Config, Direction::Internal);
    r.ts = "2026-10-21T09:59:00.000Z".into();
    r.request_id = "5f0e1d2c-3b4a-4596-8877-665544332211".into();
    r.trace_id = "9a8b7c6d5e4f30211203f4e5d6c7b8a9".into();
    r.span_id = "8888888888888888".into();
    r.parent_span_id = None;
    r.agent = None;
    r.caller = "control-plane".into();
    r.callee = "charter".into();
    r.input = json!({"source": "control-plane", "epoch": "e1", "version": "7", "sha256": "c".repeat(64), "weakened": []});
    r.rule = Some("config.applied".into());
    r.latency_ms = 12;
    out.push(("config", r));

    let mut r = base(Kind::Learning, Direction::Internal);
    r.ts = "2026-10-21T10:00:05.000Z".into();
    r.span_id = "9999999999999999".into();
    r.parent_span_id = Some(INVOCATION_SPAN.into());
    r.callee = "learning".into();
    r.input = json!({"request_id_of_run": REQUEST});
    r.output = json!({"note": "Check stock before promising dates.", "rationale": "Asked twice."});
    r.rule = Some("learning.proposed".into());
    out.push(("learning", r));

    out
}

/// A `config` record with no usable trace or span id (e.g. written before any request).
pub fn config_without_trace() -> AuditRecord {
    let mut r = base(Kind::Config, Direction::Internal);
    r.ts = "2026-10-21T09:58:00.000Z".into();
    r.request_id = String::new();
    r.trace_id = String::new();
    r.span_id = String::new();
    r.parent_span_id = None;
    r.agent = None;
    r.caller = "file".into();
    r.callee = "certificate".into();
    r.decision = "allow".into();
    r.rule = Some("cert.renew_failed".into());
    r.error = Some("CA unreachable".into());
    r
}

pub fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join(name)
}

/// The scope version is the crate version; goldens hold `"<version>"` so a release bump does
/// not touch them.
fn normalize_scope_version(v: &mut Value) {
    for (outer, inner) in [
        ("resourceSpans", "scopeSpans"),
        ("resourceMetrics", "scopeMetrics"),
    ] {
        let Some(resources) = v.get_mut(outer).and_then(Value::as_array_mut) else {
            continue;
        };
        for r in resources {
            let Some(scopes) = r.get_mut(inner).and_then(Value::as_array_mut) else {
                continue;
            };
            for s in scopes {
                if let Some(version) = s.get_mut("scope").and_then(|s| s.get_mut("version")) {
                    assert_eq!(version, &json!(env!("CARGO_PKG_VERSION")));
                    *version = json!("<version>");
                }
            }
        }
    }
}

/// Compare `actual` with the golden file; with `AGENTSC_UPDATE_GOLDEN=1` write it instead.
pub fn assert_golden(name: &str, actual: &Value) {
    let mut actual = actual.clone();
    normalize_scope_version(&mut actual);
    let actual = &actual;
    let path = golden_path(name);
    let pretty = serde_json::to_string_pretty(actual).expect("serialize") + "\n";
    if std::env::var_os("AGENTSC_UPDATE_GOLDEN").is_some() {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).expect("create golden dir");
        }
        std::fs::write(&path, pretty).expect("write golden");
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e}; run with AGENTSC_UPDATE_GOLDEN=1 to create it",
            path.display()
        )
    });
    let expected: Value = serde_json::from_str(&expected).expect("golden is JSON");
    assert_eq!(
        actual,
        &expected,
        "{} differs; actual:\n{pretty}",
        path.display()
    );
}
