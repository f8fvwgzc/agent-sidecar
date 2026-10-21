//! Metric aggregation: what each record adds to which series.
mod common;

use attache_common::audit::{Direction, Kind, Tokens};
use attache_otel::metrics::{LATENCY_BOUNDS_MS, MetricsState, TOKEN_BOUNDS};
use attache_otel::otlp::{AnyValue, Metric};
use common::*;

fn find<'a>(metrics: &'a [Metric], name: &str) -> Option<&'a Metric> {
    metrics.iter().find(|m| m.name == name)
}

fn attrs_of(kv: &[attache_otel::otlp::KeyValue]) -> Vec<(String, String)> {
    kv.iter()
        .map(|kv| {
            let v = match &kv.value {
                AnyValue::StringValue(s) => s.clone(),
                other => format!("{other:?}"),
            };
            (kv.key.clone(), v)
        })
        .collect()
}

fn pairs(p: &[(&str, &str)]) -> Vec<(String, String)> {
    p.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// `(attributes, asInt)` of an int sum.
fn int_points(m: &Metric) -> Vec<(Vec<(String, String)>, u64)> {
    m.sum
        .as_ref()
        .map(|s| {
            s.data_points
                .iter()
                .map(|p| {
                    (
                        attrs_of(&p.attributes),
                        p.as_int
                            .as_deref()
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(u64::MAX),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn nothing_recorded_reports_only_dropped() {
    let metrics = MetricsState::new().to_metrics(1, 2, 0);
    assert_eq!(metrics.len(), 1);
    assert_eq!(metrics[0].name, "attache.otel.dropped");
    assert_eq!(int_points(&metrics[0]), vec![(vec![], 0)]);
}

#[test]
fn invocations_count_agent_invocations_by_agent_and_decision() {
    let mut m = MetricsState::new();
    for decision in ["allow", "allow", "deny"] {
        let mut r = base(Kind::AgentInvocation, Direction::Inbound);
        r.decision = decision.into();
        m.record(&r);
    }
    let mut other = base(Kind::AgentInvocation, Direction::Inbound);
    other.agent = Some("stock-analyst".into());
    m.record(&other);
    m.record(&base(Kind::ToolCall, Direction::Internal)); // not an invocation
    let metrics = m.to_metrics(1, 2, 0);
    let inv = find(&metrics, "attache.invocations").expect("invocations");
    assert_eq!(
        int_points(inv),
        vec![
            (
                pairs(&[("agent", "ops-assistant"), ("decision", "allow")]),
                2
            ),
            (
                pairs(&[("agent", "ops-assistant"), ("decision", "deny")]),
                1
            ),
            (
                pairs(&[("agent", "stock-analyst"), ("decision", "allow")]),
                1
            ),
        ]
    );
    let sum = inv.sum.as_ref().expect("sum");
    assert!(sum.is_monotonic);
    assert_eq!(sum.aggregation_temporality, 2);
}

#[test]
fn decisions_count_every_record_by_kind_decision_and_rule() {
    let mut m = MetricsState::new();
    let mut deny = base(Kind::Budget, Direction::Internal);
    deny.decision = "deny".into();
    deny.rule = Some("budget.max_calls_per_minute".into());
    m.record(&deny);
    m.record(&deny);
    m.record(&base(Kind::ModelCall, Direction::Outbound));
    let metrics = m.to_metrics(1, 2, 0);
    assert_eq!(
        int_points(find(&metrics, "attache.decisions").expect("decisions")),
        vec![
            (
                pairs(&[
                    ("kind", "budget"),
                    ("decision", "deny"),
                    ("rule", "budget.max_calls_per_minute")
                ]),
                2
            ),
            (pairs(&[("kind", "model_call"), ("decision", "allow")]), 1),
        ]
    );
}

#[test]
fn tokens_and_cost_come_from_model_calls_only() {
    let mut m = MetricsState::new();
    for (input, output, cost) in [(812, 96, 0.0052), (100, 4, 0.001)] {
        let mut r = base(Kind::ModelCall, Direction::Outbound);
        r.callee = "anthropic:claude-opus-5-5".into();
        r.tokens = Some(Tokens { input, output });
        r.cost_usd = Some(cost);
        m.record(&r);
    }
    // invocation and agent_call records repeat their model calls' totals: not counted again
    for kind in [Kind::AgentInvocation, Kind::AgentCall] {
        let mut r = base(kind, Direction::Outbound);
        r.tokens = Some(Tokens {
            input: 912,
            output: 100,
        });
        r.cost_usd = Some(0.0062);
        m.record(&r);
    }
    // a model call with no usage adds nothing to the token histogram or cost
    let mut bare = base(Kind::ModelCall, Direction::Outbound);
    bare.callee = "mock".into();
    m.record(&bare);

    let metrics = m.to_metrics(1, 2, 0);
    let tokens = find(&metrics, "gen_ai.client.token.usage").expect("tokens");
    let h = tokens.histogram.as_ref().expect("histogram");
    assert_eq!(h.aggregation_temporality, 2);
    assert_eq!(h.data_points.len(), 2);
    let input = &h.data_points[0];
    assert_eq!(
        attrs_of(&input.attributes),
        pairs(&[
            ("agent", "ops-assistant"),
            ("model", "claude-opus-5-5"),
            ("gen_ai.token.type", "input")
        ])
    );
    assert_eq!(input.count, "2");
    assert_eq!(input.sum, 912.0);
    assert_eq!(input.explicit_bounds, TOKEN_BOUNDS);
    let mut buckets = vec!["0".to_string(); TOKEN_BOUNDS.len() + 1];
    buckets[4] = "1".into(); // 100 in (64, 256]
    buckets[5] = "1".into(); // 812 in (256, 1024]
    assert_eq!(input.bucket_counts, buckets);
    assert_eq!((input.min, input.max), (Some(100.0), Some(812.0)));
    let output = &h.data_points[1];
    assert_eq!(output.count, "2");
    assert_eq!(output.sum, 100.0);

    let cost = find(&metrics, "attache.cost.usd").expect("cost");
    let points = &cost.sum.as_ref().expect("sum").data_points;
    assert_eq!(points.len(), 1);
    assert_eq!(
        attrs_of(&points[0].attributes),
        pairs(&[("agent", "ops-assistant"), ("model", "claude-opus-5-5")])
    );
    let total = points[0].as_double.unwrap_or_default();
    assert!((total - 0.0062).abs() < 1e-12, "{total}");
    assert_eq!(points[0].as_int, None);
}

#[test]
fn latency_is_a_histogram_by_kind_and_agent() {
    let mut m = MetricsState::new();
    for ms in [3, 900, 900, 70_000] {
        let mut r = base(Kind::ModelCall, Direction::Outbound);
        r.latency_ms = ms;
        m.record(&r);
    }
    let h = m
        .latency("model_call", Some("ops-assistant"))
        .expect("series");
    let mut expected = vec![0u64; LATENCY_BOUNDS_MS.len() + 1];
    expected[0] = 1; // 3
    expected[7] = 2; // 900 in (500, 1000]
    expected[13] = 1; // above 60000
    assert_eq!(h.bucket_counts(), expected.as_slice());
    assert_eq!(h.count(), 4);
    assert_eq!(h.sum(), 71_803.0);
    let mut no_agent = base(Kind::Authz, Direction::Inbound);
    no_agent.agent = None;
    m.record(&no_agent);
    assert!(m.latency("authz", None).is_some());
}

#[test]
fn totals_are_cumulative_across_pushes() {
    let mut m = MetricsState::new();
    m.record(&base(Kind::AgentInvocation, Direction::Inbound));
    let first = m.to_metrics(10, 20, 1);
    m.record(&base(Kind::AgentInvocation, Direction::Inbound));
    let second = m.to_metrics(10, 30, 4);
    let count = |ms: &[Metric]| int_points(find(ms, "attache.invocations").expect("inv"))[0].1;
    assert_eq!((count(&first), count(&second)), (1, 2));
    let dropped =
        |ms: &[Metric]| int_points(find(ms, "attache.otel.dropped").expect("dropped"))[0].1;
    assert_eq!((dropped(&first), dropped(&second)), (1, 4));
    let p = &find(&second, "attache.invocations")
        .and_then(|m| m.sum.as_ref())
        .expect("sum")
        .data_points[0];
    assert_eq!(
        (p.start_time_unix_nano.as_str(), p.time_unix_nano.as_str()),
        ("10", "30")
    );
}
