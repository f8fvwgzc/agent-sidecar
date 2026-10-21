//! Cumulative metrics aggregated from audit records (design §9).
//!
//! | metric | type | attributes | from |
//! | --- | --- | --- | --- |
//! | `agentsc.invocations` | sum (int) | `agent`, `decision` | `agent_invocation` records |
//! | `agentsc.decisions` | sum (int) | `kind`, `decision`, `rule` | every record |
//! | `gen_ai.client.token.usage` | histogram | `agent`, `model`, `gen_ai.token.type` | `model_call` records with tokens |
//! | `agentsc.cost.usd` | sum (double) | `agent`, `model` | `model_call` records with a cost |
//! | `agentsc.latency` | histogram (ms) | `kind`, `agent` | every record |
//! | `agentsc.otel.dropped` | sum (int) | — | records this exporter lost |
//!
//! Tokens and cost are taken from `model_call` records only: `agent_invocation` and `agent_call`
//! records repeat the totals of the model calls under them, and counting them too would count
//! every token twice (or, across services, three times). An attribute whose record field is null
//! is left out. Each metric keeps at most [`MAX_SERIES`] attribute sets; further ones are folded
//! into one series with the single attribute `otel.metric.overflow=true`.
use crate::otlp::{
    AGGREGATION_TEMPORALITY_CUMULATIVE, AnyValue, Histogram, HistogramDataPoint, KeyValue, Metric,
    NumberDataPoint, Sum,
};
use crate::spans::model_of;
use agentsc_common::audit::{AuditRecord, Kind};
use std::collections::BTreeMap;

/// Explicit bucket bounds of `agentsc.latency`, in milliseconds.
pub const LATENCY_BOUNDS_MS: &[f64] = &[
    5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0, 30000.0, 60000.0,
];

/// Explicit bucket bounds of `gen_ai.client.token.usage`.
pub const TOKEN_BOUNDS: &[f64] = &[
    1.0, 4.0, 16.0, 64.0, 256.0, 1024.0, 4096.0, 16384.0, 65536.0, 262144.0,
];

/// Attribute sets kept per metric before new ones go to the overflow series.
pub const MAX_SERIES: usize = 1000;

type Attrs = Vec<(&'static str, String)>;

fn overflow_attrs() -> Attrs {
    vec![("otel.metric.overflow", "true".to_string())]
}

/// One explicit-bucket histogram series.
#[derive(Debug, Clone, PartialEq)]
pub struct HistogramState {
    bounds: &'static [f64],
    buckets: Vec<u64>,
    count: u64,
    sum: f64,
    min: f64,
    max: f64,
}

impl HistogramState {
    fn new(bounds: &'static [f64]) -> Self {
        Self {
            bounds,
            buckets: vec![0; bounds.len() + 1],
            count: 0,
            sum: 0.0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
        }
    }

    /// Bucket `i` holds values in `(bounds[i-1], bounds[i]]`; the last one everything above.
    fn record(&mut self, v: f64) {
        if !v.is_finite() {
            return;
        }
        let i = self
            .bounds
            .iter()
            .position(|b| v <= *b)
            .unwrap_or(self.bounds.len());
        if let Some(b) = self.buckets.get_mut(i) {
            *b += 1;
        }
        self.count += 1;
        self.sum += v;
        self.min = self.min.min(v);
        self.max = self.max.max(v);
    }

    pub fn bucket_counts(&self) -> &[u64] {
        &self.buckets
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn sum(&self) -> f64 {
        self.sum
    }
}

fn entry<V>(map: &mut BTreeMap<Attrs, V>, attrs: Attrs, new: impl Fn() -> V) -> &mut V {
    let key = if map.contains_key(&attrs) || map.len() < MAX_SERIES {
        attrs
    } else {
        overflow_attrs()
    };
    map.entry(key).or_insert_with(new)
}

fn attrs(pairs: &[(&'static str, Option<&str>)]) -> Attrs {
    pairs
        .iter()
        .filter_map(|(k, v)| v.map(|v| (*k, v.to_string())))
        .collect()
}

/// Cumulative state since the exporter started.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MetricsState {
    invocations: BTreeMap<Attrs, u64>,
    decisions: BTreeMap<Attrs, u64>,
    tokens: BTreeMap<Attrs, HistogramState>,
    cost: BTreeMap<Attrs, f64>,
    latency: BTreeMap<Attrs, HistogramState>,
}

impl MetricsState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one record.
    pub fn record(&mut self, rec: &AuditRecord) {
        let kind = rec.kind.as_str();
        let agent = rec.agent.as_deref();
        let decision = rec.decision.as_str();
        if rec.kind == Kind::AgentInvocation {
            *entry(
                &mut self.invocations,
                attrs(&[("agent", agent), ("decision", Some(decision))]),
                || 0,
            ) += 1;
        }
        *entry(
            &mut self.decisions,
            attrs(&[
                ("kind", Some(kind)),
                ("decision", Some(decision)),
                ("rule", rec.rule.as_deref()),
            ]),
            || 0,
        ) += 1;
        if rec.kind == Kind::ModelCall {
            let model = model_of(&rec.callee).1;
            if let Some(t) = rec.tokens {
                for (token_type, n) in [("input", t.input), ("output", t.output)] {
                    entry(
                        &mut self.tokens,
                        attrs(&[
                            ("agent", agent),
                            ("model", Some(model)),
                            ("gen_ai.token.type", Some(token_type)),
                        ]),
                        || HistogramState::new(TOKEN_BOUNDS),
                    )
                    .record(f64::from(n));
                }
            }
            if let Some(cost) = rec.cost_usd.filter(|c| c.is_finite() && *c >= 0.0) {
                *entry(
                    &mut self.cost,
                    attrs(&[("agent", agent), ("model", Some(model))]),
                    || 0.0,
                ) += cost;
            }
        }
        entry(
            &mut self.latency,
            attrs(&[("kind", Some(kind)), ("agent", agent)]),
            || HistogramState::new(LATENCY_BOUNDS_MS),
        )
        .record(rec.latency_ms as f64);
    }

    /// The `agentsc.latency` series for these attributes (for tests and diagnostics).
    pub fn latency(&self, kind: &str, agent: Option<&str>) -> Option<&HistogramState> {
        let key: Attrs = attrs(&[("kind", Some(kind)), ("agent", agent)]);
        self.latency.get(&key)
    }

    /// The metrics to export: cumulative since `start_unix_nano`, as of `now_unix_nano`, with
    /// `dropped` as `agentsc.otel.dropped`. Metrics with no data points are left out, except
    /// `agentsc.otel.dropped`, which is always reported.
    pub fn to_metrics(
        &self,
        start_unix_nano: u64,
        now_unix_nano: u64,
        dropped: u64,
    ) -> Vec<Metric> {
        let (start, now) = (start_unix_nano.to_string(), now_unix_nano.to_string());
        let int_sum = |name: &str, description: &str, unit: &str, map: &BTreeMap<Attrs, u64>| {
            sum_metric(
                name,
                description,
                unit,
                map.iter()
                    .map(|(a, v)| number_point(a, &start, &now, Some(v.to_string()), None))
                    .collect(),
            )
        };
        let histogram =
            |name: &str, description: &str, unit: &str, map: &BTreeMap<Attrs, HistogramState>| {
                Metric {
                    name: name.into(),
                    description: description.into(),
                    unit: unit.into(),
                    sum: None,
                    histogram: Some(Histogram {
                        data_points: map
                            .iter()
                            .map(|(a, h)| HistogramDataPoint {
                                attributes: key_values(a),
                                start_time_unix_nano: start.clone(),
                                time_unix_nano: now.clone(),
                                count: h.count.to_string(),
                                sum: h.sum,
                                bucket_counts: h.buckets.iter().map(u64::to_string).collect(),
                                explicit_bounds: h.bounds.to_vec(),
                                min: (h.count > 0).then_some(h.min),
                                max: (h.count > 0).then_some(h.max),
                            })
                            .collect(),
                        aggregation_temporality: AGGREGATION_TEMPORALITY_CUMULATIVE,
                    }),
                }
            };
        let mut out = Vec::new();
        if !self.invocations.is_empty() {
            out.push(int_sum(
                "agentsc.invocations",
                "Agent invocations handled by the sidecar.",
                "{invocation}",
                &self.invocations,
            ));
        }
        if !self.decisions.is_empty() {
            out.push(int_sum(
                "agentsc.decisions",
                "Audit records by kind, decision and rule.",
                "{decision}",
                &self.decisions,
            ));
        }
        if !self.tokens.is_empty() {
            out.push(histogram(
                "gen_ai.client.token.usage",
                "Tokens used per model call.",
                "{token}",
                &self.tokens,
            ));
        }
        if !self.cost.is_empty() {
            out.push(sum_metric(
                "agentsc.cost.usd",
                "Model cost in US dollars.",
                "USD",
                self.cost
                    .iter()
                    .map(|(a, v)| number_point(a, &start, &now, None, Some(*v)))
                    .collect(),
            ));
        }
        if !self.latency.is_empty() {
            out.push(histogram(
                "agentsc.latency",
                "Duration of each audited step.",
                "ms",
                &self.latency,
            ));
        }
        out.push(sum_metric(
            "agentsc.otel.dropped",
            "Audit records the OpenTelemetry exporter could not export.",
            "{record}",
            vec![number_point(
                &[],
                &start,
                &now,
                Some(dropped.to_string()),
                None,
            )],
        ));
        out
    }
}

fn key_values(a: &[(&'static str, String)]) -> Vec<KeyValue> {
    a.iter()
        .map(|(k, v)| KeyValue {
            key: (*k).to_string(),
            value: AnyValue::StringValue(v.clone()),
        })
        .collect()
}

fn number_point(
    a: &[(&'static str, String)],
    start: &str,
    now: &str,
    as_int: Option<String>,
    as_double: Option<f64>,
) -> NumberDataPoint {
    NumberDataPoint {
        attributes: key_values(a),
        start_time_unix_nano: start.to_string(),
        time_unix_nano: now.to_string(),
        as_int,
        as_double,
    }
}

fn sum_metric(name: &str, description: &str, unit: &str, points: Vec<NumberDataPoint>) -> Metric {
    Metric {
        name: name.into(),
        description: description.into(),
        unit: unit.into(),
        sum: Some(Sum {
            data_points: points,
            aggregation_temporality: AGGREGATION_TEMPORALITY_CUMULATIVE,
            is_monotonic: true,
        }),
        histogram: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_buckets_are_upper_inclusive() {
        let mut h = HistogramState::new(LATENCY_BOUNDS_MS);
        for v in [
            0.0,
            5.0,
            5.5,
            10.0,
            60000.0,
            60001.0,
            f64::NAN,
            f64::INFINITY,
        ] {
            h.record(v);
        }
        let mut expected = vec![0u64; LATENCY_BOUNDS_MS.len() + 1];
        expected[0] = 2; // 0, 5
        expected[1] = 2; // 5.5, 10
        expected[12] = 1; // 60000
        expected[13] = 1; // 60001
        assert_eq!(h.bucket_counts(), expected.as_slice());
        assert_eq!(h.count(), 6);
        assert_eq!(h.sum(), 0.0 + 5.0 + 5.5 + 10.0 + 60000.0 + 60001.0);
        assert_eq!((h.min, h.max), (0.0, 60001.0));
    }

    #[test]
    fn series_beyond_the_limit_go_to_overflow() {
        let mut m: BTreeMap<Attrs, u64> = BTreeMap::new();
        for i in 0..MAX_SERIES + 5 {
            *entry(&mut m, vec![("agent", i.to_string())], || 0) += 1;
        }
        assert_eq!(m.len(), MAX_SERIES + 1);
        assert_eq!(m.get(&overflow_attrs()), Some(&5));
        // an existing series still counts as itself
        *entry(&mut m, vec![("agent", "0".to_string())], || 0) += 1;
        assert_eq!(m.get(&vec![("agent", "0".to_string())]), Some(&2));
    }
}
