//! OTLP/HTTP JSON wire types, written by hand with serde.
//!
//! The encoding follows the OTLP specification's JSON rules (the proto3 JSON mapping with the
//! OTLP exceptions): field names are lowerCamelCase, `traceId`/`spanId`/`parentSpanId` are
//! lowercase hex (not base64), enums are integers, and 64-bit integers (`*UnixNano`, `asInt`,
//! `intValue`, `count`, `bucketCounts`) are decimal strings. Fields at their default value are
//! left out.
use serde::Serialize;

/// `SpanKind` values.
pub const SPAN_KIND_INTERNAL: i32 = 1;
pub const SPAN_KIND_SERVER: i32 = 2;
pub const SPAN_KIND_CLIENT: i32 = 3;

/// `Status.code` for an error.
pub const STATUS_CODE_ERROR: i32 = 2;

/// `AggregationTemporality.AGGREGATION_TEMPORALITY_CUMULATIVE`.
pub const AGGREGATION_TEMPORALITY_CUMULATIVE: i32 = 2;

/// The instrumentation scope every span and metric is reported under.
pub const SCOPE_NAME: &str = "agentsc-otel";
pub const SCOPE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// `AnyValue`: exactly one of its fields is set.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AnyValue {
    StringValue(String),
    /// int64, as a decimal string.
    IntValue(String),
    DoubleValue(f64),
    BoolValue(bool),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct KeyValue {
    pub key: String,
    pub value: AnyValue,
}

impl KeyValue {
    pub fn string(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: AnyValue::StringValue(value.into()),
        }
    }

    pub fn int(key: impl Into<String>, value: i64) -> Self {
        Self {
            key: key.into(),
            value: AnyValue::IntValue(value.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Resource {
    pub attributes: Vec<KeyValue>,
}

impl Resource {
    pub fn from_pairs(pairs: &[(String, String)]) -> Self {
        Self {
            attributes: pairs
                .iter()
                .map(|(k, v)| KeyValue::string(k.clone(), v.clone()))
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InstrumentationScope {
    pub name: String,
    pub version: String,
}

impl Default for InstrumentationScope {
    fn default() -> Self {
        Self {
            name: SCOPE_NAME.into(),
            version: SCOPE_VERSION.into(),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Traces

/// The body of `POST /v1/traces`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportTraceServiceRequest {
    pub resource_spans: Vec<ResourceSpans>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceSpans {
    pub resource: Resource,
    pub scope_spans: Vec<ScopeSpans>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ScopeSpans {
    pub scope: InstrumentationScope,
    pub spans: Vec<Span>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Span {
    /// 32 lowercase hex characters.
    pub trace_id: String,
    /// 16 lowercase hex characters.
    pub span_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    pub name: String,
    pub kind: i32,
    pub start_time_unix_nano: String,
    pub end_time_unix_nano: String,
    pub attributes: Vec<KeyValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Status {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub message: String,
    pub code: i32,
}

impl ExportTraceServiceRequest {
    /// One resource, one scope, these spans.
    pub fn new(resource: &[(String, String)], spans: Vec<Span>) -> Self {
        Self {
            resource_spans: vec![ResourceSpans {
                resource: Resource::from_pairs(resource),
                scope_spans: vec![ScopeSpans {
                    scope: InstrumentationScope::default(),
                    spans,
                }],
            }],
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Metrics

/// The body of `POST /v1/metrics`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportMetricsServiceRequest {
    pub resource_metrics: Vec<ResourceMetrics>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceMetrics {
    pub resource: Resource,
    pub scope_metrics: Vec<ScopeMetrics>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ScopeMetrics {
    pub scope: InstrumentationScope,
    pub metrics: Vec<Metric>,
}

/// A metric: exactly one of `sum` and `histogram` is set.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Metric {
    pub name: String,
    pub description: String,
    pub unit: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sum: Option<Sum>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub histogram: Option<Histogram>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Sum {
    pub data_points: Vec<NumberDataPoint>,
    pub aggregation_temporality: i32,
    pub is_monotonic: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NumberDataPoint {
    pub attributes: Vec<KeyValue>,
    pub start_time_unix_nano: String,
    pub time_unix_nano: String,
    /// sfixed64, as a decimal string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_int: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_double: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Histogram {
    pub data_points: Vec<HistogramDataPoint>,
    pub aggregation_temporality: i32,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistogramDataPoint {
    pub attributes: Vec<KeyValue>,
    pub start_time_unix_nano: String,
    pub time_unix_nano: String,
    /// fixed64, as a decimal string.
    pub count: String,
    pub sum: f64,
    /// fixed64 each, as decimal strings; one more entry than `explicit_bounds`.
    pub bucket_counts: Vec<String>,
    pub explicit_bounds: Vec<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
}

impl ExportMetricsServiceRequest {
    /// One resource, one scope, these metrics.
    pub fn new(resource: &[(String, String)], metrics: Vec<Metric>) -> Self {
        Self {
            resource_metrics: vec![ResourceMetrics {
                resource: Resource::from_pairs(resource),
                scope_metrics: vec![ScopeMetrics {
                    scope: InstrumentationScope::default(),
                    metrics,
                }],
            }],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn any_value_uses_the_otlp_json_field_names() {
        let kv = [
            KeyValue::string("s", "x"),
            KeyValue::int("i", -7),
            KeyValue {
                key: "d".into(),
                value: AnyValue::DoubleValue(0.5),
            },
            KeyValue {
                key: "b".into(),
                value: AnyValue::BoolValue(true),
            },
        ];
        assert_eq!(
            serde_json::to_value(kv).ok(),
            Some(json!([
                {"key": "s", "value": {"stringValue": "x"}},
                {"key": "i", "value": {"intValue": "-7"}},
                {"key": "d", "value": {"doubleValue": 0.5}},
                {"key": "b", "value": {"boolValue": true}},
            ]))
        );
    }

    #[test]
    fn unset_optional_fields_are_left_out() {
        let span = Span {
            trace_id: "0".repeat(32),
            span_id: "0".repeat(16),
            parent_span_id: None,
            name: "n".into(),
            kind: SPAN_KIND_INTERNAL,
            start_time_unix_nano: "1".into(),
            end_time_unix_nano: "2".into(),
            attributes: vec![],
            status: None,
        };
        let v = serde_json::to_value(&span).unwrap_or_default();
        assert!(v.get("parentSpanId").is_none());
        assert!(v.get("status").is_none());
        let status = serde_json::to_value(Status {
            message: String::new(),
            code: STATUS_CODE_ERROR,
        })
        .unwrap_or_default();
        assert_eq!(status, json!({"code": 2}));
    }
}
