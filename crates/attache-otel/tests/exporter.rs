//! The exporter end to end against a local OTLP/HTTP receiver (axum): the JSON it posts, batching,
//! periodic metrics, retry, timeout, drop counting, and a lagging audit stream.
mod common;

use attache_common::audit::{AuditRecord, Direction, Kind};
use attache_otel::{ExportTiming, Exporter, OtelConfig};
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri};
use common::*;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};

#[derive(Debug)]
struct Post {
    path: String,
    headers: HeaderMap,
    body: Value,
}

/// How the receiver answers the `n`th (0-based) request to a path: status and a delay first.
type Plan = Arc<dyn Fn(&str, usize) -> (StatusCode, Duration) + Send + Sync>;

#[derive(Clone)]
struct Receiver {
    tx: mpsc::UnboundedSender<Post>,
    plan: Plan,
    seen: Arc<Mutex<HashMap<String, usize>>>,
}

async fn handle(
    State(r): State<Receiver>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let path = uri.path().to_string();
    let n = {
        let mut seen = r.seen.lock().unwrap_or_else(|e| e.into_inner());
        let c = seen.entry(path.clone()).or_insert(0);
        *c += 1;
        *c - 1
    };
    let (status, delay) = (r.plan)(&path, n);
    let body = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let _ = r.tx.send(Post {
        path,
        headers,
        body,
    });
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    status
}

/// A receiver on 127.0.0.1; returns its base URL and the posts it gets.
async fn receiver(plan: Plan) -> (String, mpsc::UnboundedReceiver<Post>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = mpsc::unbounded_channel();
    let app = Router::new().fallback(handle).with_state(Receiver {
        tx,
        plan,
        seen: Arc::new(Mutex::new(HashMap::new())),
    });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), rx)
}

fn ok() -> Plan {
    Arc::new(|_, _| (StatusCode::OK, Duration::ZERO))
}

fn config(endpoint: &str) -> OtelConfig {
    OtelConfig {
        endpoint: endpoint.to_string(),
        headers: vec![("x-api-key".into(), "k1".into())],
        resource: resource(),
        traces: true,
        metrics: true,
        export_payloads: false,
    }
}

/// Nothing happens on a timer unless a test asks for it.
fn timing() -> ExportTiming {
    ExportTiming {
        batch_size: 256,
        batch_interval: Duration::from_secs(600),
        metrics_interval: Duration::from_secs(600),
        request_timeout: Duration::from_secs(5),
        retry_delay: Duration::from_millis(10),
        queue_capacity: 2,
    }
}

async fn next(posts: &mut mpsc::UnboundedReceiver<Post>) -> Post {
    tokio::time::timeout(Duration::from_secs(10), posts.recv())
        .await
        .expect("a post within 10 s")
        .expect("receiver alive")
}

/// Every post that has arrived (call after the exporter has shut down).
fn all(posts: &mut mpsc::UnboundedReceiver<Post>) -> Vec<Post> {
    let mut out = Vec::new();
    while let Ok(p) = posts.try_recv() {
        out.push(p);
    }
    out
}

fn spans(post: &Post) -> Vec<Value> {
    post.body["resourceSpans"][0]["scopeSpans"][0]["spans"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn send(tx: &broadcast::Sender<Arc<AuditRecord>>, rec: AuditRecord) {
    tx.send(Arc::new(rec)).expect("a subscriber");
}

fn golden_span(name: &str) -> Value {
    let text =
        std::fs::read_to_string(golden_path(&format!("traces/{name}.json"))).expect("golden");
    let v: Value = serde_json::from_str(&text).expect("json");
    v["resourceSpans"][0]["scopeSpans"][0]["spans"][0].clone()
}

fn records() -> HashMap<&'static str, AuditRecord> {
    one_of_every_kind().into_iter().collect()
}

fn resource_json() -> Value {
    json!({"attributes": [
        {"key": "service.name", "value": {"stringValue": "orders"}},
        {"key": "service.namespace", "value": {"stringValue": "shop"}},
        {"key": "service.version", "value": {"stringValue": "0.2.0"}},
        {"key": "attache.identity", "value": {"stringValue": "spiffe://attache/ns/shop/svc/orders"}},
    ]})
}

fn scope_json() -> Value {
    json!({"name": "attache-otel", "version": env!("CARGO_PKG_VERSION")})
}

fn kv(key: &str, value: &str) -> Value {
    json!({"key": key, "value": {"stringValue": value}})
}

/// Replace every data point's timestamps with placeholders, checking they are one consistent
/// cumulative window.
fn mask_metric_times(body: &mut Value) {
    let mut window: Option<(u64, u64)> = None;
    let metrics = body["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
        .as_array_mut()
        .expect("metrics");
    for m in metrics {
        for kind in ["sum", "histogram"] {
            let Some(points) = m
                .get_mut(kind)
                .and_then(|k| k.get_mut("dataPoints"))
                .and_then(Value::as_array_mut)
            else {
                continue;
            };
            for p in points {
                let start: u64 = p["startTimeUnixNano"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .expect("start is a decimal string");
                let time: u64 = p["timeUnixNano"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .expect("time is a decimal string");
                assert!(start > 0 && start <= time);
                match window {
                    None => window = Some((start, time)),
                    Some(w) => assert_eq!(w, (start, time)),
                }
                p["startTimeUnixNano"] = json!("START");
                p["timeUnixNano"] = json!("TIME");
            }
        }
    }
}

fn int_point(attrs: Vec<Value>, n: u64) -> Value {
    json!({"attributes": attrs, "startTimeUnixNano": "START", "timeUnixNano": "TIME", "asInt": n.to_string()})
}

fn hist_point(attrs: Vec<Value>, value: f64, bucket: usize, bounds: &[f64]) -> Value {
    let mut buckets = vec!["0".to_string(); bounds.len() + 1];
    buckets[bucket] = "1".into();
    json!({
        "attributes": attrs, "startTimeUnixNano": "START", "timeUnixNano": "TIME",
        "count": "1", "sum": value, "bucketCounts": buckets, "explicitBounds": bounds,
        "min": value, "max": value,
    })
}

#[tokio::test]
async fn posts_traces_and_metrics_as_otlp_json() {
    let (url, mut posts) = receiver(ok()).await;
    let (tx, rx) = broadcast::channel(16);
    let handle = Exporter::spawn_with(config(&url), rx, timing());
    let recs = records();
    for name in ["agent_invocation", "model_call", "guardrail"] {
        send(&tx, recs[name].clone());
    }
    handle.shutdown().await;
    let got = all(&mut posts);
    assert_eq!(got.len(), 2, "{got:?}");

    // --- traces
    let traces = &got[0];
    assert_eq!(traces.path, "/v1/traces");
    assert_eq!(traces.headers["content-type"], "application/json");
    assert_eq!(traces.headers["x-api-key"], "k1");
    let mut body = traces.body.clone();
    let derived = body["resourceSpans"][0]["scopeSpans"][0]["spans"][2]["spanId"].clone();
    let derived = derived.as_str().expect("span id").to_string();
    assert_eq!(derived.len(), 16);
    assert!(derived.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_ne!(derived, INVOCATION_SPAN);
    body["resourceSpans"][0]["scopeSpans"][0]["spans"][2]["spanId"] = json!("DERIVED");
    let mut guardrail = golden_span("guardrail");
    guardrail["spanId"] = json!("DERIVED");
    assert_eq!(
        body,
        json!({"resourceSpans": [{
            "resource": resource_json(),
            "scopeSpans": [{
                "scope": scope_json(),
                "spans": [golden_span("agent_invocation"), golden_span("model_call"), guardrail],
            }],
        }]})
    );
    // spelled out once more, for the hop and the event
    let s = spans(traces);
    assert_eq!(s[0]["traceId"], TRACE);
    assert_eq!(s[0]["spanId"], INVOCATION_SPAN);
    assert_eq!(s[0]["parentSpanId"], PARENT_SPAN);
    assert_eq!(s[0]["name"], "agent_invocation ops-assistant");
    assert_eq!(s[0]["kind"], 2);
    assert_eq!(s[0]["startTimeUnixNano"], "1792576800000000000");
    assert_eq!(s[0]["endTimeUnixNano"], "1792576801180000000");
    assert_eq!(s[2]["parentSpanId"], INVOCATION_SPAN);
    assert_eq!(s[2]["kind"], 1);

    // --- metrics
    let metrics = &got[1];
    assert_eq!(metrics.path, "/v1/metrics");
    assert_eq!(metrics.headers["content-type"], "application/json");
    assert_eq!(metrics.headers["x-api-key"], "k1");
    let mut body = metrics.body.clone();
    mask_metric_times(&mut body);
    let latency = attache_otel::metrics::LATENCY_BOUNDS_MS;
    let tokens = attache_otel::metrics::TOKEN_BOUNDS;
    let agent = || kv("agent", "ops-assistant");
    assert_eq!(
        body,
        json!({"resourceMetrics": [{
            "resource": resource_json(),
            "scopeMetrics": [{
                "scope": scope_json(),
                "metrics": [
                    {"name": "attache.invocations", "description": "Agent invocations handled by the sidecar.", "unit": "{invocation}",
                     "sum": {"dataPoints": [int_point(vec![agent(), kv("decision", "allow")], 1)],
                             "aggregationTemporality": 2, "isMonotonic": true}},
                    {"name": "attache.decisions", "description": "Audit records by kind, decision and rule.", "unit": "{decision}",
                     "sum": {"dataPoints": [
                                int_point(vec![kv("kind", "agent_invocation"), kv("decision", "allow")], 1),
                                int_point(vec![kv("kind", "guardrail"), kv("decision", "allow"), kv("rule", "guardrail.pii_redact")], 1),
                                int_point(vec![kv("kind", "model_call"), kv("decision", "allow")], 1),
                             ],
                             "aggregationTemporality": 2, "isMonotonic": true}},
                    {"name": "gen_ai.client.token.usage", "description": "Tokens used per model call.", "unit": "{token}",
                     "histogram": {"dataPoints": [
                                hist_point(vec![agent(), kv("model", "claude-opus-5-5"), kv("gen_ai.token.type", "input")], 812.0, 5, tokens),
                                hist_point(vec![agent(), kv("model", "claude-opus-5-5"), kv("gen_ai.token.type", "output")], 96.0, 4, tokens),
                             ],
                             "aggregationTemporality": 2}},
                    {"name": "attache.cost.usd", "description": "Model cost in US dollars.", "unit": "USD",
                     "sum": {"dataPoints": [{"attributes": [agent(), kv("model", "claude-opus-5-5")],
                                             "startTimeUnixNano": "START", "timeUnixNano": "TIME", "asDouble": 0.0052}],
                             "aggregationTemporality": 2, "isMonotonic": true}},
                    {"name": "attache.latency", "description": "Duration of each audited step.", "unit": "ms",
                     "histogram": {"dataPoints": [
                                hist_point(vec![kv("kind", "agent_invocation"), agent()], 1180.0, 8, latency),
                                hist_point(vec![kv("kind", "guardrail"), agent()], 0.0, 0, latency),
                                hist_point(vec![kv("kind", "model_call"), agent()], 900.0, 7, latency),
                             ],
                             "aggregationTemporality": 2}},
                    {"name": "attache.otel.dropped", "description": "Audit records the OpenTelemetry exporter could not export.", "unit": "{record}",
                     "sum": {"dataPoints": [int_point(vec![], 0)],
                             "aggregationTemporality": 2, "isMonotonic": true}},
                ],
            }],
        }]})
    );
}

#[tokio::test]
async fn batches_by_size_then_flushes_the_rest_on_shutdown() {
    let (url, mut posts) = receiver(ok()).await;
    let (tx, rx) = broadcast::channel(16);
    let config = OtelConfig {
        metrics: false,
        ..config(&url)
    };
    let handle = Exporter::spawn_with(
        config,
        rx,
        ExportTiming {
            batch_size: 2,
            ..timing()
        },
    );
    for _ in 0..5 {
        send(&tx, base(Kind::ToolCall, Direction::Internal));
    }
    // two full batches go out without waiting for a timer or shutdown
    for _ in 0..2 {
        let p = next(&mut posts).await;
        assert_eq!(p.path, "/v1/traces");
        assert_eq!(spans(&p).len(), 2);
    }
    handle.shutdown().await;
    let rest = all(&mut posts);
    assert_eq!(rest.len(), 1, "metrics are off, so only the last span");
    assert_eq!(rest[0].path, "/v1/traces");
    assert_eq!(spans(&rest[0]).len(), 1);
}

#[tokio::test]
async fn a_partial_batch_goes_out_after_the_batch_interval() {
    let (url, mut posts) = receiver(ok()).await;
    let (tx, rx) = broadcast::channel(16);
    let handle = Exporter::spawn_with(
        OtelConfig {
            metrics: false,
            ..config(&url)
        },
        rx,
        ExportTiming {
            batch_interval: Duration::from_millis(50),
            ..timing()
        },
    );
    send(&tx, base(Kind::ModelCall, Direction::Outbound));
    let p = next(&mut posts).await;
    assert_eq!(p.path, "/v1/traces");
    assert_eq!(spans(&p).len(), 1);
    handle.shutdown().await;
    assert!(all(&mut posts).is_empty());
}

#[tokio::test]
async fn cumulative_metrics_are_pushed_on_the_interval() {
    let (url, mut posts) = receiver(ok()).await;
    let (tx, rx) = broadcast::channel(16);
    let handle = Exporter::spawn_with(
        OtelConfig {
            traces: false,
            ..config(&url)
        },
        rx,
        ExportTiming {
            metrics_interval: Duration::from_millis(50),
            ..timing()
        },
    );
    send(&tx, base(Kind::AgentInvocation, Direction::Inbound));
    let mut seen = Vec::new();
    while seen.len() < 2 {
        let p = next(&mut posts).await;
        assert_eq!(p.path, "/v1/metrics", "traces are off");
        let metrics = p.body["resourceMetrics"][0]["scopeMetrics"][0]["metrics"].clone();
        let inv = metrics
            .as_array()
            .and_then(|ms| ms.iter().find(|m| m["name"] == "attache.invocations"))
            .cloned();
        if let Some(inv) = inv {
            let point = &inv["sum"]["dataPoints"][0];
            seen.push((
                point["asInt"].clone(),
                point["startTimeUnixNano"].clone(),
                point["timeUnixNano"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0),
            ));
        }
    }
    // the same cumulative total and window start, a later time
    assert_eq!(seen[0].0, json!("1"));
    assert_eq!(seen[1].0, json!("1"));
    assert_eq!(seen[0].1, seen[1].1);
    assert!(seen[1].2 >= seen[0].2);
    handle.shutdown().await;
}

/// Send `n` tool_call records with traces only, shut down, and return the posts and the final
/// dropped count.
async fn run_against(plan: Plan, timing: ExportTiming, n: usize) -> (Vec<Post>, u64) {
    let (url, mut posts) = receiver(plan).await;
    let (tx, rx) = broadcast::channel(16);
    let handle = Exporter::spawn_with(
        OtelConfig {
            metrics: false,
            ..config(&url)
        },
        rx,
        timing,
    );
    for _ in 0..n {
        send(&tx, base(Kind::ToolCall, Direction::Internal));
    }
    let dropped = handle.shutdown().await;
    (all(&mut posts), dropped)
}

fn traces_posts(posts: &[Post]) -> Vec<&Post> {
    posts.iter().filter(|p| p.path == "/v1/traces").collect()
}

#[tokio::test]
async fn a_retryable_failure_is_retried_once() {
    let plan: Plan = Arc::new(|_, n| {
        if n == 0 {
            (StatusCode::SERVICE_UNAVAILABLE, Duration::ZERO)
        } else {
            (StatusCode::OK, Duration::ZERO)
        }
    });
    let (posts, dropped) = run_against(plan, timing(), 3).await;
    let t = traces_posts(&posts);
    assert_eq!(t.len(), 2, "one attempt and one retry");
    assert_eq!(t[0].body, t[1].body, "the retry sends the same batch");
    assert_eq!(spans(t[1]).len(), 3);
    assert_eq!(dropped, 0);
}

#[tokio::test]
async fn after_the_retry_fails_the_batch_is_dropped_and_counted() {
    for status in [
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::BAD_GATEWAY,
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::GATEWAY_TIMEOUT,
    ] {
        let plan: Plan = Arc::new(move |_, _| (status, Duration::ZERO));
        let (posts, dropped) = run_against(plan, timing(), 3).await;
        assert_eq!(traces_posts(&posts).len(), 2, "{status}");
        assert_eq!(dropped, 3, "{status}");
    }
}

#[tokio::test]
async fn a_non_retryable_status_is_not_retried() {
    for status in [StatusCode::BAD_REQUEST, StatusCode::INTERNAL_SERVER_ERROR] {
        let plan: Plan = Arc::new(move |_, _| (status, Duration::ZERO));
        let (posts, dropped) = run_against(plan, timing(), 2).await;
        assert_eq!(traces_posts(&posts).len(), 1, "{status}");
        assert_eq!(dropped, 2, "{status}");
    }
}

#[tokio::test]
async fn each_attempt_times_out() {
    let plan: Plan = Arc::new(|_, _| (StatusCode::OK, Duration::from_secs(30)));
    let started = std::time::Instant::now();
    let (posts, dropped) = run_against(
        plan,
        ExportTiming {
            request_timeout: Duration::from_millis(100),
            ..timing()
        },
        1,
    )
    .await;
    assert_eq!(traces_posts(&posts).len(), 2, "timeout, then one retry");
    assert_eq!(dropped, 1);
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[tokio::test]
async fn an_unreachable_collector_drops_and_counts() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    let (tx, rx) = broadcast::channel(16);
    let handle = Exporter::spawn_with(config(&format!("http://{addr}")), rx, timing());
    for _ in 0..4 {
        send(&tx, base(Kind::ModelCall, Direction::Outbound));
    }
    assert_eq!(handle.shutdown().await, 4);
}

#[tokio::test]
async fn a_lagging_receiver_counts_what_it_missed() {
    let (url, mut posts) = receiver(ok()).await;
    // Room for 4: on this single-threaded runtime the exporter does not run before the 10 sends,
    // so it misses the 6 oldest.
    let (tx, rx) = broadcast::channel(4);
    let handle = Exporter::spawn_with(config(&url), rx, timing());
    for i in 0..10u64 {
        let mut r = base(Kind::AgentInvocation, Direction::Inbound);
        r.latency_ms = i;
        send(&tx, r);
    }
    assert_eq!(handle.shutdown().await, 6);
    let got = all(&mut posts);
    let t = traces_posts(&got);
    assert_eq!(t.len(), 1);
    let s = spans(t[0]);
    assert_eq!(s.len(), 4, "the 4 newest records");
    let metrics = got
        .iter()
        .find(|p| p.path == "/v1/metrics")
        .expect("final metrics");
    let ms = metrics.body["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let by_name = |n: &str| ms.iter().find(|m| m["name"] == n).cloned();
    let dropped = by_name("attache.otel.dropped").expect("dropped metric");
    assert_eq!(dropped["sum"]["dataPoints"][0]["asInt"], "6");
    let inv = by_name("attache.invocations").expect("invocations");
    assert_eq!(inv["sum"]["dataPoints"][0]["asInt"], "4");
}

#[tokio::test]
async fn a_hanging_collector_never_holds_up_the_audit_stream() {
    // The collector accepts and never answers in time; the queue holds one batch.
    let plan: Plan = Arc::new(|_, _| (StatusCode::OK, Duration::from_secs(30)));
    let (url, mut posts) = receiver(plan).await;
    let (tx, rx) = broadcast::channel(4096);
    let handle = Exporter::spawn_with(
        OtelConfig {
            metrics: false,
            ..config(&url)
        },
        rx,
        ExportTiming {
            batch_size: 10,
            request_timeout: Duration::from_millis(200),
            queue_capacity: 1,
            ..timing()
        },
    );
    let started = std::time::Instant::now();
    for i in 0..1000 {
        send(&tx, base(Kind::ToolCall, Direction::Internal));
        if i % 10 == 9 {
            tokio::task::yield_now().await;
        }
    }
    // Writing 1000 records never waited on the network.
    assert!(started.elapsed() < Duration::from_secs(5));
    let dropped = handle.shutdown().await;
    assert_eq!(dropped, 1000, "every record is accounted for");
    let attempts = traces_posts(&all(&mut posts)).len();
    assert!(
        attempts <= 8,
        "batches beyond the queue are dropped, not piled up: {attempts} attempts"
    );
}

#[tokio::test]
async fn a_detached_exporter_flushes_when_the_audit_writer_goes_away() {
    let (url, mut posts) = receiver(ok()).await;
    let (tx, rx) = broadcast::channel(16);
    drop(Exporter::spawn_with(config(&url), rx, timing()));
    send(&tx, base(Kind::AgentInvocation, Direction::Inbound));
    drop(tx);
    let first = next(&mut posts).await;
    assert_eq!(first.path, "/v1/traces");
    assert_eq!(spans(&first).len(), 1);
    let second = next(&mut posts).await;
    assert_eq!(second.path, "/v1/metrics");
}

#[tokio::test]
async fn endpoint_with_a_base_path_gets_the_signal_paths_appended() {
    let (url, mut posts) = receiver(ok()).await;
    let (tx, rx) = broadcast::channel(16);
    let handle = Exporter::spawn_with(config(&format!("{url}/otlp")), rx, timing());
    send(&tx, base(Kind::ModelCall, Direction::Outbound));
    handle.shutdown().await;
    let paths: Vec<String> = all(&mut posts).into_iter().map(|p| p.path).collect();
    assert_eq!(paths, ["/otlp/v1/traces", "/otlp/v1/metrics"]);
}

#[tokio::test]
async fn payloads_leave_only_with_export_payloads() {
    for export_payloads in [false, true] {
        let (url, mut posts) = receiver(ok()).await;
        let (tx, rx) = broadcast::channel(16);
        let handle = Exporter::spawn_with(
            OtelConfig {
                export_payloads,
                metrics: false,
                ..config(&url)
            },
            rx,
            timing(),
        );
        send(&tx, records()["http_call"].clone());
        handle.shutdown().await;
        let got = all(&mut posts);
        let keys: Vec<String> = spans(&got[0])[0]["attributes"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|a| a["key"].as_str().map(str::to_string))
            .collect();
        for key in ["url.full", "url.path", "attache.input"] {
            assert_eq!(
                keys.iter().any(|k| k == key),
                export_payloads,
                "{key} with export_payloads={export_payloads}"
            );
        }
    }
}

#[tokio::test]
async fn zero_intervals_do_not_stop_the_exporter() {
    let (url, mut posts) = receiver(ok()).await;
    let (tx, rx) = broadcast::channel(16);
    let handle = Exporter::spawn_with(
        config(&url),
        rx,
        ExportTiming {
            batch_interval: Duration::ZERO,
            metrics_interval: Duration::ZERO,
            retry_delay: Duration::ZERO,
            ..timing()
        },
    );
    send(&tx, base(Kind::ModelCall, Direction::Outbound));
    let mut paths = std::collections::HashSet::new();
    while paths.len() < 2 {
        paths.insert(next(&mut posts).await.path);
    }
    handle.shutdown().await;
}
