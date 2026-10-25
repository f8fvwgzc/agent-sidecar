//! The model gateway (CONTRACT.md §4.4): the runtime's model calls go out through the sidecar,
//! which holds the key, binds each call to a run, enforces `max_tokens_per_call`, `max_steps`
//! and the daily cost budget itself, and counts the usage the provider reported. Here the test
//! plays the runtime (a gated fake answers Execute; the test makes the model calls) and a fake
//! Anthropic API stands upstream.
mod common;

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agentsc_charter::{Charter, HarnessSpec, LearningSpec};
use agentsc_common::audit::{AuditRecord, Direction, Kind};
use agentsc_common::trace::TraceContext;
use agentsc_proto::{AuditEvent, ExecuteResponse, Usage};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::post;
use common::*;
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};

const MODEL: &str = "claude-opus-5-5";
const KEY: &str = "sk-ant-sidecar-only";

/// One canned upstream answer.
#[derive(Clone)]
struct Canned {
    status: u16,
    headers: Vec<(&'static str, String)>,
    /// Sent one after the other, `delay` apart.
    chunks: Vec<String>,
    delay: Duration,
}

impl Canned {
    fn sse(events: &[Value]) -> Self {
        Self {
            status: 200,
            headers: vec![("content-type", "text/event-stream".into())],
            chunks: events
                .iter()
                .map(|e| format!("event: {}\ndata: {e}\n\n", e["type"].as_str().unwrap()))
                .collect(),
            delay: Duration::ZERO,
        }
    }
}

/// An answer with `text`, `input` and `output` tokens, and `extra` events before the end.
fn answer(input: u64, output: u64, text: &str) -> Canned {
    Canned::sse(&[
        json!({"type": "message_start", "message": {"id": "msg_1", "model": MODEL, "role": "assistant",
            "content": [], "usage": {"input_tokens": input, "output_tokens": 1}}}),
        json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}}),
        json!({"type": "content_block_stop", "index": 0}),
        json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": output}}),
        json!({"type": "message_stop"}),
    ])
}

#[derive(Clone, Default)]
struct Upstream {
    script: Arc<Mutex<Vec<Canned>>>,
    seen: Arc<Mutex<Vec<(HeaderMap, Value)>>>,
}

impl Upstream {
    fn push(&self, c: Canned) {
        self.script.lock().unwrap().push(c);
    }
    fn seen(&self) -> Vec<(HeaderMap, Value)> {
        self.seen.lock().unwrap().clone()
    }
}

async fn upstream_handler(
    State(u): State<Upstream>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    u.seen.lock().unwrap().push((
        headers,
        serde_json::from_slice(&body).unwrap_or(Value::Null),
    ));
    let c = {
        let mut s = u.script.lock().unwrap();
        if s.is_empty() {
            answer(10, 2, "default")
        } else {
            s.remove(0)
        }
    };
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<String, std::io::Error>>(8);
    let (chunks, delay) = (c.chunks.clone(), c.delay);
    tokio::spawn(async move {
        for chunk in chunks {
            tokio::time::sleep(delay).await;
            if tx.send(Ok(chunk)).await.is_err() {
                return;
            }
        }
    });
    let mut resp = Response::new(Body::from_stream(
        tokio_stream::wrappers::ReceiverStream::new(rx),
    ));
    *resp.status_mut() = StatusCode::from_u16(c.status).unwrap();
    for (k, v) in c.headers {
        resp.headers_mut().insert(k, v.parse().unwrap());
    }
    resp
}

async fn upstream() -> (Upstream, String) {
    let u = Upstream::default();
    let app = axum::Router::new()
        .route("/v1/messages", post(upstream_handler))
        .with_state(u.clone());
    let addr = serve_app(app).await;
    (u, format!("http://{addr}"))
}

/// The orders charter with ops-assistant on a priced model.
fn priced(c: &mut Charter, max_cost: f64) {
    let a = &mut c.agents[0];
    a.model = MODEL.into();
    a.budgets.max_tokens_per_call = 1024;
    a.budgets.max_cost_usd_per_day = max_cost;
}

async fn gateway_rig(charter: impl FnOnce(&mut Charter)) -> (Rig, Upstream, mpsc_gate::Gate) {
    let (u, base) = upstream().await;
    let (runtime, gate) = FakeRuntime::gated();
    let rig = rig(runtime, charter, move |cfg| {
        cfg.anthropic_api_key = Some(KEY.into());
        cfg.anthropic_base_url = base;
    })
    .await;
    (rig, u, gate)
}

mod mpsc_gate {
    pub type Gate = tokio::sync::mpsc::UnboundedReceiver<super::Pending>;
}

struct Answer {
    status: u16,
    headers: HeaderMap,
    body: String,
    /// The body ended in an error (the gateway cut it).
    broken: bool,
}

/// One model call over `<sock>/model.sock`, as the runtime's SDK makes it.
async fn model_call(sock: &Path, headers: &[(&str, &str)], body: &Value) -> Answer {
    let stream = tokio::net::UnixStream::connect(sock.join("model.sock"))
        .await
        .unwrap();
    let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);
    let mut req = hyper::Request::post("http://agentsc-model-gateway/v1/messages")
        .header("content-type", "application/json")
        .header("x-api-key", "sk-runtime-has-no-key");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let req = req
        .body(http_body_util::Full::new(axum::body::Bytes::from(
            body.to_string(),
        )))
        .unwrap();
    let resp = send.send_request(req).await.unwrap();
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let (body, broken) = match resp.into_body().collect().await {
        Ok(b) => (b.to_bytes(), false),
        Err(_) => (axum::body::Bytes::new(), true),
    };
    Answer {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
        broken,
    }
}

fn request(max_tokens: u64) -> Value {
    json!({
        "model": MODEL, "max_tokens": max_tokens, "stream": true,
        "system": "You are the ops assistant.",
        "messages": [{"role": "user", "content": "How is order 1001?"}],
        "tools": [{"name": "lookup_order", "description": "d", "input_schema": {"type": "object"}}],
        "output_config": {"effort": "low"}
    })
}

fn bound<'a>(id: &'a str, agent: &'a str) -> Vec<(&'static str, &'a str)> {
    vec![("x-agentsc-request-id", id), ("x-agentsc-agent", agent)]
}

fn rule(a: &Answer) -> String {
    a.headers
        .get("x-agentsc-rule")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default()
}

/// Start an invocation the gated runtime holds; returns the Execute and its answer sender.
async fn start_run(
    rig: &Rig,
    gate: &mut mpsc_gate::Gate,
    input: &str,
) -> (
    agentsc_proto::ExecuteRequest,
    tokio::sync::oneshot::Sender<ExecuteResponse>,
    tokio::task::JoinHandle<(u16, Value)>,
) {
    let url = rig.invoke_url("ops-assistant");
    let input = input.to_string();
    let call = tokio::spawn(async move {
        let r = reqwest::Client::new()
            .post(url)
            .json(&json!({ "input": input }))
            .send()
            .await
            .unwrap();
        (r.status().as_u16(), r.json::<Value>().await.unwrap())
    });
    let (req, done) = gate.recv().await.unwrap();
    (req, done, call)
}

/// What a lying runtime answers: an error with made-up, near-zero usage.
fn lie(rule: &str) -> ExecuteResponse {
    ExecuteResponse {
        status: "error".into(),
        rule: rule.into(),
        reason: "the model call failed".into(),
        usage: Some(Usage {
            input_tokens: 1,
            output_tokens: 1,
            cost_usd: 0.0,
        }),
        ..Default::default()
    }
}

fn report(request_id: &str, callee: &str, cost: f64) -> AuditEvent {
    let mut r = AuditRecord::new(
        Kind::ModelCall,
        Direction::Outbound,
        request_id,
        &TraceContext::from_traceparent(&format!("00-{TRACE_ID}-00f067aa0ba902b7-01")),
        Some("ops-assistant"),
        "local",
        None,
        callee,
        json!({"messages": []}),
        Value::Null,
    );
    r.cost_usd = Some(cost);
    AuditEvent {
        json: r.to_json_line(),
    }
}

fn model_records(rig: &Rig, id: &str) -> Vec<Value> {
    rig.records(|v| v["request_id"] == id && v["kind"] == "model_call")
}

#[tokio::test]
async fn a_runtime_that_lies_about_cost_cannot_spend_past_the_budget() {
    // $0.07 a day. One call can cost up to ~$0.055 (4.3K input tokens as cache writes + 1024
    // output on claude-opus-5-5); this one costs 3000 × $4/M + 1000 × $20/M = $0.032.
    let (rig, up, mut gate) = gateway_rig(|c| priced(c, 0.07)).await;
    let (req, done, call) = start_run(&rig, &mut gate, "spend it all").await;
    let id = req.request_id.clone();

    // The runtime's own accounting is not taken: a provider call it reports is refused, and the
    // cost of a mock call it reports is the price table's (nothing).
    let mut tools = tools(&rig.sock).await;
    let err = tools
        .report_event(report(&id, &format!("anthropic:{MODEL}"), 0.0))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    tools.report_event(report(&id, "mock", 9.99)).await.unwrap();

    up.push(answer(3000, 1000, "first"));
    let first = model_call(&rig.sock, &bound(&id, "ops-assistant"), &request(1024)).await;
    assert_eq!(first.status, 200, "{}", first.body);
    assert!(first.body.contains("first"));

    // The next call could take the day past $0.07: refused before it leaves the pod.
    let second = model_call(&rig.sock, &bound(&id, "ops-assistant"), &request(1024)).await;
    assert_eq!(second.status, 403, "{}", second.body);
    assert_eq!(rule(&second), "budget.max_cost_usd_per_day");
    assert!(second.body.contains("permission_error"), "{}", second.body);
    assert_eq!(
        up.seen().len(),
        1,
        "the refused call never reached the provider"
    );

    // The runtime claims it spent nothing; the answer and the records say what it did spend.
    done.send(lie("model.error")).unwrap();
    let (status, body) = call.await.unwrap();
    assert_eq!(status, 429, "{body}");
    assert_eq!(body["rule"], "budget.max_cost_usd_per_day");
    assert_eq!(body["usage"]["cost_usd"], 0.032);
    assert_eq!(body["usage"]["input_tokens"], 3000);
    assert_eq!(body["usage"]["output_tokens"], 1000);
    let costs: Vec<f64> = rig
        .records(|v| v["request_id"] == id.as_str() && v["kind"] == "model_call")
        .iter()
        .map(|v| v["cost_usd"].as_f64().unwrap())
        .collect();
    assert_eq!(costs, [0.0, 0.032], "the mock report counts nothing");
    let inv = rig.records(|v| v["request_id"] == id.as_str() && v["kind"] == "agent_invocation");
    assert_eq!(inv[0]["cost_usd"], 0.032);
    let total: f64 = costs.iter().sum();
    assert!(total <= 0.07);
    rig.sidecar.abort();
}

#[tokio::test]
async fn concurrent_calls_cannot_overshoot_the_budget_together() {
    let (rig, up, mut gate) = gateway_rig(|c| priced(c, 0.07)).await;
    let (req, done, call) = start_run(&rig, &mut gate, "two at once").await;
    let id = req.request_id.clone();
    let mut slow = answer(3000, 1000, "slow");
    slow.delay = Duration::from_millis(300);
    up.push(slow);
    let sock = rig.sock.clone();
    let id2 = id.clone();
    let first = tokio::spawn(async move {
        model_call(&sock, &bound(&id2, "ops-assistant"), &request(1024)).await
    });
    // the first call is in flight (its reservation held) when the second arrives
    eventually("the first call reaches the provider", || {
        up.seen().len() == 1
    })
    .await;
    let second = model_call(&rig.sock, &bound(&id, "ops-assistant"), &request(1024)).await;
    assert_eq!(rule(&second), "budget.max_cost_usd_per_day");
    assert_eq!(first.await.unwrap().status, 200);
    done.send(ok("done")).unwrap();
    let (status, body) = call.await.unwrap();
    assert_eq!(
        (status, body["usage"]["cost_usd"].clone()),
        (200, json!(0.032))
    );
    rig.sidecar.abort();
}

#[tokio::test]
async fn the_sidecar_holds_the_key_and_the_charters_limits() {
    let (rig, up, mut gate) = gateway_rig(|c| {
        priced(c, 5.0);
        c.agents[0].budgets.max_steps = 2;
        c.agents[0].harness = Some(HarnessSpec {
            max_retries: 0,
            ..HarnessSpec::default()
        });
    })
    .await;
    let (req, done, call) = start_run(&rig, &mut gate, "limits").await;
    let id = req.request_id.clone();
    let mut h = bound(&id, "ops-assistant");
    h.push(("anthropic-beta", "fast-mode-2026-02-01"));
    h.push(("authorization", "Bearer runtime-token"));

    let a = model_call(&rig.sock, &h, &request(1024)).await;
    assert_eq!(a.status, 200, "{}", a.body);
    let (headers, body) = up.seen().remove(0);
    assert_eq!(
        headers["x-api-key"], KEY,
        "the sidecar's key, not the runtime's"
    );
    assert!(headers.get("anthropic-beta").is_none());
    assert!(headers.get("authorization").is_none());
    assert_eq!(body, request(1024), "the body goes upstream as sent");

    // refused before anything goes out
    let mut over = request(4096);
    let refused = [
        (
            model_call(&rig.sock, &h, &over).await,
            403,
            "budget.max_tokens_per_call",
        ),
        (
            {
                over = request(64);
                over["model"] = json!("claude-fable-5-1");
                model_call(&rig.sock, &h, &over).await
            },
            403,
            "model.not_allowed",
        ),
        (
            {
                over = request(64);
                over["tools"] = json!([{"type": "web_search_20260209", "name": "web_search"}]);
                model_call(&rig.sock, &h, &over).await
            },
            400,
            "model.request_invalid",
        ),
        (
            {
                over = request(64);
                over["speed"] = json!("fast");
                model_call(&rig.sock, &h, &over).await
            },
            400,
            "model.request_invalid",
        ),
        (
            {
                over = request(64);
                over["messages"] = json!([
                    {"role": "user", "content": "q"}, {"role": "assistant", "content": "a"},
                    {"role": "user", "content": "q"}, {"role": "assistant", "content": "a"},
                    {"role": "user", "content": "q"}]);
                model_call(&rig.sock, &h, &over).await
            },
            403,
            "budget.max_steps",
        ),
    ];
    for (answer, status, want) in &refused {
        assert_eq!(
            (answer.status, rule(answer).as_str()),
            (*status, *want),
            "{}",
            answer.body
        );
    }
    assert_eq!(up.seen().len(), 1);

    // max_steps 2 × (1 + 0 retries) = 2 calls per run; the step-limit refusal above counted one
    let b = model_call(&rig.sock, &h, &request(64)).await;
    assert_eq!(rule(&b), "budget.max_steps", "{}", b.body);

    let recs = rig.records(|v| v["request_id"] == id.as_str() && v["decision"] == "deny");
    let rules: Vec<&str> = recs.iter().map(|v| v["rule"].as_str().unwrap()).collect();
    assert!(rules.contains(&"budget.max_tokens_per_call") && rules.contains(&"model.not_allowed"));
    done.send(lie("model.error")).unwrap();
    let (status, body) = call.await.unwrap();
    assert_eq!(
        (status, body["rule"].as_str()),
        (502, Some("budget.max_tokens_per_call")),
        "the first budget the gateway refused names the outcome"
    );
    rig.sidecar.abort();
}

#[tokio::test]
async fn model_calls_need_a_run_and_the_reflection_comes_once() {
    let (rig, _up, mut gate) = gateway_rig(|c| {
        priced(c, 5.0);
        c.agents[0].learning = Some(LearningSpec {
            enabled: true,
            ..LearningSpec::default()
        });
    })
    .await;
    for headers in [
        vec![],
        bound("no-such-run", "ops-assistant"),
        bound("no-such-run", "not-an-agent"),
    ] {
        let a = model_call(&rig.sock, &headers, &request(64)).await;
        assert_eq!(
            (a.status, rule(&a)),
            (403, "model.unbound".into()),
            "{headers:?}"
        );
    }
    let (req, done, call) = start_run(&rig, &mut gate, "then reflect").await;
    let id = req.request_id.clone();
    let other = model_call(&rig.sock, &bound(&id, "order-triage"), &request(64)).await;
    assert_eq!(
        rule(&other),
        "model.unbound",
        "another agent's run is not this one"
    );
    done.send(ok("done")).unwrap();
    assert_eq!(call.await.unwrap().0, 200);

    let mut h = bound(&id, "ops-assistant");
    h.push(("x-agentsc-purpose", "reflection"));
    let reflection = model_call(&rig.sock, &h, &request(64)).await;
    assert_eq!(reflection.status, 200, "{}", reflection.body);
    let again = model_call(&rig.sock, &h, &request(64)).await;
    assert_eq!(rule(&again), "model.unbound", "one reflection per run");
    let recs = model_records(&rig, &id);
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["input"]["purpose"], "reflection");
    rig.sidecar.abort();
}

#[tokio::test]
async fn answers_stream_through_unchanged_and_are_recorded() {
    let (rig, up, mut gate) = gateway_rig(|c| priced(c, 5.0)).await;
    let (req, done, call) = start_run(&rig, &mut gate, "stream it").await;
    let id = req.request_id.clone();
    let mut h = bound(&id, "ops-assistant");
    h.push(("x-agentsc-attempt", "1"));

    let streamed = Canned::sse(&[
        json!({"type": "message_start", "message": {"id": "msg_1", "model": MODEL, "role": "assistant",
            "content": [], "usage": {"input_tokens": 1200, "output_tokens": 1}}}),
        json!({"type": "content_block_start", "index": 0, "content_block":
            {"type": "tool_use", "id": "toolu_1", "name": "lookup_order", "input": {}}}),
        json!({"type": "content_block_delta", "index": 0, "delta":
            {"type": "input_json_delta", "partial_json": "{\"order_id\": \"1001\"}"}}),
        json!({"type": "content_block_stop", "index": 0}),
        json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 345}}),
        json!({"type": "message_stop"}),
    ]);
    let sent: String = streamed.chunks.concat();
    up.push(streamed);
    let a = model_call(&rig.sock, &h, &request(1024)).await;
    assert_eq!(a.status, 200);
    assert_eq!(
        a.body, sent,
        "the runtime reads the provider's stream byte for byte"
    );
    assert_eq!(a.headers["content-type"], "text/event-stream");

    // A 429 goes back as it came, retry-after included: the runtime's harness retries it.
    up.push(Canned {
        status: 429,
        headers: vec![
            ("content-type", "application/json".into()),
            ("retry-after", "7".into()),
        ],
        chunks: vec![
            json!({"type": "error", "error": {"type": "rate_limit_error", "message": "slow down"}})
                .to_string(),
        ],
        delay: Duration::ZERO,
    });
    h[2] = ("x-agentsc-attempt", "2");
    let limited = model_call(&rig.sock, &h, &request(1024)).await;
    assert_eq!(limited.status, 429);
    assert_eq!(limited.headers["retry-after"], "7");
    assert!(limited.body.contains("rate_limit_error"));

    // An overload mid-stream: the input the provider reported before it is still counted.
    up.push(Canned::sse(&[
        json!({"type": "message_start", "message": {"usage": {"input_tokens": 900, "output_tokens": 1}}}),
        json!({"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}}),
    ]));
    h[2] = ("x-agentsc-attempt", "fallback");
    let overloaded = model_call(&rig.sock, &h, &request(1024)).await;
    assert!(overloaded.body.contains("overloaded_error"));

    done.send(ok("done")).unwrap();
    let (status, body) = call.await.unwrap();
    assert_eq!(status, 200);
    let recs = model_records(&rig, &id);
    assert_eq!(recs.len(), 3, "{recs:?}");
    let r = &recs[0];
    assert_eq!(r["callee"], format!("anthropic:{MODEL}"));
    assert_eq!(r["direction"], "outbound");
    assert_eq!(r["service"], "orders");
    assert_eq!(r["trace_id"], req.trace_id.as_str());
    assert_eq!(
        r["parent_span_id"],
        req.span_id.as_str(),
        "under the invocation's span"
    );
    assert_eq!(r["tokens"], json!({"input": 1200, "output": 345}));
    assert_eq!(r["cost_usd"], 0.0117, "1200 × $4/M + 345 × $20/M");
    assert_eq!(r["input"]["attempt"], 1);
    assert_eq!(r["input"]["tools"], json!(["lookup_order"]));
    assert_eq!(
        r["output"],
        json!([{"type": "tool_use", "id": "toolu_1", "name": "lookup_order", "input": {"order_id": "1001"}}])
    );
    assert_eq!(recs[1]["cost_usd"], 0.0);
    assert!(
        recs[1]["error"]
            .as_str()
            .unwrap()
            .contains("rate_limit_error")
    );
    assert_eq!(recs[2]["input"]["fallback"], true);
    assert_eq!(recs[2]["tokens"]["input"], 900);
    assert!(
        recs[2]["error"]
            .as_str()
            .unwrap()
            .contains("overloaded_error")
    );
    assert_eq!(body["usage"]["input_tokens"], 2100);
    rig.sidecar.abort();
}

#[tokio::test]
async fn a_call_the_runtime_abandons_is_read_to_the_end_and_counted() {
    let (rig, up, mut gate) = gateway_rig(|c| priced(c, 5.0)).await;
    let (req, done, call) = start_run(&rig, &mut gate, "abandon it").await;
    let id = req.request_id.clone();
    let mut slow = answer(500, 100, "late");
    slow.delay = Duration::from_millis(100);
    up.push(slow);
    let sock = rig.sock.clone();
    let id2 = id.clone();
    let gone = tokio::spawn(async move {
        model_call(&sock, &bound(&id2, "ops-assistant"), &request(1024)).await
    });
    eventually("the call reaches the provider", || up.seen().len() == 1).await;
    gone.abort();
    let recs = wait_audit(&rig.audit, 1, |v| {
        v["request_id"] == id.as_str() && v["kind"] == "model_call"
    })
    .await;
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["tokens"], json!({"input": 500, "output": 100}));
    assert_eq!(recs[0]["cost_usd"], 0.004);
    assert!(
        recs[0]["error"].as_str().unwrap().starts_with("cancelled:"),
        "{}",
        recs[0]
    );
    done.send(ok("done")).unwrap();
    assert_eq!(call.await.unwrap().1["usage"]["cost_usd"], 0.004);
    rig.sidecar.abort();
}

#[tokio::test]
async fn a_model_call_ends_at_the_runs_deadline() {
    use agentsc_proto::InvokeAgentRequest;
    use agentsc_proto::app_api_client::AppApiClient;
    let (rig, up, mut gate) = gateway_rig(|c| priced(c, 5.0)).await;
    let mut app = AppApiClient::connect(format!("http://{}", rig.sidecar.grpc_addr))
        .await
        .unwrap();
    let mut inv = tonic::Request::new(InvokeAgentRequest {
        agent: "ops-assistant".into(),
        input: "a short deadline".into(),
        ..Default::default()
    });
    inv.set_timeout(Duration::from_secs(3));
    let call = tokio::spawn(async move { app.invoke_agent(inv).await });
    let (req, done) = gate.recv().await.unwrap();
    // the provider never answers in time
    let mut stuck = answer(10, 2, "too late");
    stuck.delay = Duration::from_secs(10);
    up.push(stuck);
    let started = Instant::now();
    let a = model_call(
        &rig.sock,
        &bound(&req.request_id, "ops-assistant"),
        &request(64),
    )
    .await;
    let took = started.elapsed();
    assert!(
        took < Duration::from_secs(3),
        "the call gave up inside the deadline: {took:?}"
    );
    assert!(took > Duration::from_secs(1), "{took:?}");
    assert!(
        a.status == 200 && a.broken,
        "the answer started, then was cut"
    );
    let recs = wait_audit(&rig.audit, 1, |v| {
        v["request_id"] == req.request_id.as_str() && v["kind"] == "model_call"
    })
    .await;
    assert!(recs[0]["error"].is_string(), "{}", recs[0]);
    drop(done);
    let _ = call.await;
    rig.sidecar.abort();
}
