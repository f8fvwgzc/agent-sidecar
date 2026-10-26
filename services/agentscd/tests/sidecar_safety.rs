//! One sidecar core with a fake runtime on `runtime.sock` and a fake app on loopback:
//! redirects go back to the caller unfollowed, a payload a content guardrail denied never reaches
//! the audit log (its hash does), and a dropped or timed-out call is still audited while its
//! deadline reaches the next hop (CONTRACT.md §4.3, §6).
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agentsc_charter::{AuditSink, Charter, RegexRule, ToolSpec, ToolType};
use agentsc_common::audit::{AuditRecord, CANCELLED, Direction, Kind, payload_bytes, sha256_hex};
use agentsc_common::trace::TraceContext;
use agentsc_proto::app_api_client::AppApiClient;
use agentsc_proto::runtime_server::{Runtime, RuntimeServer};
use agentsc_proto::sidecar_tools_client::SidecarToolsClient;
use agentsc_proto::{
    AuditEvent, Empty, ExecuteRequest, ExecuteResponse, HealthResponse, InvokeAgentRequest,
    ToolAgentRequest, ToolContext, ToolHttpRequest, ToolServiceRequest,
};
use agentscd::{Config, Sidecar};
use axum::Router;
use axum::extract::Path as UrlPath;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

const ORDERS: &str = include_str!("../../../examples/charters/orders.charter.yaml");

/// Stands in for the agent runtime: answers `output`, or never answers when it is `None`.
#[derive(Clone, Default)]
struct FakeRuntime {
    output: Option<String>,
    /// The time each Execute was given (its `grpc-timeout`), as seen on arrival.
    budgets: Arc<Mutex<Vec<Option<Duration>>>>,
}

#[tonic::async_trait]
impl Runtime for FakeRuntime {
    async fn execute(
        &self,
        request: tonic::Request<ExecuteRequest>,
    ) -> Result<tonic::Response<ExecuteResponse>, tonic::Status> {
        let budget = agentscd::deadline::from_metadata(request.metadata())
            .map(|d| d.saturating_duration_since(Instant::now()));
        self.budgets.lock().unwrap().push(budget);
        match &self.output {
            Some(output) => Ok(tonic::Response::new(ExecuteResponse {
                status: "ok".into(),
                output: output.clone(),
                ..Default::default()
            })),
            None => {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Err(tonic::Status::internal("a run that outlasts its caller"))
            }
        }
    }

    async fn health(
        &self,
        _: tonic::Request<Empty>,
    ) -> Result<tonic::Response<HealthResponse>, tonic::Status> {
        Ok(tonic::Response::new(HealthResponse {
            ok: true,
            model_provider: "mock".into(),
            version: "test".into(),
        }))
    }
}

#[derive(Default)]
struct Hits {
    /// `/admin/reset` on the app: what a post-authz redirect would reach.
    admin: AtomicUsize,
    /// Another origin: what an http tool's redirect would reach (think 169.254.169.254).
    elsewhere: AtomicUsize,
}

async fn serve(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

fn redirect(code: StatusCode, to: String) -> Response {
    (code, [(header::LOCATION, to)]).into_response()
}

async fn fake_app(hits: Arc<Hits>) -> SocketAddr {
    let h = hits.clone();
    let elsewhere = serve(Router::new().fallback(move || async move {
        h.elsewhere.fetch_add(1, Ordering::SeqCst);
        "instance credentials"
    }))
    .await;
    let away = format!("http://{elsewhere}/latest/meta-data/");
    let (a, b) = (away.clone(), away);
    let app = Router::new()
        .route(
            "/r",
            get(move || async move { redirect(StatusCode::FOUND, a) })
                .post(move || async move { redirect(StatusCode::TEMPORARY_REDIRECT, b) }),
        )
        .route(
            "/orders/{id}",
            get(|UrlPath(id): UrlPath<String>| async move {
                if id == "slow" {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    return "late".into_response();
                }
                // bigger than the sidecar reads (--max-response-bytes, 3 MiB): with a length,
                // and streamed without one
                if id == "huge" {
                    return "x".repeat(HUGE).into_response();
                }
                if id == "huge-stream" {
                    let chunks = (0..HUGE / 65536).map(|_| {
                        Ok::<_, std::io::Error>(axum::body::Bytes::from(vec![b'x'; 65536]))
                    });
                    return axum::body::Body::from_stream(futures::stream::iter(chunks))
                        .into_response();
                }
                // e.g. a trailing-slash or legacy-path redirect, into a path authz never allowed
                redirect(StatusCode::TEMPORARY_REDIRECT, "/admin/reset".into())
            }),
        )
        .route(
            "/admin/reset",
            any(move || async move {
                hits.admin.fetch_add(1, Ordering::SeqCst);
                "reset"
            }),
        );
    serve(app).await
}

/// A response body bigger than the sidecar's default limit.
const HUGE: usize = 4 * 1024 * 1024;

/// The demo orders charter on the fake app, with two http tools and an output rule.
fn charter(app: SocketAddr, audit: &Path) -> Charter {
    let mut c = Charter::from_yaml(ORDERS).unwrap();
    c.service.app_port = app.port();
    c.audit.sink = AuditSink::File;
    c.audit.file = Some(audit.to_string_lossy().into_owned());
    let ops = c
        .agents
        .iter_mut()
        .find(|a| a.name == "ops-assistant")
        .unwrap();
    for (name, method) in [("partner_get", "GET"), ("partner_post", "POST")] {
        ops.tools.push(ToolSpec {
            name: name.into(),
            description: "partner API".into(),
            tool_type: ToolType::Http,
            parameters: None,
            service: None,
            method: Some(method.into()),
            path: None,
            agent: None,
            url: Some(format!("http://{app}/r")),
            label: None,
            effect: None,
        });
    }
    c.guardrails
        .allowed_tools
        .get_mut("ops-assistant")
        .unwrap()
        .extend(["partner_get".into(), "partner_post".into()]);
    c.guardrails.output_deny.push(RegexRule {
        name: "no-keys".into(),
        regex: r"(?i)api[_-]?key\s*[:=]".into(),
    });
    c
}

struct Rig {
    _tmp: tempfile::TempDir,
    sidecar: Sidecar,
    app: SocketAddr,
    hits: Arc<Hits>,
    runtime: FakeRuntime,
    sock: PathBuf,
    audit: PathBuf,
}

async fn rig(output: Option<&str>) -> Rig {
    let tmp = tempfile::tempdir().unwrap();
    let hits = Arc::new(Hits::default());
    let app = fake_app(hits.clone()).await;
    let audit = tmp.path().join("audit.jsonl");
    let charter_path = tmp.path().join("orders.charter.yaml");
    std::fs::write(
        &charter_path,
        serde_yaml_ng::to_string(&charter(app, &audit)).unwrap(),
    )
    .unwrap();
    let sock = tmp.path().join("sock");
    std::fs::create_dir_all(&sock).unwrap();
    let runtime = FakeRuntime {
        output: output.map(str::to_string),
        ..Default::default()
    };
    let listener = tokio::net::UnixListener::bind(sock.join("runtime.sock")).unwrap();
    let svc = RuntimeServer::new(runtime.clone());
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener))
            .await
            .unwrap()
    });
    let cfg = Config::for_test(charter_path, tmp.path().join("no-tls"), sock.clone());
    let sidecar = agentscd::start(cfg).await.expect("sidecar starts");
    Rig {
        _tmp: tmp,
        sidecar,
        app,
        hits,
        runtime,
        sock,
        audit,
    }
}

impl Rig {
    async fn tools(&self) -> SidecarToolsClient<Channel> {
        let path = self.sock.join("sidecar.sock");
        let channel =
            Endpoint::try_from("http://tools.agentsc.local")
                .unwrap()
                .connect_with_connector(service_fn(move |_: Uri| {
                    let path = path.clone();
                    async move {
                        Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?))
                    }
                }))
                .await
                .unwrap();
        SidecarToolsClient::new(channel)
    }

    fn raw_audit(&self) -> String {
        std::fs::read_to_string(&self.audit).unwrap_or_default()
    }

    fn records(&self, pred: impl Fn(&Value) -> bool) -> Vec<Value> {
        self.raw_audit()
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .filter(|v| pred(v))
            .collect()
    }

    /// Records written by a handler the server dropped arrive asynchronously; wait for `n`.
    async fn wait_for(&self, n: usize, pred: impl Fn(&Value) -> bool) -> Vec<Value> {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            let found = self.records(&pred);
            if found.len() >= n || Instant::now() > until {
                return found;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn invoke_url(&self) -> String {
        format!(
            "http://{}/v1/agents/ops-assistant/invoke",
            self.sidecar.http_addr
        )
    }
}

impl Rig {
    /// Hold an Execute of ops-assistant for `request_id` in flight, as the pipeline does while
    /// the runtime runs, so the test may make that run's tool calls (tools.rs refuses others).
    fn in_flight(&self, request_id: &str) -> agentscd::runs::RunGuard<'_> {
        self.sidecar.state.runs.start(
            request_id,
            "ops-assistant",
            "local",
            "4bf92f3577b34da6a3ce929d0e0e4736",
        )
    }
}

fn ctx(tool: &str, request_id: &str) -> Option<ToolContext> {
    Some(ToolContext {
        request_id: request_id.into(),
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".into(),
        span_id: "00f067aa0ba902b7".into(),
        agent: "ops-assistant".into(),
        tool: tool.into(),
        depth: 0,
    })
}

fn slow_lookup(request_id: &str) -> ToolServiceRequest {
    ToolServiceRequest {
        ctx: ctx("lookup_order", request_id),
        service: "orders".into(),
        method: "GET".into(),
        path: "/orders/slow".into(),
        headers: Default::default(),
        body: vec![],
    }
}

#[tokio::test]
async fn redirects_go_back_to_the_caller_unfollowed() {
    let rig = rig(None).await;
    let mut tools = rig.tools().await;
    let _run = rig.in_flight("req-redirect");

    // An http tool's origin answers 302/307 to another origin: the runtime gets the 3xx, nothing
    // is fetched there, and the POST body is not replayed.
    for (tool, method, code) in [("partner_get", "GET", 302), ("partner_post", "POST", 307)] {
        let resp = tools
            .invoke_http(ToolHttpRequest {
                ctx: ctx(tool, "req-redirect"),
                method: method.into(),
                url: format!("http://{}/r", rig.app),
                headers: Default::default(),
                body: br#"{"input":"run ops-assistant"}"#.to_vec(),
            })
            .await
            .expect(tool)
            .into_inner();
        assert_eq!(resp.status, code, "{tool}");
        assert!(
            resp.headers["location"].ends_with("/latest/meta-data/"),
            "{:?}",
            resp.headers
        );
    }
    // The app answers an authorized path with a redirect into one authz never allowed.
    let resp = tools
        .invoke_service(ToolServiceRequest {
            ctx: ctx("lookup_order", "req-redirect"),
            service: "orders".into(),
            method: "GET".into(),
            path: "/orders/1001".into(),
            headers: Default::default(),
            body: vec![],
        })
        .await
        .expect("lookup is allowed")
        .into_inner();
    assert_eq!(resp.status, 307);
    assert_eq!(resp.headers["location"], "/admin/reset");

    assert_eq!(
        rig.hits.elsewhere.load(Ordering::SeqCst),
        0,
        "followed off-origin"
    );
    assert_eq!(
        rig.hits.admin.load(Ordering::SeqCst),
        0,
        "followed past authz"
    );
    let statuses: Vec<Value> = rig
        .records(|v| v["kind"] == "http_call" || v["kind"] == "service_call")
        .iter()
        .map(|v| v["output"]["status"].clone())
        .collect();
    assert_eq!(statuses, [json!(302), json!(307), json!(307)]);
    rig.sidecar.abort();
}

#[tokio::test]
async fn content_guardrail_denials_log_the_hash_not_the_payload() {
    let output = "export done: api_key = sk-OUT-789";
    let rig = rig(Some(output)).await;
    let http = reqwest::Client::new();
    const IN_RULE: &str = "guardrail.input_deny.no-secrets";

    // 1. input_deny, matched in the input, with a context alongside
    let body =
        json!({"input": "use api_key = sk-IN-123 for the export", "context": {"ticket": "T-1"}});
    let r = http
        .post(rig.invoke_url())
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["rule"], IN_RULE);
    let denied_in = v["request_id"].as_str().unwrap().to_string();

    // 2. output_deny on what the runtime answered
    let r = http
        .post(rig.invoke_url())
        .json(&json!({"input": "export the report"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["rule"], "guardrail.output_deny.no-keys");
    let denied_out = v["request_id"].as_str().unwrap().to_string();

    // 3. a local agent call whose callee refuses the input: the calling agent's tool records
    //    withhold it too, and so does its next prompt, which quotes the tool input. The runtime
    //    reports for a run the sidecar knows (design §6.5): one more ops-assistant run, whose
    //    Execute just returned.
    let r = http
        .post(rig.invoke_url())
        .json(&json!({"input": "plan the export"}))
        .send()
        .await
        .unwrap();
    let v: Value = r.json().await.unwrap();
    let run = v["request_id"].as_str().unwrap().to_string();
    // the runtime's own nested call, made while that Execute is (again) in flight
    let _in_flight = rig.in_flight(&run);
    let mut tools = rig.tools().await;
    let nested = "triage this: password = sk-NESTED-456";
    let err = tools
        .invoke_agent(ToolAgentRequest {
            ctx: ctx("order_triage", &run),
            target_service: String::new(),
            target_agent: "order-triage".into(),
            input: nested.into(),
        })
        .await
        .expect_err("callee's guardrail denies");
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err:?}");
    let prompt = json!({"messages": [{"role": "assistant", "content": [
        {"type": "tool_use", "name": "order_triage", "input": {"input": nested}}]}]});
    let model_call = AuditRecord::new(
        Kind::ModelCall,
        Direction::Outbound,
        &run,
        &TraceContext::new_root(),
        Some("ops-assistant"),
        "local",
        None,
        "mock",
        prompt,
        Value::Null,
    );
    tools
        .report_event(AuditEvent {
            json: model_call.to_json_line(),
        })
        .await
        .unwrap();

    let raw = rig.raw_audit();
    for secret in ["sk-IN-123", "sk-OUT-789", "sk-NESTED-456"] {
        assert!(!raw.contains(secret), "{secret} in the audit log:\n{raw}");
    }

    // The hashes still prove what was sent.
    let in_hash = sha256_hex(&payload_bytes(&body));
    let recs = rig.records(|v| v["request_id"] == denied_in.as_str());
    let kinds: Vec<&str> = recs.iter().map(|v| v["kind"].as_str().unwrap()).collect();
    assert_eq!(kinds, ["guardrail", "agent_invocation"]);
    for r in &recs {
        assert_eq!(r["decision"], "deny");
        assert_eq!(r["input"], format!("[redacted:{IN_RULE}]"));
        assert_eq!(r["input_sha256"], in_hash.as_str());
    }

    let recs = rig.records(|v| v["request_id"] == denied_out.as_str());
    let guard = recs.iter().find(|v| v["kind"] == "guardrail").unwrap();
    assert_eq!(guard["output"], "[redacted:guardrail.output_deny.no-keys]");
    assert_eq!(
        guard["output_sha256"],
        sha256_hex(output.as_bytes()).as_str()
    );
    let inv = recs
        .iter()
        .find(|v| v["kind"] == "agent_invocation")
        .unwrap();
    assert_eq!(
        inv["input"], "export the report",
        "an input no rule matched is kept"
    );
    assert!(inv["output"].is_null());

    // after the run's own two records (its output was denied too)
    let recs: Vec<Value> = rig
        .records(|v| v["request_id"] == run.as_str())
        .into_iter()
        .skip(2)
        .collect();
    let kinds: Vec<&str> = recs.iter().map(|v| v["kind"].as_str().unwrap()).collect();
    assert_eq!(
        kinds,
        [
            "guardrail",
            "agent_invocation",
            "tool_call",
            "agent_call",
            "model_call"
        ]
    );
    for r in &recs[..4] {
        assert_eq!(r["input"], format!("[redacted:{IN_RULE}]"), "{r}");
        assert_eq!(r["input_sha256"], sha256_hex(nested.as_bytes()).as_str());
    }
    assert_eq!(
        recs[4]["input"]["messages"][0]["content"][0]["input"]["input"],
        "[redacted]"
    );
    rig.sidecar.abort();
}

#[tokio::test]
async fn invocations_are_audited_when_dropped_and_their_deadline_reaches_the_runtime() {
    let rig = rig(None).await; // the runtime never answers
    let mut app = AppApiClient::connect(format!("http://{}", rig.sidecar.grpc_addr))
        .await
        .unwrap();

    // 1. The app sets a 2s deadline: the runtime is given less, and the sidecar answers (and
    //    audits) before the app gives up.
    let mut req = tonic::Request::new(InvokeAgentRequest {
        agent: "ops-assistant".into(),
        input: "with a deadline".into(),
        ..Default::default()
    });
    req.set_timeout(Duration::from_secs(2));
    let started = Instant::now();
    let err = app
        .invoke_agent(req)
        .await
        .expect_err("the runtime never answers");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(err.code(), tonic::Code::Unavailable, "{err:?}");
    assert_eq!(
        err.metadata().get("x-agentsc-rule").unwrap(),
        "runtime.unavailable"
    );
    let given = rig.runtime.budgets.lock().unwrap()[0].expect("Execute carries a deadline");
    assert!(
        given <= Duration::from_secs(2) - agentscd::deadline::HOP_MARGIN
            && given > Duration::from_secs(1),
        "{given:?}"
    );
    let recs = rig.records(|v| v["input"] == "with a deadline");
    assert_eq!(recs.len(), 1);
    assert!(recs[0]["error"].as_str().unwrap().starts_with("runtime:"));

    // 2. Without a deadline, a client that gives up drops the handler mid-run: still one record.
    let call = app.invoke_agent(InvokeAgentRequest {
        agent: "ops-assistant".into(),
        input: "dropped over grpc".into(),
        ..Default::default()
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(300), call)
            .await
            .is_err()
    );
    let given = rig.runtime.budgets.lock().unwrap()[1].expect("Execute carries a deadline");
    let run = agentscd::deadline::RUN_TIMEOUT;
    assert!(
        given <= run && given > run - Duration::from_secs(5),
        "{given:?}"
    );

    // 3. The same over the HTTP API: the app's HTTP client times out and disconnects.
    let gone = reqwest::Client::new()
        .post(rig.invoke_url())
        .timeout(Duration::from_millis(300))
        .json(&json!({"input": "dropped over http"}))
        .send()
        .await;
    assert!(gone.is_err());

    for input in ["dropped over grpc", "dropped over http"] {
        let recs = rig.wait_for(1, |v| v["input"] == input).await;
        assert_eq!(recs.len(), 1, "{input}: {}", rig.raw_audit());
        assert_eq!(recs[0]["kind"], "agent_invocation");
        assert_eq!(recs[0]["decision"], "allow");
        assert_eq!(recs[0]["error"], CANCELLED);
    }
    rig.sidecar.abort();
}

#[tokio::test]
async fn tool_calls_are_audited_when_dropped_and_fail_cleanly_at_their_deadline() {
    let rig = rig(None).await;
    let mut tools = rig.tools().await;
    let _runs = (rig.in_flight("req-dropped"), rig.in_flight("req-deadline"));

    // 1. The runtime gives up on a call the app is still serving: both records, as cancelled.
    let call = tools.invoke_service(slow_lookup("req-dropped"));
    assert!(
        tokio::time::timeout(Duration::from_millis(300), call)
            .await
            .is_err()
    );
    let recs = rig.wait_for(2, |v| v["request_id"] == "req-dropped").await;
    let kinds: Vec<&str> = recs.iter().map(|v| v["kind"].as_str().unwrap()).collect();
    assert_eq!(kinds, ["tool_call", "service_call"], "{}", rig.raw_audit());
    for r in &recs {
        assert_eq!(r["decision"], "allow");
        assert_eq!(r["error"], CANCELLED);
    }

    // 2. With a deadline the sidecar stops waiting for the app first and answers in time.
    let mut req = tonic::Request::new(slow_lookup("req-deadline"));
    req.set_timeout(Duration::from_secs(1));
    let started = Instant::now();
    let err = tools
        .invoke_service(req)
        .await
        .expect_err("the app is too slow");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(err.code(), tonic::Code::Unavailable, "{err:?}");
    assert_eq!(
        err.metadata().get("x-agentsc-rule").unwrap(),
        "app.unavailable"
    );
    let recs = rig.records(|v| v["request_id"] == "req-deadline");
    assert_eq!(recs.len(), 2);
    for r in &recs {
        let e = r["error"].as_str().unwrap();
        assert!(e != CANCELLED && !e.is_empty(), "{e}");
    }
    rig.sidecar.abort();
}

#[tokio::test]
async fn a_response_bigger_than_the_limit_fails_the_call_instead_of_filling_memory() {
    let rig = rig(None).await;
    let mut tools = rig.tools().await;
    let _run = rig.in_flight("req-huge");
    for id in ["huge", "huge-stream"] {
        let err = tools
            .invoke_service(ToolServiceRequest {
                ctx: ctx("lookup_order", "req-huge"),
                service: "orders".into(),
                method: "GET".into(),
                path: format!("/orders/{id}"),
                headers: Default::default(),
                body: vec![],
            })
            .await
            .expect_err("the body is over the limit");
        assert_eq!(err.code(), tonic::Code::Unavailable, "{id}: {err:?}");
        assert_eq!(
            err.metadata().get("x-agentsc-rule").unwrap(),
            "http.response_too_large",
            "{id}"
        );
    }
    let recs = rig.records(|v| v["request_id"] == "req-huge" && v["kind"] == "service_call");
    assert_eq!(recs.len(), 2);
    assert!(recs.iter().all(|v| {
        v["error"]
            .as_str()
            .unwrap()
            .contains("more than the 3145728 bytes")
    }));
    rig.sidecar.abort();
}
