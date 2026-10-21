//! Shared rigs for the sidecar's integration tests: a scriptable fake runtime on `runtime.sock`,
//! a client for `sidecar.sock`, audit log readers and a standalone sidecar.
#![allow(dead_code)]

pub mod cp;

use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agentsc_charter::{AuditSink, Charter};
use agentsc_proto::runtime_server::{Runtime, RuntimeServer};
use agentsc_proto::sidecar_tools_client::SidecarToolsClient;
use agentsc_proto::{Empty, ExecuteRequest, ExecuteResponse, HealthResponse, ToolContext};
use agentscd::{Config, Sidecar};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

pub const ORDERS: &str = include_str!("../../../../examples/charters/orders.charter.yaml");
pub const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";

pub type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;
pub type Behavior = Arc<dyn Fn(ExecuteRequest) -> BoxFut<ExecuteResponse> + Send + Sync>;
pub type Pending = (
    ExecuteRequest,
    tokio::sync::oneshot::Sender<ExecuteResponse>,
);

/// Stands in for the agent runtime: every Execute is recorded, then answered by `behavior`.
#[derive(Clone)]
pub struct FakeRuntime {
    pub seen: Arc<Mutex<Vec<ExecuteRequest>>>,
    behavior: Behavior,
}

pub fn ok(output: &str) -> ExecuteResponse {
    ExecuteResponse {
        status: "ok".into(),
        output: output.into(),
        ..Default::default()
    }
}

impl FakeRuntime {
    pub fn answering(output: &str) -> Self {
        let output = output.to_string();
        Self::with(move |_| {
            let output = output.clone();
            Box::pin(async move { ok(&output) })
        })
    }

    pub fn with(
        f: impl Fn(ExecuteRequest) -> BoxFut<ExecuteResponse> + Send + Sync + 'static,
    ) -> Self {
        Self {
            seen: Arc::default(),
            behavior: Arc::new(f),
        }
    }

    /// Every Execute waits until the test answers it: the test gets the request (the run is in
    /// flight) and a sender for the response.
    pub fn gated() -> (Self, tokio::sync::mpsc::UnboundedReceiver<Pending>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Pending>();
        let rt = Self::with(move |req| {
            let tx = tx.clone();
            Box::pin(async move {
                let (done, wait) = tokio::sync::oneshot::channel();
                if tx.send((req, done)).is_err() {
                    return ok("nobody is waiting");
                }
                wait.await.unwrap_or_else(|_| ok("dropped"))
            })
        });
        (rt, rx)
    }

    pub fn seen(&self) -> Vec<ExecuteRequest> {
        self.seen.lock().unwrap().clone()
    }

    /// The `agent_spec_json` of the last Execute of `agent`.
    pub fn last_spec(&self, agent: &str) -> Value {
        let seen = self.seen();
        let req = seen
            .iter()
            .rev()
            .find(|r| serde_json::from_str::<Value>(&r.agent_spec_json).unwrap()["name"] == agent)
            .unwrap_or_else(|| panic!("no Execute of {agent}"));
        serde_json::from_str(&req.agent_spec_json).unwrap()
    }
}

#[tonic::async_trait]
impl Runtime for FakeRuntime {
    async fn execute(
        &self,
        request: tonic::Request<ExecuteRequest>,
    ) -> Result<tonic::Response<ExecuteResponse>, tonic::Status> {
        let req = request.into_inner();
        self.seen.lock().unwrap().push(req.clone());
        Ok(tonic::Response::new((self.behavior)(req).await))
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

/// Serve `runtime` on `<sock>/runtime.sock`.
pub fn serve_runtime(sock: &Path, runtime: FakeRuntime) {
    std::fs::create_dir_all(sock).unwrap();
    let path = sock.join("runtime.sock");
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(path).unwrap();
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(RuntimeServer::new(runtime))
            .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener))
            .await;
    });
}

/// A `SidecarTools` client on `<sock>/sidecar.sock`.
pub async fn tools(sock: &Path) -> SidecarToolsClient<Channel> {
    let path = sock.join("sidecar.sock");
    let channel = Endpoint::try_from("http://tools.agentsc.local")
        .unwrap()
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
        }))
        .await
        .unwrap();
    SidecarToolsClient::new(channel)
}

pub fn ctx(agent: &str, tool: &str, request_id: &str, span_id: &str) -> Option<ToolContext> {
    Some(ToolContext {
        request_id: request_id.into(),
        trace_id: TRACE_ID.into(),
        span_id: span_id.into(),
        agent: agent.into(),
        tool: tool.into(),
        depth: 0,
    })
}

/// The tool context a runtime builds for an Execute.
pub fn ctx_for(req: &ExecuteRequest, agent: &str, tool: &str) -> Option<ToolContext> {
    Some(ToolContext {
        request_id: req.request_id.clone(),
        trace_id: req.trace_id.clone(),
        span_id: req.span_id.clone(),
        agent: agent.into(),
        tool: tool.into(),
        depth: req.depth,
    })
}

pub fn read_audit(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .collect()
}

/// Wait (up to 10 s) until `pred` holds for the audit log, and return the matching records.
pub async fn wait_audit(path: &Path, n: usize, pred: impl Fn(&Value) -> bool) -> Vec<Value> {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        let found: Vec<Value> = read_audit(path).into_iter().filter(|v| pred(v)).collect();
        if found.len() >= n || Instant::now() > until {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Wait (up to 10 s) for `cond`.
pub async fn eventually(what: &str, mut cond: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(Instant::now() < until, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// The demo orders charter with its audit log in `audit`.
pub fn orders(audit: &Path) -> Charter {
    let mut c = Charter::from_yaml(ORDERS).unwrap();
    c.audit.sink = AuditSink::File;
    c.audit.file = Some(audit.to_string_lossy().into_owned());
    c
}

pub fn write_charter(path: &Path, c: &Charter) {
    // written through a temporary file, as a ConfigMap update would swap it
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_yaml_ng::to_string(c).unwrap()).unwrap();
    std::fs::rename(tmp, path).unwrap();
}

pub async fn serve_app(app: axum::Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// A standalone sidecar with a fake runtime, its charter in a file it polls quickly.
pub struct Rig {
    pub tmp: tempfile::TempDir,
    pub sidecar: Sidecar,
    pub runtime: FakeRuntime,
    pub sock: PathBuf,
    pub audit: PathBuf,
    pub charter_path: PathBuf,
}

pub fn fast_timing() -> agentscd::config::Timing {
    agentscd::config::Timing {
        charter_poll: Duration::from_millis(100),
        run_window: Duration::from_secs(120),
        heartbeat: Duration::from_millis(200),
        reconnect_min: Duration::from_millis(100),
        reconnect_max: Duration::from_millis(300),
        renew_retry: Duration::from_millis(300),
        audit_flush: Duration::from_millis(100),
        issue_timeout: Duration::from_secs(5),
    }
}

pub async fn rig(
    runtime: FakeRuntime,
    charter: impl FnOnce(&mut Charter),
    config: impl FnOnce(&mut Config),
) -> Rig {
    let tmp = tempfile::tempdir().unwrap();
    let audit = tmp.path().join("audit.jsonl");
    let mut c = orders(&audit);
    charter(&mut c);
    let charter_path = tmp.path().join("charter.yaml");
    write_charter(&charter_path, &c);
    let sock = tmp.path().join("sock");
    serve_runtime(&sock, runtime.clone());
    let mut cfg = Config::for_test(
        charter_path.clone(),
        tmp.path().join("no-tls"),
        sock.clone(),
    );
    cfg.timing = fast_timing();
    config(&mut cfg);
    let sidecar = agentscd::start(cfg).await.expect("sidecar starts");
    Rig {
        tmp,
        sidecar,
        runtime,
        sock,
        audit,
        charter_path,
    }
}

impl Rig {
    pub fn records(&self, pred: impl Fn(&Value) -> bool) -> Vec<Value> {
        read_audit(&self.audit)
            .into_iter()
            .filter(|v| pred(v))
            .collect()
    }

    pub fn invoke_url(&self, agent: &str) -> String {
        format!("http://{}/v1/agents/{agent}/invoke", self.sidecar.http_addr)
    }

    pub async fn invoke(&self, agent: &str, input: &str) -> (u16, Value) {
        let r = reqwest::Client::new()
            .post(self.invoke_url(agent))
            .json(&serde_json::json!({ "input": input }))
            .send()
            .await
            .unwrap();
        (r.status().as_u16(), r.json().await.unwrap())
    }

    /// Rewrite the charter file and wait for the reload's `config` record (`n` in total).
    pub async fn reload(&self, c: &Charter, n: usize) -> Value {
        write_charter(&self.charter_path, c);
        let recs = wait_audit(&self.audit, n, |v| {
            v["kind"] == "config" && v["callee"] == "charter"
        })
        .await;
        assert!(recs.len() >= n, "no config record for the reload");
        recs[n - 1].clone()
    }
}
