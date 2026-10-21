//! A running `embassy serve` (components `controlplane,api,ui`, a temporary file store, a test
//! CA) and clients for it: HTTP with tokens of every role, SSE, and sidecars over mTLS.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use agentsc_proto::control_plane_client::ControlPlaneClient;
use agentsc_proto::{ControlMessage, Hello, SidecarMessage, sidecar_message};
use clap::Parser;
use embassy::ca::CaMaterial;
use embassy::config::{Anonymous, ControlPlaneConfig, PolicyConfig, Role, TokenEntry};
use embassy::hub::Hub;
use embassy::serve::{ServeArgs, Started};
use reqwest::header::HeaderMap;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};
use tonic::{Status, Streaming};

pub const NS: &str = "shop";
pub const WAIT: Duration = Duration::from_secs(10);

#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    serve: ServeArgs,
}

/// How to start the server.
#[derive(Debug, Clone, Default)]
pub struct Opts {
    pub auto_adopt: bool,
    pub dev_anonymous: bool,
    pub policy: Option<PolicyConfig>,
    /// Run the `ca` component too (Connect then shares --grpc-addr with optional client certs).
    pub with_ca: bool,
    pub http_tls: bool,
    pub retain_bytes: Option<u64>,
}

/// One response.
#[derive(Debug)]
pub struct Resp {
    pub status: u16,
    pub headers: HeaderMap,
    pub text: String,
    pub body: Value,
}

impl Resp {
    pub fn error(&self) -> &str {
        self.body["error"].as_str().unwrap_or("")
    }

    pub fn details(&self) -> String {
        self.body["details"]
            .as_array()
            .map(|d| {
                d.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default()
    }

    pub fn etag(&self) -> Option<String> {
        self.headers
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string())
    }

    pub fn version(&self) -> String {
        self.body["version"].as_str().unwrap_or("").to_string()
    }
}

pub struct Env {
    pub dir: tempfile::TempDir,
    started: Option<Started>,
    pub hub: Arc<Hub>,
    pub base: String,
    pub grpc: Option<SocketAddr>,
    pub ca: Arc<CaMaterial>,
    /// name → token
    pub tokens: BTreeMap<String, String>,
    pub http: reqwest::Client,
    pub store_dir: std::path::PathBuf,
}

fn entry(name: &str, token: &str, role: Role, namespaces: &[&str], payloads: bool) -> TokenEntry {
    TokenEntry {
        name: name.into(),
        role,
        sha256: embassy::token::sha256_hex(token),
        namespaces: namespaces.iter().map(|s| s.to_string()).collect(),
        payloads,
    }
}

impl Env {
    pub async fn start() -> Env {
        Self::start_with(Opts::default()).await
    }

    pub async fn start_with(opts: Opts) -> Env {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let ca = agentsc_pki::ca_init().unwrap();
        let ca_dir = dir.path().join("ca");
        std::fs::create_dir_all(&ca_dir).unwrap();
        std::fs::write(ca_dir.join("ca.crt"), &ca.cert_pem).unwrap();
        std::fs::write(ca_dir.join("ca.key"), &ca.key_pem).unwrap();
        let ca = Arc::new(CaMaterial::from_pems(&ca.cert_pem, &ca.key_pem).unwrap());
        let tls = dir.path().join("tls");
        std::fs::create_dir_all(&tls).unwrap();
        let serving = ca
            .sign_server(
                &["localhost".to_string()],
                embassy::servingcert::CONTROL_PLANE_SPIFFE_ID,
                Duration::from_secs(3600),
            )
            .unwrap();
        std::fs::write(tls.join("tls.crt"), &serving.cert_pem).unwrap();
        std::fs::write(tls.join("tls.key"), &serving.key_pem).unwrap();
        std::fs::write(tls.join("ca.crt"), ca.roots_pem()).unwrap();

        let mut tokens = BTreeMap::new();
        let mut config = ControlPlaneConfig::default();
        for (name, role, ns, payloads) in [
            ("alice", Role::Admin, &["*"][..], true),
            ("bob", Role::Editor, &["*"][..], true),
            ("carol", Role::Viewer, &[NS][..], false),
            ("dave", Role::Editor, &["other"][..], true),
            ("erin", Role::Admin, &[NS][..], false),
        ] {
            let t = embassy::token::generate().unwrap();
            config.auth.tokens.push(entry(name, &t, role, ns, payloads));
            tokens.insert(name.to_string(), t);
        }
        if opts.dev_anonymous {
            config.auth.anonymous = Anonymous::Viewer;
        }
        config.policy = opts.policy.clone();
        if let Some(r) = opts.retain_bytes {
            config.events.retain_bytes = r;
        }
        let store_dir = dir.path().join("store");
        let store = format!("file:{}", store_dir.display());
        let mut argv: Vec<String> = vec![
            "serve".into(),
            "--components".into(),
            if opts.with_ca {
                "ca,controlplane,api,ui".into()
            } else {
                "controlplane,api,ui".into()
            },
            "--store".into(),
            store,
            "--http-addr".into(),
            "127.0.0.1:0".into(),
            "--grpc-addr".into(),
            "127.0.0.1:0".into(),
            "--dns-name".into(),
            "embassy.test".into(),
            "--dns-name".into(),
            "localhost".into(),
        ];
        if opts.with_ca {
            argv.push("--ca-dir".into());
            argv.push(ca_dir.display().to_string());
        } else {
            argv.push("--tls-dir".into());
            argv.push(tls.display().to_string());
        }
        if opts.auto_adopt {
            argv.push("--auto-adopt".into());
        }
        if opts.dev_anonymous {
            argv.push("--dev".into());
        }
        if opts.http_tls {
            argv.push("--http-tls".into());
        }
        let args = Cli::try_parse_from(argv).unwrap().serve;
        args.validate().unwrap();
        let started = embassy::serve::start(args, config, CancellationToken::new())
            .await
            .unwrap();
        let hub = started.hub.clone().unwrap();
        let http_addr = started.http_addr.unwrap();
        let scheme = if opts.http_tls { "https" } else { "http" };
        let host = if opts.http_tls {
            format!("localhost:{}", http_addr.port())
        } else {
            http_addr.to_string()
        };
        let mut http = reqwest::Client::builder().no_proxy();
        if opts.http_tls {
            http = http.add_root_certificate(
                reqwest::Certificate::from_pem(ca.roots_pem().as_bytes()).unwrap(),
            );
        }
        Env {
            base: format!("{scheme}://{host}"),
            grpc: started.grpc_addr,
            started: Some(started),
            hub,
            ca,
            tokens,
            http: http.build().unwrap(),
            store_dir,
            dir,
        }
    }

    pub async fn stop(mut self) {
        if let Some(s) = self.started.take() {
            s.stop().await.unwrap();
        }
    }

    pub fn token(&self, who: &str) -> &str {
        &self.tokens[who]
    }

    /// A request with the CSRF header and JSON content type on mutations.
    pub fn req(&self, method: &str, path: &str, who: Option<&str>) -> reqwest::RequestBuilder {
        let m: reqwest::Method = method.parse().unwrap();
        let mut b = self.http.request(m.clone(), format!("{}{path}", self.base));
        if let Some(w) = who {
            b = b.bearer_auth(self.token(w));
        }
        if m != reqwest::Method::GET {
            b = b
                .header("X-Agentsc-CSRF", "1")
                .header("Content-Type", "application/json");
        }
        b
    }

    pub async fn send(b: reqwest::RequestBuilder) -> Resp {
        let r = b.send().await.unwrap();
        let status = r.status().as_u16();
        let headers = r.headers().clone();
        let text = r.text().await.unwrap();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Resp {
            status,
            headers,
            text,
            body,
        }
    }

    pub async fn get(&self, path: &str, who: &str) -> Resp {
        Self::send(self.req("GET", &format!("/api/v1{path}"), Some(who))).await
    }

    pub async fn call(
        &self,
        method: &str,
        path: &str,
        who: &str,
        body: Option<Value>,
        if_match: Option<&str>,
    ) -> Resp {
        let mut b = self.req(method, &format!("/api/v1{path}"), Some(who));
        if let Some(v) = if_match {
            b = b.header("If-Match", format!("\"{v}\""));
        }
        b = match body {
            Some(v) => b.body(v.to_string()),
            None => b,
        };
        Self::send(b).await
    }

    /// Store a service's first charter as alice (admin, `If-None-Match: *`); its version.
    pub async fn create(&self, svc: &str, yaml: &str) -> String {
        let r = Self::send(
            self.req(
                "PUT",
                &format!("/api/v1/services/{NS}/{svc}/charter"),
                Some("alice"),
            )
            .header("If-None-Match", "*")
            .body(json!({ "yaml": yaml }).to_string()),
        )
        .await;
        assert_eq!(r.status, 200, "{}", r.text);
        r.version()
    }

    pub async fn charter(&self, svc: &str) -> (String, Value) {
        let r = self
            .get(&format!("/services/{NS}/{svc}/charter"), "alice")
            .await;
        assert_eq!(r.status, 200, "{}", r.text);
        (r.version(), r.body["charter"].clone())
    }

    /// Take in an audit record as if a sidecar of its service sent it.
    pub fn ingest(&self, rec: Value) {
        self.hub.ingest_record(serde_json::from_value(rec).unwrap());
    }

    /// A workload certificate and key for `ns/svc` from the test CA.
    pub fn workload(&self, ns: &str, svc: &str) -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::default()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap();
        let public = agentsc_pki::verify_csr_p256(&csr).unwrap();
        let leaf = self
            .ca
            .sign_workload(&public, ns, svc, Duration::from_secs(3600))
            .unwrap();
        (leaf.cert_pem, key.serialize_pem())
    }

    pub async fn channel(&self, identity: Option<(String, String)>) -> tonic::transport::Channel {
        let mut tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(self.ca.roots_pem()))
            .domain_name("localhost");
        if let Some((cert, key)) = identity {
            tls = tls.identity(Identity::from_pem(cert, key));
        }
        let port = self.grpc.unwrap().port();
        Endpoint::from_shared(format!("https://localhost:{port}"))
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .connect()
            .await
            .unwrap()
    }

    /// A sidecar of `ns/svc` (its certificate) that sends `hello` first.
    pub async fn sidecar(&self, ns: &str, svc: &str, hello: Hello) -> Result<Sidecar, Status> {
        let channel = self.channel(Some(self.workload(ns, svc))).await;
        Sidecar::open(channel, hello).await
    }
}

pub fn hello(ns: &str, svc: &str, pod: &str) -> Hello {
    Hello {
        service: svc.into(),
        namespace: ns.into(),
        pod: pod.into(),
        sidecar_version: "0.2.0".into(),
        charter_schema_level: 2,
        app_port: 8080,
        mesh_port: 50002,
        ..Default::default()
    }
}

pub struct Sidecar {
    pub tx: mpsc::Sender<SidecarMessage>,
    pub rx: Streaming<ControlMessage>,
}

impl Sidecar {
    pub async fn open(channel: tonic::transport::Channel, hello: Hello) -> Result<Sidecar, Status> {
        let (tx, rx) = mpsc::channel(64);
        tx.send(SidecarMessage {
            msg: Some(sidecar_message::Msg::Hello(hello)),
        })
        .await
        .unwrap();
        let mut client = ControlPlaneClient::new(channel);
        let resp = client.connect(ReceiverStream::new(rx)).await?;
        Ok(Sidecar {
            tx,
            rx: resp.into_inner(),
        })
    }

    pub async fn send(&self, msg: sidecar_message::Msg) {
        self.tx
            .send(SidecarMessage { msg: Some(msg) })
            .await
            .unwrap();
    }

    /// The next control message, or `None` after `wait`.
    pub async fn next_within(&mut self, wait: Duration) -> Option<ControlMessage> {
        match tokio::time::timeout(wait, self.rx.message()).await {
            Ok(Ok(m)) => m,
            _ => None,
        }
    }

    pub async fn next(&mut self) -> ControlMessage {
        self.next_within(WAIT).await.expect("a control message")
    }
}

/// One SSE frame.
#[derive(Debug, Clone)]
pub struct Frame {
    pub id: Option<u64>,
    pub event: String,
    pub data: Value,
    pub comment: bool,
}

/// Reads SSE frames from a streaming response.
pub struct SseReader {
    pub resp: reqwest::Response,
    buf: String,
}

impl SseReader {
    pub fn new(resp: reqwest::Response) -> Self {
        Self {
            resp,
            buf: String::new(),
        }
    }

    /// The next frame (comments included), or `None` after `wait`.
    pub async fn next_within(&mut self, wait: Duration) -> Option<Frame> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            if let Some(pos) = self.buf.find("\n\n") {
                let block: String = self.buf[..pos].to_string();
                self.buf.drain(..pos + 2);
                let mut f = Frame {
                    id: None,
                    event: String::new(),
                    data: Value::Null,
                    comment: false,
                };
                let mut data = Vec::new();
                for line in block.lines() {
                    if let Some(c) = line.strip_prefix(':') {
                        f.comment = true;
                        f.event = c.trim().to_string();
                        continue;
                    }
                    let (k, v) = line.split_once(": ").unwrap_or((line, ""));
                    match k {
                        "id" => f.id = v.parse().ok(),
                        "event" => f.event = v.to_string(),
                        "data" => data.push(v.to_string()),
                        _ => {}
                    }
                }
                if !data.is_empty() {
                    f.data = serde_json::from_str(&data.join("\n")).unwrap();
                }
                return Some(f);
            }
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(left, self.resp.chunk()).await {
                Ok(Ok(Some(bytes))) => self.buf.push_str(&String::from_utf8_lossy(&bytes)),
                _ => return None,
            }
        }
    }

    /// The next event (not a comment) named `name`, skipping others.
    pub async fn until(&mut self, name: &str) -> Frame {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let f = self
                .next_within(left)
                .await
                .unwrap_or_else(|| panic!("no {name} event"));
            if !f.comment && f.event == name {
                return f;
            }
        }
    }
}

/// Poll `f` until it is true (at most [`WAIT`]).
pub async fn eventually<F, Fut>(what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + WAIT;
    while tokio::time::Instant::now() < deadline {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for {what}");
}

pub fn now_ts() -> String {
    embassy::cp_audit::now_ts()
}

/// An audit record of `orders/ops` in `shop`, with `over` merged in.
pub fn rec(kind: &str, over: Value) -> Value {
    let mut r = json!({
        "ts": now_ts(), "kind": kind, "request_id": "0c4a3f8e-1111-4222-8333-444455556666",
        "trace_id": "6e2d9ff960031afca28de8fa28704004", "span_id": "00f067aa0ba902b7",
        "parent_span_id": null, "service": "orders", "namespace": NS, "agent": "ops",
        "caller": "local", "caller_agent": null, "callee": "ops", "direction": "inbound",
        "input": {"input": "How many WIDGET-1 are in stock?"}, "output": {"text": "42"},
        "input_sha256": null, "output_sha256": null, "tokens": null, "cost_usd": null,
        "latency_ms": 100, "decision": "allow", "rule": null, "reason": null, "error": null
    });
    if let (Some(m), Some(o)) = (r.as_object_mut(), over.as_object()) {
        for (k, v) in o {
            m.insert(k.clone(), v.clone());
        }
    }
    r
}

/// The orders charter: orchestrator `ops` (tools to its own app, to `inventory/stock` and to
/// the local `triage`) and `triage`.
pub fn orders_yaml() -> String {
    format!(
        r#"apiVersion: agentsc.io/v1alpha1
kind: Charter
service:
  name: orders
  namespace: {NS}
  app_port: 8080
agents:
  - name: ops
    type: orchestrator
    model: mock
    tools:
      - name: lookup_order
        description: Look up an order.
        type: service
        service: orders
        method: GET
        path: /orders/{{id}}
      - name: ask_stock
        description: Ask the stock agent.
        type: agent
        service: inventory
        agent: stock
      - name: ask_triage
        description: Ask triage.
        type: agent
        agent: triage
  - name: triage
    model: claude-opus-5-5
guardrails:
  pii_redact: true
  input_deny:
    - name: no-secrets
      regex: "(?i)password\\s*[:=]"
  allowed_tools:
    ops: [lookup_order, ask_stock, ask_triage]
authz:
  default: deny
  callers:
    - identity: local
      agents: ["*"]
"#
    )
}

/// The inventory charter: `stock`, callable by orders' `ops`.
pub fn inventory_yaml() -> String {
    format!(
        r#"apiVersion: agentsc.io/v1alpha1
kind: Charter
service:
  name: inventory
  namespace: {NS}
  app_port: 8081
agents:
  - name: stock
    model: mock
    tools:
      - name: get_stock
        description: Read stock.
        type: service
        service: inventory
        method: GET
        path: /stock
authz:
  default: deny
  callers:
    - identity: local
      agents: [stock]
    - identity: spiffe://agentsc/ns/{NS}/svc/orders
      agents: [stock]
      caller_agents: [ops]
"#
    )
}

/// The support charter: `helper` learns in review mode (at most 2 notes of at most 60
/// characters); `faq` does not learn.
pub fn support_yaml(learning: bool) -> String {
    format!(
        r#"apiVersion: agentsc.io/v1alpha1
kind: Charter
service:
  name: support
  namespace: {NS}
  app_port: 8090
agents:
  - name: helper
    type: orchestrator
    model: mock
    learning:
      enabled: {learning}
      max_notes: 2
      max_note_chars: 60
  - name: faq
    model: mock
authz:
  default: deny
  callers:
    - identity: local
      agents: ["*"]
"#
    )
}
