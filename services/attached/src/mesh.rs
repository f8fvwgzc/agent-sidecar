//! `Mesh`: what other pods' sidecars call, over mTLS (CONTRACT.md §4.2, §5).
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use attache_common::audit::{AuditRecord, Direction, Kind};
use attache_common::authz::{self, Verdict};
use attache_common::trace::TraceContext;
use attache_proto::mesh_server::{Mesh, MeshServer};
use attache_proto::{InvokeAgentRequest, InvokeAgentResponse, ServiceRequest, ServiceResponse};
use serde_json::{Value, json};
use tonic::{Request, Response, Status};

use crate::deadline;
use crate::pipeline::{self, Invocation};
use crate::state::AppState;
use crate::tools::is_reserved_header;

pub const RULE_IDENTITY: &str = "authz.identity.invalid";
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub struct MeshService {
    state: Arc<AppState>,
}

/// Serve the mesh over mTLS with the current workload certificate (design §6.3.2): the TLS
/// handshake runs here with rustls, so a renewed certificate is used by the next connection.
/// Handshakes run concurrently; a client that fails one never reaches the service.
pub async fn serve(
    state: Arc<AppState>,
    addr: SocketAddr,
) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let acceptor = tokio_rustls::TlsAcceptor::from(crate::tls::mesh_server_config(&state.tls)?);
    let (tx, rx) = tokio::sync::mpsc::channel::<
        Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, std::io::Error>,
    >(64);
    let accept = async move {
        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!(error = %e, "mesh accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                    Ok(Ok(tls)) => {
                        let _ = tx.send(Ok(tls)).await;
                    }
                    Ok(Err(e)) => tracing::debug!(%peer, error = %e, "mesh TLS handshake failed"),
                    Err(_) => tracing::debug!(%peer, "mesh TLS handshake timed out"),
                }
            });
        }
    };
    let server = tonic::transport::Server::builder()
        .add_service(MeshServer::new(MeshService { state }))
        .serve_with_incoming(tokio_stream::wrappers::ReceiverStream::new(rx));
    let task = tokio::spawn(async move {
        tokio::select! {
            r = server => if let Err(e) = r {
                tracing::error!(error = %e, "mesh server stopped");
            },
            _ = accept => {}
        }
    });
    Ok((bound, task))
}

fn meta<T>(req: &Request<T>, key: &str) -> Option<String> {
    req.metadata()
        .get(key)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

fn deny_status(v: &Verdict) -> Status {
    let mut st = Status::permission_denied(format!("{}: {}", v.rule, v.reason));
    if let Ok(val) = v.rule.parse() {
        st.metadata_mut().insert("x-attache-rule", val);
    }
    st
}

fn body_value(body: &[u8]) -> Value {
    if body.is_empty() {
        return Value::Null;
    }
    serde_json::from_slice(body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(body).into_owned()))
}

/// What every inbound mesh call carries, read once.
struct Inbound {
    caller: Result<String, Verdict>,
    agent: Option<String>,
    trace: TraceContext,
    request_id: String,
    deadline: Option<Instant>,
}

fn inbound<T>(
    req: &Request<T>,
    body_traceparent: &str,
    body_request_id: &str,
    body_agent: &str,
) -> Inbound {
    let caller = match req.peer_certs() {
        None => Err(Verdict::deny(RULE_IDENTITY, "no client certificate")),
        Some(certs) => match certs.first() {
            None => Err(Verdict::deny(
                RULE_IDENTITY,
                "empty client certificate chain",
            )),
            Some(leaf) => match attache_pki::spiffe_id_of(leaf) {
                Ok(Some(id)) => Ok(id.uri()),
                Ok(None) => Err(Verdict::deny(
                    RULE_IDENTITY,
                    "client certificate has no spiffe://attache/ URI SAN",
                )),
                Err(e) => Err(Verdict::deny(
                    RULE_IDENTITY,
                    format!("client certificate unreadable: {e}"),
                )),
            },
        },
    };
    let tp = meta(req, "traceparent").unwrap_or_else(|| body_traceparent.to_string());
    Inbound {
        caller,
        agent: meta(req, "x-attache-agent")
            .or_else(|| (!body_agent.is_empty()).then(|| body_agent.to_string())),
        trace: TraceContext::from_traceparent(&tp),
        request_id: meta(req, "x-attache-request-id")
            .or_else(|| (!body_request_id.is_empty()).then(|| body_request_id.to_string()))
            .unwrap_or_else(attache_common::trace::new_request_id),
        deadline: deadline::from_metadata(req.metadata()),
    }
}

impl MeshService {
    /// A refused peer still leaves a trace in the callee's log (CONTRACT.md §6, kind `authz`).
    fn audit_identity_denial(&self, inb: &Inbound, v: &Verdict, callee: &str, started: Instant) {
        let rec = AuditRecord::new(
            Kind::Authz,
            Direction::Inbound,
            &inb.request_id,
            &inb.trace,
            None,
            "unknown",
            inb.agent.as_deref(),
            callee,
            Value::Null,
            Value::Null,
        )
        .verdict(v)
        .latency(started);
        self.state.audit.write(rec);
    }
}

#[tonic::async_trait]
impl Mesh for MeshService {
    async fn invoke_agent(
        &self,
        request: Request<InvokeAgentRequest>,
    ) -> Result<Response<InvokeAgentResponse>, Status> {
        let started = Instant::now();
        let inb = {
            let body = request.get_ref();
            inbound(
                &request,
                &body.traceparent,
                &body.request_id,
                &body.caller_agent,
            )
        };
        let req = request.into_inner();
        let caller = match &inb.caller {
            Ok(c) => c.clone(),
            Err(v) => {
                self.audit_identity_denial(&inb, v, &req.agent, started);
                return Err(deny_status(v));
            }
        };
        let inv = Invocation {
            agent: req.agent,
            input: req.input,
            context_json: req.context_json,
            request_id: inb.request_id.clone(),
            trace: inb.trace.clone(),
            caller,
            caller_agent: inb.agent.clone(),
            depth: req.depth,
            deadline: inb.deadline,
        };
        let resp = pipeline::invoke(&self.state, inv).await;
        match pipeline::grpc_status(&resp) {
            Some(st) => Err(st),
            None => Ok(Response::new(resp)),
        }
    }

    async fn invoke_service(
        &self,
        request: Request<ServiceRequest>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let started = Instant::now();
        let inb = {
            let body = request.get_ref();
            inbound(&request, &body.traceparent, &body.request_id, &body.agent)
        };
        let req = request.into_inner();
        let me = self.state.service.clone();
        let raw_callee = format!("{me} {} {}", req.method, req.path);
        let caller = match &inb.caller {
            Ok(c) => c.clone(),
            Err(v) => {
                self.audit_identity_denial(&inb, v, &raw_callee, started);
                return Err(deny_status(v));
            }
        };
        let mut input =
            json!({ "method": req.method, "path": req.path, "body": body_value(&req.body) });
        let record = |callee: &str, input: &Value, output: Value| {
            AuditRecord::new(
                Kind::ServiceCall,
                Direction::Inbound,
                &inb.request_id,
                &inb.trace,
                inb.agent.as_deref(),
                &caller,
                inb.agent.as_deref(),
                callee,
                input.clone(),
                output,
            )
            .latency(started)
        };

        // The peer's sidecar canonicalised method and path already; a peer is still not trusted to have.
        let canonical = authz::canonical_method(&req.method)
            .and_then(|m| authz::canonical_path(&req.path).map(|p| (m, p)));
        let (method, path) = match canonical {
            Ok(mp) => mp,
            Err(reason) => {
                let v = Verdict::deny(authz::RULE_PATH, reason);
                self.state
                    .audit
                    .write(record(&raw_callee, &input, Value::Null).verdict(&v));
                return Err(deny_status(&v));
            }
        };
        input["method"] = json!(method);
        input["path"] = json!(path);
        let callee = format!("{me} {method} {path}");
        let Some(snap) = self.state.loaded() else {
            let mut rec = record(&callee, &input, Value::Null);
            rec.error = Some("no charter is loaded yet".into());
            rec.rule = Some(crate::tools::RULE_NO_CHARTER.into());
            self.state.audit.write(rec);
            return Err(crate::tools::status_with_rule(
                tonic::Code::Unavailable,
                crate::tools::RULE_NO_CHARTER,
                "no charter is loaded yet",
            ));
        };
        let v = authz::authorize_service_call(
            &snap.charter,
            Some(&caller),
            inb.agent.as_deref(),
            &me,
            &method,
            &path,
        );
        if !v.allow {
            self.state
                .audit
                .write(record(&callee, &input, Value::Null).verdict(&v));
            return Err(deny_status(&v));
        }

        let url = format!("{}{}", self.state.app_base_url(&snap), path);
        let method = match reqwest::Method::from_bytes(method.as_bytes()) {
            Ok(m) => m,
            Err(e) => {
                let v = Verdict::deny(authz::RULE_PATH, format!("bad method {method:?}: {e}"));
                self.state
                    .audit
                    .write(record(&callee, &input, Value::Null).verdict(&v));
                return Err(deny_status(&v));
            }
        };
        let mut hreq = self
            .state
            .http
            .request(method, &url)
            .timeout(deadline::budget(inb.deadline, deadline::HTTP_TIMEOUT));
        // Identity and trace headers come from this sidecar only; a peer's copies are dropped.
        for (k, val) in &req.headers {
            if !is_reserved_header(k) {
                hreq = hreq.header(k, val);
            }
        }
        hreq = hreq
            .header("traceparent", inb.trace.traceparent())
            .header("x-attache-request-id", &inb.request_id)
            .header("x-attache-caller", &caller)
            .header("x-attache-agent", inb.agent.clone().unwrap_or_default());
        if !req.body.is_empty() {
            hreq = hreq.body(req.body.clone());
        }
        // The app may act on the request before the peer gives up; its record is owed either way.
        let pending = self.state.audit.on_cancel(
            vec![record(&callee, &input, Value::Null).verdict(&v)],
            started,
        );
        let sent = match hreq.send().await {
            Ok(resp) => Ok(crate::tools::to_service_response(resp).await),
            Err(e) => Err(e),
        };
        pending.disarm();
        match sent {
            Ok(sr) => {
                let out = json!({ "status": sr.status, "body": body_value(&sr.body) });
                self.state
                    .audit
                    .write(record(&callee, &input, out).verdict(&v));
                Ok(Response::new(sr))
            }
            Err(e) => {
                let mut rec = record(&callee, &input, Value::Null).verdict(&v);
                rec.error = Some(format!("app unreachable at {url}: {e}"));
                self.state.audit.write(rec);
                Err(crate::tools::status_with_rule(
                    tonic::Code::Unavailable,
                    crate::tools::RULE_APP_UNAVAILABLE,
                    &format!("{me} app unreachable: {e}"),
                ))
            }
        }
    }
}
