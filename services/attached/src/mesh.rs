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

use crate::pipeline::{self, Invocation};
use crate::state::AppState;

pub struct MeshService {
    state: Arc<AppState>,
}

pub async fn serve(
    state: Arc<AppState>,
    addr: SocketAddr,
) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let tls = state
        .tls
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("mesh needs TLS material"))?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let server = tonic::transport::Server::builder()
        .tls_config(crate::tls::server_config(tls))?
        .add_service(MeshServer::new(MeshService { state }));
    let task = tokio::spawn(async move {
        if let Err(e) = server.serve_with_incoming(incoming).await {
            tracing::error!(error = %e, "mesh server stopped");
        }
    });
    Ok((bound, task))
}

/// Caller identity from the client certificate's URI SAN, or a denial.
fn caller_identity<T>(req: &Request<T>) -> Result<String, Status> {
    let certs = req.peer_certs().ok_or_else(|| {
        deny_status(&Verdict::deny(
            "authz.identity.invalid",
            "no client certificate",
        ))
    })?;
    let leaf = certs.first().ok_or_else(|| {
        deny_status(&Verdict::deny(
            "authz.identity.invalid",
            "empty client certificate chain",
        ))
    })?;
    match attache_pki::spiffe_id_of(leaf) {
        Ok(Some(id)) => Ok(id.uri()),
        Ok(None) => Err(deny_status(&Verdict::deny(
            "authz.identity.invalid",
            "client certificate has no spiffe://attache/ URI SAN",
        ))),
        Err(e) => Err(deny_status(&Verdict::deny(
            "authz.identity.invalid",
            format!("client certificate unreadable: {e}"),
        ))),
    }
}

fn meta<T>(req: &Request<T>, key: &str) -> Option<String> {
    req.metadata()
        .get(key)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
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

#[tonic::async_trait]
impl Mesh for MeshService {
    async fn invoke_agent(
        &self,
        request: Request<InvokeAgentRequest>,
    ) -> Result<Response<InvokeAgentResponse>, Status> {
        let caller = caller_identity(&request)?;
        let caller_agent = meta(&request, "x-attache-agent");
        let traceparent = meta(&request, "traceparent");
        let request_id = meta(&request, "x-attache-request-id");
        let req = request.into_inner();
        let trace =
            TraceContext::from_traceparent(traceparent.as_deref().unwrap_or(&req.traceparent));
        let request_id = request_id
            .filter(|s| !s.is_empty())
            .or_else(|| (!req.request_id.is_empty()).then(|| req.request_id.clone()))
            .unwrap_or_else(attache_common::trace::new_request_id);
        let inv = Invocation {
            agent: req.agent,
            input: req.input,
            context_json: req.context_json,
            request_id,
            trace,
            caller,
            caller_agent: caller_agent
                .filter(|s| !s.is_empty())
                .or_else(|| (!req.caller_agent.is_empty()).then(|| req.caller_agent.clone())),
            depth: req.depth,
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
        let caller = caller_identity(&request)?;
        let agent = meta(&request, "x-attache-agent");
        let traceparent = meta(&request, "traceparent");
        let request_id = meta(&request, "x-attache-request-id");
        let req = request.into_inner();
        let trace =
            TraceContext::from_traceparent(traceparent.as_deref().unwrap_or(&req.traceparent));
        let request_id = request_id
            .filter(|s| !s.is_empty())
            .unwrap_or(req.request_id.clone());
        let agent = agent
            .filter(|s| !s.is_empty())
            .or_else(|| (!req.agent.is_empty()).then(|| req.agent.clone()));
        let me = self.state.charter.service.name.clone();
        let callee = format!("{me} {} {}", req.method, req.path);
        let input =
            json!({ "method": req.method, "path": req.path, "body": body_value(&req.body) });
        let record = |output: Value| {
            AuditRecord::new(
                Kind::ServiceCall,
                Direction::Inbound,
                &request_id,
                &trace,
                agent.as_deref(),
                &caller,
                agent.as_deref(),
                &callee,
                input.clone(),
                output,
            )
        };

        let v = authz::authorize_service_call(
            &self.state.charter,
            Some(&caller),
            agent.as_deref(),
            &me,
            &req.method,
            &req.path,
        );
        if !v.allow {
            self.state
                .audit
                .write(record(Value::Null).verdict(&v).latency(started));
            return Err(deny_status(&v));
        }

        let url = format!("{}{}", self.state.app_base_url(), req.path);
        let method = reqwest::Method::from_bytes(req.method.as_bytes())
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let mut hreq = self.state.http.request(method, &url);
        for (k, val) in &req.headers {
            if k.eq_ignore_ascii_case("host") || k.eq_ignore_ascii_case("content-length") {
                continue;
            }
            hreq = hreq.header(k, val);
        }
        hreq = hreq
            .header("traceparent", trace.traceparent())
            .header("x-attache-request-id", &request_id)
            .header("x-attache-caller", &caller)
            .header("x-attache-agent", agent.clone().unwrap_or_default());
        if !req.body.is_empty() {
            hreq = hreq.body(req.body.clone());
        }
        match hreq.send().await {
            Ok(resp) => {
                let sr = crate::tools::to_service_response(resp).await;
                let out = json!({ "status": sr.status, "body": body_value(&sr.body) });
                let mut rec = record(out).verdict(&v).latency(started);
                rec.rule = Some(v.rule.clone());
                self.state.audit.write(rec);
                Ok(Response::new(sr))
            }
            Err(e) => {
                let mut rec = record(Value::Null).verdict(&v).latency(started);
                rec.error = Some(format!("app unreachable at {url}: {e}"));
                self.state.audit.write(rec);
                Err(Status::unavailable(format!("{me} app unreachable: {e}")))
            }
        }
    }
}
