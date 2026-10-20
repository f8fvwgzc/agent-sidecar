//! `SidecarTools`: every tool call the runtime makes comes through here (CONTRACT.md §4.3).
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use attache_common::audit::{AuditRecord, Direction, Kind};
use attache_common::authz::{self, Verdict};
use attache_common::trace::TraceContext;
use attache_proto::sidecar_tools_server::{SidecarTools, SidecarToolsServer};
use attache_proto::{
    AuditEvent, Empty, InvokeAgentRequest, InvokeAgentResponse, ServiceRequest, ServiceResponse,
    ToolAgentRequest, ToolContext, ToolHttpRequest, ToolServiceRequest,
};
use serde_json::{Value, json};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{Request, Response, Status};

use crate::pipeline::{self, Invocation};
use crate::state::AppState;

pub struct ToolsService {
    state: Arc<AppState>,
}

pub async fn serve(
    state: Arc<AppState>,
    socket: PathBuf,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let _ = std::fs::remove_file(&socket);
    let listener = tokio::net::UnixListener::bind(&socket)?;
    let incoming = UnixListenerStream::new(listener);
    let svc = SidecarToolsServer::new(ToolsService { state });
    Ok(tokio::spawn(async move {
        if let Err(e) = tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(incoming)
            .await
        {
            tracing::error!(error = %e, "tools server stopped");
        }
    }))
}

fn ctx_of(ctx: &Option<ToolContext>) -> Result<(ToolContext, TraceContext), Status> {
    let c = ctx
        .clone()
        .ok_or_else(|| Status::invalid_argument("ctx is required"))?;
    if c.agent.is_empty() || c.tool.is_empty() {
        return Err(Status::invalid_argument(
            "ctx.agent and ctx.tool are required",
        ));
    }
    let trace = TraceContext {
        trace_id: c.trace_id.clone(),
        span_id: attache_common::trace::TraceContext::new_root().span_id,
        parent_span_id: (!c.span_id.is_empty()).then(|| c.span_id.clone()),
    };
    Ok((c, trace))
}

fn denied_status(v: &Verdict) -> Status {
    let mut st = Status::permission_denied(v.reason.clone());
    if let Ok(val) = v.rule.parse() {
        st.metadata_mut().insert("x-attache-rule", val);
    }
    st
}

fn rule_from_status(st: &Status) -> String {
    st.metadata()
        .get("x-attache-rule")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("mesh.error")
        .to_string()
}

/// The callee writes "<rule>: <reason>" in the status message; the rule travels in metadata already.
fn reason_from_status(st: &Status) -> String {
    let rule = rule_from_status(st);
    let msg = st.message();
    msg.strip_prefix(&format!("{rule}: "))
        .unwrap_or(msg)
        .to_string()
}

impl ToolsService {
    /// guardrails.allowed_tools / allowed_services for a tool call.
    fn check_tool(&self, agent: &str, tool: &str, service: Option<&str>) -> Verdict {
        let Some(spec) = self.state.charter.agent(agent) else {
            return Verdict::deny(
                pipeline::RULE_UNKNOWN_AGENT,
                format!("agent {agent:?} is not declared"),
            );
        };
        if !self
            .state
            .charter
            .allowed_tools(spec)
            .iter()
            .any(|t| t == tool)
        {
            return Verdict::deny(
                "guardrail.allowed_tools",
                format!("agent {agent} may not use tool {tool}"),
            );
        }
        if let Some(s) = service
            && !self
                .state
                .charter
                .allowed_services(spec)
                .iter()
                .any(|x| x == s)
        {
            return Verdict::deny(
                "guardrail.allowed_services",
                format!("agent {agent} may not call service {s}"),
            );
        }
        Verdict::allow("guardrail.allowed_tools")
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        kind: Kind,
        dir: Direction,
        c: &ToolContext,
        trace: &TraceContext,
        callee: &str,
        input: Value,
        output: Value,
    ) -> AuditRecord {
        AuditRecord::new(
            kind,
            dir,
            &c.request_id,
            trace,
            Some(&c.agent),
            "local",
            Some(&c.agent),
            callee,
            input,
            output,
        )
    }

    async fn call_local_app(
        &self,
        method: &str,
        path: &str,
        headers: &std::collections::HashMap<String, String>,
        body: &[u8],
    ) -> Result<ServiceResponse, String> {
        let url = format!("{}{}", self.state.app_base_url(), path);
        let m = reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?;
        let mut req = self.state.http.request(m, &url);
        for (k, v) in headers {
            if k.eq_ignore_ascii_case("host") || k.eq_ignore_ascii_case("content-length") {
                continue;
            }
            req = req.header(k, v);
        }
        if !body.is_empty() {
            req = req.body(body.to_vec());
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("app unreachable at {url}: {e}"))?;
        Ok(to_service_response(resp).await)
    }
}

pub async fn to_service_response(resp: reqwest::Response) -> ServiceResponse {
    let status = resp.status().as_u16() as u32;
    let headers = resp
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_string(), v.to_string()))
        })
        .collect();
    let body = resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
    ServiceResponse {
        status,
        headers,
        body,
    }
}

fn body_value(body: &[u8]) -> Value {
    if body.is_empty() {
        return Value::Null;
    }
    serde_json::from_slice(body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(body).into_owned()))
}

#[tonic::async_trait]
impl SidecarTools for ToolsService {
    async fn invoke_service(
        &self,
        request: Request<ToolServiceRequest>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let started = Instant::now();
        let req = request.into_inner();
        let (c, trace) = ctx_of(&req.ctx)?;
        let target = req.service.clone();
        let callee = format!("{} {} {}", target, req.method, req.path);
        let input =
            json!({ "method": req.method, "path": req.path, "body": body_value(&req.body) });
        let tool_rec = |v: &Verdict, output: Value| {
            self.record(
                Kind::ToolCall,
                Direction::Internal,
                &c,
                &trace,
                &c.tool,
                input.clone(),
                output,
            )
            .verdict(v)
            .latency(started)
        };

        let mut v = self.check_tool(&c.agent, &c.tool, Some(&target));
        if v.allow {
            v = authz::authorize_service_call(
                &self.state.charter,
                Some(&self.state.self_identity),
                Some(&c.agent),
                &target,
                &req.method,
                &req.path,
            );
        }
        if !v.allow {
            self.state.audit.write(tool_rec(&v, Value::Null));
            return Err(denied_status(&v));
        }

        let is_self = target == self.state.charter.service.name;
        let result: Result<ServiceResponse, Status> = if is_self {
            self.call_local_app(&req.method, &req.path, &req.headers, &req.body)
                .await
                .map_err(Status::unavailable)
        } else {
            let mut client = self
                .state
                .mesh_client(&target)
                .map_err(|e| Status::unavailable(e.to_string()))?;
            let mut greq = Request::new(ServiceRequest {
                method: req.method.clone(),
                path: req.path.clone(),
                headers: req.headers.clone(),
                body: req.body.clone(),
                request_id: c.request_id.clone(),
                traceparent: trace.traceparent(),
                agent: c.agent.clone(),
            });
            let md = greq.metadata_mut();
            md.insert("traceparent", trace.traceparent().parse().unwrap());
            md.insert(
                "x-attache-request-id",
                c.request_id
                    .parse()
                    .map_err(|_| Status::invalid_argument("bad request_id"))?,
            );
            md.insert(
                "x-attache-agent",
                c.agent
                    .parse()
                    .map_err(|_| Status::invalid_argument("bad agent"))?,
            );
            client.invoke_service(greq).await.map(|r| r.into_inner())
        };

        let dir = if is_self {
            Direction::Internal
        } else {
            Direction::Outbound
        };
        match result {
            Ok(resp) => {
                let out = json!({ "status": resp.status, "body": body_value(&resp.body) });
                let ok = Verdict::allow(v.rule.clone());
                self.state.audit.write(tool_rec(&ok, out.clone()));
                let mut rec = self
                    .record(
                        Kind::ServiceCall,
                        dir,
                        &c,
                        &trace.child(),
                        &callee,
                        input.clone(),
                        out,
                    )
                    .latency(started);
                rec.decision = "allow".into();
                self.state.audit.write(rec);
                Ok(Response::new(resp))
            }
            Err(st) => {
                let remote_rule = rule_from_status(&st);
                let denied = st.code() == tonic::Code::PermissionDenied;
                let rv = if denied {
                    Verdict::deny(
                        remote_rule.clone(),
                        format!("denied by {target}: {}", reason_from_status(&st)),
                    )
                } else {
                    Verdict::allow(v.rule.clone())
                };
                let mut rec = tool_rec(&rv, Value::Null);
                if !denied {
                    rec.error = Some(format!("{}: {}", st.code(), st.message()));
                }
                self.state.audit.write(rec);
                let mut rec = self
                    .record(
                        Kind::ServiceCall,
                        dir,
                        &c,
                        &trace.child(),
                        &callee,
                        input,
                        Value::Null,
                    )
                    .verdict(&rv)
                    .latency(started);
                if !denied {
                    rec.error = Some(format!("{}: {}", st.code(), st.message()));
                }
                self.state.audit.write(rec);
                let mut out = Status::new(
                    st.code(),
                    if denied {
                        rv.reason.clone()
                    } else {
                        st.message().to_string()
                    },
                );
                if let Ok(val) = remote_rule.parse() {
                    out.metadata_mut().insert("x-attache-rule", val);
                }
                Err(out)
            }
        }
    }

    async fn invoke_agent(
        &self,
        request: Request<ToolAgentRequest>,
    ) -> Result<Response<InvokeAgentResponse>, Status> {
        let started = Instant::now();
        let req = request.into_inner();
        let (c, trace) = ctx_of(&req.ctx)?;
        let remote =
            !req.target_service.is_empty() && req.target_service != self.state.charter.service.name;
        let callee = if remote {
            format!("{}/{}", req.target_service, req.target_agent)
        } else {
            req.target_agent.clone()
        };
        let input = Value::String(req.input.clone());
        let tool_rec = |v: &Verdict, output: Value| {
            self.record(
                Kind::ToolCall,
                Direction::Internal,
                &c,
                &trace,
                &c.tool,
                input.clone(),
                output,
            )
            .verdict(v)
            .latency(started)
        };

        let v = self.check_tool(
            &c.agent,
            &c.tool,
            remote.then_some(req.target_service.as_str()),
        );
        if !v.allow {
            self.state.audit.write(tool_rec(&v, Value::Null));
            return Err(denied_status(&v));
        }

        let resp = if remote {
            let mut client = self
                .state
                .mesh_client(&req.target_service)
                .map_err(|e| Status::unavailable(e.to_string()))?;
            let mut greq = Request::new(InvokeAgentRequest {
                agent: req.target_agent.clone(),
                input: req.input.clone(),
                context_json: String::new(),
                request_id: c.request_id.clone(),
                traceparent: trace.traceparent(),
                caller_agent: c.agent.clone(),
                depth: c.depth + 1,
            });
            let md = greq.metadata_mut();
            md.insert("traceparent", trace.traceparent().parse().unwrap());
            md.insert(
                "x-attache-request-id",
                c.request_id
                    .parse()
                    .map_err(|_| Status::invalid_argument("bad request_id"))?,
            );
            md.insert(
                "x-attache-agent",
                c.agent
                    .parse()
                    .map_err(|_| Status::invalid_argument("bad agent"))?,
            );
            match client.invoke_agent(greq).await {
                Ok(r) => r.into_inner(),
                Err(st) => {
                    // The callee answers denials as a status; turn them into an envelope so the model sees the reason.
                    InvokeAgentResponse {
                        status: if st.code() == tonic::Code::PermissionDenied
                            || st.code() == tonic::Code::ResourceExhausted
                        {
                            "denied".into()
                        } else {
                            "error".into()
                        },
                        request_id: c.request_id.clone(),
                        trace_id: trace.trace_id.clone(),
                        agent: req.target_agent.clone(),
                        output: String::new(),
                        usage: None,
                        steps: vec![],
                        rule: rule_from_status(&st),
                        reason: reason_from_status(&st),
                    }
                }
            }
        } else {
            pipeline::invoke(
                &self.state,
                Invocation {
                    agent: req.target_agent.clone(),
                    input: req.input.clone(),
                    context_json: String::new(),
                    request_id: c.request_id.clone(),
                    trace: trace.child(),
                    caller: "local".into(),
                    caller_agent: Some(c.agent.clone()),
                    depth: c.depth + 1,
                },
            )
            .await
        };

        let verdict = if resp.status == "ok" {
            Verdict::allow(v.rule.clone())
        } else {
            Verdict::deny(resp.rule.clone(), resp.reason.clone())
        };
        let output = if resp.status == "ok" {
            Value::String(resp.output.clone())
        } else {
            Value::Null
        };
        self.state.audit.write(tool_rec(&verdict, output.clone()));
        let dir = if remote {
            Direction::Outbound
        } else {
            Direction::Internal
        };
        let mut rec = self
            .record(
                Kind::AgentCall,
                dir,
                &c,
                &trace.child(),
                &callee,
                input,
                output,
            )
            .latency(started);
        if resp.status == "ok" {
            rec.decision = "allow".into();
            if let Some(u) = &resp.usage {
                rec.tokens = Some(attache_common::audit::Tokens {
                    input: u.input_tokens,
                    output: u.output_tokens,
                });
                rec.cost_usd = Some(u.cost_usd);
            }
        } else {
            rec = rec.verdict(&verdict);
            if resp.status == "error" {
                rec.error = Some(resp.reason.clone());
            }
        }
        self.state.audit.write(rec);
        Ok(Response::new(resp))
    }

    async fn invoke_http(
        &self,
        request: Request<ToolHttpRequest>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let started = Instant::now();
        let req = request.into_inner();
        let (c, trace) = ctx_of(&req.ctx)?;
        let input = json!({ "method": req.method, "url": req.url, "body": body_value(&req.body) });
        let tool_rec = |v: &Verdict, output: Value| {
            self.record(
                Kind::ToolCall,
                Direction::Internal,
                &c,
                &trace,
                &c.tool,
                input.clone(),
                output,
            )
            .verdict(v)
            .latency(started)
        };
        let v = self.check_tool(&c.agent, &c.tool, None);
        if !v.allow {
            self.state.audit.write(tool_rec(&v, Value::Null));
            return Err(denied_status(&v));
        }
        let m = reqwest::Method::from_bytes(req.method.as_bytes())
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let mut hreq = self.state.http.request(m, &req.url);
        for (k, val) in &req.headers {
            hreq = hreq.header(k, val);
        }
        if !req.body.is_empty() {
            hreq = hreq.body(req.body.clone());
        }
        let callee = format!("{} {}", req.method, req.url);
        match hreq.send().await {
            Ok(resp) => {
                let sr = to_service_response(resp).await;
                let out = json!({ "status": sr.status, "body": body_value(&sr.body) });
                self.state.audit.write(tool_rec(&v, out.clone()));
                let mut rec = self
                    .record(
                        Kind::HttpCall,
                        Direction::Outbound,
                        &c,
                        &trace.child(),
                        &callee,
                        input,
                        out,
                    )
                    .latency(started);
                rec.decision = "allow".into();
                self.state.audit.write(rec);
                Ok(Response::new(sr))
            }
            Err(e) => {
                let mut rec = tool_rec(&v, Value::Null);
                rec.error = Some(e.to_string());
                self.state.audit.write(rec);
                let mut rec = self
                    .record(
                        Kind::HttpCall,
                        Direction::Outbound,
                        &c,
                        &trace.child(),
                        &callee,
                        input,
                        Value::Null,
                    )
                    .latency(started);
                rec.error = Some(e.to_string());
                self.state.audit.write(rec);
                Err(Status::unavailable(e.to_string()))
            }
        }
    }

    async fn report_event(&self, request: Request<AuditEvent>) -> Result<Response<Empty>, Status> {
        let ev = request.into_inner();
        let mut rec: AuditRecord = serde_json::from_str(&ev.json)
            .map_err(|e| Status::invalid_argument(format!("audit record: {e}")))?;
        if rec.ts.is_empty() {
            rec.ts = attache_common::audit::now_rfc3339();
        }
        if rec.kind == Kind::ModelCall
            && let (Some(agent), Some(cost)) = (&rec.agent, rec.cost_usd)
            && cost > 0.0
        {
            self.state.budgets.add_cost(agent, cost);
        }
        self.state.audit.write(rec);
        Ok(Response::new(Empty {}))
    }
}
