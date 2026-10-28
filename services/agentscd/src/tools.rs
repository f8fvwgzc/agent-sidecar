//! `SidecarTools`: every tool call the runtime makes comes through here (CONTRACT.md §4.3).
//!
//! The runtime is in the pod but it is driven by a model, so nothing it sends is taken on trust:
//! the call must belong to an Execute of its agent that is in flight (its request id and agent
//! name a run the sidecar started, runs.rs; the run's trace and depth replace the runtime's), it
//! must match a tool the agent declared and may use, the path is canonicalised before
//! authz, and every outcome — allowed, denied, failed or cancelled — leaves exactly one `tool_call`
//! record plus, once something was actually attempted, one `service_call` / `agent_call` / `http_call`.
//! `ReportEvent` takes only what design §6.5 allows, for runs this sidecar knows.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use agentsc_charter::{AgentSpec, LOAD_SKILL_TOOL, ToolEffect, ToolSpec, ToolType};
use agentsc_common::audit::{AuditRecord, AuditRecordView, Direction, Kind, OnCancel, Tokens};
use agentsc_common::authz::{self, Verdict};
use agentsc_common::guardrails::INPUT_DENY;
use agentsc_common::trace::TraceContext;
use agentsc_proto::sidecar_tools_server::{SidecarTools, SidecarToolsServer};
use agentsc_proto::{
    AuditEvent, Empty, InvokeAgentRequest, InvokeAgentResponse, LessonRequest, LessonResponse,
    ServiceRequest, ServiceResponse, ToolAgentRequest, ToolContext, ToolHttpRequest,
    ToolServiceRequest,
};
use serde_json::{Value, json};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::metadata::MetadataValue;
use tonic::{Code, Request, Response, Status};

use crate::deadline;
use crate::loaded::Loaded;
use crate::outbox;
use crate::pipeline::{self, Invocation};
use crate::state::AppState;

pub const RULE_TOOL_SPEC: &str = "guardrail.tool_spec";
/// A tool call that names no Execute of its agent in flight.
pub const RULE_UNBOUND: &str = "tool.unbound";
pub const RULE_MESH_UNAVAILABLE: &str = "mesh.unavailable";
pub const RULE_APP_UNAVAILABLE: &str = "app.unavailable";
pub const RULE_HTTP_ERROR: &str = "http.error";
/// A response body larger than `--max-response-bytes`.
pub const RULE_RESPONSE_TOO_LARGE: &str = "http.response_too_large";
/// A record or lesson the runtime may not send (design §6.5).
pub const RULE_REPORT_REJECTED: &str = "runtime.report_rejected";
/// On every `ReportEvent` answer once the agent's daily cost budget is spent (design §6.5).
pub const RULE_COST_BUDGET: &str = "budget.max_cost_usd_per_day";
/// The only model whose calls the runtime reports itself: it runs in the runtime and costs nothing.
pub const MOCK_MODEL: &str = "mock";
/// No charter is loaded yet (managed mode, before the control plane sent one).
pub const RULE_NO_CHARTER: &str = "config.no_charter";
/// Upper bound for a message the runtime sends us (tool bodies are small; prompts never come here).
const MAX_DECODE: usize = 16 * 1024 * 1024;

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
    let svc = SidecarToolsServer::new(ToolsService { state }).max_decoding_message_size(MAX_DECODE);
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

fn valid_trace_id(trace_id: &str) -> bool {
    TraceContext::parse(&format!("00-{trace_id}-00f067aa0ba902b7-01")).is_some()
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
    let trace_id = if valid_trace_id(&c.trace_id) {
        c.trace_id.clone()
    } else {
        TraceContext::new_root().trace_id
    };
    let trace = TraceContext {
        trace_id,
        span_id: TraceContext::new_root().span_id,
        parent_span_id: (!c.span_id.is_empty()).then(|| c.span_id.clone()),
    };
    Ok((c, trace))
}

/// A status whose message is the reason and whose `x-agentsc-rule` metadata is the rule.
pub fn status_with_rule(code: Code, rule: &str, reason: &str) -> Status {
    let mut st = Status::new(code, reason.to_string());
    if let Ok(val) = rule.parse() {
        st.metadata_mut().insert("x-agentsc-rule", val);
    }
    st
}

fn denied_status(v: &Verdict) -> Status {
    let code = if v.rule.starts_with("budget.") {
        Code::ResourceExhausted
    } else {
        Code::PermissionDenied
    };
    status_with_rule(code, &v.rule, &v.reason)
}

fn rule_from_status(st: &Status, fallback: &str) -> String {
    st.metadata()
        .get("x-agentsc-rule")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(fallback)
        .to_string()
}

/// The callee writes "<rule>: <reason>" in the status message; the rule travels in metadata already.
fn reason_from_status(st: &Status, rule: &str) -> String {
    let msg = st.message();
    msg.strip_prefix(&format!("{rule}: "))
        .unwrap_or(msg)
        .to_string()
}

fn is_denial(code: Code) -> bool {
    matches!(code, Code::PermissionDenied | Code::ResourceExhausted)
}

fn body_value(body: &[u8]) -> Value {
    if body.is_empty() {
        return Value::Null;
    }
    serde_json::from_slice(body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(body).into_owned()))
}

/// A response body that could not be read whole: too large ([`RULE_RESPONSE_TOO_LARGE`]), or the
/// connection failed mid-body (the caller's rule).
#[derive(Debug)]
pub struct BodyError {
    pub rule: &'static str,
    pub reason: String,
}

/// The response as a `ServiceResponse`, its body read chunk by chunk and refused past `max`
/// bytes (`--max-response-bytes`): one large answer from the app, a peer or an http tool's origin
/// must not exhaust the sidecar's memory. A body that breaks off is an error (`read_rule`), not
/// a short answer.
pub async fn to_service_response(
    mut resp: reqwest::Response,
    max: usize,
    read_rule: &'static str,
) -> Result<ServiceResponse, BodyError> {
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
    let too_large = |what: String| BodyError {
        rule: RULE_RESPONSE_TOO_LARGE,
        reason: format!("the response body is {what}, more than the {max} bytes the sidecar reads"),
    };
    if let Some(len) = resp.content_length()
        && len > max as u64
    {
        return Err(too_large(format!("{len} bytes")));
    }
    let mut body = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > max {
                    return Err(too_large("longer".into()));
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => {
                return Err(BodyError {
                    rule: read_rule,
                    reason: format!("the response body broke off: {e}"),
                });
            }
        }
    }
    Ok(ServiceResponse {
        status,
        headers,
        body,
    })
}

/// Headers the sidecar owns. Values for them from the runtime or a peer are dropped, never forwarded.
pub fn is_reserved_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "host"
        || n == "content-length"
        || n == "traceparent"
        || n == "tracestate"
        || n.starts_with("x-agentsc-")
}

/// Does the canonical `path` fit the tool's declared path template? A runtime that sends a path
/// the template does not produce (`/orders` for `/orders/{id}`) is not making that tool's call.
fn fits_template(template: Option<&str>, path: &str) -> bool {
    template
        .and_then(|t| agentsc_charter::PathTemplate::parse(t).ok())
        .is_some_and(|t| t.matches(path))
}

fn no_charter() -> Status {
    status_with_rule(
        Code::Unavailable,
        RULE_NO_CHARTER,
        "no charter is loaded yet",
    )
}

/// Refuse what the runtime reported (design §6.5): an `authz` record with rule
/// `runtime.report_rejected`, then `INVALID_ARGUMENT`. `input` summarizes what was refused (the
/// refused record itself is not written: the runtime may not author records).
pub(crate) fn reject_report(
    state: &AppState,
    request_id: &str,
    trace_id: &str,
    agent: Option<&str>,
    input: Value,
    reason: String,
) -> Status {
    let trace = if valid_trace_id(trace_id) {
        TraceContext {
            trace_id: trace_id.to_string(),
            span_id: TraceContext::new_root().span_id,
            parent_span_id: None,
        }
    } else {
        TraceContext::new_root()
    };
    let v = Verdict::deny(RULE_REPORT_REJECTED, reason.clone());
    let rec = AuditRecord::new(
        Kind::Authz,
        Direction::Internal,
        request_id,
        &trace,
        agent,
        agentsc_charter::LOCAL_IDENTITY,
        None,
        "runtime",
        input,
        Value::Null,
    )
    .verdict(&v);
    state.audit.write(rec);
    tracing::warn!(%reason, request_id, "runtime report rejected");
    status_with_rule(Code::InvalidArgument, RULE_REPORT_REJECTED, &reason)
}

/// One tool call in flight: its context, its span and the records it owes the audit log.
struct Call<'a> {
    svc: &'a ToolsService,
    c: ToolContext,
    trace: TraceContext,
    started: Instant,
    /// The runtime's deadline for this call (its `grpc-timeout`); the next hop gets what is left.
    deadline: Option<Instant>,
    /// Set when the callee's content guardrail denied the input: records keep its hash, not its text.
    withhold: Option<String>,
}

impl<'a> Call<'a> {
    fn record(
        &self,
        kind: Kind,
        dir: Direction,
        trace: &TraceContext,
        callee: &str,
        input: &Value,
        output: Value,
    ) -> AuditRecord {
        let rec = AuditRecord::new(
            kind,
            dir,
            &self.c.request_id,
            trace,
            Some(&self.c.agent),
            "local",
            Some(&self.c.agent),
            callee,
            input.clone(),
            output,
        )
        .latency(self.started);
        match &self.withhold {
            Some(rule) => rec.withhold_input(rule),
            None => rec,
        }
    }

    /// The `tool_call` record. `error` set ⇒ decision allow (policy let it through, it failed).
    fn tool(&self, input: &Value, output: Value, v: &Verdict, error: Option<String>) {
        let mut rec = self
            .record(
                Kind::ToolCall,
                Direction::Internal,
                &self.trace,
                &self.c.tool,
                input,
                output,
            )
            .verdict(v);
        rec.error = error;
        self.svc.state.audit.write(rec);
    }

    /// The record of what was actually attempted (`service_call` / `agent_call` / `http_call`).
    #[allow(clippy::too_many_arguments)]
    fn attempt(
        &self,
        kind: Kind,
        dir: Direction,
        child: &TraceContext,
        callee: &str,
        input: &Value,
        output: Value,
        v: &Verdict,
        error: Option<String>,
        tokens: Option<(Tokens, f64)>,
    ) {
        let mut rec = self
            .record(kind, dir, child, callee, input, output)
            .verdict(v);
        rec.error = error;
        if let Some((t, cost)) = tokens {
            rec.tokens = Some(t);
            rec.cost_usd = Some(cost);
        }
        self.svc.state.audit.write(rec);
    }

    /// The attempt begins: a span start for the timeline (design §6.4, its span = the attempt
    /// record's), then the `tool_call` and attempt records owed while the call is awaited — if the
    /// runtime drops it (gone, or its deadline passed) they are written as cancelled; the target
    /// may have acted. The span start leaves the pod outside the audit writer, so its callee
    /// (an http tool's URL with its query) is redacted like the records' first.
    fn begin(
        &self,
        kind: Kind,
        dir: Direction,
        child: &TraceContext,
        callee: &str,
        input: &Value,
        v: &Verdict,
    ) -> OnCancel<'a> {
        let audit = &self.svc.state.audit;
        audit.remember(&self.c.request_id, "input", input);
        self.svc.state.outbox.span_start(outbox::span(
            kind.as_str(),
            &self.c.request_id,
            child,
            &self.c.agent,
            "local",
            Some(&self.c.agent),
            &audit.redact_text(&self.c.request_id, callee),
            dir,
        ));
        let tool = self
            .record(
                Kind::ToolCall,
                Direction::Internal,
                &self.trace,
                &self.c.tool,
                input,
                Value::Null,
            )
            .verdict(v);
        let attempt = self
            .record(kind, dir, child, callee, input, Value::Null)
            .verdict(v);
        self.svc
            .state
            .audit
            .on_cancel(vec![tool, attempt], self.started)
    }

    /// The call must belong to an Execute of its agent in flight (runs.rs): a runtime cannot make
    /// up a request id (a fresh, untainted one, say), act for another agent, or keep calling after
    /// its run returned. The run's trace and agent-call depth replace what the runtime sent.
    fn bind(&mut self) -> Result<(), Verdict> {
        let c = &self.c;
        match self.svc.state.runs.lookup(&c.request_id, &c.agent) {
            Some(run) if run.in_flight => {
                self.c.depth = run.depth;
                if !run.trace_id.is_empty() {
                    self.trace.trace_id = run.trace_id.clone();
                    self.c.trace_id = run.trace_id;
                }
                Ok(())
            }
            Some(_) => Err(Verdict::deny(
                RULE_UNBOUND,
                format!(
                    "the Execute of {} for request {:?} has returned; its tools are closed",
                    c.agent, c.request_id
                ),
            )),
            None => Err(Verdict::deny(
                RULE_UNBOUND,
                format!(
                    "no Execute of {} for request {:?} is in flight",
                    c.agent, c.request_id
                ),
            )),
        }
    }

    /// Deny before anything was attempted: one `tool_call` record, then the status for the runtime.
    fn deny(&self, input: &Value, v: Verdict) -> Status {
        self.tool(input, Value::Null, &v, None);
        denied_status(&v)
    }

    /// The taint rules (taint.rs): deny the call, or in audit mode record what would be denied.
    fn taint_gate(&self, spec: &AgentSpec, tool: &ToolSpec, input: &Value) -> Result<(), Status> {
        let Some(v) = self.svc.state.taint.check(spec, tool, &self.c.request_id) else {
            return Ok(());
        };
        if !v.allow {
            return Err(self.deny(input, v));
        }
        let rec = self
            .record(
                Kind::Guardrail,
                Direction::Internal,
                &self.trace,
                &self.c.tool,
                input,
                Value::Null,
            )
            .verdict(&v);
        self.svc.state.audit.write(rec);
        Ok(())
    }

    /// A quarantined agent's run calls nothing more (CONTRACT.md §5.3): its runs in flight are
    /// refused at their next tool call.
    fn quarantine_gate(&self, input: &Value) -> Result<(), Status> {
        match self.svc.state.quarantine_verdict(&self.c.agent) {
            Some(v) => Err(self.deny(input, v)),
            None => Ok(()),
        }
    }

    /// A tool with `approval` waits for a person's decision (approvals.rs, CONTRACT.md §5.4):
    /// approved, the call goes on after an `authz` record (`approval.granted`); denied, expired
    /// or with no control plane to ask, it is refused like any other denial.
    async fn approval_gate(&self, tool: &ToolSpec, input: &Value) -> Result<(), Status> {
        use crate::approvals::{RULE_DENIED, RULE_EXPIRED, RULE_GRANTED, RULE_UNAVAILABLE};
        let Some(a) = &tool.approval else {
            return Ok(());
        };
        let state = &self.svc.state;
        if !state.managed {
            return Err(self.deny(
                input,
                Verdict::deny(
                    RULE_UNAVAILABLE,
                    format!(
                        "{} needs an approval, and this sidecar has no control plane to ask",
                        tool.name
                    ),
                ),
            ));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let rx = state.approvals.ask(agentsc_proto::ApprovalRequest {
            id: id.clone(),
            agent: self.c.agent.clone(),
            tool: tool.name.clone(),
            request_id: self.c.request_id.clone(),
            trace_id: self.trace.trace_id.clone(),
            args_sha256: agentsc_common::audit::sha256_hex(&agentsc_common::audit::payload_bytes(
                input,
            )),
            timeout_s: a.timeout_s,
            requested_at: agentsc_common::audit::now_rfc3339(),
        });
        let wait = deadline::budget(
            self.deadline,
            std::time::Duration::from_secs(u64::from(a.timeout_s)),
        );
        let decided = tokio::time::timeout(wait, rx).await;
        let who = |d: &agentsc_proto::ApprovalDecision| {
            if d.decided_by.is_empty() {
                "the control plane".to_string()
            } else {
                d.decided_by.clone()
            }
        };
        match decided {
            Ok(Ok(d)) if d.decision == "approved" => {
                // a quarantine that arrived while the call waited wins (nexc-engine withholds it too)
                self.quarantine_gate(input)?;
                let reason = if d.reason.trim().is_empty() {
                    format!("{} approved by {}", tool.name, who(&d))
                } else {
                    format!("{} approved by {}: {}", tool.name, who(&d), d.reason.trim())
                };
                let v = Verdict {
                    allow: true,
                    rule: RULE_GRANTED.into(),
                    reason,
                };
                let rec = self
                    .record(
                        Kind::Authz,
                        Direction::Internal,
                        &self.trace,
                        &self.c.tool,
                        input,
                        Value::Null,
                    )
                    .verdict(&v);
                state.audit.write(rec);
                Ok(())
            }
            Ok(Ok(d)) if d.decision == "denied" => Err(self.deny(
                input,
                Verdict::deny(
                    RULE_DENIED,
                    format!(
                        "{} was denied by {}: {}",
                        tool.name,
                        who(&d),
                        d.reason.trim()
                    ),
                ),
            )),
            _ => {
                state.approvals.forget(&id);
                Err(self.deny(
                    input,
                    Verdict::deny(
                        RULE_EXPIRED,
                        format!("{}: nobody decided before the approval expired", tool.name),
                    ),
                ))
            }
        }
    }

    /// The call returned data to the run: the run now carries the tool's label.
    fn taint_mark(&self, tool: &ToolSpec) {
        self.svc
            .state
            .taint
            .add(&self.c.request_id, tool.effective_label(), &tool.name);
    }
}

impl ToolsService {
    /// The declared tool, if this agent may use it (guardrails.allowed_tools).
    fn tool_spec<'l>(
        &self,
        snap: &'l Loaded,
        agent: &str,
        tool: &str,
    ) -> Result<(&'l AgentSpec, &'l ToolSpec), Verdict> {
        let charter = &snap.charter;
        let Some(spec) = charter.agent(agent) else {
            return Err(Verdict::deny(
                pipeline::RULE_UNKNOWN_AGENT,
                format!("agent {agent:?} is not declared"),
            ));
        };
        if !charter.allowed_tools(spec).iter().any(|t| t == tool) {
            return Err(Verdict::deny(
                "guardrail.allowed_tools",
                format!("agent {agent} may not use tool {tool}"),
            ));
        }
        match spec.tools.iter().find(|t| t.name == tool) {
            Some(t) => Ok((spec, t)),
            None => Err(Verdict::deny(
                "guardrail.allowed_tools",
                format!("agent {agent} declares no tool {tool}"),
            )),
        }
    }

    fn check_service(&self, snap: &Loaded, spec: &AgentSpec, service: &str) -> Verdict {
        if snap
            .charter
            .allowed_services(spec)
            .iter()
            .any(|x| x == service)
        {
            Verdict::allow("guardrail.allowed_services")
        } else {
            Verdict::deny(
                "guardrail.allowed_services",
                format!("agent {} may not call service {service}", spec.name),
            )
        }
    }

    fn is_self(&self, service: Option<&str>) -> bool {
        match service {
            None => true,
            Some(s) => s.is_empty() || s == self.state.service,
        }
    }

    fn sidecar_headers(
        &self,
        c: &ToolContext,
        child: &TraceContext,
    ) -> Vec<(&'static str, String)> {
        vec![
            ("traceparent", child.traceparent()),
            ("x-agentsc-request-id", c.request_id.clone()),
            ("x-agentsc-caller", "local".to_string()),
            ("x-agentsc-agent", c.agent.clone()),
        ]
    }

    #[allow(clippy::too_many_arguments)]
    async fn call_local_app(
        &self,
        snap: &Loaded,
        c: &ToolContext,
        child: &TraceContext,
        deadline: Option<Instant>,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> Result<ServiceResponse, Status> {
        let unavailable = |e: String| status_with_rule(Code::Unavailable, RULE_APP_UNAVAILABLE, &e);
        let url = format!("{}{}", self.state.app_base_url(snap), path);
        let m = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| unavailable(e.to_string()))?;
        let mut req = self
            .state
            .http
            .request(m, &url)
            .timeout(deadline::budget(deadline, deadline::HTTP_TIMEOUT));
        for (k, v) in headers {
            if !is_reserved_header(k) {
                req = req.header(k, v);
            }
        }
        for (k, v) in self.sidecar_headers(c, child) {
            req = req.header(k, v);
        }
        if !body.is_empty() {
            req = req.body(body.to_vec());
        }
        let resp = req
            .send()
            .await
            .map_err(|e| unavailable(format!("app unreachable at {url}: {e}")))?;
        to_service_response(
            resp,
            self.state.config.max_response_bytes,
            RULE_APP_UNAVAILABLE,
        )
        .await
        .map_err(|e| status_with_rule(Code::Unavailable, e.rule, &e.reason))
    }

    fn mesh_request<T>(
        &self,
        c: &ToolContext,
        child: &TraceContext,
        deadline: Option<Instant>,
        msg: T,
    ) -> Request<T> {
        let mut req = Request::new(msg);
        req.set_timeout(deadline::budget(deadline, deadline::RUN_TIMEOUT));
        let md = req.metadata_mut();
        if let Ok(v) = child.traceparent().parse() {
            md.insert("traceparent", v);
        }
        if let Ok(v) = c.request_id.parse() {
            md.insert("x-agentsc-request-id", v);
        }
        if let Ok(v) = c.agent.parse() {
            md.insert("x-agentsc-agent", v);
        }
        let taint = self.state.taint.header(&c.request_id);
        if !taint.is_empty()
            && let Ok(v) = taint.parse()
        {
            md.insert(crate::taint::HEADER, v);
        }
        req
    }
}

#[tonic::async_trait]
impl SidecarTools for ToolsService {
    async fn invoke_service(
        &self,
        request: Request<ToolServiceRequest>,
    ) -> Result<Response<ServiceResponse>, Status> {
        self.state.audit.gate_tool(request.get_ref().ctx.as_ref())?;
        let deadline = deadline::from_metadata(request.metadata());
        let req = request.into_inner();
        let (c, trace) = ctx_of(&req.ctx)?;
        let snap = self.state.loaded().ok_or_else(no_charter)?;
        let mut call = Call {
            svc: self,
            c,
            trace,
            started: Instant::now(),
            deadline,
            withhold: None,
        };
        let mut input = json!({ "service": req.service, "method": req.method, "path": req.path, "body": body_value(&req.body) });

        // 0. the call belongs to a run in flight
        if let Err(v) = call.bind() {
            return Err(call.deny(&input, v));
        }
        // 1. the call must be a tool this agent declared and may use, with the declared target
        let (spec, tool) = match self.tool_spec(&snap, &call.c.agent, &call.c.tool) {
            Ok(x) => x,
            Err(v) => return Err(call.deny(&input, v)),
        };
        call.taint_gate(spec, tool, &input)?;
        call.quarantine_gate(&input)?;
        call.approval_gate(tool, &input).await?;
        let method = req.method.to_ascii_uppercase();
        let mismatch = |path: &str| {
            Verdict::deny(
                RULE_TOOL_SPEC,
                format!(
                    "{} {path} on {} does not match tool {} ({:?} {:?} on {:?})",
                    req.method, req.service, tool.name, tool.method, tool.path, tool.service
                ),
            )
        };
        let declared = tool.tool_type == ToolType::Service
            && tool.service.as_deref() == Some(req.service.as_str())
            && tool
                .method
                .as_deref()
                .map(str::to_ascii_uppercase)
                .as_deref()
                == Some(method.as_str());
        if !declared {
            return Err(call.deny(&input, mismatch(&req.path)));
        }
        let target = req.service.clone();
        let v = self.check_service(&snap, spec, &target);
        if !v.allow {
            return Err(call.deny(&input, v));
        }
        // 2. authorize exactly the path that will be sent, and only one the tool's template allows
        let path = match authz::canonical_path(&req.path) {
            Ok(p) => p,
            Err(reason) => return Err(call.deny(&input, Verdict::deny(authz::RULE_PATH, reason))),
        };
        input["method"] = json!(method);
        input["path"] = json!(path);
        if !fits_template(tool.path.as_deref(), &path) {
            return Err(call.deny(&input, mismatch(&path)));
        }
        let v = authz::authorize_service_call(
            &snap.charter,
            Some(authz::LOCAL),
            Some(&call.c.agent),
            &target,
            &method,
            &path,
        );
        if !v.allow {
            return Err(call.deny(&input, v));
        }

        // The response cache (cache.rs), after authz: a read the app marked cacheable is
        // answered here without leaving the pod; a write empties the target's entries here (the
        // target's own sidecar empties its own), so this run's next read sees what it wrote.
        let cache_key = crate::cache::Key {
            service: target.clone(),
            caller: authz::LOCAL.to_string(),
            agent: call.c.agent.clone(),
            method: method.clone(),
            path: path.clone(),
        };
        let cacheable = crate::cache::cacheable_method(&method)
            && matches!(tool.effective_effect(), ToolEffect::Read);
        if !cacheable {
            self.state.response_cache.invalidate_service(&target);
        }

        // 3. perform it: our own app on localhost, or a peer's sidecar over mTLS
        let callee = format!("{target} {method} {path}");
        let child = call.trace.child();
        let is_self = self.is_self(Some(&target));
        let dir = if is_self {
            Direction::Internal
        } else {
            Direction::Outbound
        };
        let pending = call.begin(Kind::ServiceCall, dir, &child, &callee, &input, &v);
        let hit = if cacheable {
            self.state.response_cache.get(&cache_key, &req.headers)
        } else {
            None
        };
        let from_cache = hit.is_some();
        let result: Result<ServiceResponse, Status> = if let Some(hit) = hit {
            Ok(hit.response)
        } else if is_self {
            self.call_local_app(
                &snap,
                &call.c,
                &child,
                call.deadline,
                &method,
                &path,
                &req.headers,
                &req.body,
            )
            .await
        } else {
            match self.state.mesh_client(&snap, &target) {
                Err(e) => Err(status_with_rule(
                    Code::Unavailable,
                    RULE_MESH_UNAVAILABLE,
                    &e.to_string(),
                )),
                Ok(mut client) => {
                    let headers = req
                        .headers
                        .iter()
                        .filter(|(k, _)| !is_reserved_header(k))
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                    let msg = ServiceRequest {
                        method: method.clone(),
                        path: path.clone(),
                        headers,
                        body: req.body.clone(),
                        request_id: call.c.request_id.clone(),
                        traceparent: child.traceparent(),
                        agent: call.c.agent.clone(),
                    };
                    client
                        .invoke_service(self.mesh_request(&call.c, &child, call.deadline, msg))
                        .await
                        .map(|r| r.into_inner())
                }
            }
        };
        pending.disarm();

        match result {
            Ok(resp) => {
                if cacheable && !from_cache {
                    self.state
                        .response_cache
                        .store(cache_key, &resp, &req.headers);
                }
                let out = json!({ "status": resp.status, "body": body_value(&resp.body) });
                call.taint_mark(tool);
                call.tool(&input, out.clone(), &v, None);
                call.attempt(
                    Kind::ServiceCall,
                    dir,
                    &child,
                    &callee,
                    &input,
                    out,
                    &v,
                    None,
                    None,
                );
                Ok(Response::new(resp))
            }
            Err(st) if is_denial(st.code()) => {
                let rule = rule_from_status(&st, "mesh.denied");
                let dv = Verdict::deny(
                    rule.clone(),
                    format!("denied by {target}: {}", reason_from_status(&st, &rule)),
                );
                call.tool(&input, Value::Null, &dv, None);
                call.attempt(
                    Kind::ServiceCall,
                    dir,
                    &child,
                    &callee,
                    &input,
                    Value::Null,
                    &dv,
                    None,
                    None,
                );
                Err(denied_status(&dv))
            }
            Err(st) => {
                let rule = rule_from_status(&st, RULE_MESH_UNAVAILABLE);
                let err = format!("{}: {}", st.code(), st.message());
                call.tool(&input, Value::Null, &v, Some(err.clone()));
                call.attempt(
                    Kind::ServiceCall,
                    dir,
                    &child,
                    &callee,
                    &input,
                    Value::Null,
                    &v,
                    Some(err.clone()),
                    None,
                );
                Err(status_with_rule(Code::Unavailable, &rule, &err))
            }
        }
    }

    async fn invoke_agent(
        &self,
        request: Request<ToolAgentRequest>,
    ) -> Result<Response<InvokeAgentResponse>, Status> {
        self.state.audit.gate_tool(request.get_ref().ctx.as_ref())?;
        let deadline = deadline::from_metadata(request.metadata());
        let req = request.into_inner();
        let (c, trace) = ctx_of(&req.ctx)?;
        let snap = self.state.loaded().ok_or_else(no_charter)?;
        let mut call = Call {
            svc: self,
            c,
            trace,
            started: Instant::now(),
            deadline,
            withhold: None,
        };
        // the callee's `context` goes with the input, in our records as in the callee's
        let input = pipeline::input_value(&req.input, &req.context_json);

        if let Err(v) = call.bind() {
            return Err(call.deny(&input, v));
        }
        let (spec, tool) = match self.tool_spec(&snap, &call.c.agent, &call.c.tool) {
            Ok(x) => x,
            Err(v) => return Err(call.deny(&input, v)),
        };
        call.taint_gate(spec, tool, &input)?;
        call.quarantine_gate(&input)?;
        call.approval_gate(tool, &input).await?;
        let remote = !self.is_self(Some(&req.target_service));
        let declared = tool.tool_type == ToolType::Agent
            && tool.agent.as_deref() == Some(req.target_agent.as_str())
            && self.is_self(tool.service.as_deref()) == !remote
            && (!remote || tool.service.as_deref() == Some(req.target_service.as_str()));
        if !declared {
            return Err(call.deny(
                &input,
                Verdict::deny(
                    RULE_TOOL_SPEC,
                    format!(
                        "agent {}/{} does not match tool {} ({:?}/{:?})",
                        req.target_service, req.target_agent, tool.name, tool.service, tool.agent
                    ),
                ),
            ));
        }
        if !req.context_json.trim().is_empty() && !input["context"].is_object() {
            return Err(call.deny(
                &input,
                Verdict::deny(RULE_TOOL_SPEC, "the context must be a JSON object"),
            ));
        }
        let v = if remote {
            self.check_service(&snap, spec, &req.target_service)
        } else {
            Verdict::allow("guardrail.allowed_tools")
        };
        if !v.allow {
            return Err(call.deny(&input, v));
        }

        let callee = if remote {
            format!("{}/{}", req.target_service, req.target_agent)
        } else {
            req.target_agent.clone()
        };
        let child = call.trace.child();
        let dir = if remote {
            Direction::Outbound
        } else {
            Direction::Internal
        };
        let pending = call.begin(Kind::AgentCall, dir, &child, &callee, &input, &v);
        let resp = if remote {
            match self.state.mesh_client(&snap, &req.target_service) {
                Err(e) => envelope(
                    &call.c,
                    &child,
                    &req.target_agent,
                    "error",
                    RULE_MESH_UNAVAILABLE,
                    &e.to_string(),
                ),
                Ok(mut client) => {
                    let msg = InvokeAgentRequest {
                        agent: req.target_agent.clone(),
                        input: req.input.clone(),
                        context_json: req.context_json.clone(),
                        request_id: call.c.request_id.clone(),
                        traceparent: child.traceparent(),
                        caller_agent: call.c.agent.clone(),
                        depth: call.c.depth + 1,
                    };
                    match client
                        .invoke_agent(self.mesh_request(&call.c, &child, call.deadline, msg))
                        .await
                    {
                        Ok(r) => {
                            // the callee's run read these labels: so has this one now
                            if let Some(h) = r
                                .metadata()
                                .get(crate::taint::HEADER)
                                .and_then(|v| v.to_str().ok())
                            {
                                self.state.taint.add_header(
                                    &call.c.request_id,
                                    h,
                                    &format!("agent {}", req.target_agent),
                                );
                            }
                            r.into_inner()
                        }
                        Err(st) => {
                            let denied = is_denial(st.code());
                            let rule = rule_from_status(
                                &st,
                                if denied {
                                    "mesh.denied"
                                } else {
                                    RULE_MESH_UNAVAILABLE
                                },
                            );
                            let reason = reason_from_status(&st, &rule);
                            envelope(
                                &call.c,
                                &child,
                                &req.target_agent,
                                if denied { "denied" } else { "error" },
                                &rule,
                                &reason,
                            )
                        }
                    }
                }
            }
        } else {
            // The nested invocation is its own span, a child of this agent_call's (design §6.4).
            pipeline::invoke(
                &self.state,
                Invocation {
                    agent: req.target_agent.clone(),
                    input: req.input.clone(),
                    context_json: req.context_json.clone(),
                    request_id: call.c.request_id.clone(),
                    trace: child.child(),
                    caller: authz::LOCAL.into(),
                    caller_agent: Some(call.c.agent.clone()),
                    depth: call.c.depth + 1,
                    deadline: call.deadline,
                },
            )
            .await
        };
        pending.disarm();
        let tokens = resp.usage.as_ref().map(|u| {
            (
                Tokens {
                    input: u.input_tokens,
                    output: u.output_tokens,
                },
                u.cost_usd,
            )
        });
        match resp.status.as_str() {
            "ok" => {
                let out = Value::String(resp.output.clone());
                call.taint_mark(tool);
                call.tool(&input, out.clone(), &v, None);
                call.attempt(
                    Kind::AgentCall,
                    dir,
                    &child,
                    &callee,
                    &input,
                    out,
                    &v,
                    None,
                    tokens,
                );
                Ok(Response::new(resp))
            }
            "denied" => {
                let dv = Verdict::deny(resp.rule.clone(), resp.reason.clone());
                // The callee's content rule matched this input or context (CONTRACT.md §6): keep
                // them out of our records too, and out of the calling agent's next prompt, which
                // quotes them, the context as a JSON value.
                if dv.rule.starts_with(INPUT_DENY) {
                    self.state.audit.withhold(
                        &call.c.request_id,
                        [req.input.clone(), req.context_json.clone()],
                    );
                    self.state.audit.withhold_value(&call.c.request_id, &input);
                    call.withhold = Some(dv.rule.clone());
                }
                call.tool(&input, Value::Null, &dv, None);
                call.attempt(
                    Kind::AgentCall,
                    dir,
                    &child,
                    &callee,
                    &input,
                    Value::Null,
                    &dv,
                    None,
                    tokens,
                );
                Err(denied_status(&dv))
            }
            _ => {
                let err = format!("{}: {}", resp.rule, resp.reason);
                call.tool(&input, Value::Null, &v, Some(err.clone()));
                call.attempt(
                    Kind::AgentCall,
                    dir,
                    &child,
                    &callee,
                    &input,
                    Value::Null,
                    &v,
                    Some(err),
                    tokens,
                );
                let code = if resp.rule == pipeline::RULE_UNKNOWN_AGENT {
                    Code::NotFound
                } else {
                    Code::Unavailable
                };
                Err(status_with_rule(code, &resp.rule, &resp.reason))
            }
        }
    }

    async fn invoke_http(
        &self,
        request: Request<ToolHttpRequest>,
    ) -> Result<Response<ServiceResponse>, Status> {
        self.state.audit.gate_tool(request.get_ref().ctx.as_ref())?;
        let deadline = deadline::from_metadata(request.metadata());
        let req = request.into_inner();
        let (c, trace) = ctx_of(&req.ctx)?;
        let snap = self.state.loaded().ok_or_else(no_charter)?;
        let mut call = Call {
            svc: self,
            c,
            trace,
            started: Instant::now(),
            deadline,
            withhold: None,
        };
        let mut input =
            json!({ "method": req.method, "url": req.url, "body": body_value(&req.body) });

        if let Err(v) = call.bind() {
            return Err(call.deny(&input, v));
        }
        let (spec, tool) = match self.tool_spec(&snap, &call.c.agent, &call.c.tool) {
            Ok(x) => x,
            Err(v) => return Err(call.deny(&input, v)),
        };
        call.taint_gate(spec, tool, &input)?;
        call.quarantine_gate(&input)?;
        call.approval_gate(tool, &input).await?;
        let method = req.method.to_ascii_uppercase();
        let mismatch = |url: &str| {
            Verdict::deny(
                RULE_TOOL_SPEC,
                format!(
                    "{} {url} does not match tool {} ({:?} {:?})",
                    req.method, tool.name, tool.method, tool.url
                ),
            )
        };
        // the origin (scheme://host:port) is fixed by the charter; the model only fills the path
        let declared_origin = tool.url.as_deref().and_then(agentsc_charter::http_origin);
        let url = url::Url::parse(&req.url).ok();
        let origin = url
            .as_ref()
            .and_then(|u| agentsc_charter::http_origin(u.as_str()));
        let declared = tool.tool_type == ToolType::Http
            && tool
                .method
                .as_deref()
                .map(str::to_ascii_uppercase)
                .as_deref()
                == Some(method.as_str())
            && declared_origin.is_some()
            && origin == declared_origin
            && url
                .as_ref()
                .is_some_and(|u| u.username().is_empty() && u.password().is_none());
        let Some(mut url) = url.filter(|_| declared) else {
            return Err(call.deny(&input, mismatch(&req.url)));
        };
        // the path and query are canonicalised like a service path (§5.1), and the path must fit
        // the declared URL's template, so a `{param}` can neither climb out nor go missing
        let pq =
            match authz::canonical_path(&url[url::Position::BeforePath..url::Position::AfterQuery])
            {
                Ok(p) => p,
                Err(reason) => {
                    return Err(call.deny(&input, Verdict::deny(authz::RULE_PATH, reason)));
                }
            };
        let (path, query) = match pq.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (pq.as_str(), None),
        };
        url.set_path(path);
        url.set_query(query);
        url.set_fragment(None);
        input["method"] = json!(method);
        input["url"] = json!(url.as_str());
        if !fits_template(
            tool.url.as_deref().map(agentsc_charter::http_url_path),
            path,
        ) {
            return Err(call.deny(&input, mismatch(url.as_str())));
        }
        let v = Verdict::allow("guardrail.allowed_tools");
        let m = match reqwest::Method::from_bytes(method.as_bytes()) {
            Ok(m) => m,
            Err(e) => return Err(call.deny(&input, Verdict::deny(RULE_TOOL_SPEC, e.to_string()))),
        };
        let child = call.trace.child();
        let mut hreq = self
            .state
            .egress
            .request(m, url.clone())
            .timeout(deadline::budget(call.deadline, deadline::HTTP_TIMEOUT));
        for (k, val) in &req.headers {
            if !is_reserved_header(k) {
                hreq = hreq.header(k, val);
            }
        }
        hreq = hreq
            .header("traceparent", child.traceparent())
            .header("x-agentsc-request-id", &call.c.request_id);
        if !req.body.is_empty() {
            hreq = hreq.body(req.body.clone());
        }
        let callee = format!("{method} {url}");
        let pending = call.begin(
            Kind::HttpCall,
            Direction::Outbound,
            &child,
            &callee,
            &input,
            &v,
        );
        let max = self.state.config.max_response_bytes;
        let sent = match hreq.send().await {
            Ok(resp) => to_service_response(resp, max, RULE_HTTP_ERROR).await,
            Err(e) => Err(BodyError {
                rule: RULE_HTTP_ERROR,
                reason: e.to_string(),
            }),
        };
        pending.disarm();
        match sent {
            Ok(sr) => {
                let out = json!({ "status": sr.status, "body": body_value(&sr.body) });
                call.taint_mark(tool);
                call.tool(&input, out.clone(), &v, None);
                call.attempt(
                    Kind::HttpCall,
                    Direction::Outbound,
                    &child,
                    &callee,
                    &input,
                    out,
                    &v,
                    None,
                    None,
                );
                Ok(Response::new(sr))
            }
            Err(e) => {
                call.tool(&input, Value::Null, &v, Some(e.reason.clone()));
                call.attempt(
                    Kind::HttpCall,
                    Direction::Outbound,
                    &child,
                    &callee,
                    &input,
                    Value::Null,
                    &v,
                    Some(e.reason.clone()),
                    None,
                );
                Err(status_with_rule(Code::Unavailable, e.rule, &e.reason))
            }
        }
    }

    /// Design §6.5: only `model_call` records of the `mock` model (a provider's calls go through
    /// the model gateway, which writes their records itself), and — while the Execute runs —
    /// `tool_call` records for `load_skill:<skill>` of that agent's skills, for an (agent, request
    /// id) whose Execute is in flight or returned less than the run window ago. Anything else is
    /// refused with `INVALID_ARGUMENT` and an `authz` record `runtime.report_rejected`. The
    /// record's `cost_usd` is the price table's, never the runtime's (`mock` costs nothing). Once
    /// the agent's daily cost budget is spent, every answer carries
    /// `x-agentsc-rule: budget.max_cost_usd_per_day`.
    async fn report_event(&self, request: Request<AuditEvent>) -> Result<Response<Empty>, Status> {
        let state = &self.state;
        let ev = request.into_inner();
        let mut rec: AuditRecord = match serde_json::from_str(&ev.json) {
            Ok(r) => r,
            Err(e) => {
                // what can be told about it, for the refusal record
                let view = AuditRecordView::from_json(&ev.json).ok();
                let (request_id, trace_id, agent, kind) = match &view {
                    Some(v) => (
                        v.request_id.clone(),
                        v.trace_id.clone(),
                        v.agent.clone(),
                        Value::String(v.kind.clone()),
                    ),
                    None => (String::new(), String::new(), None, Value::Null),
                };
                return Err(reject_report(
                    state,
                    &request_id,
                    &trace_id,
                    agent.as_deref(),
                    json!({ "kind": kind }),
                    format!("not an audit record this sidecar accepts: {e}"),
                ));
            }
        };
        let summary = json!({ "kind": rec.kind.as_str(), "callee": rec.callee });
        let reject = |reason: String| {
            reject_report(
                state,
                &rec.request_id,
                &rec.trace_id,
                rec.agent.as_deref(),
                summary.clone(),
                reason,
            )
        };
        let Some(agent) = rec.agent.clone().filter(|a| !a.is_empty()) else {
            return Err(reject("the record names no agent".into()));
        };
        let Some(run) = state.runs.lookup(&rec.request_id, &agent) else {
            return Err(reject(format!(
                "no Execute of {agent} for request {:?} in flight or finished in the last {}s",
                rec.request_id,
                state.runs.window().as_secs()
            )));
        };
        let snap = state.loaded().ok_or_else(no_charter)?;
        match rec.kind {
            Kind::ModelCall if rec.callee != MOCK_MODEL => {
                return Err(reject(format!(
                    "model calls to a provider ({:?}) go through the model gateway, which records them",
                    rec.callee
                )));
            }
            Kind::ModelCall => {}
            Kind::ToolCall if !run.in_flight => {
                return Err(reject(
                    "after its Execute returned a run reports only model_call records".into(),
                ));
            }
            Kind::ToolCall => {
                let skill = rec
                    .callee
                    .strip_prefix(LOAD_SKILL_TOOL)
                    .and_then(|r| r.strip_prefix(':'));
                let known = skill.is_some_and(|s| {
                    snap.charter
                        .agent(&agent)
                        .is_some_and(|a| a.skills.iter().any(|x| x == s))
                });
                if !known {
                    return Err(reject(format!(
                        "tool_call records are accepted only for {LOAD_SKILL_TOOL}:<skill> of {agent}'s skills, not {:?}",
                        rec.callee
                    )));
                }
            }
            other => {
                return Err(reject(format!(
                    "{other} records are not accepted from the runtime"
                )));
            }
        }
        if rec.ts.is_empty() {
            rec.ts = agentsc_common::audit::now_rfc3339();
        }
        if rec.kind == Kind::ModelCall {
            rec.cost_usd = Some(0.0);
        }
        state.audit.write(rec);
        let mut resp = Response::new(Empty {});
        if let Some(spec) = snap.charter.agent(&agent)
            && !state
                .budgets
                .check_cost(&agent, spec.budgets.max_cost_usd_per_day)
                .allow
        {
            resp.metadata_mut().insert(
                "x-agentsc-rule",
                MetadataValue::from_static(RULE_COST_BUDGET),
            );
        }
        Ok(resp)
    }

    async fn propose_lesson(
        &self,
        request: Request<LessonRequest>,
    ) -> Result<Response<LessonResponse>, Status> {
        self.state.audit.gate()?;
        crate::learning::propose(&self.state, request.into_inner()).map(Response::new)
    }
}

fn envelope(
    c: &ToolContext,
    trace: &TraceContext,
    agent: &str,
    status: &str,
    rule: &str,
    reason: &str,
) -> InvokeAgentResponse {
    InvokeAgentResponse {
        status: status.into(),
        request_id: c.request_id.clone(),
        trace_id: trace.trace_id.clone(),
        agent: agent.into(),
        output: String::new(),
        usage: None,
        steps: vec![],
        rule: rule.into(),
        reason: reason.into(),
        questions: Vec::new(),
    }
}
