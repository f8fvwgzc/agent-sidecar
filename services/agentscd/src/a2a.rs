//! The sidecar's A2A 1.0 server (docs/design/a2a.md): on `--a2a-addr`, every agent with an `a2a`
//! block gets an agent card and a JSON-RPC endpoint. A message is an invocation like an app's
//! (CONTRACT.md §4.1), with these differences:
//!
//! - The caller is `a2a:<name>`: the bearer token matched the file `<name>` in
//!   `--a2a-callers-dir`, and `authz.callers` must have a rule for that identity and the agent.
//! - The run starts with the `untrusted` label (pipeline.rs): the text is another party's.
//! - A run that asks the caller (`ask_caller`) becomes a task in `TASK_STATE_INPUT_REQUIRED`; the
//!   caller's next message with that `taskId` is the answer, and the sidecar invokes the agent
//!   again with the first input and every answer so far in `context.answers` (§4.1 Questions).
//!
//! Tasks live in memory for an hour after their last change and are lost on a restart; nothing
//! streams and nothing is pushed (`capabilities.streaming` and `pushNotifications` are false).
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agentsc_charter::{A2A_IDENTITY_PREFIX, AgentSpec, Charter};
use agentsc_common::a2a::{self, ROLE_AGENT, ROLE_USER, code, method, rpc_error, state};
use agentsc_common::audit::{AuditRecord, Direction, Kind};
use agentsc_common::authz::Verdict;
use agentsc_common::trace::{TraceContext, new_request_id};
use agentsc_proto::{InvokeAgentResponse, Question};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};

use crate::pipeline::{self, Invocation};
use crate::state::AppState;

/// A request without a known caller's token (an `authz` record names it).
pub const RULE_UNAUTHENTICATED: &str = "a2a.unauthenticated";
/// How long a task is kept after its last change.
pub const TASK_TTL: Duration = Duration::from_secs(3600);
/// At most this many tasks are kept; the oldest go first.
pub const MAX_TASKS: usize = 10_000;
/// The path of an agent's card and endpoint: `/a2a/<agent>`.
const PREFIX: &str = "/a2a/";
const CARD_PATH: &str = "/.well-known/agent-card.json";

/// One task the sidecar answered.
struct Task {
    caller: String,
    agent: String,
    context_id: String,
    /// The first message's text and data: every later run of the task starts from them.
    input: String,
    context: serde_json::Map<String, Value>,
    /// Every answer so far, `{"question", "answer"}` (CONTRACT.md §4.1 Questions).
    answers: Vec<Value>,
    /// The questions of the last run, which the next message answers.
    questions: Vec<Question>,
    /// What `GetTask` returns.
    json: Value,
    updated: Instant,
}

impl Task {
    fn state(&self) -> &str {
        self.json
            .pointer("/status/state")
            .and_then(Value::as_str)
            .unwrap_or("")
    }
}

/// The tasks of this sidecar's A2A server.
#[derive(Default)]
pub struct Tasks {
    inner: Mutex<HashMap<String, Task>>,
}

impl Tasks {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Task>> {
        crate::state::lock(&self.inner)
    }

    fn put(&self, id: String, task: Task) {
        let mut tasks = self.lock();
        let now = Instant::now();
        tasks.retain(|_, t| now.duration_since(t.updated) < TASK_TTL);
        while tasks.len() >= MAX_TASKS {
            let Some(oldest) = tasks
                .iter()
                .min_by_key(|(_, t)| t.updated)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            tasks.remove(&oldest);
        }
        tasks.insert(id, task);
    }

    /// How many tasks are kept (tests).
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(CARD_PATH, get(only_card))
        .route("/a2a/{agent}/.well-known/agent-card.json", get(card))
        .route("/a2a/{agent}", post(rpc))
        .with_state(state)
}

pub async fn serve(
    state: Arc<AppState>,
    addr: SocketAddr,
) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let _ = state.a2a_bound.set(bound);
    let app = router(state);
    let task = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!(error = %e, "a2a server stopped");
        }
    });
    Ok((bound, task))
}

fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": "no such agent on this A2A server"})),
    )
        .into_response()
}

/// The agent `name`, if the charter serves it over A2A.
fn served<'a>(charter: &'a Charter, name: &str) -> Option<&'a AgentSpec> {
    charter.agent(name).filter(|a| a.a2a.is_some())
}

/// The base URL callers reach this server at.
fn public_url(state: &AppState) -> String {
    match &state.config.a2a_public_url {
        Some(u) => u.trim_end_matches('/').to_string(),
        None => match state.a2a_bound.get().or(state.config.a2a_addr.as_ref()) {
            Some(a) => format!("http://{a}"),
            None => String::new(),
        },
    }
}

/// The agent card of `agent` (A2A 1.0 `AgentCard`, proto3 JSON names).
pub fn agent_card(agent: &AgentSpec, base: &str, version: &str) -> Value {
    let Some(a2a) = &agent.a2a else {
        return Value::Null;
    };
    let skills: Vec<Value> = if a2a.skills.is_empty() {
        vec![json!({
            "id": agent.name,
            "name": agent.name,
            "description": a2a.description,
            "tags": [format!("{:?}", agent.agent_type).to_ascii_lowercase()],
        })]
    } else {
        a2a.skills
            .iter()
            .map(|s| {
                let mut v = json!({
                    "id": s.id, "name": s.name, "description": s.description, "tags": s.tags,
                });
                if !s.examples.is_empty() {
                    v["examples"] = json!(s.examples);
                }
                v
            })
            .collect()
    };
    json!({
        "name": agent.name,
        "description": a2a.description,
        "supportedInterfaces": [{
            "url": format!("{base}{PREFIX}{}", agent.name),
            "protocolBinding": a2a::BINDING,
            "protocolVersion": a2a::VERSION,
        }],
        "version": version,
        "capabilities": {"streaming": false, "pushNotifications": false, "extendedAgentCard": false},
        "securitySchemes": {"bearer": {"httpAuthSecurityScheme": {"scheme": "Bearer"}}},
        "securityRequirements": [{"schemes": {"bearer": {"list": []}}}],
        "defaultInputModes": ["text/plain", "application/json"],
        "defaultOutputModes": ["text/plain", "application/json"],
        "skills": skills,
    })
}

/// The card's `version`: the charter's version when embassy sent it, else its hash's first 12
/// hex digits, so a caller can tell that the card changed.
fn card_version(snap: &crate::loaded::Loaded) -> String {
    if !snap.version.is_empty() {
        return snap.version.clone();
    }
    snap.sha256.chars().take(12).collect()
}

fn card_response(state: &AppState, name: &str) -> Response {
    let Some(snap) = state.loaded() else {
        return not_found();
    };
    let Some(agent) = served(&snap.charter, name) else {
        return not_found();
    };
    let mut resp =
        Json(agent_card(agent, &public_url(state), &card_version(&snap))).into_response();
    resp.headers_mut()
        .insert("cache-control", HeaderValue::from_static("max-age=60"));
    resp
}

/// `/.well-known/agent-card.json`: the card, when the charter serves exactly one agent.
async fn only_card(State(state): State<Arc<AppState>>) -> Response {
    let Some(snap) = state.loaded() else {
        return not_found();
    };
    let mut served = snap.charter.agents.iter().filter(|a| a.a2a.is_some());
    match (served.next(), served.next()) {
        (Some(a), None) => card_response(&state, &a.name),
        _ => not_found(),
    }
}

async fn card(State(state): State<Arc<AppState>>, Path(agent): Path<String>) -> Response {
    card_response(&state, &agent)
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// The caller whose token the request carries: an `a2a:<name>` identity some `authz.callers` rule
/// names for `agent` (or `*`), whose file in `--a2a-callers-dir` holds that token. Every file is
/// read and compared, so the time does not tell which names exist.
async fn caller_of(
    state: &AppState,
    charter: &Charter,
    agent: &str,
    authorization: Option<&str>,
) -> Option<String> {
    let names: std::collections::BTreeSet<&str> = charter
        .authz
        .callers
        .iter()
        .filter(|r| r.agents.iter().any(|a| a == "*" || a == agent))
        .filter_map(|r| r.identity.strip_prefix(A2A_IDENTITY_PREFIX))
        .filter(|n| agentsc_charter::is_dns_label(n))
        .collect();
    let mut found = None;
    for name in names {
        let Ok(text) = tokio::fs::read_to_string(state.config.a2a_callers_dir.join(name)).await
        else {
            continue;
        };
        let token = text.trim();
        if token.is_empty() || token.chars().any(char::is_control) {
            continue;
        }
        let expected = crate::app_auth::digest(token);
        if crate::app_auth::authorized(&expected, authorization) && found.is_none() {
            found = Some(format!("{A2A_IDENTITY_PREFIX}{name}"));
        }
    }
    found
}

/// A JSON-RPC answer: HTTP 200 with `result` or `error`.
fn answer(
    id: &Value,
    outcome: Result<Value, Value>,
    request_id: Option<&str>,
    trace: &TraceContext,
) -> Response {
    let body = match outcome {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err(error) => json!({"jsonrpc": "2.0", "id": id, "error": error}),
    };
    let mut resp = (StatusCode::OK, Json(body)).into_response();
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&trace.traceparent()) {
        h.insert("traceparent", v);
    }
    if let Some(Ok(v)) = request_id.map(HeaderValue::from_str) {
        h.insert("x-agentsc-request-id", v);
    }
    h.insert(a2a::VERSION_HEADER, HeaderValue::from_static(a2a::VERSION));
    resp
}

async fn rpc(
    State(state): State<Arc<AppState>>,
    Path(agent): Path<String>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    body: axum::body::Bytes,
) -> Response {
    let trace = header(&headers, "traceparent")
        .map(TraceContext::from_traceparent)
        .unwrap_or_else(TraceContext::new_root);
    let Some(snap) = state.loaded() else {
        return not_found();
    };
    if served(&snap.charter, &agent).is_none() {
        return not_found();
    }
    let Some(caller) = caller_of(
        &state,
        &snap.charter,
        &agent,
        header(&headers, "authorization"),
    )
    .await
    else {
        let reason = if header(&headers, "authorization").is_some() {
            "the token is not an A2A caller's that authz.callers admits for this agent"
        } else {
            "the A2A server needs Authorization: Bearer <token>"
        };
        let v = Verdict::deny(RULE_UNAUTHENTICATED, reason);
        state.audit.write(
            AuditRecord::new(
                Kind::Authz,
                Direction::Inbound,
                &new_request_id(),
                &trace,
                Some(&agent),
                "a2a",
                None,
                &format!("POST {PREFIX}{agent}"),
                Value::Null,
                Value::Null,
            )
            .verdict(&v),
        );
        let mut resp = (
            StatusCode::UNAUTHORIZED,
            Json(json!({"jsonrpc": "2.0", "id": null, "error": rpc_error(code::INVALID_REQUEST, reason)})),
        )
            .into_response();
        resp.headers_mut()
            .insert("www-authenticate", HeaderValue::from_static("Bearer"));
        return resp;
    };
    // the version: the header, else the query parameter; an empty one is 0.3 (A2A 1.0 §3.6)
    let query_version = uri.query().and_then(|q| {
        q.split('&')
            .filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| k.eq_ignore_ascii_case(a2a::VERSION_HEADER))
            .map(|(_, v)| v.to_string())
    });
    let version = header(&headers, a2a::VERSION_HEADER)
        .map(str::to_string)
        .or(query_version)
        .unwrap_or_default();
    let msg: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return answer(
                &Value::Null,
                Err(rpc_error(code::PARSE_ERROR, format!("not JSON: {e}"))),
                None,
                &trace,
            );
        }
    };
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let (Some("2.0"), Some(m)) = (
        msg.get("jsonrpc").and_then(Value::as_str),
        msg.get("method").and_then(Value::as_str),
    ) else {
        return answer(
            &id,
            Err(rpc_error(
                code::INVALID_REQUEST,
                "not a JSON-RPC 2.0 request",
            )),
            None,
            &trace,
        );
    };
    if !a2a::version_supported(&version) {
        let shown = if version.is_empty() {
            "none (0.3)"
        } else {
            version.as_str()
        };
        return answer(
            &id,
            Err(rpc_error(
                code::VERSION_NOT_SUPPORTED,
                format!(
                    "this server speaks A2A {}; the request's A2A-Version is {shown}",
                    a2a::VERSION
                ),
            )),
            None,
            &trace,
        );
    }
    let params = msg.get("params").cloned().unwrap_or(Value::Null);
    let call = Rpc {
        state: &state,
        agent: &agent,
        caller: &caller,
        trace: &trace,
    };
    match m {
        method::SEND_MESSAGE => {
            let (outcome, request_id) = call.send(&params).await;
            answer(&id, outcome, request_id.as_deref(), &trace)
        }
        method::GET_TASK => answer(&id, call.get(&params), None, &trace),
        method::CANCEL_TASK => answer(&id, call.cancel(&params), None, &trace),
        method::SEND_STREAMING_MESSAGE | method::SUBSCRIBE_TO_TASK | method::LIST_TASKS => answer(
            &id,
            Err(rpc_error(
                code::UNSUPPORTED_OPERATION,
                format!("{m} is not supported: this server neither streams nor lists tasks"),
            )),
            None,
            &trace,
        ),
        method::GET_EXTENDED_AGENT_CARD => answer(
            &id,
            Err(rpc_error(
                code::EXTENDED_AGENT_CARD_NOT_CONFIGURED,
                "there is no extended agent card",
            )),
            None,
            &trace,
        ),
        m if method::PUSH_CONFIG.contains(&m) => answer(
            &id,
            Err(rpc_error(
                code::PUSH_NOTIFICATION_NOT_SUPPORTED,
                "push notifications are not supported",
            )),
            None,
            &trace,
        ),
        other => answer(
            &id,
            Err(rpc_error(
                code::METHOD_NOT_FOUND,
                format!("no method {other:?}"),
            )),
            None,
            &trace,
        ),
    }
}

/// One JSON-RPC request of a known caller to a served agent.
struct Rpc<'a> {
    state: &'a Arc<AppState>,
    agent: &'a str,
    caller: &'a str,
    trace: &'a TraceContext,
}

fn invalid(reason: impl Into<String>) -> Value {
    rpc_error(code::INVALID_PARAMS, reason)
}

/// The text and data of a user message's parts: text parts joined by a blank line; data parts that
/// are objects merged, later keys winning. Files (`raw`, `url`) are refused.
fn read_parts(message: &Value) -> Result<(String, serde_json::Map<String, Value>), Value> {
    let parts = message
        .get("parts")
        .and_then(Value::as_array)
        .filter(|p| !p.is_empty())
        .ok_or_else(|| invalid("message.parts must be a non-empty array"))?;
    let mut texts = Vec::new();
    let mut data = serde_json::Map::new();
    for p in parts {
        if let Some(t) = p.get("text").and_then(Value::as_str) {
            texts.push(t);
        } else if let Some(d) = p.get("data") {
            match d {
                Value::Object(m) => data.extend(m.clone()),
                _ => return Err(invalid("a data part must hold a JSON object")),
            }
        } else if p.get("raw").is_some() || p.get("url").is_some() {
            return Err(rpc_error(
                code::CONTENT_TYPE_NOT_SUPPORTED,
                "this agent takes text and JSON data parts, not files",
            ));
        } else {
            return Err(invalid("a part needs text, raw, url or data"));
        }
    }
    Ok((texts.join("\n\n"), data))
}

impl Rpc<'_> {
    /// A task of this caller and agent.
    fn visible(&self, t: &Task) -> bool {
        t.caller == self.caller && t.agent == self.agent
    }

    fn not_found(id: &str) -> Value {
        rpc_error(code::TASK_NOT_FOUND, format!("no task {id:?}"))
    }

    fn get(&self, params: &Value) -> Result<Value, Value> {
        let id = params
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("params.id must be a string"))?;
        let tasks = self.state.a2a_tasks.lock();
        match tasks.get(id).filter(|t| self.visible(t)) {
            Some(t) => Ok(t.json.clone()),
            None => Err(Self::not_found(id)),
        }
    }

    fn cancel(&self, params: &Value) -> Result<Value, Value> {
        let id = params
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("params.id must be a string"))?;
        let mut tasks = self.state.a2a_tasks.lock();
        let Some(t) = tasks.get_mut(id).filter(|t| self.visible(t)) else {
            return Err(Self::not_found(id));
        };
        // only a task waiting for the caller can be canceled: a run in progress is not stopped
        if t.state() != state::INPUT_REQUIRED {
            return Err(rpc_error(
                code::TASK_NOT_CANCELABLE,
                format!("task {id:?} is {}", t.state()),
            ));
        }
        t.json["status"] = json!({"state": state::CANCELED, "timestamp": now()});
        t.updated = Instant::now();
        Ok(t.json.clone())
    }

    /// `SendMessage`: a new task, or the answer to one that waits for input. The invocation's
    /// request id goes back in the `x-agentsc-request-id` header.
    async fn send(&self, params: &Value) -> (Result<Value, Value>, Option<String>) {
        match self.send_inner(params).await {
            Ok((task, rid)) => (Ok(json!({"task": task})), Some(rid)),
            Err(e) => (Err(e), None),
        }
    }

    async fn send_inner(&self, params: &Value) -> Result<(Value, String), Value> {
        let message = params
            .get("message")
            .filter(|m| m.is_object())
            .ok_or_else(|| invalid("params.message must be a Message"))?;
        if message.get("role").and_then(Value::as_str) != Some(ROLE_USER) {
            return Err(invalid(format!("message.role must be {ROLE_USER}")));
        }
        if message
            .get("messageId")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(invalid("message.messageId must be a non-empty string"));
        }
        let (text, data) = read_parts(message)?;
        let context_id = message.get("contextId").and_then(Value::as_str);
        let (task_id, ctx_id, input, mut context, answers) =
            match message.get("taskId").and_then(Value::as_str) {
                None => {
                    if text.trim().is_empty() {
                        return Err(invalid("a new task needs a text part"));
                    }
                    let ctx_id = context_id
                        .map(str::to_string)
                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                    (
                        uuid::Uuid::new_v4().to_string(),
                        ctx_id,
                        text,
                        data,
                        Vec::new(),
                    )
                }
                Some(task_id) => self.answer_of(task_id, context_id, &text, &data)?,
            };
        if !answers.is_empty() {
            context.insert("answers".into(), Value::Array(answers.clone()));
        }
        let request_id = new_request_id();
        let inv = Invocation {
            agent: self.agent.to_string(),
            input: input.clone(),
            context_json: if context.is_empty() {
                String::new()
            } else {
                Value::Object(context.clone()).to_string()
            },
            request_id: request_id.clone(),
            trace: self.trace.clone(),
            caller: self.caller.to_string(),
            caller_agent: None,
            depth: 0,
            deadline: None,
        };
        let mut base = context;
        base.remove("answers");
        // a working task: a second answer waits for this run's (GetTask shows it working)
        self.state.a2a_tasks.put(
            task_id.clone(),
            Task {
                caller: self.caller.to_string(),
                agent: self.agent.to_string(),
                context_id: ctx_id.clone(),
                input: input.clone(),
                context: base.clone(),
                answers: answers.clone(),
                questions: Vec::new(),
                json: task_json(
                    &task_id,
                    &ctx_id,
                    json!({"state": state::WORKING, "timestamp": now()}),
                    None,
                ),
                updated: Instant::now(),
            },
        );
        // an A2A caller carries no person's token: a tool with `delegation` is refused in this run
        let resp = pipeline::invoke(self.state, inv).await;
        let (status, artifacts, questions) = outcome(&resp, &task_id, &ctx_id);
        let mut json = task_json(&task_id, &ctx_id, status, artifacts);
        json["metadata"] = json!({"agentsc.io/request_id": request_id});
        self.state.a2a_tasks.put(
            task_id.clone(),
            Task {
                caller: self.caller.to_string(),
                agent: self.agent.to_string(),
                context_id: ctx_id,
                input,
                context: base,
                answers,
                questions,
                json: json.clone(),
                updated: Instant::now(),
            },
        );
        Ok((json, request_id))
    }

    /// The task a message answers: its id, context id, first input and context, and every answer
    /// with this one added. The text answers the last run's questions; a data part's `answers`
    /// list (`[{"question", "answer"}]`) answers them one by one.
    #[allow(clippy::type_complexity)]
    fn answer_of(
        &self,
        task_id: &str,
        context_id: Option<&str>,
        text: &str,
        data: &serde_json::Map<String, Value>,
    ) -> Result<
        (
            String,
            String,
            String,
            serde_json::Map<String, Value>,
            Vec<Value>,
        ),
        Value,
    > {
        let tasks = self.state.a2a_tasks.lock();
        let Some(t) = tasks.get(task_id).filter(|t| self.visible(t)) else {
            return Err(Self::not_found(task_id));
        };
        if t.state() != state::INPUT_REQUIRED {
            return Err(rpc_error(
                code::UNSUPPORTED_OPERATION,
                format!("task {task_id:?} is {}, not waiting for input", t.state()),
            ));
        }
        if context_id.is_some_and(|c| c != t.context_id) {
            return Err(invalid("message.contextId is not the task's"));
        }
        let mut answers = t.answers.clone();
        let mut added = false;
        if let Some(list) = data.get("answers") {
            let Some(list) = list.as_array().filter(|l| {
                l.iter().all(|a| {
                    a.get("question").is_some_and(Value::is_string)
                        && a.get("answer").is_some_and(Value::is_string)
                })
            }) else {
                return Err(invalid(
                    "data.answers must be [{\"question\": string, \"answer\": string}]",
                ));
            };
            answers.extend(list.iter().cloned());
            added = !list.is_empty();
        }
        if !text.trim().is_empty() {
            let question = match t.questions.as_slice() {
                [one] => one.question.clone(),
                many => many
                    .iter()
                    .enumerate()
                    .map(|(k, q)| format!("{}. {}", k + 1, q.question))
                    .collect::<Vec<_>>()
                    .join("\n"),
            };
            answers.push(json!({"question": question, "answer": text}));
            added = true;
        }
        if !added {
            return Err(invalid("an answer needs a text part or data.answers"));
        }
        Ok((
            task_id.to_string(),
            t.context_id.clone(),
            t.input.clone(),
            t.context.clone(),
            answers,
        ))
    }
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn task_json(id: &str, context_id: &str, status: Value, artifacts: Option<Value>) -> Value {
    let mut t = json!({"id": id, "contextId": context_id, "status": status});
    if let Some(a) = artifacts {
        t["artifacts"] = a;
    }
    t
}

fn agent_message(task_id: &str, context_id: &str, parts: Value) -> Value {
    json!({
        "messageId": uuid::Uuid::new_v4().to_string(),
        "role": ROLE_AGENT,
        "taskId": task_id,
        "contextId": context_id,
        "parts": parts,
    })
}

/// A run's response as a task status, its artifacts and its questions: `ok` is completed (the
/// output as an artifact) or input-required (the questions, as text and as data); `denied` is
/// rejected and `error` failed, with the rule and reason.
fn outcome(
    resp: &InvokeAgentResponse,
    task_id: &str,
    context_id: &str,
) -> (Value, Option<Value>, Vec<Question>) {
    let ts = now();
    match resp.status.as_str() {
        "ok" if resp.questions.is_empty() => (
            json!({"state": state::COMPLETED, "timestamp": ts}),
            Some(json!([{
                "artifactId": uuid::Uuid::new_v4().to_string(),
                "name": "output",
                "parts": [{"text": resp.output}],
            }])),
            Vec::new(),
        ),
        "ok" => {
            let qs: Vec<Value> = resp
                .questions
                .iter()
                .map(|q| json!({"question": q.question, "recommended": q.recommended}))
                .collect();
            let parts = json!([
                {"text": resp.output},
                {"data": {"questions": qs}, "mediaType": "application/json"},
            ]);
            (
                json!({"state": state::INPUT_REQUIRED, "message": agent_message(task_id, context_id, parts), "timestamp": ts}),
                None,
                resp.questions.clone(),
            )
        }
        status => {
            let st = if status == "denied" {
                state::REJECTED
            } else {
                state::FAILED
            };
            let text = format!("{status} by {}: {}", resp.rule, resp.reason);
            (
                json!({"state": st, "message": agent_message(task_id, context_id, json!([{"text": text}])), "timestamp": ts}),
                None,
                Vec::new(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parts_and_outcomes() {
        let m = json!({"parts": [{"text": "a"}, {"data": {"x": 1}}, {"text": "b"}]});
        let (t, d) = read_parts(&m).unwrap();
        assert_eq!(t, "a\n\nb");
        assert_eq!(Value::Object(d), json!({"x": 1}));
        let err = read_parts(&json!({"parts": [{"url": "https://x"}]})).unwrap_err();
        assert_eq!(err["code"], code::CONTENT_TYPE_NOT_SUPPORTED);
        assert_eq!(
            read_parts(&json!({"parts": []})).unwrap_err()["code"],
            code::INVALID_PARAMS
        );

        let ok = InvokeAgentResponse {
            status: "ok".into(),
            output: "42".into(),
            ..Default::default()
        };
        let (s, a, q) = outcome(&ok, "t", "c");
        assert_eq!(s["state"], state::COMPLETED);
        assert_eq!(a.unwrap()[0]["parts"][0]["text"], "42");
        assert!(q.is_empty());
        let ask = InvokeAgentResponse {
            status: "ok".into(),
            output: "I need …".into(),
            questions: vec![Question {
                question: "Card or credit?".into(),
                recommended: "Credit".into(),
            }],
            ..Default::default()
        };
        let (s, a, q) = outcome(&ask, "t", "c");
        assert_eq!(s["state"], state::INPUT_REQUIRED);
        assert_eq!(s["message"]["role"], ROLE_AGENT);
        assert_eq!(
            s["message"]["parts"][1]["data"]["questions"][0]["recommended"],
            "Credit"
        );
        assert!(a.is_none());
        assert_eq!(q.len(), 1);
        let denied = InvokeAgentResponse {
            status: "denied".into(),
            rule: "guardrail.input_deny.x".into(),
            reason: "no".into(),
            ..Default::default()
        };
        assert_eq!(outcome(&denied, "t", "c").0["state"], state::REJECTED);
    }
}
