//! The model gateway (CONTRACT.md §4.4): every model call of the runtime goes out through the
//! sidecar, on `unix:<socket-dir>/model.sock`. The runtime is driven by a model and is not
//! trusted with spend, so the sidecar
//!
//! - holds the provider key (the runtime never has it: runtime.rs removes it from the child's
//!   environment) and adds it to the upstream request;
//! - binds every call to a run (`x-agentsc-request-id` + `x-agentsc-agent`): a step of an
//!   Execute in flight, or the one reflection after it returned (design §12);
//! - holds the call to the agent's charter: `model` is the agent's model or its
//!   `harness.fallback_model`, `max_tokens` at most `budgets.max_tokens_per_call`, at most
//!   `max_steps × (1 + max_retries + fallback)` calls per run and no request with `max_steps`
//!   assistant turns already, and only the request fields the provider adapter allows (no
//!   server tools, which bill outside the token price);
//! - reserves the most the call can cost against `budgets.max_cost_usd_per_day` before it goes
//!   out (budget.rs), and settles it with the cost of the usage the provider itself reported,
//!   priced from the one table in `agentsc_common::pricing`;
//! - writes the call's `model_call` record. A call keeps going when the runtime goes away:
//!   the provider bills it, so it is read to the end and counted.
//!
//! The provider's answer reaches the runtime unchanged, streamed as it arrives (status,
//! `retry-after` headers, SSE events, errors), so the runtime's harness classifies and retries
//! exactly as against the provider. A call the gateway refuses gets `403` (`400` for a request it
//! cannot read) with an error body in the provider's shape and `x-agentsc-rule`; a refused budget
//! is remembered for the run, and the invocation's answer names it (pipeline.rs). With
//! `--audit-fail-closed` and a failing audit sink, every call is refused with `503` and
//! `audit.unavailable` before anything else (audit.rs).
//!
//! Providers are adapters ([`Provider`]), each for one wire format ([`Wire`]): the Anthropic
//! Messages API (`POST /v1/messages`, anthropic.rs), OpenAI Chat Completions and Responses
//! (`POST /v1/chat/completions`, `POST /v1/responses`, openai.rs), and the platform's model
//! gateway itself (chain.rs: the LLM connection contract's gateway mode, so the pod holds no
//! provider key). The runtime speaks Messages; the standalone gateway (standalone.rs,
//! `agentsc-gateway`, docs/LLM-CONNECTION.md) serves all three.
pub mod anthropic;
pub mod chain;
pub mod openai;
pub mod standalone;

use std::sync::Arc;
use std::time::{Duration, Instant};

use agentsc_charter::AgentSpec;
use agentsc_common::audit::{AuditRecord, Direction, Kind, Tokens};
use agentsc_common::authz::Verdict;
use agentsc_common::llm_contract::{Contract, ProviderKind, SecretSource, Upstream};
use agentsc_common::pricing::{self, Usage};
use agentsc_common::trace::TraceContext;
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::{Map, Value, json};

use crate::deadline;
use crate::runs::{CallKind, CallLimits, RunState};
use crate::state::AppState;

/// The socket's file name in `--socket-dir`.
pub const SOCKET: &str = "model.sock";
/// The call names no run in flight (or returned in the run window) of a declared agent.
pub const RULE_UNBOUND: &str = "model.unbound";
/// The model is not the agent's `model` or `harness.fallback_model`.
pub const RULE_NOT_ALLOWED: &str = "model.not_allowed";
/// The request is not one the provider adapter lets through.
pub const RULE_INVALID: &str = "model.request_invalid";
/// The sidecar has no key for the provider.
pub const RULE_NO_PROVIDER: &str = "model.provider_unavailable";
/// The upstream call failed before an answer arrived.
pub const RULE_UPSTREAM: &str = "model.upstream_unavailable";
pub const RULE_MAX_TOKENS: &str = "budget.max_tokens_per_call";
pub const RULE_MAX_STEPS: &str = "budget.max_steps";
pub const RULE_DEADLINE: &str = "deadline.exceeded";
/// Headers the runtime binds a call with, and the informational ones its records carry.
pub const HEADER_REQUEST_ID: &str = "x-agentsc-request-id";
pub const HEADER_AGENT: &str = "x-agentsc-agent";
/// `1`, `2`, … for attempts, `fallback` for the fallback model.
pub const HEADER_ATTEMPT: &str = "x-agentsc-attempt";
/// `reflection` for the learning reflection.
pub const HEADER_PURPOSE: &str = "x-agentsc-purpose";
pub const HEADER_RULE: &str = "x-agentsc-rule";
/// The provider's request limit (32 MB).
pub const MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;
/// The longest a model request may take (CONTRACT.md §4.3).
pub const MODEL_TIMEOUT: Duration = Duration::from_secs(600);
/// Added to a request's size in bytes for the most input tokens it can bill: the provider adds
/// its own system prompt for tool use. A text token is at least one byte. A request with images
/// or documents is bounded by the model's context window instead (`pricing::context_window`).
pub const PROMPT_OVERHEAD_TOKENS: u64 = 4096;
/// The `error` of a call whose runtime went away before the answer was read (cf. audit.rs).
pub const CANCELLED: &str = "cancelled: the runtime went away before the answer was read; the call ran to the end and is counted";

/// The API shape of a request: the path it arrives on, how its body is checked and how its
/// answer is metered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Wire {
    /// Anthropic Messages (`/v1/messages`).
    Messages,
    /// OpenAI Chat Completions (`/v1/chat/completions`).
    ChatCompletions,
    /// OpenAI Responses (`/v1/responses`).
    Responses,
}

impl Wire {
    pub const ALL: [Wire; 3] = [Wire::Messages, Wire::ChatCompletions, Wire::Responses];

    /// The request path, from the API root.
    pub fn path(&self) -> &'static str {
        match self {
            Wire::Messages => "/v1/messages",
            Wire::ChatCompletions => "/v1/chat/completions",
            Wire::Responses => "/v1/responses",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Wire::Messages => "anthropic-messages",
            Wire::ChatCompletions => "openai-chat-completions",
            Wire::Responses => "openai-responses",
        }
    }

    /// Check a request body of this shape; `Err` is why it is refused (`model.request_invalid`).
    pub fn check(&self, body: &Map<String, Value>) -> Result<Checked, String> {
        match self {
            Wire::Messages => anthropic::check(body),
            Wire::ChatCompletions => openai::check_chat(body),
            Wire::Responses => openai::check_responses(body),
        }
    }

    /// Change a checked body before it goes out (Chat Completions: ask for the usage of a
    /// stream); `true` when it changed.
    pub fn rewrite(&self, body: &mut Map<String, Value>) -> bool {
        match self {
            Wire::ChatCompletions => openai::rewrite_chat(body),
            Wire::Messages | Wire::Responses => false,
        }
    }

    /// A meter for one answer.
    pub fn meter(&self, stream: bool) -> Box<dyn Meter> {
        match self {
            Wire::Messages => anthropic::meter(stream),
            Wire::ChatCompletions => openai::chat_meter(stream),
            Wire::Responses => openai::responses_meter(stream),
        }
    }
}

/// What a provider adapter made of a request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    pub model: String,
    /// The most output tokens the request asks for (`None`: it names no limit, which only the
    /// OpenAI shapes allow).
    pub max_tokens: Option<u64>,
    pub stream: bool,
    /// Assistant turns already in the conversation: the step this request is (0-based).
    pub assistant_turns: u32,
    /// Images or documents in the request: their tokens are not bounded by its bytes.
    pub has_media: bool,
}

/// How an answer ended, which decides what it is counted at.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Ended {
    /// The provider's answer arrived whole: its usage is what the provider bills.
    Completed,
    /// The provider refused the request (an error status) or it never reached the provider (no
    /// connection): nothing was generated, nothing is billed.
    Refused,
    /// Cut before it completed (the deadline, a timeout, a broken connection, a mid-stream
    /// error): the provider may bill more than it had reported, so the call is counted at its
    /// reservation, the most it could cost.
    #[default]
    Cut,
}

/// What a meter read from one answer.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Metered {
    pub usage: Usage,
    pub ended: Ended,
    /// The content blocks as the provider sent them (`Null` when none arrived).
    pub content: Value,
    pub stop_reason: Option<String>,
    /// The provider's error (`overloaded_error: Overloaded`), mid-stream or as the answer.
    pub error: Option<String>,
}

/// Reads one answer as it streams by, for its usage and content.
pub trait Meter: Send {
    fn feed(&mut self, chunk: &[u8]);
    /// The answer ended; `status` is its HTTP status.
    fn finish(self: Box<Self>, status: StatusCode) -> Metered;
}

/// One upstream model API, in one wire format.
pub trait Provider: Send + Sync {
    /// `anthropic`: the prefix of `model_call` callees (`anthropic:claude-opus-5-5`).
    fn name(&self) -> &'static str;
    /// The wire format it speaks.
    fn wire(&self) -> Wire;
    /// Check a request body; `Err` is the reason it is refused (`model.request_invalid`).
    fn check(&self, body: &Map<String, Value>) -> Result<Checked, String> {
        self.wire().check(body)
    }
    /// See [`Wire::rewrite`].
    fn rewrite(&self, body: &mut Map<String, Value>) -> bool {
        self.wire().rewrite(body)
    }
    /// The upstream request for `body`, with the provider's credentials (read now: a key file
    /// may have been rotated); `Err` when there is no credential to send.
    fn request(
        &self,
        client: &reqwest::Client,
        body: Vec<u8>,
        incoming: &HeaderMap,
    ) -> Result<reqwest::RequestBuilder, String>;
    /// A meter for one answer.
    fn meter(&self, stream: bool) -> Box<dyn Meter> {
        self.wire().meter(stream)
    }
}

/// The providers the sidecar has keys for, and the client their calls go out on.
pub struct Providers {
    /// Where the runtime's Messages calls go: Anthropic, or the platform's model gateway.
    pub anthropic: Option<Arc<dyn Provider>>,
    /// No redirects, the environment's proxy, a connect timeout; each call sets its own deadline.
    pub client: reqwest::Client,
    /// `LLM_TIMEOUT_SECS`: no call takes longer.
    pub timeout: Option<Duration>,
    /// `LLM_MAX_RETRIES`: retries of a connection that could not be made.
    pub retries: u32,
}

/// The client every upstream call goes out on.
pub fn client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .build()?)
}

impl Providers {
    pub fn from_config(config: &crate::Config) -> anyhow::Result<Self> {
        let contract = config.llm_contract.as_ref();
        let anthropic = match (config.anthropic_key()?, contract) {
            (Some(key), _) => Some(Arc::new(anthropic::Anthropic::new(
                key,
                &config.anthropic_base_url,
            )) as Arc<dyn Provider>),
            (None, Some(c)) => Some(sidecar_upstream(c)?),
            (None, None) => None,
        };
        Ok(Self {
            anthropic,
            client: client()?,
            timeout: contract.and_then(|c| c.timeout),
            retries: contract.and_then(|c| c.max_retries).unwrap_or(0),
        })
    }

    /// The wire formats this sidecar can call, by the name the runtime knows them by
    /// (`GET /v1/agentsc/providers`): `anthropic` for Messages, whether to Anthropic itself or
    /// through the platform's gateway.
    pub fn names(&self) -> Vec<&'static str> {
        self.anthropic.iter().map(|_| "anthropic").collect()
    }
}

/// The sidecar's upstream from the LLM connection contract. Its runtime speaks Anthropic
/// Messages, so the contract must name Anthropic, or the platform's gateway (whose Messages
/// endpoint it then calls).
fn sidecar_upstream(c: &Contract) -> anyhow::Result<Arc<dyn Provider>> {
    match &c.upstream {
        Upstream::Provider(p) if p.kind == ProviderKind::Anthropic => {
            let key = p.key.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "LLM_API_KEY or LLM_API_KEY_FILE is required with LLM_PROVIDER=anthropic"
                )
            })?;
            Ok(Arc::new(anthropic::Anthropic::with_key(key, &p.base_url)))
        }
        Upstream::Provider(p) => anyhow::bail!(
            "LLM_PROVIDER={}: the agent runtime speaks Anthropic Messages; set LLM_PROVIDER=anthropic, or use the model gateway (LLM_GATEWAY_URL)",
            p.kind
        ),
        Upstream::Gateway {
            root,
            token_file,
            wire,
        } => {
            if *wire != ProviderKind::Anthropic {
                tracing::warn!(
                    "LLM_PROVIDER={wire} in gateway mode: the agent runtime speaks Anthropic Messages, so the sidecar calls the gateway's /v1/messages"
                );
            }
            Ok(Arc::new(chain::Gateway::new(
                root,
                SecretSource::File(token_file.clone()),
                Wire::Messages,
            )))
        }
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/messages", post(messages))
        .route("/v1/agentsc/providers", get(providers))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(state)
}

/// Serve the gateway on `socket` (removed first if a previous run left it).
pub async fn serve(
    state: Arc<AppState>,
    socket: std::path::PathBuf,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let _ = std::fs::remove_file(&socket);
    let listener = tokio::net::UnixListener::bind(&socket)?;
    let app = router(state);
    Ok(tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!(error = %e, "model gateway stopped");
        }
    }))
}

async fn providers(State(state): State<Arc<AppState>>) -> Response {
    axum::Json(json!({ "providers": state.providers.names() })).into_response()
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
}

/// An error answer in the provider's shape (the runtime's SDK raises its usual classes).
fn refusal(status: StatusCode, rule: &str, reason: &str) -> Response {
    let kind = match status {
        StatusCode::BAD_REQUEST => "invalid_request_error",
        StatusCode::FORBIDDEN => "permission_error",
        _ => "api_error",
    };
    let body = json!({ "type": "error", "error": { "type": kind, "message": format!("{rule}: {reason}") } });
    let mut resp = (status, axum::Json(body)).into_response();
    if let Ok(v) = HeaderValue::from_str(rule) {
        resp.headers_mut().insert(HEADER_RULE, v);
    }
    resp
}

/// One call on its way: who it is for and what the gateway decided so far.
struct Call {
    request_id: String,
    agent: String,
    callee: String,
    started: Instant,
    run: Option<RunState>,
}

impl Call {
    fn trace(&self) -> TraceContext {
        match &self.run {
            Some(r) if !r.trace_id.is_empty() => TraceContext {
                trace_id: r.trace_id.clone(),
                span_id: TraceContext::new_root().span_id,
                parent_span_id: (!r.span_id.is_empty()).then(|| r.span_id.clone()),
            },
            _ => TraceContext::new_root(),
        }
    }

    fn record(&self, kind: Kind, input: Value, output: Value) -> AuditRecord {
        let caller = self
            .run
            .as_ref()
            .map_or(agentsc_charter::LOCAL_IDENTITY, |r| r.caller.as_str());
        let caller_agent = self.run.as_ref().and_then(|r| r.caller_agent.as_deref());
        AuditRecord::new(
            kind,
            Direction::Outbound,
            &self.request_id,
            &self.trace(),
            Some(&self.agent)
                .filter(|a| !a.is_empty())
                .map(String::as_str),
            caller,
            caller_agent,
            &self.callee,
            input,
            output,
        )
        .latency(self.started)
    }

    /// Refuse the call: an `authz` record (`budget` for a budget rule), then the error answer.
    fn refuse(&self, state: &AppState, status: StatusCode, v: Verdict) -> Response {
        let kind = if v.rule.starts_with("budget.") {
            Kind::Budget
        } else {
            Kind::Authz
        };
        state
            .audit
            .write(self.record(kind, Value::Null, Value::Null).verdict(&v));
        if v.rule.starts_with("budget.") {
            state.runs.note_denial(&self.request_id, &self.agent, &v);
        }
        tracing::warn!(rule = %v.rule, reason = %v.reason, request_id = %self.request_id, agent = %self.agent, "model call refused");
        refusal(status, &v.rule, &v.reason)
    }
}

/// The calls one run may make (runs.rs [`CallLimits`]).
fn limits(spec: &AgentSpec, run: Option<&RunState>) -> CallLimits {
    let h = spec.harness_or_default();
    let per_step = 1 + h.max_retries + u32::from(h.fallback_model.is_some());
    let learning = spec.learning_or_default();
    let learns = learning.enabled
        && run.is_some_and(|r| r.caller == agentsc_charter::LOCAL_IDENTITY || learning.from_peers);
    CallLimits {
        calls: spec.budgets.max_steps.saturating_mul(per_step),
        reflections: u32::from(learns),
    }
}

/// `input` of the `model_call` record: what the runtime's records carried (CONTRACT.md §9).
fn record_input(body: &Map<String, Value>, headers: &HeaderMap, kind: CallKind) -> Value {
    let tools: Vec<Value> = body
        .get("tools")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|t| t.get("name").cloned())
        .collect();
    let mut input = json!({
        "system": body.get("system").cloned().unwrap_or(Value::String(String::new())),
        "messages": body.get("messages").cloned().unwrap_or(Value::Array(vec![])),
        "tools": tools,
    });
    if kind == CallKind::Reflection || header(headers, HEADER_PURPOSE) == Some("reflection") {
        input["purpose"] = json!("reflection");
    } else if header(headers, HEADER_ATTEMPT) == Some("fallback") {
        input["fallback"] = json!(true);
    } else if let Some(n) = header(headers, HEADER_ATTEMPT).and_then(|a| a.parse::<u32>().ok()) {
        input["attempt"] = json!(n);
        input["fallback"] = json!(false);
    }
    input
}

/// Response headers the runtime gets from the provider: all but the hop-by-hop ones, the
/// length (the body is re-chunked) and cookies.
fn passthrough(headers: &reqwest::header::HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (k, v) in headers {
        let n = k.as_str();
        if matches!(
            n,
            "connection"
                | "keep-alive"
                | "transfer-encoding"
                | "content-length"
                | "set-cookie"
                | "proxy-authenticate"
                | "upgrade"
                | "trailer"
        ) {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(k.as_str().as_bytes()),
            HeaderValue::from_bytes(v.as_bytes()),
        ) {
            out.append(name, value);
        }
    }
    out
}

async fn messages(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let request_id = header(&headers, HEADER_REQUEST_ID)
        .unwrap_or("")
        .to_string();
    let agent = header(&headers, HEADER_AGENT).unwrap_or("").to_string();
    let mut call = Call {
        request_id: request_id.clone(),
        agent: agent.clone(),
        callee: "model-gateway".into(),
        started: Instant::now(),
        run: None,
    };
    // Fail-closed (audit.rs): no model call goes out while the audit sink fails.
    if let Err(v) = state.audit.check() {
        return call.refuse(&state, StatusCode::SERVICE_UNAVAILABLE, v);
    }
    let Some(provider) = state.providers.anthropic.clone() else {
        return call.refuse(
            &state,
            StatusCode::FORBIDDEN,
            Verdict::deny(
                RULE_NO_PROVIDER,
                "this sidecar has no Anthropic API key (ANTHROPIC_API_KEY or --anthropic-api-key-file)",
            ),
        );
    };
    let Some(snap) = state.loaded() else {
        return call.refuse(
            &state,
            StatusCode::FORBIDDEN,
            Verdict::deny(crate::tools::RULE_NO_CHARTER, "no charter is loaded yet"),
        );
    };
    let unbound = |why: String| Verdict::deny(RULE_UNBOUND, why);
    if request_id.is_empty() || agent.is_empty() {
        return call.refuse(
            &state,
            StatusCode::FORBIDDEN,
            unbound(format!(
                "a model call names its run with {HEADER_REQUEST_ID} and {HEADER_AGENT}"
            )),
        );
    }
    let Some(spec) = snap.charter.agent(&agent) else {
        return call.refuse(
            &state,
            StatusCode::FORBIDDEN,
            unbound(format!("agent {agent:?} is not declared")),
        );
    };
    call.run = state.runs.lookup(&request_id, &agent);
    let body: Map<String, Value> = match serde_json::from_slice(&bytes) {
        Ok(Value::Object(m)) => m,
        Ok(_) => {
            return call.refuse(
                &state,
                StatusCode::BAD_REQUEST,
                Verdict::deny(RULE_INVALID, "the request body is not a JSON object"),
            );
        }
        Err(e) => {
            return call.refuse(
                &state,
                StatusCode::BAD_REQUEST,
                Verdict::deny(RULE_INVALID, format!("the request body is not JSON: {e}")),
            );
        }
    };
    let checked = match provider.check(&body) {
        Ok(c) => c,
        Err(reason) => {
            return call.refuse(
                &state,
                StatusCode::BAD_REQUEST,
                Verdict::deny(RULE_INVALID, reason),
            );
        }
    };
    call.callee = format!("{}:{}", provider.name(), checked.model);
    let harness = spec.harness_or_default();
    if checked.model != spec.model && harness.fallback_model.as_deref() != Some(&checked.model) {
        return call.refuse(
            &state,
            StatusCode::FORBIDDEN,
            Verdict::deny(
                RULE_NOT_ALLOWED,
                format!(
                    "agent {agent} uses model {} (fallback {:?}), not {}",
                    spec.model, harness.fallback_model, checked.model
                ),
            ),
        );
    }
    let max_tokens = u64::from(spec.budgets.max_tokens_per_call.max(1));
    // the Messages check requires max_tokens
    let asked = checked.max_tokens.unwrap_or(u64::MAX);
    if asked > max_tokens {
        return call.refuse(
            &state,
            StatusCode::FORBIDDEN,
            Verdict::deny(
                RULE_MAX_TOKENS,
                format!(
                    "max_tokens {asked} exceeds agent {agent}'s budgets.max_tokens_per_call={max_tokens}"
                ),
            ),
        );
    }

    // Bind the call to its run and count it.
    let max_steps = spec.budgets.max_steps;
    let (kind, run) = match state.runs.admit_model_call(
        &request_id,
        &agent,
        limits(spec, call.run.as_ref()),
        max_steps,
    ) {
        Ok(x) => x,
        Err(None) => {
            return call.refuse(
                &state,
                StatusCode::FORBIDDEN,
                unbound(format!(
                    "no Execute of {agent} for request {request_id:?} in flight or returned in the last {}s",
                    state.runs.window().as_secs()
                )),
            );
        }
        Err(Some(v)) => return call.refuse(&state, StatusCode::FORBIDDEN, v),
    };
    call.run = Some(run.clone());
    if kind == CallKind::Step && checked.assistant_turns >= max_steps {
        return call.refuse(
            &state,
            StatusCode::FORBIDDEN,
            Verdict::deny(
                RULE_MAX_STEPS,
                format!(
                    "the request is step {} of agent {agent}, which has max_steps={max_steps}",
                    checked.assistant_turns + 1
                ),
            ),
        );
    }
    let timeout = match kind {
        CallKind::Step => deadline::budget(run.deadline, MODEL_TIMEOUT),
        CallKind::Reflection => MODEL_TIMEOUT.min(Duration::from_secs(u64::from(
            harness.request_timeout_seconds,
        ))),
    };
    let timeout = state.providers.timeout.map_or(timeout, |t| timeout.min(t));
    if timeout.is_zero() {
        return call.refuse(
            &state,
            StatusCode::FORBIDDEN,
            Verdict::deny(
                RULE_DEADLINE,
                "the Execute's caller stops waiting before a model call could answer",
            ),
        );
    }

    // Hold the most this call can cost, then send it.
    let text_bound = bytes.len() as u64 + PROMPT_OVERHEAD_TOKENS;
    let prompt_bound = if checked.has_media {
        text_bound.max(pricing::context_window(&checked.model))
    } else {
        text_bound
    };
    let worst = pricing::worst_case_usd(&checked.model, prompt_bound, asked);
    let reservation = match state
        .budgets
        .reserve(&agent, worst, spec.budgets.max_cost_usd_per_day)
    {
        Ok(r) => r,
        Err(v) => return call.refuse(&state, StatusCode::FORBIDDEN, v),
    };
    let input = record_input(&body, &headers, kind);
    let upstream = match provider.request(&state.providers.client, bytes.to_vec(), &headers) {
        Ok(r) => r.timeout(timeout),
        Err(why) => {
            return call.refuse(
                &state,
                StatusCode::FORBIDDEN,
                Verdict::deny(RULE_NO_PROVIDER, format!("{}: {why}", provider.name())),
            );
        }
    };
    let model = checked.model.clone();
    let callee = call.callee.clone();
    let task_state = state.clone();
    let retries = state.providers.retries;
    let relayed = relay(
        upstream,
        retries,
        provider,
        checked.stream,
        callee,
        move |o| {
            let state = task_state;
            let metered = o.metered;
            let metered_cost = pricing::cost_usd(&model, &metered.usage);
            let held = reservation.usd();
            let cost = match metered.ended {
                Ended::Cut => metered_cost.max(held),
                Ended::Completed | Ended::Refused => metered_cost,
            };
            state.budgets.settle(reservation, cost);
            state.runs.add_usage(
                &call.request_id,
                &call.agent,
                metered.usage.prompt_tokens(),
                metered.usage.output,
                cost,
            );
            let mut rec = call.record(Kind::ModelCall, input, metered.content.clone());
            rec.tokens = Some(Tokens {
                input: u32::try_from(metered.usage.prompt_tokens()).unwrap_or(u32::MAX),
                output: u32::try_from(metered.usage.output).unwrap_or(u32::MAX),
            });
            rec.cost_usd = Some(cost);
            if metered.stop_reason.as_deref() == Some("refusal") {
                rec = rec.verdict(&Verdict::deny(
                    "model.refusal",
                    "the model refused the request",
                ));
            }
            rec.error = outcome_error(o.status, &metered, o.abandoned, held);
            state.audit.write(rec);
        },
    )
    .await;

    match relayed {
        Relayed::Answer {
            status,
            mut headers,
            body,
        } => {
            if !state
                .budgets
                .check_cost(&agent, spec.budgets.max_cost_usd_per_day)
                .allow
            {
                headers.insert(
                    HEADER_RULE,
                    HeaderValue::from_static(agentsc_common::budget::RULE_COST),
                );
            }
            let mut resp = Response::new(body);
            *resp.status_mut() = status;
            *resp.headers_mut() = headers;
            resp
        }
        Relayed::Unreachable(reason) => refusal(StatusCode::BAD_GATEWAY, RULE_UPSTREAM, &reason),
        Relayed::Ended => refusal(
            StatusCode::BAD_GATEWAY,
            RULE_UPSTREAM,
            "the model call ended before it answered",
        ),
    }
}

/// The `error` of a call's record: the provider's, the HTTP status, or how it was cut. A cut
/// call is counted at its reservation (`held`), and its error says so.
pub(crate) fn outcome_error(
    status: StatusCode,
    metered: &Metered,
    abandoned: bool,
    held: f64,
) -> Option<String> {
    let mut error = match (&metered.error, status.is_success()) {
        (Some(e), _) => Some(e.clone()),
        (None, false) => Some(format!("HTTP {}", status.as_u16())),
        (None, true) if abandoned => Some(CANCELLED.into()),
        (None, true) if metered.ended == Ended::Cut => Some("the answer broke off".into()),
        (None, true) => None,
    };
    if metered.ended == Ended::Cut
        && let Some(e) = error.as_mut()
    {
        e.push_str(&format!(
            "; cut before it completed: counted at its reservation, ${held:.6}"
        ));
    }
    error
}

/// How a relayed call ended, for its record and its budget.
pub struct Outcome {
    pub status: StatusCode,
    pub metered: Metered,
    /// The caller went away before it read the whole answer (which was read to the end anyway).
    pub abandoned: bool,
}

/// What [`relay`] got back first.
pub enum Relayed {
    /// The answer: its status and headers now, its body as it arrives.
    Answer {
        status: StatusCode,
        headers: HeaderMap,
        body: Body,
    },
    /// The upstream could not be reached (the reason names the callee and the error).
    Unreachable(String),
    /// The call ended before it answered.
    Ended,
}

/// The pause before retry `attempt` (1-based) of a connection that could not be made.
fn backoff(attempt: u32) -> Duration {
    Duration::from_millis(250u64.saturating_mul(1 << attempt.saturating_sub(1).min(5)))
        .min(Duration::from_secs(8))
}

/// Send `upstream`, stream the answer back as it arrives through `provider`'s meter, and call
/// `done` once it ended. A connection that cannot be made is tried again up to `retries` times
/// (nothing was sent, so nothing is billed); an answer is never retried here. The answer is read
/// to the end even when the caller goes away: the provider bills it.
pub async fn relay(
    upstream: reqwest::RequestBuilder,
    retries: u32,
    provider: Arc<dyn Provider>,
    stream: bool,
    callee: String,
    done: impl FnOnce(Outcome) + Send + 'static,
) -> Relayed {
    let (head_tx, head_rx) =
        tokio::sync::oneshot::channel::<Result<(StatusCode, HeaderMap), String>>();
    let (body_tx, body_rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(64);
    tokio::spawn(async move {
        let mut attempt = 0;
        let sent = loop {
            let this = match upstream.try_clone() {
                Some(r) if attempt < retries => r,
                _ => break upstream.send().await,
            };
            match this.send().await {
                Err(e) if e.is_connect() => {
                    attempt += 1;
                    tracing::warn!(callee = %callee, attempt, error = %e, "model upstream unreachable; retrying");
                    tokio::time::sleep(backoff(attempt)).await;
                }
                other => break other,
            }
        };
        let (status, metered, abandoned) = match sent {
            Err(e) => {
                let abandoned = head_tx.send(Err(format!("{callee}: {e}"))).is_err();
                let metered = Metered {
                    error: Some(format!("upstream unreachable: {e}")),
                    // a connection never made sent nothing; a timeout may have been billed
                    ended: if e.is_connect() {
                        Ended::Refused
                    } else {
                        Ended::Cut
                    },
                    ..Metered::default()
                };
                (StatusCode::BAD_GATEWAY, metered, abandoned)
            }
            Ok(mut resp) => {
                let status =
                    StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
                let mut abandoned = head_tx
                    .send(Ok((status, passthrough(resp.headers()))))
                    .is_err();
                let mut meter = provider.meter(stream && status.is_success());
                loop {
                    match resp.chunk().await {
                        Ok(Some(chunk)) => {
                            meter.feed(&chunk);
                            if !abandoned && body_tx.send(Ok(chunk)).await.is_err() {
                                abandoned = true;
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            let _ = body_tx
                                .send(Err(std::io::Error::other(e.to_string())))
                                .await;
                            meter.feed(
                                format!(
                                    "event: error\ndata: {}\n\n",
                                    json!({"type": "error", "error": {"type": "transport_error", "message": e.to_string()}})
                                )
                                .as_bytes(),
                            );
                            break;
                        }
                    }
                }
                drop(body_tx);
                (status, meter.finish(status), abandoned)
            }
        };
        done(Outcome {
            status,
            metered,
            abandoned,
        });
    });
    match head_rx.await {
        Ok(Ok((status, headers))) => Relayed::Answer {
            status,
            headers,
            body: Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(body_rx)),
        },
        Ok(Err(reason)) => Relayed::Unreachable(reason),
        Err(_) => Relayed::Ended,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_follow_the_charter() {
        let spec: AgentSpec = serde_json::from_value(json!({
            "name": "a", "model": "claude-opus-5-5",
            "budgets": {"max_steps": 4},
            "harness": {"max_retries": 2, "fallback_model": "claude-sonnet-5-5"},
            "learning": {"enabled": true}
        }))
        .unwrap();
        let local = RunState {
            in_flight: true,
            caller: "local".into(),
            caller_agent: None,
            trace_id: String::new(),
            span_id: String::new(),
            deadline: None,
            depth: 0,
            meter: Default::default(),
        };
        let l = limits(&spec, Some(&local));
        assert_eq!(
            (l.calls, l.reflections),
            (16, 1),
            "4 steps × (1 + 2 retries + fallback)"
        );
        let peer = RunState {
            caller: "spiffe://agentsc/ns/n/svc/s".into(),
            ..local
        };
        assert_eq!(limits(&spec, Some(&peer)).reflections, 0, "no from_peers");
    }

    #[test]
    fn records_keep_the_runtimes_attempt_shape() {
        let body: Map<String, Value> = serde_json::from_value(json!({
            "system": "s", "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"name": "lookup", "input_schema": {}}]
        }))
        .unwrap();
        let mut h = HeaderMap::new();
        h.insert(HEADER_ATTEMPT, HeaderValue::from_static("2"));
        let v = record_input(&body, &h, CallKind::Step);
        assert_eq!(v["tools"], json!(["lookup"]));
        assert_eq!(
            (v["attempt"].clone(), v["fallback"].clone()),
            (json!(2), json!(false))
        );
        h.insert(HEADER_ATTEMPT, HeaderValue::from_static("fallback"));
        assert_eq!(
            record_input(&body, &h, CallKind::Step)["fallback"],
            json!(true)
        );
        assert_eq!(
            record_input(&body, &h, CallKind::Reflection)["purpose"],
            json!("reflection")
        );
    }
}
