//! The standalone model gateway (`agentsc-gateway`, docs/LLM-CONNECTION.md): the sidecar's model
//! gateway on its own, without a sidecar, a charter or Kubernetes. Every core of the platform
//! (texc-symphony, onto-intelli, Codex, Claude Code, sidecars in gateway mode) sends its model
//! calls here with a token; the gateway holds the provider keys.
//!
//! - **Wire formats.** `POST /v1/messages` (Anthropic Messages), `POST /v1/chat/completions`
//!   (OpenAI Chat Completions) and `POST /v1/responses` (OpenAI Responses). A call goes to a
//!   provider that speaks its format, unchanged but for the checks below: Anthropic speaks
//!   Messages; OpenAI Chat Completions and Responses; an OpenAI-compatible server Chat
//!   Completions; another attache gateway all three. There is no translation between formats:
//!   a call no provider of its model speaks is refused (`model.wire_unsupported`, naming the
//!   formats that would work).
//! - **Callers** are tenants of the tenants file ([`TenantsFile`]), each with a token (only its
//!   SHA-256 is in the file), sent as `Authorization: Bearer <token>` or `x-api-key: <token>`.
//!   No token or an unknown one is `401`.
//! - **Providers.** The platform's upstream is the LLM connection contract (`LLM_*`) of the
//!   gateway's own process. A tenant may bring its own keys (`providers`): its calls then go to
//!   the first of its providers that speaks the call's format and lists its model, and to the
//!   platform's only with `use_platform: true` (the default for a tenant without providers).
//!   Keys and tokens are files, read again for every call.
//! - **Checks and spend**, as in the sidecar: only allowed request fields, no hosted tools, no
//!   media the provider would fetch from a URL; the most the call can cost is reserved against the
//!   tenant's `max_cost_usd_per_day` before it goes out and settled with the usage the provider
//!   reported, priced from the one table (`agentsc_common::pricing`, plus `--prices-file`). A
//!   call cut before it completed is counted at its reservation. A request that names no output
//!   limit (OpenAI allows that) is reserved as [`DEFAULT_MAX_OUTPUT_TOKENS`].
//! - **Records.** Every call writes a `model_call` audit record on stdout (caller
//!   `tenant:<name>`, callee `<provider>:<model>`, tokens, cost, error); a refusal an `authz` or
//!   `budget` record. Prompts and answers are left out unless `--audit-payloads`.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use agentsc_common::audit::{AuditRecord, AuditWriter, Direction, Kind, Tokens};
use agentsc_common::authz::Verdict;
use agentsc_common::budget::Budgets;
use agentsc_common::llm_contract::{Contract, ProviderKind, SecretSource, Upstream};
use agentsc_common::pricing;
use agentsc_common::trace::TraceContext;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::{
    Ended, HEADER_REQUEST_ID, HEADER_RULE, MAX_REQUEST_BYTES, MODEL_TIMEOUT,
    PROMPT_OVERHEAD_TOKENS, Provider, RULE_INVALID, RULE_NO_PROVIDER, RULE_NOT_ALLOWED,
    RULE_UPSTREAM, Relayed, Wire, anthropic, chain, openai, outcome_error, relay,
};

/// The call's wire format is not one any provider of its model speaks.
pub const RULE_WIRE_UNSUPPORTED: &str = "model.wire_unsupported";
/// The output limit a request reserves when it names none.
pub const DEFAULT_MAX_OUTPUT_TOKENS: u64 = 128_000;
/// The `service` of the gateway's audit records.
pub const SERVICE: &str = "agentsc-gateway";

/// The tenants file (`--tenants-file`, YAML).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantsFile {
    pub tenants: Vec<TenantSpec>,
}

/// One caller of the gateway.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantSpec {
    /// Lowercase letters, digits and `-` (its audit caller is `tenant:<name>`).
    pub name: String,
    /// The SHA-256 (64 hex) of the tenant's token (`printf %s "$TOKEN" | sha256sum`).
    pub token_sha256: String,
    /// The most the tenant may spend per UTC day, in USD; none: no limit.
    #[serde(default)]
    pub max_cost_usd_per_day: Option<f64>,
    /// The models the tenant may call ([`model_matches`] patterns); empty: any.
    #[serde(default)]
    pub models: Vec<String>,
    /// The tenant's own providers (bring your own key), in order of preference.
    #[serde(default)]
    pub providers: Vec<ProviderSpec>,
    /// Whether calls no own provider takes may use the platform's upstream; default: only when
    /// the tenant has no providers.
    #[serde(default)]
    pub use_platform: Option<bool>,
}

/// A tenant's own provider.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSpec {
    /// `anthropic`, `openai` or `openai-compatible`.
    pub kind: String,
    /// Required for `openai-compatible`; else the provider's default.
    #[serde(default)]
    pub base_url: Option<String>,
    /// The key, as a file (a mounted Secret); none for a server that needs none.
    #[serde(default)]
    pub api_key_file: Option<PathBuf>,
    /// The models it serves ([`model_matches`] patterns); empty: any.
    #[serde(default)]
    pub models: Vec<String>,
}

/// `pattern` is a model id, or a prefix ending in `*` (`claude-*`), or `*`.
pub fn model_matches(pattern: &str, model: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => model.starts_with(prefix),
        None => pattern == model,
    }
}

fn any_matches(patterns: &[String], model: &str) -> bool {
    patterns.is_empty() || patterns.iter().any(|p| model_matches(p, model))
}

/// A provider for one wire format, and the models it takes.
struct Route {
    provider: Arc<dyn Provider>,
    models: Vec<String>,
}

/// The providers of one connection: one per wire format it speaks.
fn routes(
    kind: ProviderKind,
    base_url: &str,
    key: Option<SecretSource>,
    models: &[String],
) -> Vec<Route> {
    let route = |provider: Arc<dyn Provider>| Route {
        provider,
        models: models.to_vec(),
    };
    match kind {
        ProviderKind::Anthropic => vec![route(Arc::new(anthropic::Anthropic::with_key(
            key.unwrap_or(SecretSource::Text(String::new())),
            base_url,
        )))],
        ProviderKind::OpenAi => [Wire::ChatCompletions, Wire::Responses]
            .into_iter()
            .map(|w| {
                route(Arc::new(openai::OpenAi::new(
                    kind,
                    w,
                    base_url,
                    key.clone(),
                )))
            })
            .collect(),
        ProviderKind::OpenAiCompatible => vec![route(Arc::new(openai::OpenAi::new(
            kind,
            Wire::ChatCompletions,
            base_url,
            key,
        )))],
    }
}

/// The platform's routes, from the gateway process's own contract.
fn platform_routes(c: &Contract) -> Vec<Route> {
    match &c.upstream {
        Upstream::Provider(p) => routes(p.kind, &p.base_url, p.key.clone(), &[]),
        Upstream::Gateway {
            root, token_file, ..
        } => Wire::ALL
            .into_iter()
            .map(|w| Route {
                provider: Arc::new(chain::Gateway::new(
                    root,
                    SecretSource::File(token_file.clone()),
                    w,
                )),
                models: vec![],
            })
            .collect(),
    }
}

struct Tenant {
    name: String,
    token_sha256: [u8; 32],
    max_cost_usd_per_day: f64,
    models: Vec<String>,
    routes: Vec<Route>,
    platform: bool,
}

fn is_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

fn tenant(spec: TenantSpec) -> Result<Tenant, String> {
    let name = spec.name;
    if !is_name(&name) {
        return Err(format!(
            "tenant {name:?}: a name is lowercase letters, digits and -"
        ));
    }
    let mut token_sha256 = [0u8; 32];
    match hex::decode(&spec.token_sha256) {
        Ok(b) if b.len() == 32 && spec.token_sha256 == spec.token_sha256.to_lowercase() => {
            token_sha256.copy_from_slice(&b)
        }
        _ => {
            return Err(format!(
                "tenant {name}: token_sha256 is not 64 lowercase hex"
            ));
        }
    }
    let max_cost_usd_per_day = match spec.max_cost_usd_per_day {
        None => f64::INFINITY,
        Some(x) if x.is_finite() && x >= 0.0 => x,
        Some(_) => return Err(format!("tenant {name}: max_cost_usd_per_day must be >= 0")),
    };
    let mut own = Vec::new();
    for p in &spec.providers {
        let kind = ProviderKind::parse(&p.kind)
            .ok_or_else(|| format!("tenant {name}: provider kind {:?} is invalid", p.kind))?;
        let base_url = match (&p.base_url, kind.default_base_url()) {
            (Some(b), _) => b.trim_end_matches('/').to_string(),
            (None, Some(d)) => d.to_string(),
            (None, None) => {
                return Err(format!(
                    "tenant {name}: an openai-compatible provider needs base_url"
                ));
            }
        };
        match url::Url::parse(&base_url) {
            Ok(u) if matches!(u.scheme(), "http" | "https") => {}
            _ => return Err(format!("tenant {name}: base_url {base_url:?} is invalid")),
        }
        let key = p.api_key_file.clone().map(SecretSource::File);
        if key.is_none() && kind != ProviderKind::OpenAiCompatible {
            return Err(format!(
                "tenant {name}: a {kind} provider needs api_key_file"
            ));
        }
        own.extend(routes(kind, &base_url, key, &p.models));
    }
    let platform = spec.use_platform.unwrap_or(spec.providers.is_empty());
    Ok(Tenant {
        name,
        token_sha256,
        max_cost_usd_per_day,
        models: spec.models,
        routes: own,
        platform,
    })
}

/// The gateway's state.
pub struct Gateway {
    tenants: Vec<Tenant>,
    platform: Vec<Route>,
    client: reqwest::Client,
    budgets: Arc<Budgets>,
    audit: AuditWriter,
    payloads: bool,
    timeout: Duration,
    retries: u32,
    /// `GET /v1/models`: the contract's models.
    models: Vec<String>,
}

/// What `agentsc-gateway` is started with.
pub struct Settings {
    pub tenants: TenantsFile,
    /// The platform's upstream: the process's `LLM_*`; `None`: tenants' own providers only.
    pub contract: Option<Contract>,
    /// Record prompts and answers in the audit records.
    pub audit_payloads: bool,
    /// Where the audit records go (stdout in `agentsc-gateway`).
    pub audit: AuditWriter,
}

impl Gateway {
    pub fn new(settings: Settings) -> Result<Arc<Self>, String> {
        let mut tenants = Vec::new();
        for spec in settings.tenants.tenants {
            let t = tenant(spec)?;
            if tenants.iter().any(|o: &Tenant| o.name == t.name) {
                return Err(format!("tenant {} is listed twice", t.name));
            }
            if tenants
                .iter()
                .any(|o: &Tenant| o.token_sha256 == t.token_sha256)
            {
                return Err(format!("tenant {}: its token is another tenant's", t.name));
            }
            tenants.push(t);
        }
        let c = settings.contract.as_ref();
        if let Some(Upstream::Provider(p)) = c.map(|c| &c.upstream)
            && p.key.is_none()
            && p.kind != ProviderKind::OpenAiCompatible
        {
            return Err(format!(
                "LLM_API_KEY or LLM_API_KEY_FILE is required with LLM_PROVIDER={}",
                p.kind
            ));
        }
        if c.is_none() && tenants.iter().any(|t| t.platform) {
            return Err("a tenant uses the platform's provider, but no LLM connection contract is set (LLM_PROVIDER or LLM_GATEWAY_URL)".into());
        }
        Ok(Arc::new(Self {
            tenants,
            platform: c.map(platform_routes).unwrap_or_default(),
            client: super::client().map_err(|e| e.to_string())?,
            budgets: Arc::new(Budgets::new()),
            audit: settings.audit,
            payloads: settings.audit_payloads,
            timeout: c.and_then(|c| c.timeout).unwrap_or(MODEL_TIMEOUT),
            retries: c.and_then(|c| c.max_retries).unwrap_or(0),
            models: c
                .map(|c| {
                    std::iter::once(c.model.clone())
                        .chain(c.model_small.clone())
                        .collect()
                })
                .unwrap_or_default(),
        }))
    }

    /// The tenant whose token this is (every tenant is compared, in constant time each).
    fn authenticate(&self, headers: &HeaderMap) -> Option<&Tenant> {
        let bearer = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| {
                v.strip_prefix("Bearer ")
                    .or_else(|| v.strip_prefix("bearer "))
            });
        let token = bearer.or_else(|| headers.get("x-api-key").and_then(|v| v.to_str().ok()))?;
        let digest: [u8; 32] = Sha256::digest(token.trim().as_bytes()).into();
        let mut found = None;
        for t in &self.tenants {
            let same = t
                .token_sha256
                .iter()
                .zip(digest.iter())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0;
            if same && found.is_none() {
                found = Some(t);
            }
        }
        found
    }

    /// The provider for `model` in `wire`, or why there is none.
    fn route(&self, t: &Tenant, wire: Wire, model: &str) -> Result<Arc<dyn Provider>, Verdict> {
        let candidates: Vec<&Route> = t
            .routes
            .iter()
            .chain(self.platform.iter().filter(|_| t.platform))
            .filter(|r| any_matches(&r.models, model))
            .collect();
        if let Some(r) = candidates.iter().find(|r| r.provider.wire() == wire) {
            return Ok(r.provider.clone());
        }
        if candidates.is_empty() {
            return Err(Verdict::deny(
                RULE_NO_PROVIDER,
                format!("no provider of tenant {} serves model {model}", t.name),
            ));
        }
        let mut speak: Vec<&str> = candidates
            .iter()
            .map(|r| r.provider.wire().path())
            .collect();
        speak.dedup();
        Err(Verdict::deny(
            RULE_WIRE_UNSUPPORTED,
            format!(
                "the provider of model {model} does not speak {} (call {} instead)",
                wire.as_str(),
                speak.join(" or ")
            ),
        ))
    }
}

/// The router: the three wire formats, `GET /v1/models`, `/healthz` and `/readyz`.
pub fn router(gw: Arc<Gateway>) -> Router {
    Router::new()
        .route("/v1/messages", post(messages))
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/responses", post(responses))
        .route("/v1/models", get(models))
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/readyz",
            get(|State(gw): State<Arc<Gateway>>| async move {
                let h = gw.audit.health();
                let ready = h.healthy;
                let body = json!({"ready": ready, "tenants": gw.tenants.len(), "platform": !gw.platform.is_empty()});
                let code = if ready {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                };
                (code, axum::Json(body))
            }),
        )
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(gw)
}

/// Serve on `addr`; the bound address and the server task.
pub async fn serve(
    gw: Arc<Gateway>,
    addr: SocketAddr,
) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let app = router(gw);
    Ok((
        bound,
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                tracing::error!(error = %e, "model gateway stopped");
            }
        }),
    ))
}

/// Read the tenants file.
pub fn load_tenants(path: &Path) -> anyhow::Result<TenantsFile> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("--tenants-file {}: {e}", path.display()))?;
    serde_yaml_ng::from_str(&text)
        .map_err(|e| anyhow::anyhow!("--tenants-file {}: {e}", path.display()))
}

/// Read the prices file (`--prices-file`, YAML: `<model>: {input, output, cache_read}`, USD per
/// 1M tokens) into the one price table.
pub fn load_prices(path: &Path) -> anyhow::Result<usize> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("--prices-file {}: {e}", path.display()))?;
    let prices: HashMap<String, pricing::Price> = serde_yaml_ng::from_str(&text)
        .map_err(|e| anyhow::anyhow!("--prices-file {}: {e}", path.display()))?;
    let n = prices.len();
    pricing::add_prices(prices).map_err(|e| anyhow::anyhow!("--prices-file: {e}"))?;
    Ok(n)
}

/// An error answer in `wire`'s shape, with `x-agentsc-rule`.
fn refusal(wire: Wire, status: StatusCode, rule: &str, reason: &str) -> Response {
    let message = format!("{rule}: {reason}");
    let body = match wire {
        Wire::Messages => {
            let kind = match status {
                StatusCode::BAD_REQUEST => "invalid_request_error",
                StatusCode::UNAUTHORIZED => "authentication_error",
                StatusCode::FORBIDDEN => "permission_error",
                _ => "api_error",
            };
            json!({"type": "error", "error": {"type": kind, "message": message}})
        }
        Wire::ChatCompletions | Wire::Responses => {
            let kind = match status {
                StatusCode::BAD_REQUEST => "invalid_request_error",
                StatusCode::UNAUTHORIZED => "authentication_error",
                StatusCode::FORBIDDEN => "permission_error",
                _ => "server_error",
            };
            json!({"error": {"type": kind, "code": rule, "message": message}})
        }
    };
    let mut resp = (status, axum::Json(body)).into_response();
    if let Ok(v) = HeaderValue::from_str(rule) {
        resp.headers_mut().insert(HEADER_RULE, v);
    }
    if status == StatusCode::UNAUTHORIZED {
        resp.headers_mut()
            .insert("www-authenticate", HeaderValue::from_static("Bearer"));
    }
    resp
}

async fn messages(State(gw): State<Arc<Gateway>>, headers: HeaderMap, body: Bytes) -> Response {
    handle(gw, Wire::Messages, headers, body).await
}

async fn chat_completions(
    State(gw): State<Arc<Gateway>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle(gw, Wire::ChatCompletions, headers, body).await
}

async fn responses(State(gw): State<Arc<Gateway>>, headers: HeaderMap, body: Bytes) -> Response {
    handle(gw, Wire::Responses, headers, body).await
}

async fn models(State(gw): State<Arc<Gateway>>, headers: HeaderMap) -> Response {
    if gw.authenticate(&headers).is_none() {
        return refusal(
            Wire::ChatCompletions,
            StatusCode::UNAUTHORIZED,
            "auth.unauthenticated",
            "send a gateway token",
        );
    }
    let data: Vec<Value> = gw
        .models
        .iter()
        .map(|m| json!({"id": m, "object": "model", "owned_by": "agentsc-gateway"}))
        .collect();
    axum::Json(json!({"object": "list", "data": data})).into_response()
}

/// One call on its way.
struct Call {
    gw: Arc<Gateway>,
    wire: Wire,
    request_id: String,
    caller: String,
    callee: String,
    started: Instant,
}

impl Call {
    fn record(&self, kind: Kind, input: Value, output: Value) -> AuditRecord {
        AuditRecord::new(
            kind,
            Direction::Outbound,
            &self.request_id,
            &TraceContext::new_root(),
            None,
            &self.caller,
            None,
            &self.callee,
            input,
            output,
        )
        .latency(self.started)
    }

    fn refuse(&self, status: StatusCode, v: Verdict) -> Response {
        let kind = if v.rule.starts_with("budget.") {
            Kind::Budget
        } else {
            Kind::Authz
        };
        self.gw
            .audit
            .write(self.record(kind, Value::Null, Value::Null).verdict(&v));
        tracing::warn!(rule = %v.rule, reason = %v.reason, caller = %self.caller, "model call refused");
        refusal(self.wire, status, &v.rule, &v.reason)
    }
}

async fn handle(gw: Arc<Gateway>, wire: Wire, headers: HeaderMap, bytes: Bytes) -> Response {
    let Some(tenant) = gw.authenticate(&headers) else {
        tracing::debug!(wire = wire.as_str(), "a call without a known gateway token");
        return refusal(
            wire,
            StatusCode::UNAUTHORIZED,
            "auth.unauthenticated",
            "send the tenant's gateway token as Authorization: Bearer <token> or x-api-key",
        );
    };
    let request_id = headers
        .get(HEADER_REQUEST_ID)
        .or_else(|| headers.get("x-request-id"))
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty() && v.len() <= 128)
        .map(str::to_string)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let mut call = Call {
        gw: gw.clone(),
        wire,
        request_id,
        caller: format!("tenant:{}", tenant.name),
        callee: "model-gateway".into(),
        started: Instant::now(),
    };
    let mut body: Map<String, Value> = match serde_json::from_slice(&bytes) {
        Ok(Value::Object(m)) => m,
        Ok(_) => {
            return call.refuse(
                StatusCode::BAD_REQUEST,
                Verdict::deny(RULE_INVALID, "the request body is not a JSON object"),
            );
        }
        Err(e) => {
            return call.refuse(
                StatusCode::BAD_REQUEST,
                Verdict::deny(RULE_INVALID, format!("the request body is not JSON: {e}")),
            );
        }
    };
    let checked = match wire.check(&body) {
        Ok(c) => c,
        Err(reason) => {
            return call.refuse(StatusCode::BAD_REQUEST, Verdict::deny(RULE_INVALID, reason));
        }
    };
    call.callee = format!("model-gateway:{}", checked.model);
    if !any_matches(&tenant.models, &checked.model) {
        return call.refuse(
            StatusCode::FORBIDDEN,
            Verdict::deny(
                RULE_NOT_ALLOWED,
                format!(
                    "tenant {} may not call model {}",
                    tenant.name, checked.model
                ),
            ),
        );
    }
    let provider = match gw.route(tenant, wire, &checked.model) {
        Ok(p) => p,
        Err(v) => {
            let status = if v.rule == RULE_WIRE_UNSUPPORTED {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::FORBIDDEN
            };
            return call.refuse(status, v);
        }
    };
    call.callee = format!("{}:{}", provider.name(), checked.model);
    let out = if provider.rewrite(&mut body) {
        serde_json::to_vec(&body).unwrap_or_else(|_| bytes.to_vec())
    } else {
        bytes.to_vec()
    };

    // Hold the most this call can cost, then send it.
    let text_bound = out.len() as u64 + PROMPT_OVERHEAD_TOKENS;
    let prompt_bound = if checked.has_media {
        text_bound.max(pricing::context_window(&checked.model))
    } else {
        text_bound
    };
    let max_out = checked.max_tokens.unwrap_or(DEFAULT_MAX_OUTPUT_TOKENS);
    let worst = pricing::worst_case_usd(&checked.model, prompt_bound, max_out);
    let reservation = match gw
        .budgets
        .reserve(&tenant.name, worst, tenant.max_cost_usd_per_day)
    {
        Ok(r) => r,
        Err(v) => return call.refuse(StatusCode::FORBIDDEN, v),
    };
    let upstream = match provider.request(&gw.client, out, &headers) {
        Ok(r) => r.timeout(gw.timeout),
        Err(why) => {
            return call.refuse(
                StatusCode::FORBIDDEN,
                Verdict::deny(RULE_NO_PROVIDER, format!("{}: {why}", provider.name())),
            );
        }
    };
    let input = if gw.payloads {
        Value::Object(body)
    } else {
        json!({"wire": wire.as_str(), "model": checked.model, "stream": checked.stream})
    };
    let model = checked.model.clone();
    let tenant_name = tenant.name.clone();
    let callee = call.callee.clone();
    let relayed = relay(
        upstream,
        gw.retries,
        provider,
        checked.stream,
        callee,
        move |o| {
            let metered = o.metered;
            let metered_cost = pricing::cost_usd(&model, &metered.usage);
            let held = reservation.usd();
            let cost = match metered.ended {
                Ended::Cut => metered_cost.max(held),
                Ended::Completed | Ended::Refused => metered_cost,
            };
            call.gw.budgets.settle(reservation, cost);
            let output = if call.gw.payloads {
                metered.content.clone()
            } else {
                Value::Null
            };
            let mut rec = call.record(Kind::ModelCall, input, output);
            rec.tokens = Some(Tokens {
                input: u32::try_from(metered.usage.prompt_tokens()).unwrap_or(u32::MAX),
                output: u32::try_from(metered.usage.output).unwrap_or(u32::MAX),
            });
            rec.cost_usd = Some(cost);
            rec.error = outcome_error(o.status, &metered, o.abandoned, held);
            call.gw.audit.write(rec);
        },
    )
    .await;
    match relayed {
        Relayed::Answer {
            status,
            mut headers,
            body,
        } => {
            if gw.budgets.spent_today(&tenant_name) > tenant.max_cost_usd_per_day {
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
        Relayed::Unreachable(reason) => {
            refusal(wire, StatusCode::BAD_GATEWAY, RULE_UPSTREAM, &reason)
        }
        Relayed::Ended => refusal(
            wire,
            StatusCode::BAD_GATEWAY,
            RULE_UPSTREAM,
            "the model call ended before it answered",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(yaml: &str) -> TenantsFile {
        serde_yaml_ng::from_str(yaml).unwrap()
    }

    fn sha(token: &str) -> String {
        hex::encode(Sha256::digest(token.as_bytes()))
    }

    #[test]
    fn model_patterns() {
        assert!(model_matches("claude-*", "claude-opus-5-5"));
        assert!(model_matches("*", "anything"));
        assert!(model_matches("gpt-5", "gpt-5") && !model_matches("gpt-5", "gpt-5-mini"));
        assert!(any_matches(&[], "x"), "no patterns: any model");
    }

    #[test]
    fn tenants_are_checked_at_start_up() {
        let gw = |yaml: &str, contract: Option<Contract>| {
            Gateway::new(Settings {
                tenants: spec(yaml),
                contract,
                audit_payloads: false,
                audit: AuditWriter::with_sink(SERVICE, "", vec![], Box::new(std::io::sink())),
            })
            .map(|_| ())
        };
        let t = sha("t");
        assert!(
            gw(&format!("tenants: [{{name: a, token_sha256: {t}}}]"), None)
                .unwrap_err()
                .contains("no LLM connection contract")
        );
        for (yaml, want) in [
            (
                format!("tenants: [{{name: A, token_sha256: {t}}}]"),
                "a name is",
            ),
            (
                "tenants: [{name: a, token_sha256: abc}]".to_string(),
                "64 lowercase hex",
            ),
            (
                format!(
                    "tenants: [{{name: a, token_sha256: {t}, use_platform: false, providers: [{{kind: openai-compatible}}]}}]"
                ),
                "needs base_url",
            ),
            (
                format!(
                    "tenants: [{{name: a, token_sha256: {t}, use_platform: false}}, {{name: b, token_sha256: {t}, use_platform: false}}]"
                ),
                "another tenant's",
            ),
        ] {
            let e = gw(&yaml, None).unwrap_err();
            assert!(e.contains(want), "{want}: {e}");
        }
        assert!(
            serde_yaml_ng::from_str::<TenantsFile>(
                "tenants: [{name: a, token_sha256: x, api_key: sk}]"
            )
            .is_err(),
            "keys are files, never text in the tenants file"
        );
    }
}
