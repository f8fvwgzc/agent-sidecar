//! App-facing HTTP API on localhost (CONTRACT.md §4.1).
use std::net::SocketAddr;
use std::sync::Arc;

use agentsc_common::trace::{TraceContext, new_request_id};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::pipeline::{self, Invocation};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct InvokeBody {
    pub input: String,
    #[serde(default)]
    pub context: Option<Value>,
}

pub fn router(state: Arc<AppState>) -> Router {
    // Every app route needs the app token when one is configured (design §6.6); the health
    // endpoints stay open.
    let app = Router::new()
        .route("/v1/agents/{name}/invoke", post(invoke))
        .route("/v1/agents", get(list_agents))
        .route("/v1/charter", get(charter))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_token));
    Router::new()
        .merge(app)
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(readyz))
        .with_state(state)
}

pub async fn serve(
    state: Arc<AppState>,
    addr: SocketAddr,
) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let app = router(state);
    let task = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!(error = %e, "http server stopped");
        }
    });
    Ok((bound, task))
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

async fn require_token(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let callee = format!("{} {}", req.method(), req.uri().path());
    let headers = req.headers();
    match crate::app_auth::check(
        &state,
        header(headers, "authorization"),
        header(headers, "traceparent"),
        &callee,
    ) {
        Ok(()) => next.run(req).await,
        Err(v) => {
            let body = json!({ "status": "denied", "rule": v.rule, "reason": v.reason });
            let mut resp = (StatusCode::UNAUTHORIZED, Json(body)).into_response();
            resp.headers_mut()
                .insert("www-authenticate", HeaderValue::from_static("Bearer"));
            resp
        }
    }
}

async fn invoke(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let trace = header(&headers, "traceparent")
        .map(TraceContext::from_traceparent)
        .unwrap_or_else(TraceContext::new_root);
    let request_id = new_request_id();
    let parsed: Result<InvokeBody, _> = serde_json::from_slice(&body);
    let body = match parsed {
        Ok(b) => b,
        Err(e) => {
            let v = json!({ "status": "error", "request_id": request_id, "trace_id": trace.trace_id, "agent": name, "rule": "request.invalid", "reason": format!("body must be {{\"input\": string, \"context\"?: object}}: {e}") });
            return with_headers(StatusCode::BAD_REQUEST, &request_id, &trace, Json(v));
        }
    };
    let inv = Invocation {
        agent: name,
        input: body.input,
        context_json: body.context.map(|c| c.to_string()).unwrap_or_default(),
        request_id: request_id.clone(),
        trace: trace.clone(),
        caller: "local".into(),
        caller_agent: None,
        depth: 0,
        deadline: None,
    };
    let resp = pipeline::invoke(&state, inv).await;
    let status = StatusCode::from_u16(pipeline::http_status(&resp))
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    with_headers(
        status,
        &request_id,
        &trace,
        Json(pipeline::response_json(&resp)),
    )
}

fn with_headers(
    status: StatusCode,
    request_id: &str,
    trace: &TraceContext,
    body: Json<Value>,
) -> Response {
    let mut resp = (status, body).into_response();
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&trace.traceparent()) {
        h.insert("traceparent", v);
    }
    if let Ok(v) = HeaderValue::from_str(request_id) {
        h.insert("x-agentsc-request-id", v);
    }
    resp
}

fn no_charter() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "status": "error", "rule": crate::tools::RULE_NO_CHARTER, "reason": "no charter is loaded yet" })),
    )
        .into_response()
}

async fn list_agents(State(state): State<Arc<AppState>>) -> Response {
    let Some(snap) = state.loaded() else {
        return no_charter();
    };
    let agents: Vec<Value> = snap
        .charter
        .agents
        .iter()
        .map(|a| {
            json!({
                "name": a.name,
                "type": a.agent_type,
                "model": a.model,
                "tools": snap.charter.allowed_tools(a),
            })
        })
        .collect();
    Json(json!({ "agents": agents })).into_response()
}

async fn charter(State(state): State<Arc<AppState>>) -> Response {
    let Some(snap) = state.loaded() else {
        return no_charter();
    };
    Json(serde_json::to_value(&snap.charter).unwrap_or(Value::Null)).into_response()
}

async fn readyz(State(state): State<Arc<AppState>>) -> Response {
    let provider = crate::state::lock(&state.runtime_provider).clone();
    let runtime = state
        .runtime_ready
        .load(std::sync::atomic::Ordering::Relaxed);
    // a probe is also a retry of a failing audit sink (audit.rs)
    state.audit.retry();
    let ready = state.is_ready();
    let audit = state.audit.health();
    let body = json!({
        "ready": ready,
        "runtime": runtime,
        "model_provider": provider,
        "mesh": state.tls().is_some(),
        "charter": state.loaded().is_some(),
        "cert_expires_in_s": state.cert_expires_in_s(),
        "audit": {
            "healthy": audit.healthy,
            "fail_closed": state.audit.fail_closed(),
            "write_errors": audit.write_errors,
            "dropped": audit.dropped,
            "pending_bytes": audit.pending_bytes,
            "last_error": audit.last_error,
        },
    });
    let code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(body)).into_response()
}
