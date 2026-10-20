//! App-facing HTTP API on localhost (CONTRACT.md §4.1).
use std::net::SocketAddr;
use std::sync::Arc;

use attache_common::trace::{TraceContext, new_request_id};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
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
    Router::new()
        .route("/v1/agents/{name}/invoke", post(invoke))
        .route("/v1/agents", get(list_agents))
        .route("/v1/charter", get(charter))
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

async fn invoke(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let trace = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
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
        h.insert("x-attache-request-id", v);
    }
    resp
}

async fn list_agents(State(state): State<Arc<AppState>>) -> Json<Value> {
    let agents: Vec<Value> = state
        .charter
        .agents
        .iter()
        .map(|a| {
            json!({
                "name": a.name,
                "type": a.agent_type,
                "model": a.model,
                "tools": state.charter.allowed_tools(a),
            })
        })
        .collect();
    Json(json!({ "agents": agents }))
}

async fn charter(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(serde_json::to_value(&state.charter).unwrap_or(Value::Null))
}

async fn readyz(State(state): State<Arc<AppState>>) -> Response {
    let provider = state.runtime_provider.lock().unwrap().clone();
    let runtime = state
        .runtime_ready
        .load(std::sync::atomic::Ordering::Relaxed);
    let body = json!({ "ready": state.is_ready(), "runtime": runtime, "model_provider": provider, "mesh": state.tls.is_some() });
    let code = if state.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(body)).into_response()
}
