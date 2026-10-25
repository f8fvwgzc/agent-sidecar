//! The REST/SSE API under `/api/v1` (design §10; contract: `docs/api/openapi.yaml`).
//!
//! - [`types`]: every JSON shape of the OpenAPI document, checked against `ui/fixtures/` by
//!   `tests/fixtures.rs`;
//! - [`ids`]: graph node and edge ids (design §3, §10.1);
//! - [`router`]: the routes, behind [`crate::auth::http::guard`] (Host check, CSRF and content
//!   type on mutations, security headers) and [`cache::conditional`] (`ETag` and `304` on every
//!   `GET`), with the UI files when the `ui` component runs.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::auth::Identity;
use crate::auth::http::HostPolicy;
use crate::hub::Hub;
use crate::names::is_dns_label;
use crate::store::ServiceKey;

pub mod cache;
pub mod edit;
pub mod error;
mod handlers;
pub mod ids;
mod learning;
mod links;
mod live;
pub mod types;
pub mod write;

use error::Fail;
pub use live::KEEPALIVE;

/// The largest request body (a charter is at most 256 KiB of YAML, sent as a JSON string).
pub const MAX_BODY: usize = 2 * 1024 * 1024;

/// The client address of a connection (plain or TLS), for the login rate limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientAddr(pub SocketAddr);

impl
    axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, tokio::net::TcpListener>>
    for ClientAddr
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, tokio::net::TcpListener>) -> Self {
        ClientAddr(*stream.remote_addr())
    }
}

impl
    axum::extract::connect_info::Connected<
        axum::serve::IncomingStream<'_, crate::serve::tls::TlsListener>,
    > for ClientAddr
{
    fn connect_info(
        stream: axum::serve::IncomingStream<'_, crate::serve::tls::TlsListener>,
    ) -> Self {
        ClientAddr(*stream.remote_addr())
    }
}

/// The caller, authenticated: a bearer token, a session, or the `--dev` anonymous viewer.
#[derive(Debug, Clone)]
pub struct Authed(pub Identity);

impl FromRequestParts<Arc<Hub>> for Authed {
    type Rejection = Fail;

    async fn from_request_parts(
        parts: &mut Parts,
        hub: &Arc<Hub>,
    ) -> Result<Self, Self::Rejection> {
        crate::auth::authenticate(&hub.auth, &parts.headers)
            .map(Authed)
            .ok_or_else(Fail::unauthenticated)
    }
}

/// A JSON body; malformed bodies are 400 `invalid` with the parser's message.
#[derive(Debug, Clone)]
pub struct JsonBody<T>(pub T);

impl<T: DeserializeOwned> FromRequest<Arc<Hub>> for JsonBody<T> {
    type Rejection = Fail;

    async fn from_request(req: Request, hub: &Arc<Hub>) -> Result<Self, Self::Rejection> {
        let bytes = Bytes::from_request(req, hub)
            .await
            .map_err(|e| Fail::invalid([format!("the body could not be read: {e}")]))?;
        serde_json::from_slice(&bytes)
            .map(JsonBody)
            .map_err(|e| Fail::invalid([format!("the body is not valid: {e}")]))
    }
}

/// A path's service, checked: DNS labels (else 400), and in the caller's namespaces (else 404,
/// like a service that does not exist).
pub fn service_key(ident: &Identity, ns: &str, svc: &str) -> Result<ServiceKey, Fail> {
    for (what, v) in [("namespace", ns), ("service", svc)] {
        if !is_dns_label(v) {
            return Err(Fail::invalid([format!(
                "{what} {v:?} is not a DNS-1123 label"
            )]));
        }
    }
    if !ident.allows_namespace(ns) {
        return Err(Fail::not_found(format!("no service {ns}/{svc}")));
    }
    Ok(ServiceKey::new(ns, svc))
}

/// A DNS-label path parameter (agent, skill).
pub fn label(what: &str, v: &str) -> Result<(), Fail> {
    if is_dns_label(v) {
        Ok(())
    } else {
        Err(Fail::invalid([format!(
            "{what} {v:?} is not a DNS-1123 label"
        )]))
    }
}

/// `If-Match: "<version>"` (quoted, as in an ETag; bare digits are accepted too).
pub fn if_match(headers: &HeaderMap) -> Result<Option<String>, Fail> {
    let Some(v) = headers.get(header::IF_MATCH) else {
        return Ok(None);
    };
    let s = v.to_str().unwrap_or("").trim();
    let s = s.strip_prefix("W/").unwrap_or(s);
    let inner = s
        .strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .unwrap_or(s);
    if !inner.is_empty() && inner.bytes().all(|b| b.is_ascii_digit()) {
        Ok(Some(inner.to_string()))
    } else {
        Err(Fail::invalid([format!(
            "If-Match {s:?} is not a quoted version such as \"3\""
        )]))
    }
}

/// `If-Match` that must be there.
pub fn require_if_match(headers: &HeaderMap) -> Result<String, Fail> {
    if_match(headers)?.ok_or_else(|| Fail::invalid(["If-Match: \"<version>\" is required"]))
}

/// `If-None-Match: *`.
pub fn if_none_match_any(headers: &HeaderMap) -> bool {
    headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim() == "*")
}

/// A JSON response with `ETag: "<version>"`.
pub fn with_etag<T: Serialize>(status: StatusCode, body: &T, version: &str) -> Response {
    let mut resp = (status, axum::Json(body)).into_response();
    if let Ok(v) = HeaderValue::from_str(&format!("\"{version}\"")) {
        resp.headers_mut().insert(header::ETAG, v);
    }
    resp
}

/// Query parameters, each once.
pub type Query = axum::extract::Query<HashMap<String, String>>;

/// `limit` in `1..=1000` (default `default`).
pub fn limit(q: &HashMap<String, String>, default: usize) -> Result<usize, Fail> {
    match q.get("limit") {
        None => Ok(default),
        Some(v) => match v.parse::<usize>() {
            Ok(n) if (1..=1000).contains(&n) => Ok(n),
            _ => Err(Fail::invalid([format!("limit {v:?} is not in 1..=1000")])),
        },
    }
}

async fn api_not_found() -> Fail {
    Fail::not_found("no such API path")
}

/// The API routes (component `api`), relative to `/api/v1`.
pub fn api_routes() -> Router<Arc<Hub>> {
    Router::new()
        .route("/login", post(handlers::login))
        .route("/logout", post(handlers::logout))
        .route("/whoami", get(handlers::whoami))
        .route("/graph", get(live::graph))
        .route("/services", get(handlers::services))
        .route(
            "/services/{ns}/{svc}",
            axum::routing::delete(handlers::delete_service),
        )
        .route(
            "/services/{ns}/{svc}/charter",
            get(handlers::get_charter).put(handlers::put_charter),
        )
        .route(
            "/services/{ns}/{svc}/charter/validate",
            post(handlers::validate_charter),
        )
        .route(
            "/services/{ns}/{svc}/charter/history",
            get(handlers::history),
        )
        .route(
            "/services/{ns}/{svc}/charter/history/{version}",
            get(handlers::revision),
        )
        .route(
            "/services/{ns}/{svc}/charter/rollback",
            post(handlers::rollback),
        )
        .route("/services/{ns}/{svc}/adopt", post(handlers::adopt))
        .route("/services/{ns}/{svc}/agents", post(links::create_agent))
        .route(
            "/services/{ns}/{svc}/agents/{agent}",
            get(links::get_agent)
                .put(links::put_agent)
                .delete(links::delete_agent),
        )
        .route(
            "/services/{ns}/{svc}/skills/{skill}",
            axum::routing::put(links::put_skill).delete(links::delete_skill),
        )
        .route("/links", post(links::link))
        .route(
            "/services/{ns}/{svc}/memory",
            get(learning::get_memory).put(learning::put_memory),
        )
        .route("/proposals", get(learning::list_proposals))
        .route("/proposals/{id}/approve", post(learning::approve))
        .route("/proposals/{id}/reject", post(learning::reject))
        .route("/events/recent", get(live::recent))
        .route("/events", get(live::events))
        .route("/traces", get(live::traces))
        .route("/traces/{trace_id}", get(live::trace))
        .route("/healthz", get(handlers::healthz))
        .route("/readyz", get(handlers::readyz))
        .fallback(api_not_found)
}

/// Every route of `--http-addr`: the API (`api`), the UI (`ui`), `/healthz` and `/readyz`,
/// behind the Host check, CSRF and content-type checks and the security headers, with
/// conditional GETs ([`cache::conditional`]) inside them.
pub fn router(hub: Arc<Hub>, api: bool, ui: Option<crate::ui_assets::UiFiles>) -> Router {
    let policy = Arc::new(HostPolicy {
        dns_names: hub.opts.dns_names.clone(),
    });
    let mut app: Router<Arc<Hub>> = Router::new()
        .route("/healthz", get(handlers::healthz))
        .route("/readyz", get(handlers::readyz));
    if api {
        // every client's requests are rate limited (ratelimit.rs), probes excepted
        app = app.nest(
            "/api/v1",
            api_routes().route_layer(axum::middleware::from_fn_with_state(
                hub.clone(),
                crate::ratelimit::api_layer,
            )),
        );
    } else {
        app = app.nest("/api/v1", Router::new().fallback(api_not_found));
    }
    let app = match ui {
        Some(files) => app.fallback(move |method: axum::http::Method, uri: axum::http::Uri| {
            let files = files.clone();
            async move { crate::ui_assets::serve(&files, &method, &uri).await }
        }),
        None => app.fallback(api_not_found),
    };
    app.with_state(hub)
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
        // inside the guard, so a 304 carries the security headers like every other response
        .layer(axum::middleware::from_fn(cache::conditional))
        .layer(axum::middleware::from_fn_with_state(
            policy,
            crate::auth::http::guard,
        ))
}
