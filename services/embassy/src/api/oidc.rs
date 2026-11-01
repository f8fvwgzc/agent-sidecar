//! The console's OIDC sign-in ([`crate::auth::oidc`]): the two ends of the flow, and what the
//! sign-in screen offers.
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use subtle::ConstantTimeEq;

use super::error::Fail;
use super::handlers::PeerIp;
use super::types::{CpAction, CpResult};
use crate::auth::oidc::{self, Pending, Refused};
use crate::auth::session;
use crate::cp_audit::CpAudit;
use crate::hub::Hub;
use crate::store::{Actor, ActorKind};

/// The callback's answer: a same-site navigation carries the `SameSite=Strict` session cookie,
/// which a redirect chain that began at the issuer would not.
const SIGNED_IN: &str = "<!doctype html><html><head><meta charset=\"utf-8\">\
<meta http-equiv=\"refresh\" content=\"0;url=/\"><title>Signed in</title></head>\
<body><a href=\"/\">Continue</a></body></html>";

/// `GET /auth/methods`: what the sign-in screen offers. Public.
pub async fn methods(State(hub): State<Arc<Hub>>) -> Response {
    Json(json!({"token": true, "oidc": hub.auth.oidc().is_some()})).into_response()
}

fn with_cookie(mut resp: Response, cookie: &str) -> Response {
    if let Ok(v) = HeaderValue::from_str(cookie) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn see_other(location: &str) -> Response {
    let mut resp = StatusCode::SEE_OTHER.into_response();
    if let Ok(v) = HeaderValue::from_str(location) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp
}

/// `GET /auth/oidc/login`: to the issuer.
pub async fn login(State(hub): State<Arc<Hub>>) -> Result<Response, Fail> {
    let issuer = hub
        .auth
        .oidc()
        .ok_or_else(|| Fail::not_found("sign-in through OIDC is not configured"))?;
    let now = chrono::Utc::now().timestamp();
    let (location, state) = issuer
        .begin(&hub.auth.session_key(), now)
        .map_err(Fail::internal)?;
    let cookie = oidc::state_cookie(&state, hub.auth.secure_cookies);
    Ok(with_cookie(see_other(&location), &cookie))
}

/// A sign-in that ended without a session: audited, counted against the address, and back to the
/// sign-in screen with `signin=<code>`, which says no more than that.
async fn refuse(hub: &Hub, ip: std::net::IpAddr, code: &str, reason: String) -> Response {
    hub.auth.limiter.record_failure(ip, Instant::now());
    let unknown = Actor {
        name: "unknown".into(),
        kind: ActorKind::Session,
        role: None,
    };
    let mut rec = CpAudit::entry(CpAction::LoginFailed, &unknown, CpResult::Denied);
    rec.reason = Some(format!("OIDC sign-in from {ip}: {reason}"));
    hub.cp_audit.record(rec).await;
    let cookie = oidc::clear_state_cookie(hub.auth.secure_cookies);
    with_cookie(see_other(&format!("/?signin={code}")), &cookie)
}

/// `GET /auth/oidc/callback`: back from the issuer.
pub async fn callback(
    State(hub): State<Arc<Hub>>,
    PeerIp(ip): PeerIp,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Response, Fail> {
    let issuer = hub
        .auth
        .oidc()
        .ok_or_else(|| Fail::not_found("sign-in through OIDC is not configured"))?;
    if hub.auth.limiter.check(ip, Instant::now()).is_err() {
        return Ok(see_other("/?signin=rate_limited"));
    }
    let now = chrono::Utc::now().timestamp();
    let pending: Option<Pending> = headers
        .get(header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(oidc::state_from_cookie_header)
        .and_then(|v| session::verify_json(&hub.auth.session_key(), v))
        .filter(|p: &Pending| p.exp > now);
    let Some(pending) = pending else {
        return Ok(refuse(&hub, ip, "failed", "no sign-in in progress".into()).await);
    };
    let state = q.get("state").map(String::as_str).unwrap_or_default();
    if !bool::from(state.as_bytes().ct_eq(pending.state.as_bytes())) {
        return Ok(refuse(&hub, ip, "failed", "the state does not match".into()).await);
    }
    if q.contains_key("error") {
        // the issuer's text is not repeated: it is whatever the query string says
        return Ok(refuse(&hub, ip, "failed", "the issuer refused".into()).await);
    }
    let Some(code) = q.get("code").filter(|c| !c.is_empty()) else {
        return Ok(refuse(&hub, ip, "failed", "no code".into()).await);
    };
    let (subject, grant) = match issuer.finish(code, &pending).await {
        Ok(signed_in) => signed_in,
        Err(Refused::Failed(why)) => return Ok(refuse(&hub, ip, "failed", why).await),
        Err(Refused::NoAccess { sub }) => {
            let why = format!("subject {sub} has no entry in auth.oidc");
            return Ok(refuse(&hub, ip, "no_access", why).await);
        }
    };
    let seconds = issuer.config.session_seconds;
    let value = hub.auth.new_oidc_session(&subject, seconds);
    let actor = Actor {
        name: grant.name,
        kind: ActorKind::Session,
        role: Some(grant.role),
    };
    hub.cp_audit
        .record(CpAudit::entry(CpAction::Login, &actor, CpResult::Ok))
        .await;
    let page = (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        SIGNED_IN,
    )
        .into_response();
    let page = with_cookie(
        page,
        &hub.auth.session_cookie_for(&value, u64::from(seconds)),
    );
    Ok(with_cookie(
        page,
        &oidc::clear_state_cookie(hub.auth.secure_cookies),
    ))
}
