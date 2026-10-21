//! Session, services and charter endpoints (design §10).
use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;

use agentsc_charter::Charter;
use axum::Json;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::{FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::error::Fail;
use super::types::{
    AdoptRequest, CharterDoc, CharterYaml, CpAction, CpResult, ErrorCode, LoginRequest,
    PendingAdoption, ReadyStatus, RollbackRequest, ServiceSummary, ValidateResult, VersionResult,
};
use super::write::{self, Via, Writer};
use super::{
    Authed, ClientAddr, JsonBody, if_match, if_none_match_any, require_if_match, service_key,
    with_etag,
};
use crate::auth::Identity;
use crate::config::Role;
use crate::cp_audit::CpAudit;
use crate::hub::Hub;
use crate::store::file::sha256_hex;
use crate::store::{
    Actor, ActorKind, ChangeSource, Precondition, ServiceKey, StoreError, StoredCharter,
};

/// The client IP of the connection (unspecified when unknown).
#[derive(Debug, Clone, Copy)]
pub struct PeerIp(pub IpAddr);

impl<S: Send + Sync> FromRequestParts<S> for PeerIp {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(PeerIp(
            parts
                .extensions
                .get::<ConnectInfo<ClientAddr>>()
                .map(|c| c.0.0.ip())
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        ))
    }
}

/// 403 unless the caller has `role`.
pub fn require_role(ident: &Identity, role: Role) -> Result<(), Fail> {
    if ident.has_role(role) {
        Ok(())
    } else {
        Err(Fail::forbidden([format!("this request requires {role}")]))
    }
}

pub fn writer(ident: &Identity) -> Writer {
    Writer {
        actor: ident.actor(),
        role: Some(ident.role),
    }
}

/// The stored charter, or `None` when the service has none.
pub async fn stored(hub: &Hub, key: &ServiceKey) -> Result<Option<StoredCharter>, Fail> {
    match hub.store.get_charter(key).await {
        Ok(c) => Ok(Some(c)),
        Err(StoreError::NotFound) => Ok(None),
        Err(e) => Err(Fail::store(e, "")),
    }
}

/// The stored charter, or 404.
pub async fn stored_or_404(hub: &Hub, key: &ServiceKey) -> Result<StoredCharter, Fail> {
    stored(hub, key)
        .await?
        .ok_or_else(|| Fail::not_found(format!("no charter for {key}")))
}

/// The stored charter, if its version is exactly `if_match`; else 409 with the current version.
/// Every write computes its role-on-diff and its edit against this charter, and the store
/// refuses the write if the version moved since, so a check is never made against a charter
/// other than the one being replaced (design §8.3, §8.4).
pub async fn stored_matching(
    hub: &Hub,
    key: &ServiceKey,
    if_match: &str,
) -> Result<StoredCharter, Fail> {
    let c = stored_or_404(hub, key).await?;
    if c.version != if_match {
        return Err(Fail::conflict(c.version));
    }
    Ok(c)
}

fn version_response(status: StatusCode, s: &StoredCharter) -> Response {
    with_etag(
        status,
        &VersionResult {
            version: s.version.clone(),
        },
        &s.version,
    )
}

// ---- session -----------------------------------------------------------------------------------

pub async fn login(
    State(hub): State<Arc<Hub>>,
    PeerIp(ip): PeerIp,
    JsonBody(req): JsonBody<LoginRequest>,
) -> Result<Response, Fail> {
    let now = Instant::now();
    let unknown = Actor {
        name: "unknown".into(),
        kind: ActorKind::Token,
        role: None,
    };
    if let Err(wait) = hub.auth.limiter.check(ip, now) {
        let mut rec = CpAudit::entry(CpAction::LoginFailed, &unknown, CpResult::Denied);
        rec.reason = Some(format!("rate limited: too many failed logins from {ip}"));
        hub.cp_audit.record(rec).await;
        let mut f = Fail::new(
            ErrorCode::RateLimited,
            [format!("too many failed logins; retry in {wait} s")],
        );
        if let Ok(v) = HeaderValue::from_str(&wait.to_string()) {
            f = f.with_header(header::RETRY_AFTER, v);
        }
        return Err(f);
    }
    let Some(ident) = hub.auth.from_token(&req.token) else {
        hub.auth.limiter.record_failure(ip, now);
        let mut rec = CpAudit::entry(CpAction::LoginFailed, &unknown, CpResult::Denied);
        rec.reason = Some(format!("an unknown token from {ip}"));
        hub.cp_audit.record(rec).await;
        return Err(Fail::unauthenticated());
    };
    let session = hub.auth.new_session(&ident.name);
    let actor = Actor {
        name: ident.name.clone(),
        kind: ActorKind::Session,
        role: Some(ident.role),
    };
    hub.cp_audit
        .record(CpAudit::entry(CpAction::Login, &actor, CpResult::Ok))
        .await;
    let mut resp = Json(ident.whoami()).into_response();
    if let Ok(v) = HeaderValue::from_str(&hub.auth.session_cookie(&session)) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    Ok(resp)
}

pub async fn logout(State(hub): State<Arc<Hub>>, Authed(ident): Authed) -> Response {
    hub.cp_audit
        .record(CpAudit::entry(
            CpAction::Logout,
            &ident.actor(),
            CpResult::Ok,
        ))
        .await;
    let mut resp = StatusCode::NO_CONTENT.into_response();
    if let Ok(v) = HeaderValue::from_str(&hub.auth.clear_cookie()) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

pub async fn whoami(Authed(ident): Authed) -> Response {
    Json(ident.whoami()).into_response()
}

// ---- services ----------------------------------------------------------------------------------

pub async fn services(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
) -> Result<Response, Fail> {
    let mut keys: BTreeSet<ServiceKey> = hub
        .store
        .list_services()
        .await
        .map_err(|e| Fail::store(e, ""))?
        .into_iter()
        .collect();
    keys.extend(hub.registry.services());
    keys.retain(|k| ident.allows_namespace(&k.namespace));
    let pending: BTreeMap<ServiceKey, PendingAdoption> = hub
        .store
        .list_pending_adoptions()
        .await
        .map_err(|e| Fail::store(e, ""))?
        .iter()
        .map(|p| (p.key.clone(), PendingAdoption::from(p)))
        .collect();
    let mut out = Vec::new();
    for key in keys {
        let charter = stored(&hub, &key).await?;
        let instances = hub.registry.instances(&key);
        let memory_version = match &charter {
            Some(_) => Some(
                hub.store
                    .get_memory(&key)
                    .await
                    .map_err(|e| Fail::store(e, ""))?
                    .version,
            ),
            None => None,
        };
        out.push(ServiceSummary {
            status: crate::graph::service_status(
                charter.as_ref().map(|c| c.version.as_str()),
                &instances,
            ),
            epoch: charter.as_ref().map(|c| c.epoch.clone()),
            charter_version: charter.as_ref().map(|c| c.version.clone()),
            memory_version,
            pending_adoption: if charter.is_none() {
                pending.get(&key).cloned()
            } else {
                None
            },
            instances: instances.into_iter().map(|i| i.info).collect(),
            namespace: key.namespace,
            service: key.service,
        });
    }
    Ok(Json(out).into_response())
}

pub async fn delete_service(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path((ns, svc)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Fail> {
    let key = service_key(&ident, &ns, &svc)?;
    require_role(&ident, Role::Admin)?;
    let v = require_if_match(&headers)?;
    let before = stored_matching(&hub, &key, &v).await?;
    let result = hub
        .store
        .delete_service(&key, &v, &ident.actor())
        .await
        .map_err(|e| Fail::store(e, &format!("no charter for {key}")));
    let mut rec = CpAudit::entry(
        CpAction::DeleteService,
        &ident.actor(),
        match &result {
            Ok(()) => CpResult::Ok,
            Err(f) => write::result_of(f),
        },
    );
    rec.namespace = Some(key.namespace.clone());
    rec.service = Some(key.service.clone());
    rec.from_version = Some(before.version.clone());
    rec.sha256_before = Some(sha256_hex(&before.yaml));
    if let Err(f) = &result {
        rec.reason = Some(f.reason());
    }
    hub.cp_audit.record(rec).await;
    result?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---- charter -----------------------------------------------------------------------------------

pub async fn get_charter(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path((ns, svc)): Path<(String, String)>,
) -> Result<Response, Fail> {
    let key = service_key(&ident, &ns, &svc)?;
    let c = stored_or_404(&hub, &key).await?;
    let version = c.version.clone();
    Ok(with_etag(StatusCode::OK, &CharterDoc::from(c), &version))
}

pub async fn put_charter(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path((ns, svc)): Path<(String, String)>,
    headers: HeaderMap,
    JsonBody(body): JsonBody<CharterYaml>,
) -> Result<Response, Fail> {
    let key = service_key(&ident, &ns, &svc)?;
    require_role(&ident, Role::Editor)?;
    let (precondition, before) = if if_none_match_any(&headers) {
        if let Some(c) = stored(&hub, &key).await? {
            return Err(Fail::conflict(c.version));
        }
        (Precondition::NotExists, None)
    } else if let Some(v) = if_match(&headers)? {
        let before = stored_matching(&hub, &key, &v).await?;
        (Precondition::Version(v), Some(before))
    } else {
        return Err(Fail::invalid([
            "If-Match: \"<version>\" (or If-None-Match: * for the first charter) is required",
        ]));
    };
    let s = write::audited_write(
        &hub,
        &writer(&ident),
        CpAction::CharterPut,
        None,
        &key,
        precondition,
        before.as_ref(),
        body.yaml,
        Via::Put,
        ChangeSource::Api,
    )
    .await?;
    Ok(version_response(StatusCode::OK, &s))
}

pub async fn validate_charter(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path((ns, svc)): Path<(String, String)>,
    JsonBody(body): JsonBody<CharterYaml>,
) -> Result<Response, Fail> {
    let key = service_key(&ident, &ns, &svc)?;
    require_role(&ident, Role::Editor)?;
    let cand = write::candidate(&key, body.yaml)?;
    let policy = write::policy_problems(hub.config.load().policy.as_ref(), &cand.charter);
    if !policy.is_empty() {
        return Err(Fail::invalid(policy));
    }
    let skew = write::skew_problems(&hub.registry, &key, &cand.charter);
    if !skew.is_empty() {
        return Err(Fail::new(ErrorCode::VersionSkew, skew));
    }
    let before = stored(&hub, &key).await?;
    let (needs_role, _) = write::needed_role(before.as_ref(), &cand.charter, Via::Put);
    let weakened = before
        .as_ref()
        .and_then(|s| Charter::from_yaml(&s.yaml).ok())
        .map(|old| agentsc_charter::diff::weakened(&old, &cand.charter))
        .unwrap_or_default();
    Ok(Json(ValidateResult {
        charter: cand.json,
        needs_role,
        weakened,
    })
    .into_response())
}

pub async fn history(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path((ns, svc)): Path<(String, String)>,
) -> Result<Response, Fail> {
    let key = service_key(&ident, &ns, &svc)?;
    let h = hub
        .store
        .history(&key)
        .await
        .map_err(|e| Fail::store(e, &format!("no charter for {key}")))?;
    Ok(Json(h).into_response())
}

pub async fn revision(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path((ns, svc, version)): Path<(String, String, String)>,
) -> Result<Response, Fail> {
    let key = service_key(&ident, &ns, &svc)?;
    if version.is_empty() || !version.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Fail::invalid([format!(
            "version {version:?} is not decimal"
        )]));
    }
    let yaml = hub
        .store
        .get_revision(&key, &version)
        .await
        .map_err(|e| Fail::store(e, &format!("no version {version} of {key}")))?;
    Ok(Json(CharterYaml { yaml }).into_response())
}

pub async fn rollback(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path((ns, svc)): Path<(String, String)>,
    headers: HeaderMap,
    JsonBody(body): JsonBody<RollbackRequest>,
) -> Result<Response, Fail> {
    let key = service_key(&ident, &ns, &svc)?;
    require_role(&ident, Role::Admin)?;
    let v = require_if_match(&headers)?;
    let before = stored_matching(&hub, &key, &v).await?;
    let yaml = hub
        .store
        .get_revision(&key, &body.version)
        .await
        .map_err(|e| Fail::store(e, &format!("no version {} of {key}", body.version)))?;
    let s = write::audited_write(
        &hub,
        &writer(&ident),
        CpAction::Rollback,
        None,
        &key,
        Precondition::Version(v),
        Some(&before),
        yaml,
        Via::Rollback,
        ChangeSource::Rollback,
    )
    .await?;
    Ok(version_response(StatusCode::OK, &s))
}

pub async fn adopt(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path((ns, svc)): Path<(String, String)>,
    JsonBody(body): JsonBody<AdoptRequest>,
) -> Result<Response, Fail> {
    let key = service_key(&ident, &ns, &svc)?;
    require_role(&ident, Role::Editor)?;
    if let Some(c) = stored(&hub, &key).await? {
        return Err(Fail::conflict(c.version));
    }
    let pending = hub
        .store
        .list_pending_adoptions()
        .await
        .map_err(|e| Fail::store(e, ""))?
        .into_iter()
        .find(|p| p.key == key && p.sha256 == body.sha256)
        .ok_or_else(|| Fail::not_found(format!("no pending adoption of {key} with that sha256")))?;
    let s = write::audited_write(
        &hub,
        &writer(&ident),
        CpAction::AdoptApprove,
        None,
        &key,
        Precondition::NotExists,
        None,
        pending.yaml,
        Via::Adopt,
        ChangeSource::Adopt,
    )
    .await?;
    let _ = hub.store.take_pending_adoption(&key, &body.sha256).await;
    Ok(version_response(StatusCode::OK, &s))
}

// ---- health ------------------------------------------------------------------------------------

pub async fn healthz() -> Response {
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], "ok").into_response()
}

pub async fn readyz(State(hub): State<Arc<Hub>>) -> Response {
    let components = hub.ready.snapshot();
    let ready = !components.is_empty() && components.values().all(|r| *r);
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(ReadyStatus { ready, components })).into_response()
}
