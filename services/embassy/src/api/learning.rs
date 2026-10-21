//! Memory and proposal endpoints (design §3, §10): memory exists only for agents with learning
//! enabled; proposal decisions are atomic in the store.
use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use super::error::Fail;
use super::handlers::{require_role, stored_or_404};
use super::types::{CpAction, CpResult, MemoryPut, ProposalDecision, VersionResult};
use super::{Authed, JsonBody, Query, require_if_match, service_key, with_etag};
use crate::auth::Identity;
use crate::config::Role;
use crate::cp_audit::CpAudit;
use crate::hub::Hub;
use crate::store::{
    AgentLearning, MemoryDoc, Note, ProposalFilter, ProposalStatus, ServiceKey, StoreError,
};

/// The most characters of notes one service keeps (design §3).
pub const MAX_MEMORY_CHARS: usize = attache_charter::MAX_MEMORY_CHARS;

pub async fn get_memory(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path((ns, svc)): Path<(String, String)>,
) -> Result<Response, Fail> {
    let key = service_key(&ident, &ns, &svc)?;
    stored_or_404(&hub, &key).await?;
    let m = hub
        .store
        .get_memory(&key)
        .await
        .map_err(|e| Fail::store(e, ""))?;
    let v = m.version.clone();
    Ok(with_etag(StatusCode::OK, &m, &v))
}

/// The notes checked against the stored charter: every agent exists with learning enabled, at
/// most `max_notes` notes, new notes at most `max_note_chars`, the service at most
/// [`MAX_MEMORY_CHARS`].
pub fn check_notes(
    charter_json: &serde_json::Value,
    stored: &MemoryDoc,
    notes: &BTreeMap<String, Vec<Note>>,
) -> Vec<String> {
    let mut errs = Vec::new();
    let mut total = 0usize;
    for (agent, list) in notes {
        let Some(l) = AgentLearning::from_charter(charter_json, agent) else {
            errs.push(format!(
                "agents.{agent}: the stored charter has no agent {agent}"
            ));
            continue;
        };
        if !l.enabled {
            errs.push(format!(
                "agents.{agent}: learning is not enabled for {agent} (memory exists only for agents with learning enabled)"
            ));
            continue;
        }
        if list.len() > l.max_notes {
            errs.push(format!(
                "agents.{agent}: {} notes, learning.max_notes is {}",
                list.len(),
                l.max_notes
            ));
        }
        let kept: Vec<&str> = stored
            .agents
            .get(agent)
            .map(|v| v.iter().map(|n| n.id.as_str()).collect())
            .unwrap_or_default();
        for (i, n) in list.iter().enumerate() {
            let chars = n.text.chars().count();
            total += chars;
            if !kept.contains(&n.id.as_str()) && chars > l.max_note_chars {
                errs.push(format!(
                    "agents.{agent}[{i}]: the note has {chars} characters and learning.max_note_chars is {}",
                    l.max_note_chars
                ));
            }
        }
    }
    if total > MAX_MEMORY_CHARS {
        errs.push(format!(
            "the notes have {total} characters; a service keeps at most {MAX_MEMORY_CHARS}"
        ));
    }
    errs
}

async fn audit_memory(
    hub: &Hub,
    action: CpAction,
    ident: &Identity,
    key: &ServiceKey,
    agent: Option<&str>,
    from: Option<&str>,
    result: &Result<String, Fail>,
) {
    let mut rec = CpAudit::entry(
        action,
        &ident.actor(),
        match result {
            Ok(_) => CpResult::Ok,
            Err(f) => super::write::result_of(f),
        },
    );
    rec.namespace = Some(key.namespace.clone());
    rec.service = Some(key.service.clone());
    rec.agent = agent.map(str::to_string);
    rec.from_version = from.map(str::to_string);
    match result {
        Ok(v) => rec.to_version = Some(v.clone()),
        Err(f) => rec.reason = Some(f.reason()),
    }
    hub.cp_audit.record(rec).await;
}

pub async fn put_memory(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path((ns, svc)): Path<(String, String)>,
    headers: HeaderMap,
    JsonBody(body): JsonBody<MemoryPut>,
) -> Result<Response, Fail> {
    let key = service_key(&ident, &ns, &svc)?;
    require_role(&ident, Role::Editor)?;
    let v = require_if_match(&headers)?;
    let charter = stored_or_404(&hub, &key).await?;
    let memory = hub
        .store
        .get_memory(&key)
        .await
        .map_err(|e| Fail::store(e, ""))?;
    let result: Result<MemoryDoc, Fail> = async {
        if memory.version != v {
            return Err(Fail::conflict(memory.version.clone()));
        }
        let ts = crate::cp_audit::now_ts();
        let notes = body
            .resolve(&memory, &ident.name, &ts, || {
                uuid::Uuid::new_v4().to_string()
            })
            .map_err(Fail::invalid)?;
        let errs = check_notes(&charter.charter_json, &memory, &notes);
        if !errs.is_empty() {
            return Err(Fail::invalid(errs));
        }
        hub.store
            .put_memory(&key, &v, notes, &ident.actor())
            .await
            .map_err(|e| Fail::store(e, ""))
    }
    .await;
    let audited = result
        .as_ref()
        .map(|m| m.version.clone())
        .map_err(Clone::clone);
    audit_memory(
        &hub,
        CpAction::MemoryPut,
        &ident,
        &key,
        None,
        Some(&memory.version),
        &audited,
    )
    .await;
    let m = result?;
    Ok(with_etag(
        StatusCode::OK,
        &VersionResult {
            version: m.version.clone(),
        },
        &m.version,
    ))
}

pub async fn list_proposals(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    axum::extract::Query(q): Query,
) -> Result<Response, Fail> {
    let status = match q.get("status").map(String::as_str) {
        None | Some("") => None,
        Some("pending") => Some(ProposalStatus::Pending),
        Some("approved") => Some(ProposalStatus::Approved),
        Some("rejected") => Some(ProposalStatus::Rejected),
        Some(other) => {
            return Err(Fail::invalid([format!(
                "status {other:?} is not pending, approved or rejected"
            )]));
        }
    };
    let filter = ProposalFilter {
        status,
        namespace: q.get("namespace").filter(|s| !s.is_empty()).cloned(),
        service: q.get("service").filter(|s| !s.is_empty()).cloned(),
    };
    let list: Vec<_> = hub
        .store
        .list_proposals(&filter)
        .await
        .map_err(|e| Fail::store(e, ""))?
        .into_iter()
        .filter(|p| ident.allows_namespace(&p.namespace))
        .collect();
    Ok(Json(list).into_response())
}

async fn decide(
    hub: Arc<Hub>,
    ident: Identity,
    id: String,
    headers: HeaderMap,
    approve: bool,
) -> Result<Response, Fail> {
    require_role(&ident, Role::Editor)?;
    let v = require_if_match(&headers)?;
    let missing = || Fail::not_found(format!("no proposal {id}"));
    let p = match hub.store.get_proposal(&id).await {
        Ok(p) => p,
        Err(StoreError::NotFound) => return Err(missing()),
        Err(e) => return Err(Fail::store(e, "")),
    };
    if !ident.allows_namespace(&p.namespace) {
        return Err(missing());
    }
    let key = ServiceKey::new(&p.namespace, &p.service);
    let actor = ident.actor();
    let result = if approve {
        hub.store.approve_proposal(&key, &id, &v, &actor).await
    } else {
        hub.store.reject_proposal(&key, &id, &v, &actor).await
    }
    .map_err(|e| Fail::store(e, &format!("no proposal {id}")));
    let action = if approve {
        CpAction::ProposalApprove
    } else {
        CpAction::ProposalReject
    };
    let audited = result
        .as_ref()
        .map(|(m, _)| m.version.clone())
        .map_err(Clone::clone);
    audit_memory(
        &hub,
        action,
        &ident,
        &key,
        Some(&p.agent),
        Some(&v),
        &audited,
    )
    .await;
    let (memory, proposal) = result?;
    Ok(with_etag(
        StatusCode::OK,
        &ProposalDecision {
            proposal,
            memory_version: memory.version.clone(),
        },
        &memory.version,
    ))
}

pub async fn approve(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Fail> {
    decide(hub, ident, id, headers, true).await
}

pub async fn reject(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Fail> {
    decide(hub, ident, id, headers, false).await
}
