//! The agent registry's endpoints (docs/design/agent-registry.md, CONTRACT.md §5.3): agents by
//! id, a principal or alias resolved, and aliases. Reading needs a viewer in the agent's
//! namespace (an agent outside the caller's namespaces is 404, like one that does not exist);
//! aliases need an admin.
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use super::error::Fail;
use super::handlers::require_role;
use super::types::{CpAction, CpResult, ErrorCode};
use super::{Authed, JsonBody, Query};
use crate::auth::Identity;
use crate::config::Role;
use crate::cp_audit::CpAudit;
use crate::hub::Hub;
use crate::secops::{AgentEntry, AgentFilter, AgentStatus, SecOpsStore};
use crate::store::StoreError;
use agentsc_common::principal::{AgentId, Principal};

/// The SecOps store, or 503 `secops_unavailable`.
pub fn secops(hub: &Hub) -> Result<&Arc<dyn SecOpsStore>, Fail> {
    hub.secops().ok_or_else(|| {
        Fail::new(
            ErrorCode::SecopsUnavailable,
            ["this embassy keeps no AgentSecOps data: run it with a sqlite: or postgres store, or --secops-store"],
        )
    })
}

/// Agent `id`, if the caller may see it; else 404 (as for an agent that does not exist).
async fn visible_agent(hub: &Hub, ident: &Identity, id: &str) -> Result<AgentEntry, Fail> {
    let missing = || Fail::not_found(format!("no agent {id}"));
    if AgentId::parse(id).is_err() {
        return Err(Fail::invalid([format!(
            "{id:?} is not an agent id (agt_<uuidv7>)"
        )]));
    }
    match secops(hub)?.get_agent(id).await {
        Ok(a) if ident.allows_namespace(&a.namespace) => Ok(a),
        Ok(_) | Err(StoreError::NotFound) => Err(missing()),
        Err(e) => Err(Fail::store(e, "")),
    }
}

/// `GET /agents?namespace=&service=&status=`: the registry, filtered to the caller's namespaces.
pub async fn list_agents(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    axum::extract::Query(q): Query,
) -> Result<Response, Fail> {
    let status = match q.get("status").map(String::as_str) {
        None | Some("") => None,
        Some(s) => Some(
            AgentStatus::parse(s)
                .ok_or_else(|| Fail::invalid([format!("status {s:?} is not active or retired")]))?,
        ),
    };
    let filter = AgentFilter {
        namespace: q.get("namespace").filter(|s| !s.is_empty()).cloned(),
        service: q.get("service").filter(|s| !s.is_empty()).cloned(),
        status,
    };
    let list: Vec<AgentEntry> = secops(&hub)?
        .list_agents(&filter)
        .await
        .map_err(|e| Fail::store(e, ""))?
        .into_iter()
        .filter(|a| ident.allows_namespace(&a.namespace))
        .collect();
    Ok(Json(list).into_response())
}

/// `GET /agents/{id}`.
pub async fn get_agent(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path(id): Path<String>,
) -> Result<Response, Fail> {
    Ok(Json(visible_agent(&hub, &ident, &id).await?).into_response())
}

/// What `GET /principals?principal=` resolves to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Resolved {
    /// `agent:agt_<uuidv7>`, or an alias of an agent.
    Agent { agent: AgentEntry },
    /// `workload:spiffe://<td>/ns/<ns>/svc/<svc>`: a service and its active agents.
    Workload {
        principal: String,
        namespace: String,
        service: String,
        agents: Vec<AgentEntry>,
    },
}

/// `GET /principals?principal=<agent:…|workload:…|alias>`.
pub async fn resolve_principal(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    axum::extract::Query(q): Query,
) -> Result<Response, Fail> {
    let Some(text) = q.get("principal").filter(|s| !s.is_empty()) else {
        return Err(Fail::invalid(["the query parameter principal is required"]));
    };
    let store = secops(&hub)?;
    let missing = || Fail::not_found(format!("no principal {text}"));
    let resolved = match Principal::parse(text) {
        Ok(Principal::Agent(id)) => Resolved::Agent {
            agent: visible_agent(&hub, &ident, id.as_str()).await?,
        },
        Ok(Principal::Workload(w)) => {
            if w.trust_domain != hub.opts.trust_domain || !ident.allows_namespace(&w.namespace) {
                return Err(missing());
            }
            let agents = store
                .list_agents(&AgentFilter {
                    namespace: Some(w.namespace.clone()),
                    service: Some(w.service.clone()),
                    status: Some(AgentStatus::Active),
                })
                .await
                .map_err(|e| Fail::store(e, ""))?;
            Resolved::Workload {
                principal: text.clone(),
                namespace: w.namespace,
                service: w.service,
                agents,
            }
        }
        Err(_) => match store.resolve_alias(text).await {
            Ok(a) if ident.allows_namespace(&a.namespace) => Resolved::Agent { agent: a },
            Ok(_) | Err(StoreError::NotFound) => return Err(missing()),
            Err(e) => return Err(Fail::store(e, "")),
        },
    };
    Ok(Json(resolved).into_response())
}

/// The body of `POST /agents/{id}/aliases`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AliasBody {
    pub alias: String,
}

async fn audit_alias(
    hub: &Hub,
    action: CpAction,
    ident: &Identity,
    agent: &AgentEntry,
    alias: &str,
    result: &Result<AgentEntry, Fail>,
) {
    let (res, why) = match result {
        Ok(_) => (CpResult::Ok, None),
        Err(f) if f.code() == ErrorCode::Invalid => (CpResult::Invalid, Some(f.reason())),
        Err(f) => (CpResult::Error, Some(f.reason())),
    };
    let mut rec = CpAudit::entry(action, &ident.actor(), res);
    rec.namespace = Some(agent.namespace.clone());
    rec.service = Some(agent.service.clone());
    rec.agent = Some(agent.name.clone());
    rec.reason = Some(match why {
        None => format!("{} {alias}", agent.principal),
        Some(w) => format!("{} {alias}: {w}", agent.principal),
    });
    hub.cp_audit.record(rec).await;
}

/// `POST /agents/{id}/aliases` `{alias}`: admin. 409 `in_use` when another agent has it.
pub async fn put_alias(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path(id): Path<String>,
    JsonBody(body): JsonBody<AliasBody>,
) -> Result<Response, Fail> {
    require_role(&ident, Role::Admin)?;
    let agent = visible_agent(&hub, &ident, &id).await?;
    let result = match secops(&hub)?
        .put_alias(&id, &body.alias, &ident.actor())
        .await
    {
        Ok(a) => Ok(a),
        Err(StoreError::Conflict { current }) => Err(Fail::in_use([format!(
            "alias {} belongs to agent {current}",
            body.alias
        )])),
        Err(e) => Err(Fail::store(e, &format!("no agent {id}"))),
    };
    audit_alias(
        &hub,
        CpAction::AgentAliasPut,
        &ident,
        &agent,
        &body.alias,
        &result,
    )
    .await;
    Ok(Json(result?).into_response())
}

/// `DELETE /agents/{id}/aliases?alias=`: admin.
pub async fn delete_alias(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path(id): Path<String>,
    axum::extract::Query(q): Query,
) -> Result<Response, Fail> {
    require_role(&ident, Role::Admin)?;
    let Some(alias) = q.get("alias").filter(|s| !s.is_empty()).cloned() else {
        return Err(Fail::invalid(["the query parameter alias is required"]));
    };
    let agent = visible_agent(&hub, &ident, &id).await?;
    let result = secops(&hub)?
        .delete_alias(&id, &alias)
        .await
        .map_err(|e| Fail::store(e, &format!("agent {id} has no alias {alias}")));
    audit_alias(
        &hub,
        CpAction::AgentAliasDelete,
        &ident,
        &agent,
        &alias,
        &result,
    )
    .await;
    Ok(Json(result?).into_response())
}

/// The body of `POST /agents/{id}/quarantine`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineBody {
    pub reason: String,
}

async fn audit_quarantine(
    hub: &Hub,
    action: CpAction,
    ident: &Identity,
    agent: &AgentEntry,
    detail: &str,
    result: &Result<AgentEntry, Fail>,
) {
    let res = match result {
        Ok(_) => CpResult::Ok,
        Err(f) if f.code() == ErrorCode::Invalid => CpResult::Invalid,
        Err(_) => CpResult::Error,
    };
    let mut rec = CpAudit::entry(action, &ident.actor(), res);
    rec.namespace = Some(agent.namespace.clone());
    rec.service = Some(agent.service.clone());
    rec.agent = Some(agent.name.clone());
    rec.reason = Some(match result {
        Ok(_) => format!("{}: {detail}", agent.principal),
        Err(f) => format!("{}: {detail}: {}", agent.principal, f.reason()),
    });
    hub.cp_audit.record(rec).await;
}

/// `POST /agents/{id}/quarantine` `{reason}`: admin. The agent's sidecars refuse everything it
/// does from the push on. 409 `version_conflict` when it is quarantined already.
pub async fn quarantine(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path(id): Path<String>,
    JsonBody(body): JsonBody<QuarantineBody>,
) -> Result<Response, Fail> {
    require_role(&ident, Role::Admin)?;
    let agent = visible_agent(&hub, &ident, &id).await?;
    let result = secops(&hub)?
        .quarantine_agent(
            &id,
            &body.reason,
            &ident.actor(),
            &crate::cp_audit::now_ts(),
        )
        .await
        .map_err(|e| match e {
            StoreError::Conflict { current } => {
                Fail::conflict(current).with_detail(format!("agent {id} is quarantined already"))
            }
            e => Fail::store(e, &format!("no agent {id}")),
        });
    audit_quarantine(
        &hub,
        CpAction::AgentQuarantined,
        &ident,
        &agent,
        body.reason.trim(),
        &result,
    )
    .await;
    let a = result?;
    // a quarantined agent's calls that wait for a person are not approved any more
    crate::secops::approvals::expire_agent(&hub, &a.namespace, &a.service, &a.name).await;
    crate::controlplane::push_agents(
        &hub,
        &crate::store::ServiceKey::new(&a.namespace, &a.service),
    )
    .await;
    Ok(Json(a).into_response())
}

/// `POST /agents/{id}/release`: admin. 409 when the agent is not quarantined.
pub async fn release(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path(id): Path<String>,
) -> Result<Response, Fail> {
    require_role(&ident, Role::Admin)?;
    let agent = visible_agent(&hub, &ident, &id).await?;
    let result = secops(&hub)?.release_agent(&id).await.map_err(|e| match e {
        StoreError::Conflict { current } => {
            Fail::conflict(current).with_detail(format!("agent {id} is not quarantined"))
        }
        e => Fail::store(e, &format!("no agent {id}")),
    });
    audit_quarantine(
        &hub,
        CpAction::AgentReleased,
        &ident,
        &agent,
        "released",
        &result,
    )
    .await;
    let a = result?;
    crate::controlplane::push_agents(
        &hub,
        &crate::store::ServiceKey::new(&a.namespace, &a.service),
    )
    .await;
    Ok(Json(a).into_response())
}
