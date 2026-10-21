//! Agent, skill and link endpoints (design §10, AgentView cascades and `/links`).
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use super::edit;
use super::error::Fail;
use super::handlers::{require_role, stored_or_404, writer};
use super::types::{
    AgentView, CpAction, LinkApplied, LinkRequest, LinkResult, Skill, VersionResult,
};
use super::write::{self, Via};
use super::{Authed, JsonBody, label, require_if_match, service_key, with_etag};
use crate::auth::Identity;
use crate::config::Role;
use crate::hub::Hub;
use crate::names::is_dns_label;
use crate::store::{ChangeSource, Precondition, ServiceKey, StoredCharter};

/// Apply `change` to the stored charter and write it (If-Match `version`), audited as
/// `action` whether the change, the checks or the store refuse it.
async fn edit_write(
    hub: &Hub,
    ident: &Identity,
    action: CpAction,
    agent: Option<&str>,
    key: &ServiceKey,
    version: String,
    change: impl FnOnce(&mut Value) -> Result<(), Fail>,
) -> Result<StoredCharter, Fail> {
    let before = stored_or_404(hub, key).await?;
    let mut json = before.charter_json.clone();
    let yaml = match change(&mut json).and_then(|()| edit::to_yaml(&json)) {
        Ok(y) => y,
        Err(f) => {
            let result = Err(f.clone());
            write::audit_write(
                hub,
                action,
                &ident.actor(),
                key,
                agent,
                Some(&before),
                &result,
            )
            .await;
            return Err(f);
        }
    };
    write::audited_write(
        hub,
        &writer(ident),
        action,
        agent,
        key,
        Precondition::Version(version),
        Some(&before),
        yaml,
        Via::Edit,
        ChangeSource::Api,
    )
    .await
}

fn version(status: StatusCode, s: &StoredCharter) -> Response {
    with_etag(
        status,
        &VersionResult {
            version: s.version.clone(),
        },
        &s.version,
    )
}

pub async fn get_agent(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path((ns, svc, agent)): Path<(String, String, String)>,
) -> Result<Response, Fail> {
    let key = service_key(&ident, &ns, &svc)?;
    label("agent", &agent)?;
    let c = stored_or_404(&hub, &key).await?;
    let view = edit::agent_view(&c.charter_json, &agent)
        .ok_or_else(|| Fail::not_found(format!("no agent {agent} in {key}")))?;
    Ok(with_etag(StatusCode::OK, &view, &c.version))
}

pub async fn create_agent(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path((ns, svc)): Path<(String, String)>,
    headers: HeaderMap,
    JsonBody(view): JsonBody<AgentView>,
) -> Result<Response, Fail> {
    let key = service_key(&ident, &ns, &svc)?;
    require_role(&ident, Role::Editor)?;
    let v = require_if_match(&headers)?;
    let name = view
        .agent
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let s = edit_write(
        &hub,
        &ident,
        CpAction::AgentPost,
        Some(&name),
        &key,
        v,
        |json| edit::add_agent(json, &view).map(|_| ()),
    )
    .await?;
    Ok(version(StatusCode::CREATED, &s))
}

pub async fn put_agent(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path((ns, svc, agent)): Path<(String, String, String)>,
    headers: HeaderMap,
    JsonBody(view): JsonBody<AgentView>,
) -> Result<Response, Fail> {
    let key = service_key(&ident, &ns, &svc)?;
    label("agent", &agent)?;
    require_role(&ident, Role::Editor)?;
    let v = require_if_match(&headers)?;
    let s = edit_write(
        &hub,
        &ident,
        CpAction::AgentPut,
        Some(&agent),
        &key,
        v,
        |json| edit::replace_agent(json, &agent, &view),
    )
    .await?;
    Ok(version(StatusCode::OK, &s))
}

pub async fn delete_agent(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path((ns, svc, agent)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, Fail> {
    let key = service_key(&ident, &ns, &svc)?;
    label("agent", &agent)?;
    require_role(&ident, Role::Editor)?;
    let v = require_if_match(&headers)?;
    let own = key.service.clone();
    let s = edit_write(
        &hub,
        &ident,
        CpAction::AgentDelete,
        Some(&agent),
        &key,
        v,
        |json| edit::delete_agent(json, &own, &agent),
    )
    .await?;
    Ok(version(StatusCode::OK, &s))
}

pub async fn put_skill(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path((ns, svc, skill)): Path<(String, String, String)>,
    headers: HeaderMap,
    JsonBody(body): JsonBody<Skill>,
) -> Result<Response, Fail> {
    let key = service_key(&ident, &ns, &svc)?;
    label("skill", &skill)?;
    require_role(&ident, Role::Editor)?;
    let v = require_if_match(&headers)?;
    let s = edit_write(&hub, &ident, CpAction::SkillPut, None, &key, v, |json| {
        edit::put_skill(json, &skill, &body)
    })
    .await?;
    Ok(version(StatusCode::OK, &s))
}

pub async fn delete_skill(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path((ns, svc, skill)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, Fail> {
    let key = service_key(&ident, &ns, &svc)?;
    label("skill", &skill)?;
    require_role(&ident, Role::Editor)?;
    let v = require_if_match(&headers)?;
    let s = edit_write(&hub, &ident, CpAction::SkillDelete, None, &key, v, |json| {
        edit::delete_skill(json, &skill)
    })
    .await?;
    Ok(version(StatusCode::OK, &s))
}

/// `agent:<ns>/<svc>/<agent>`.
fn agent_id(what: &str, id: &str) -> Result<(String, String, String), Fail> {
    let parts: Vec<&str> = id
        .strip_prefix("agent:")
        .map(|r| r.split('/').collect())
        .unwrap_or_default();
    match parts.as_slice() {
        [ns, svc, agent] if is_dns_label(ns) && is_dns_label(svc) && is_dns_label(agent) => {
            Ok((ns.to_string(), svc.to_string(), agent.to_string()))
        }
        _ => Err(Fail::invalid([format!(
            "{what} {id:?} is not an agent node id (agent:<namespace>/<service>/<agent>)"
        )])),
    }
}

pub async fn link(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    JsonBody(req): JsonBody<LinkRequest>,
) -> Result<Response, Fail> {
    require_role(&ident, Role::Editor)?;
    let (ns, from_svc, from_agent) = agent_id("from", &req.from)?;
    let (to_ns, to_svc, to_agent) = agent_id("to", &req.to)?;
    if ns != to_ns {
        return Err(Fail::invalid([format!(
            "cross-namespace links are refused ({ns} → {to_ns})"
        )]));
    }
    let src = service_key(&ident, &ns, &from_svc)?;
    let dst = service_key(&ident, &ns, &to_svc)?;
    if src == dst && from_agent == to_agent {
        return Err(Fail::invalid(["an agent cannot link to itself"]));
    }
    // only orchestrators declare agent tools: refuse before the callee side is changed
    let source = stored_or_404(&hub, &src).await?;
    let from_spec = crate::store::charter_doc(&source.charter_json)
        .get("agents")
        .and_then(Value::as_array)
        .and_then(|a| {
            a.iter()
                .find(|x| x.get("name").and_then(Value::as_str) == Some(from_agent.as_str()))
        })
        .cloned()
        .ok_or_else(|| Fail::not_found(format!("no agent {from_agent} in {src}")))?;
    if from_spec.get("type").and_then(Value::as_str) != Some("orchestrator") {
        return Err(Fail::invalid([format!(
            "{} is not an orchestrator: only type: orchestrator agents may call other agents",
            req.from
        )]));
    }
    let mut result = LinkResult::default();
    let if_match = |key: &ServiceKey| {
        req.if_match.get(&key.to_string()).cloned().ok_or_else(|| {
            Fail::invalid([format!(
                "if_match has no entry for {key}, which this link changes"
            )])
        })
    };
    if src != dst {
        // the callee side first: its authz.callers admits the caller's service and agent
        let identity = agentsc_charter::spiffe_id(&ns, &from_svc);
        let target = stored_or_404(&hub, &dst).await;
        let needed = match target {
            Ok(c) => {
                let mut probe = c.charter_json.clone();
                edit::link_target(&mut probe, &identity, &from_agent, &to_agent)
            }
            Err(f) => Err(f),
        };
        match needed {
            Ok(false) => {}
            Ok(true) => {
                let outcome = match if_match(&dst) {
                    Ok(v) => {
                        edit_write(
                            &hub,
                            &ident,
                            CpAction::LinkPost,
                            Some(&to_agent),
                            &dst,
                            v,
                            |json| {
                                edit::link_target(json, &identity, &from_agent, &to_agent)
                                    .map(|_| ())
                            },
                        )
                        .await
                    }
                    Err(f) => Err(f),
                };
                match outcome {
                    Ok(s) => result.applied.push(LinkApplied {
                        service: dst.to_string(),
                        version: s.version,
                    }),
                    Err(f) => {
                        result.failed.insert(dst.to_string(), f.body);
                        return Ok(Json(result).into_response());
                    }
                }
            }
            Err(f) => {
                result.failed.insert(dst.to_string(), f.body);
                return Ok(Json(result).into_response());
            }
        }
    }
    let to_service = (src != dst).then_some(to_svc.as_str());
    let same = src == dst;
    let outcome = match if_match(&src) {
        Ok(v) => {
            edit_write(
                &hub,
                &ident,
                CpAction::LinkPost,
                Some(&from_agent),
                &src,
                v,
                |json| {
                    if same
                        && !crate::store::charter_doc(json)
                            .get("agents")
                            .and_then(Value::as_array)
                            .is_some_and(|a| {
                                a.iter().any(|x| {
                                    x.get("name").and_then(Value::as_str) == Some(to_agent.as_str())
                                })
                            })
                    {
                        return Err(Fail::not_found(format!("no agent {to_agent} in {src}")));
                    }
                    edit::link_source(json, &from_agent, &req.tool, to_service, &to_agent)
                },
            )
            .await
        }
        Err(f) => Err(f),
    };
    match outcome {
        Ok(s) => result.applied.push(LinkApplied {
            service: src.to_string(),
            version: s.version,
        }),
        Err(f) => {
            result.failed.insert(src.to_string(), f.body);
        }
    }
    Ok(Json(result).into_response())
}
