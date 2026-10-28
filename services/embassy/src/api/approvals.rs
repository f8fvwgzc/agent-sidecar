//! Approvals of tool calls (CONTRACT.md §5.4): list, read, approve, deny. Reading needs a viewer
//! in the approval's namespace (else 404); deciding needs an editor there. A deny needs a reason;
//! a decided approval is 409 `not_pending`; an approval past its time is expired, not approved.
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use super::agents::secops;
use super::error::Fail;
use super::handlers::require_role;
use super::types::{CpAction, CpResult, ErrorCode};
use super::{Authed, JsonBody, Query};
use crate::auth::Identity;
use crate::config::Role;
use crate::cp_audit::CpAudit;
use crate::hub::Hub;
use crate::secops::{Approval, ApprovalFilter, ApprovalStatus, MAX_DECISION_REASON};
use crate::store::StoreError;

async fn visible(hub: &Hub, ident: &Identity, id: &str) -> Result<Approval, Fail> {
    match secops(hub)?.get_approval(id).await {
        Ok(a) if ident.allows_namespace(&a.namespace) => Ok(a),
        Ok(_) | Err(StoreError::NotFound) => Err(Fail::not_found(format!("no approval {id}"))),
        Err(e) => Err(Fail::store(e, "")),
    }
}

/// `GET /approvals?status=&namespace=&service=&limit=`: newest first (50, at most 500).
pub async fn list(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    axum::extract::Query(q): Query,
) -> Result<Response, Fail> {
    let status = match q.get("status").filter(|s| !s.is_empty()) {
        None => None,
        Some(s) => Some(ApprovalStatus::parse(s).ok_or_else(|| {
            Fail::invalid([format!(
                "status {s:?} is not pending, approved, denied or expired"
            )])
        })?),
    };
    let limit = match q.get("limit").filter(|s| !s.is_empty()) {
        None => 50,
        Some(l) => match l.parse::<usize>() {
            Ok(n) if (1..=500).contains(&n) => n,
            _ => return Err(Fail::invalid([format!("limit {l:?} is not 1..=500")])),
        },
    };
    let filter = ApprovalFilter {
        status,
        namespace: q.get("namespace").filter(|s| !s.is_empty()).cloned(),
        service: q.get("service").filter(|s| !s.is_empty()).cloned(),
        limit,
    };
    let list: Vec<Approval> = secops(&hub)?
        .list_approvals(&filter)
        .await
        .map_err(|e| Fail::store(e, ""))?
        .into_iter()
        .filter(|a| ident.allows_namespace(&a.namespace))
        .collect();
    Ok(Json(list).into_response())
}

/// `GET /approvals/{id}`.
pub async fn get(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path(id): Path<String>,
) -> Result<Response, Fail> {
    Ok(Json(visible(&hub, &ident, &id).await?).into_response())
}

/// The body of a decision.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionBody {
    #[serde(default)]
    pub reason: String,
}

async fn decide(
    hub: Arc<Hub>,
    ident: Identity,
    id: String,
    body: DecisionBody,
    approve: bool,
) -> Result<Response, Fail> {
    require_role(&ident, Role::Editor)?;
    let a = visible(&hub, &ident, &id).await?;
    let reason = body.reason.trim();
    let result: Result<Approval, Fail> = async {
        if !approve && reason.is_empty() {
            return Err(Fail::invalid(["a deny needs a reason"]));
        }
        if reason.chars().count() > MAX_DECISION_REASON {
            return Err(Fail::invalid([format!(
                "the reason is longer than {MAX_DECISION_REASON} characters"
            )]));
        }
        let now = crate::cp_audit::now_ts();
        let reason = (!reason.is_empty()).then_some(reason);
        let decided = secops(&hub)?
            .decide_approval(&id, approve, &ident.name, reason, &now)
            .await
            .map_err(|e| match e {
                StoreError::Conflict { current } => Fail::new(
                    ErrorCode::NotPending,
                    [format!("the approval is already {current}")],
                ),
                e => Fail::store(e, &format!("no approval {id}")),
            })?;
        crate::secops::approvals::push_decision_of(
            &hub,
            &crate::store::ServiceKey::new(&decided.namespace, &decided.service),
            &decided.id,
        )
        .await;
        if decided.status == ApprovalStatus::Expired {
            return Err(Fail::new(
                ErrorCode::NotPending,
                ["the approval is already expired"],
            ));
        }
        Ok(decided)
    }
    .await;
    let (action, res) = match (&result, approve) {
        (_, true) => (CpAction::ApprovalApprove, &result),
        (_, false) => (CpAction::ApprovalDeny, &result),
    };
    let mut rec = CpAudit::entry(
        action,
        &ident.actor(),
        match res {
            Ok(_) => CpResult::Ok,
            Err(f) if f.code() == ErrorCode::Invalid => CpResult::Invalid,
            Err(_) => CpResult::Denied,
        },
    );
    rec.namespace = Some(a.namespace.clone());
    rec.service = Some(a.service.clone());
    rec.agent = Some(a.agent.clone());
    let detail = format!("{} in run {}", a.tool, a.request_id);
    rec.reason = Some(match (res, reason.is_empty()) {
        (Ok(_), true) => detail,
        (Ok(_), false) => format!("{detail}: {reason}"),
        (Err(f), _) => format!("{detail}: {}", f.reason()),
    });
    hub.cp_audit.record(rec).await;
    Ok(Json(result?).into_response())
}

/// `POST /approvals/{id}/approve` `{reason?}`: editor.
pub async fn approve(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Result<Response, Fail> {
    // the body is optional: an approval needs no reason
    let body: DecisionBody = if body.iter().all(u8::is_ascii_whitespace) {
        DecisionBody::default()
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| Fail::invalid([format!("the body is not valid: {e}")]))?
    };
    decide(hub, ident, id, body, true).await
}

/// `POST /approvals/{id}/deny` `{reason}`: editor.
pub async fn deny(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path(id): Path<String>,
    JsonBody(body): JsonBody<DecisionBody>,
) -> Result<Response, Fail> {
    decide(hub, ident, id, body, false).await
}
