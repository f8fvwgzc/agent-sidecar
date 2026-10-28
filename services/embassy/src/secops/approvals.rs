//! Approvals of tool calls in embassy (CONTRACT.md §5.4): what a sidecar asks, a person decides,
//! and the sidecars that wait learn.
//!
//! - [`on_request`]: an `ApprovalRequest` from a sidecar becomes a pending approval that expires
//!   `timeout_s` after embassy took it in (embassy's clock, not the sidecar's). A request it has
//!   already (asked again after a reconnect) is the same one: if it was decided meanwhile, the
//!   decision goes back at once. An agent with [`super::PENDING_MAX`] pending gets a denial.
//! - Decisions and expiries are `ApprovalDecided` store events (PostgreSQL `NOTIFY`s them), so the
//!   replica each waiting sidecar is connected to pushes `ControlMessage.approval_decision` to the
//!   service's instances ([`push_decision_of`]).
//! - [`expirer`] expires pending approvals past their time, every [`EXPIRY_TICK`]; quarantining an
//!   agent expires all of its pending approvals.
use std::sync::Arc;
use std::time::Duration;

use agentsc_proto::{ApprovalDecision, ApprovalRequest, ControlMessage, control_message};
use tokio_util::sync::CancellationToken;

use super::{Approval, ApprovalPut, ApprovalStatus};
use crate::hub::Hub;
use crate::store::ServiceKey;

/// How often [`expirer`] looks for approvals past their time.
pub const EXPIRY_TICK: Duration = Duration::from_secs(1);

/// RFC 3339, milliseconds, UTC, `secs` from now.
fn after(secs: u64) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(i64::try_from(secs).unwrap_or(i64::MAX / 2)))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

/// The `ApprovalDecision` of a decided (or expired) approval.
pub fn decision_message(a: &Approval) -> ControlMessage {
    ControlMessage {
        msg: Some(control_message::Msg::ApprovalDecision(ApprovalDecision {
            id: a.id.clone(),
            decision: a.status.as_str().into(),
            decided_by: a.decided_by.clone().unwrap_or_default(),
            reason: a.reason.clone().unwrap_or_default(),
        })),
    }
}

/// The `approval` SSE event (namespace-scoped) of an approval that was asked for or changed.
pub fn publish(hub: &Hub, a: &Approval) {
    hub.publish(
        crate::api::types::SseEvent::Approval(a.clone()),
        crate::events::Scope::Service {
            namespace: a.namespace.clone(),
            service: a.service.clone(),
        },
    );
}

fn push(hub: &Hub, key: &ServiceKey, msg: &ControlMessage) {
    for o in hub.registry.outboxes(key) {
        crate::controlplane::send(&o, msg.clone());
    }
}

/// Push the decision on approval `id` of `key` to the service's instances (when it is decided).
pub async fn push_decision_of(hub: &Hub, key: &ServiceKey, id: &str) {
    let Some(store) = hub.secops() else {
        return;
    };
    if let Ok(a) = store.get_approval(id).await
        && a.status != ApprovalStatus::Pending
    {
        push(hub, key, &decision_message(&a));
        publish(hub, &a);
    }
}

/// A sidecar of `key` asks for an approval (module docs).
pub async fn on_request(hub: &Hub, key: &ServiceKey, req: ApprovalRequest) {
    let deny = |reason: &str| ControlMessage {
        msg: Some(control_message::Msg::ApprovalDecision(ApprovalDecision {
            id: req.id.clone(),
            decision: "denied".into(),
            decided_by: "embassy".into(),
            reason: reason.into(),
        })),
    };
    let Some(store) = hub.secops() else {
        push(
            hub,
            key,
            &deny("this embassy keeps no approvals (no AgentSecOps store)"),
        );
        return;
    };
    if req.id.is_empty() || req.id.len() > 64 || req.tool.is_empty() || req.agent.is_empty() {
        tracing::debug!(service = %key, "dropping an approval request without an id, agent or tool");
        return;
    }
    let ids = super::registry::active_ids(hub, key)
        .await
        .unwrap_or_default();
    let timeout = u64::from(
        req.timeout_s
            .clamp(1, agentsc_charter::APPROVAL_TIMEOUT_MAX_S),
    );
    let a = Approval {
        id: req.id.clone(),
        namespace: key.namespace.clone(),
        service: key.service.clone(),
        agent_id: ids.get(&req.agent).cloned(),
        agent: req.agent.clone(),
        tool: req.tool.clone(),
        request_id: req.request_id.clone(),
        trace_id: req.trace_id.clone(),
        args_sha256: req.args_sha256.clone(),
        status: ApprovalStatus::Pending,
        requested_at: crate::cp_audit::now_ts(),
        expires_at: after(timeout),
        decided_at: None,
        decided_by: None,
        reason: None,
    };
    match store.put_approval(&a).await {
        Ok(ApprovalPut::Stored(a)) => publish(hub, &a),
        Ok(ApprovalPut::Existing(e)) if e.status != ApprovalStatus::Pending => {
            push(hub, key, &decision_message(&e));
        }
        Ok(ApprovalPut::Existing(_)) => {}
        Ok(ApprovalPut::TooMany) => push(
            hub,
            key,
            &deny(&format!(
                "agent {} has {} approvals pending already",
                req.agent,
                super::PENDING_MAX
            )),
        ),
        Err(e) => {
            tracing::error!(service = %key, error = %e, "keeping an approval request failed");
            push(
                hub,
                key,
                &deny("embassy could not keep the approval request"),
            );
        }
    }
}

/// Expire every pending approval of an agent (its quarantine) and push the expiries.
pub async fn expire_agent(hub: &Hub, namespace: &str, service: &str, agent: &str) {
    let Some(store) = hub.secops() else {
        return;
    };
    match store
        .expire_approvals(
            &crate::cp_audit::now_ts(),
            Some((namespace, service, agent)),
        )
        .await
    {
        Ok(gone) => {
            let key = ServiceKey::new(namespace, service);
            for a in &gone {
                push(hub, &key, &decision_message(a));
                publish(hub, a);
            }
        }
        Err(e) => {
            tracing::error!(error = %e, agent, "expiring a quarantined agent's approvals failed")
        }
    }
}

/// Expire the approvals past their time, every [`EXPIRY_TICK`], until shutdown.
pub async fn expirer(hub: Arc<Hub>, shutdown: CancellationToken) {
    let Some(store) = hub.secops().cloned() else {
        return;
    };
    let mut tick = tokio::time::interval(EXPIRY_TICK);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            () = shutdown.cancelled() => return,
        }
        match store
            .expire_approvals(&crate::cp_audit::now_ts(), None)
            .await
        {
            Ok(gone) => {
                for a in &gone {
                    push(
                        &hub,
                        &ServiceKey::new(&a.namespace, &a.service),
                        &decision_message(a),
                    );
                    publish(&hub, a);
                }
            }
            Err(e) => tracing::warn!(error = %e, "expiring approvals failed"),
        }
    }
}
