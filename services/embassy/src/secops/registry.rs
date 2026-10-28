//! The agent registry (docs/design/agent-registry.md, CONTRACT.md §5.3): embassy is the system of
//! record of agents. An agent is declared by its service's charter; the registry gives it a
//! principal of its own, `agent:agt_<uuidv7>`, the first time a stored charter declares it.
//!
//! - **What drives it.** Every stored charter change (API write, adoption, rollback, a file-store
//!   edit, a Charter CR change, and on PostgreSQL the other replicas' writes) is a
//!   `CharterChanged` store event; a deleted service is `ServiceDeleted`. The hub calls
//!   [`sync_service`] for each, and [`reconcile_all`] runs once at start for what changed while
//!   embassy was down. Each sync makes the service's active agents exactly the ones its stored
//!   charter declares ([`crate::secops::SyncPlan`]).
//! - **What a change leaves.** A control-plane audit record per agent (`agent_registered`,
//!   `agent_reactivated`, `agent_retired`; `reason` holds the principal), written by the replica
//!   that made the change, and an `AgentIds` push to the service's connected sidecars, which
//!   stamp the ids on their audit records.
//! - **What it never does.** Delete an agent, reuse an id, or retire an agent because a charter
//!   could not be read: only a charter that is gone or declares other agents retires one.
use std::collections::{BTreeSet, HashMap};

use super::{AgentChange, AgentFilter, AgentStatus, RegistryChange};
use crate::api::types::{CpAction, CpResult};
use crate::cp_audit::CpAudit;
use crate::hub::Hub;
use crate::store::{Actor, ActorKind, ServiceKey, StoreError};

/// The actor of the syncs that no charter write caused (start-up, a lagged event stream).
pub fn registry_actor() -> Actor {
    Actor {
        name: "embassy:registry".into(),
        kind: ActorKind::System,
        role: None,
    }
}

/// The agents the stored charter of `key` declares: `Some(empty)` when the service has no
/// charter, `None` when that cannot be told now (a store error, a charter that does not parse).
pub async fn declared_agents(hub: &Hub, key: &ServiceKey) -> Option<BTreeSet<String>> {
    match hub.store.get_charter(key).await {
        Ok(stored) => {
            let charter = crate::graph::parse_stored(&stored)?;
            Some(charter.agents.iter().map(|a| a.name.clone()).collect())
        }
        Err(StoreError::NotFound) => Some(BTreeSet::new()),
        Err(e) => {
            tracing::warn!(service = %key, error = %e, "agent registry: reading the charter failed; not synced");
            None
        }
    }
}

/// Sync the registry with the stored charter of `key` (module docs), audit what changed as done
/// by `actor`, and push the ids to the service's sidecars. Nothing without a SecOps store.
pub async fn sync_service(hub: &Hub, key: &ServiceKey, actor: &Actor) {
    let Some(secops) = hub.secops() else {
        return;
    };
    let Some(declared) = declared_agents(hub, key).await else {
        return;
    };
    match secops.sync_agents(key, &declared).await {
        Ok(changes) => {
            for c in &changes {
                audit_change(hub, actor, c).await;
            }
        }
        Err(e) => {
            tracing::error!(service = %key, error = %e, "agent registry: sync failed");
        }
    }
    crate::controlplane::push_agents(hub, key).await;
}

/// Sync every service with a stored charter, and retire the agents of services that have none
/// any more (deleted while this embassy was down).
pub async fn reconcile_all(hub: &Hub) {
    let Some(secops) = hub.secops() else {
        return;
    };
    let services = match hub.store.list_services().await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "agent registry: listing the services failed; not reconciled");
            return;
        }
    };
    let actor = registry_actor();
    for key in &services {
        sync_service(hub, key, &actor).await;
    }
    let live: BTreeSet<&ServiceKey> = services.iter().collect();
    let gone: BTreeSet<ServiceKey> = match secops
        .list_agents(&AgentFilter {
            status: Some(AgentStatus::Active),
            ..AgentFilter::default()
        })
        .await
    {
        Ok(agents) => agents
            .into_iter()
            .map(|a| ServiceKey::new(&a.namespace, &a.service))
            .filter(|k| !live.contains(k))
            .collect(),
        Err(e) => {
            tracing::error!(error = %e, "agent registry: listing the agents failed");
            return;
        }
    };
    for key in &gone {
        sync_service(hub, key, &actor).await;
    }
}

/// The active agents of `key`, name → id (what `AgentIds` carries). Empty without a SecOps store.
pub async fn active_ids(
    hub: &Hub,
    key: &ServiceKey,
) -> Result<HashMap<String, String>, StoreError> {
    let Some(secops) = hub.secops() else {
        return Ok(HashMap::new());
    };
    let agents = secops
        .list_agents(&AgentFilter {
            namespace: Some(key.namespace.clone()),
            service: Some(key.service.clone()),
            status: Some(AgentStatus::Active),
        })
        .await?;
    Ok(agents.into_iter().map(|a| (a.name, a.id)).collect())
}

async fn audit_change(hub: &Hub, actor: &Actor, c: &AgentChange) {
    let action = match c.change {
        RegistryChange::Registered => CpAction::AgentRegistered,
        RegistryChange::Reactivated => CpAction::AgentReactivated,
        RegistryChange::Retired => CpAction::AgentRetired,
    };
    let mut rec = CpAudit::entry(action, actor, CpResult::Ok);
    rec.namespace = Some(c.entry.namespace.clone());
    rec.service = Some(c.entry.service.clone());
    rec.agent = Some(c.entry.name.clone());
    rec.reason = Some(c.entry.principal.clone());
    hub.cp_audit.record(rec).await;
}
