//! [`SecOpsStore`] on the PostgreSQL store (migration 2, `postgres_schema_v2.sql`): the agent
//! registry. A sync takes a transaction-scoped advisory lock on its service first, so two
//! replicas syncing the same charter change serialize and the second finds nothing to do.
use std::collections::BTreeSet;

use async_trait::async_trait;
use deadpool_postgres::GenericClient;
use tokio_postgres::Row;

use super::{PgStore, checked_key, now_ts};
use crate::secops::{
    AgentChange, AgentEntry, AgentFilter, AgentStatus, MAX_ALIASES, RegistryChange, SecOpsStore,
    SyncPlan, check_alias,
};
use crate::store::{Actor, ServiceKey, StoreError};
use agentsc_common::principal::AgentId;

const AGENT_SELECT: &str =
    "SELECT id, namespace, service, name, status, created_at, updated_at FROM agents";

fn entry_of(r: &Row) -> AgentEntry {
    let id: String = r.get(0);
    let status: String = r.get(4);
    AgentEntry {
        principal: format!("agent:{id}"),
        id,
        namespace: r.get(1),
        service: r.get(2),
        name: r.get(3),
        status: AgentStatus::parse(&status).unwrap_or(AgentStatus::Retired),
        created_at: r.get(5),
        updated_at: r.get(6),
        aliases: Vec::new(),
    }
}

async fn with_aliases<C: GenericClient + Sync>(
    c: &C,
    mut e: AgentEntry,
) -> Result<AgentEntry, StoreError> {
    e.aliases = c
        .query(
            "SELECT alias FROM agent_aliases WHERE agent_id = $1 ORDER BY alias",
            &[&e.id],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    Ok(e)
}

async fn agent_by_id<C: GenericClient + Sync>(c: &C, id: &str) -> Result<AgentEntry, StoreError> {
    let row = c
        .query_opt(&format!("{AGENT_SELECT} WHERE id = $1"), &[&id])
        .await?
        .ok_or(StoreError::NotFound)?;
    with_aliases(c, entry_of(&row)).await
}

async fn entries<C: GenericClient + Sync>(
    c: &C,
    rows: Vec<Row>,
) -> Result<Vec<AgentEntry>, StoreError> {
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        out.push(with_aliases(c, entry_of(r)).await?);
    }
    Ok(out)
}

#[async_trait]
impl SecOpsStore for PgStore {
    async fn sync_agents(
        &self,
        key: &ServiceKey,
        declared: &BTreeSet<String>,
    ) -> Result<Vec<AgentChange>, StoreError> {
        checked_key(key)?;
        let mut client = self.client().await?;
        let tx = client.transaction().await?;
        tx.execute(
            "SELECT pg_advisory_xact_lock(hashtext('agentsc-agents:' || $1 || '/' || $2))",
            &[&key.namespace, &key.service],
        )
        .await?;
        let rows = tx
            .query(
                &format!("{AGENT_SELECT} WHERE namespace = $1 AND service = $2 ORDER BY name"),
                &[&key.namespace, &key.service],
            )
            .await?;
        let existing = entries(&tx, rows).await?;
        let plan = SyncPlan::of(&existing, declared);
        if plan.is_empty() {
            return Ok(Vec::new());
        }
        let now = now_ts();
        let mut changes = Vec::new();
        for name in &plan.register {
            let id = AgentId::generate();
            tx.execute(
                "INSERT INTO agents (id, namespace, service, name, status, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, 'active', $5, $5)",
                &[&id.as_str(), &key.namespace, &key.service, name, &now],
            )
            .await?;
            changes.push((RegistryChange::Registered, id.to_string()));
        }
        for (ids, status, change) in [
            (
                &plan.reactivate,
                AgentStatus::Active,
                RegistryChange::Reactivated,
            ),
            (&plan.retire, AgentStatus::Retired, RegistryChange::Retired),
        ] {
            for id in ids {
                tx.execute(
                    "UPDATE agents SET status = $2, updated_at = $3 WHERE id = $1",
                    &[id, &status.as_str(), &now],
                )
                .await?;
                changes.push((change, id.clone()));
            }
        }
        let mut out = Vec::with_capacity(changes.len());
        for (change, id) in changes {
            out.push(AgentChange {
                change,
                entry: agent_by_id(&tx, &id).await?,
            });
        }
        tx.commit().await?;
        Ok(out)
    }

    async fn list_agents(&self, filter: &AgentFilter) -> Result<Vec<AgentEntry>, StoreError> {
        let client = self.client().await?;
        let rows = client
            .query(
                &format!(
                    "{AGENT_SELECT} WHERE ($1::text IS NULL OR namespace = $1) \
                     AND ($2::text IS NULL OR service = $2) AND ($3::text IS NULL OR status = $3) \
                     ORDER BY namespace, service, name"
                ),
                &[
                    &filter.namespace,
                    &filter.service,
                    &filter.status.map(AgentStatus::as_str),
                ],
            )
            .await?;
        entries(&client, rows).await
    }

    async fn get_agent(&self, id: &str) -> Result<AgentEntry, StoreError> {
        let client = self.client().await?;
        agent_by_id(&client, id).await
    }

    async fn resolve_alias(&self, alias: &str) -> Result<AgentEntry, StoreError> {
        let client = self.client().await?;
        let id: String = client
            .query_opt(
                "SELECT agent_id FROM agent_aliases WHERE alias = $1",
                &[&alias],
            )
            .await?
            .ok_or(StoreError::NotFound)?
            .get(0);
        agent_by_id(&client, &id).await
    }

    async fn put_alias(
        &self,
        id: &str,
        alias: &str,
        actor: &Actor,
    ) -> Result<AgentEntry, StoreError> {
        check_alias(alias).map_err(|e| StoreError::Invalid(vec![e]))?;
        let mut client = self.client().await?;
        let tx = client.transaction().await?;
        // the agent's row, locked, so two replicas adding aliases to it count them in turn
        tx.query_opt("SELECT id FROM agents WHERE id = $1 FOR UPDATE", &[&id])
            .await?
            .ok_or(StoreError::NotFound)?;
        let agent = agent_by_id(&tx, id).await?;
        let inserted = tx
            .execute(
                "INSERT INTO agent_aliases (alias, agent_id, created_at, created_by) \
                 VALUES ($1, $2, $3, $4) ON CONFLICT (alias) DO NOTHING",
                &[&alias, &id, &now_ts(), &actor.name],
            )
            .await?;
        if inserted == 0 {
            let owner: String = tx
                .query_one(
                    "SELECT agent_id FROM agent_aliases WHERE alias = $1",
                    &[&alias],
                )
                .await?
                .get(0);
            return if owner == id {
                Ok(agent)
            } else {
                Err(StoreError::Conflict { current: owner })
            };
        }
        if agent.aliases.len() >= MAX_ALIASES {
            return Err(StoreError::Invalid(vec![format!(
                "agent {id} has {MAX_ALIASES} aliases, the most it may have"
            )]));
        }
        let out = agent_by_id(&tx, id).await?;
        tx.commit().await?;
        Ok(out)
    }

    async fn delete_alias(&self, id: &str, alias: &str) -> Result<AgentEntry, StoreError> {
        let mut client = self.client().await?;
        let tx = client.transaction().await?;
        let n = tx
            .execute(
                "DELETE FROM agent_aliases WHERE alias = $1 AND agent_id = $2",
                &[&alias, &id],
            )
            .await?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        let out = agent_by_id(&tx, id).await?;
        tx.commit().await?;
        Ok(out)
    }
}
