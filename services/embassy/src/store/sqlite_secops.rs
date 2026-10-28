//! [`SecOpsStore`] on the SQLite store (migration 2, `schema_v2.sql`): the agent registry. Every
//! call is one transaction under the store's one lock, so syncs of one service serialize.
use std::collections::BTreeSet;

use async_trait::async_trait;
use rusqlite::{OptionalExtension, Transaction, params};

use super::{SqliteStore, checked_key, now_ts};
use crate::secops::{
    AgentChange, AgentEntry, AgentFilter, AgentStatus, MAX_ALIASES, RegistryChange, SecOpsStore,
    SyncPlan, check_alias,
};
use crate::store::{Actor, ServiceKey, StoreError};
use agentsc_common::principal::AgentId;

const AGENT_SELECT: &str =
    "SELECT id, namespace, service, name, status, created_at, updated_at FROM agents";

fn entry_of(r: &rusqlite::Row<'_>) -> rusqlite::Result<AgentEntry> {
    let id: String = r.get(0)?;
    let status: String = r.get(4)?;
    Ok(AgentEntry {
        principal: format!("agent:{id}"),
        id,
        namespace: r.get(1)?,
        service: r.get(2)?,
        name: r.get(3)?,
        status: AgentStatus::parse(&status).unwrap_or(AgentStatus::Retired),
        created_at: r.get(5)?,
        updated_at: r.get(6)?,
        aliases: Vec::new(),
    })
}

fn with_aliases(tx: &Transaction<'_>, mut e: AgentEntry) -> Result<AgentEntry, StoreError> {
    let mut stmt =
        tx.prepare_cached("SELECT alias FROM agent_aliases WHERE agent_id = ?1 ORDER BY alias")?;
    e.aliases = stmt
        .query_map(params![e.id], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    Ok(e)
}

fn agent_by_id(tx: &Transaction<'_>, id: &str) -> Result<AgentEntry, StoreError> {
    let e = tx
        .query_row(
            &format!("{AGENT_SELECT} WHERE id = ?1"),
            params![id],
            entry_of,
        )
        .optional()?
        .ok_or(StoreError::NotFound)?;
    with_aliases(tx, e)
}

fn agents_of(tx: &Transaction<'_>, key: &ServiceKey) -> Result<Vec<AgentEntry>, StoreError> {
    let mut stmt = tx.prepare_cached(&format!(
        "{AGENT_SELECT} WHERE namespace = ?1 AND service = ?2 ORDER BY name"
    ))?;
    let rows = stmt
        .query_map(params![key.namespace, key.service], entry_of)?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter().map(|e| with_aliases(tx, e)).collect()
}

#[async_trait]
impl SecOpsStore for SqliteStore {
    async fn sync_agents(
        &self,
        key: &ServiceKey,
        declared: &BTreeSet<String>,
    ) -> Result<Vec<AgentChange>, StoreError> {
        checked_key(key)?;
        let (key, declared) = (key.clone(), declared.clone());
        self.run(move |conn| {
            let tx = conn.transaction()?;
            let existing = agents_of(&tx, &key)?;
            let plan = SyncPlan::of(&existing, &declared);
            if plan.is_empty() {
                return Ok(Vec::new());
            }
            let now = now_ts();
            let mut changes = Vec::new();
            for name in &plan.register {
                let id = AgentId::generate();
                tx.execute(
                    "INSERT INTO agents (id, namespace, service, name, status, created_at, updated_at) \
                     VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?5)",
                    params![id.as_str(), key.namespace, key.service, name, now],
                )?;
                changes.push((RegistryChange::Registered, id.to_string()));
            }
            for (ids, status, change) in [
                (&plan.reactivate, AgentStatus::Active, RegistryChange::Reactivated),
                (&plan.retire, AgentStatus::Retired, RegistryChange::Retired),
            ] {
                for id in ids {
                    tx.execute(
                        "UPDATE agents SET status = ?2, updated_at = ?3 WHERE id = ?1",
                        params![id, status.as_str(), now],
                    )?;
                    changes.push((change, id.clone()));
                }
            }
            let out = changes
                .into_iter()
                .map(|(change, id)| {
                    Ok(AgentChange {
                        change,
                        entry: agent_by_id(&tx, &id)?,
                    })
                })
                .collect::<Result<Vec<_>, StoreError>>()?;
            tx.commit()?;
            Ok(out)
        })
        .await
    }

    async fn list_agents(&self, filter: &AgentFilter) -> Result<Vec<AgentEntry>, StoreError> {
        let filter = filter.clone();
        self.run(move |conn| {
            let tx = conn.transaction()?;
            let mut stmt = tx.prepare_cached(&format!(
                "{AGENT_SELECT} WHERE (?1 IS NULL OR namespace = ?1) AND (?2 IS NULL OR service = ?2) \
                 AND (?3 IS NULL OR status = ?3) ORDER BY namespace, service, name"
            ))?;
            let rows = stmt
                .query_map(
                    params![
                        filter.namespace,
                        filter.service,
                        filter.status.map(AgentStatus::as_str)
                    ],
                    entry_of,
                )?
                .collect::<Result<Vec<_>, _>>()?;
            drop(stmt);
            rows.into_iter().map(|e| with_aliases(&tx, e)).collect()
        })
        .await
    }

    async fn get_agent(&self, id: &str) -> Result<AgentEntry, StoreError> {
        let id = id.to_string();
        self.run(move |conn| {
            let tx = conn.transaction()?;
            agent_by_id(&tx, &id)
        })
        .await
    }

    async fn resolve_alias(&self, alias: &str) -> Result<AgentEntry, StoreError> {
        let alias = alias.to_string();
        self.run(move |conn| {
            let tx = conn.transaction()?;
            let id: String = tx
                .query_row(
                    "SELECT agent_id FROM agent_aliases WHERE alias = ?1",
                    params![alias],
                    |r| r.get(0),
                )
                .optional()?
                .ok_or(StoreError::NotFound)?;
            agent_by_id(&tx, &id)
        })
        .await
    }

    async fn put_alias(
        &self,
        id: &str,
        alias: &str,
        actor: &Actor,
    ) -> Result<AgentEntry, StoreError> {
        check_alias(alias).map_err(|e| StoreError::Invalid(vec![e]))?;
        let (id, alias, by) = (id.to_string(), alias.to_string(), actor.name.clone());
        self.run(move |conn| {
            let tx = conn.transaction()?;
            let agent = agent_by_id(&tx, &id)?;
            let owner: Option<String> = tx
                .query_row(
                    "SELECT agent_id FROM agent_aliases WHERE alias = ?1",
                    params![alias],
                    |r| r.get(0),
                )
                .optional()?;
            match owner {
                Some(o) if o == id => return Ok(agent),
                Some(o) => return Err(StoreError::Conflict { current: o }),
                None => {}
            }
            if agent.aliases.len() >= MAX_ALIASES {
                return Err(StoreError::Invalid(vec![format!(
                    "agent {id} has {MAX_ALIASES} aliases, the most it may have"
                )]));
            }
            tx.execute(
                "INSERT INTO agent_aliases (alias, agent_id, created_at, created_by) VALUES (?1, ?2, ?3, ?4)",
                params![alias, id, now_ts(), by],
            )?;
            let out = agent_by_id(&tx, &id)?;
            tx.commit()?;
            Ok(out)
        })
        .await
    }

    async fn delete_alias(&self, id: &str, alias: &str) -> Result<AgentEntry, StoreError> {
        let (id, alias) = (id.to_string(), alias.to_string());
        self.run(move |conn| {
            let tx = conn.transaction()?;
            let n = tx.execute(
                "DELETE FROM agent_aliases WHERE alias = ?1 AND agent_id = ?2",
                params![alias, id],
            )?;
            if n == 0 {
                return Err(StoreError::NotFound);
            }
            let out = agent_by_id(&tx, &id)?;
            tx.commit()?;
            Ok(out)
        })
        .await
    }
}
