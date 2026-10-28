//! [`SecOpsStore`] on the PostgreSQL store: the agent registry (migration 2,
//! `postgres_schema_v2.sql`) and the evidence ledger (migration 3, `postgres_schema_v3.sql`). A
//! sync takes a transaction-scoped advisory lock on its service first, so two replicas syncing the
//! same charter change serialize and the second finds nothing to do; an append locks each chain's
//! head row, in chain order, so replicas appending to one chain serialize too.
use std::collections::BTreeSet;

use async_trait::async_trait;
use deadpool_postgres::GenericClient;
use tokio_postgres::Row;

use super::{PgStore, checked_key, now_ts};
use crate::secops::{
    AgentChange, AgentEntry, AgentFilter, AgentStatus, ChainFilter, ChainHead, ChainService,
    LedgerRecord, MAX_ALIASES, RegistryChange, SecOpsStore, SyncPlan, by_chain, check_alias,
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

fn unsigned(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Io(format!("{v} does not fit the database")))
}

const HEAD_SELECT: &str = "SELECT chain, entries, head, sealed, updated_at FROM ledger_heads";

fn head_of(r: &Row) -> ChainHead {
    ChainHead {
        chain: r.get(0),
        entries: unsigned(r.get(1)),
        head: r.get(2),
        sealed: unsigned(r.get(3)),
        updated_at: r.get(4),
        services: Vec::new(),
    }
}

async fn heads<C: GenericClient + Sync>(
    c: &C,
    rows: Vec<Row>,
) -> Result<Vec<ChainHead>, StoreError> {
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        let mut h = head_of(r);
        h.services = c
            .query(
                "SELECT namespace, service FROM ledger_chain_services WHERE chain = $1 \
                 ORDER BY namespace, service",
                &[&h.chain],
            )
            .await?
            .iter()
            .map(|r| ChainService {
                namespace: r.get(0),
                service: r.get(1),
            })
            .collect();
        out.push(h);
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
    async fn ledger_append(
        &self,
        ingested_at: &str,
        records: &[LedgerRecord],
    ) -> Result<u64, StoreError> {
        if records.is_empty() {
            return Ok(0);
        }
        let mut client = self.client().await?;
        let tx = client.transaction().await?;
        let mut appended = 0u64;
        for (chain, recs) in by_chain(records) {
            tx.execute(
                "INSERT INTO ledger_heads (chain, updated_at) VALUES ($1, $2) \
                 ON CONFLICT (chain) DO NOTHING",
                &[&chain, &ingested_at],
            )
            .await?;
            let row = tx
                .query_one(
                    "SELECT entries, head FROM ledger_heads WHERE chain = $1 FOR UPDATE",
                    &[&chain],
                )
                .await?;

            let mut head: String = row.get(1);
            for (seq, r) in (unsigned(row.get(0))..).zip(recs) {
                let hash = agentsc_ledger::entry_hash(&head, &chain, seq, ingested_at, &r.record)
                    .ok_or_else(|| StoreError::Io(format!("chain {chain}: a bad head")))?;
                tx.execute(
                    "INSERT INTO ledger_entries (chain, seq, ingested_at, record, prev_hash, hash, \
                     namespace, service, agent_id, kind) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                    &[
                        &chain,
                        &signed(seq)?,
                        &ingested_at,
                        &agentsc_ledger::canonical_json(&r.record),
                        &head,
                        &hash,
                        &r.namespace,
                        &r.service,
                        &r.agent_id,
                        &r.kind,
                    ],
                )
                .await?;
                tx.execute(
                    "INSERT INTO ledger_chain_services (chain, namespace, service) \
                     VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                    &[&chain, &r.namespace, &r.service],
                )
                .await?;
                head = hash;
                appended += 1;
            }
        }
        tx.commit().await?;
        Ok(appended)
    }

    async fn ledger_head(&self, chain: &str) -> Result<ChainHead, StoreError> {
        let client = self.client().await?;
        let row = client
            .query_opt(
                &format!("{HEAD_SELECT} WHERE chain = $1 AND entries > 0"),
                &[&chain],
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        Ok(heads(&client, vec![row]).await?.remove(0))
    }

    async fn ledger_chains(&self, filter: &ChainFilter) -> Result<Vec<ChainHead>, StoreError> {
        let client = self.client().await?;
        let limit = i64::try_from(filter.limit).unwrap_or(i64::MAX);
        let rows = client
            .query(
                "SELECT chain, entries, head, sealed, updated_at FROM ledger_heads h \
                 WHERE entries > 0 AND ($1::text IS NULL OR EXISTS (SELECT 1 FROM ledger_chain_services s \
                 WHERE s.chain = h.chain AND s.namespace = $1 AND ($2::text IS NULL OR s.service = $2))) \
                 ORDER BY updated_at DESC, chain LIMIT $3",
                &[&filter.namespace, &filter.service, &limit],
            )
            .await?;
        heads(&client, rows).await
    }

    async fn ledger_entries(&self, chain: &str) -> Result<Vec<agentsc_ledger::Entry>, StoreError> {
        let client = self.client().await?;
        client
            .query(
                "SELECT seq, ingested_at, record, prev_hash, hash FROM ledger_entries \
                 WHERE chain = $1 ORDER BY seq",
                &[&chain],
            )
            .await?
            .iter()
            .map(|r| {
                let record: String = r.get(2);
                Ok(agentsc_ledger::Entry {
                    seq: unsigned(r.get(0)),
                    ingested_at: r.get(1),
                    record: serde_json::from_str(&record)
                        .map_err(|e| StoreError::Io(format!("ledger record: {e}")))?,
                    prev_hash: r.get(3),
                    hash: r.get(4),
                })
            })
            .collect()
    }

    async fn ledger_seals(&self, chain: &str) -> Result<Vec<agentsc_ledger::Seal>, StoreError> {
        let client = self.client().await?;
        Ok(client
            .query(
                "SELECT statement, signature, kid FROM ledger_seals WHERE chain = $1 ORDER BY entries",
                &[&chain],
            )
            .await?
            .iter()
            .map(|r| agentsc_ledger::Seal {
                statement: r.get(0),
                signature: r.get(1),
                kid: r.get(2),
            })
            .collect())
    }

    async fn ledger_unsealed(
        &self,
        quiet_before: &str,
        limit: usize,
    ) -> Result<Vec<ChainHead>, StoreError> {
        let client = self.client().await?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = client
            .query(
                &format!(
                    "{HEAD_SELECT} WHERE sealed < entries AND updated_at <= $1 ORDER BY updated_at LIMIT $2"
                ),
                &[&quiet_before, &limit],
            )
            .await?;
        heads(&client, rows).await
    }

    async fn ledger_put_seal(
        &self,
        chain: &str,
        entries: u64,
        sealed_at: &str,
        seal: &agentsc_ledger::Seal,
    ) -> Result<bool, StoreError> {
        let client = self.client().await?;
        let n = client
            .execute(
                "INSERT INTO ledger_seals (chain, entries, statement, signature, kid, sealed_at) \
                 VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (chain, entries) DO NOTHING",
                &[
                    &chain,
                    &signed(entries)?,
                    &seal.statement,
                    &seal.signature,
                    &seal.kid,
                    &sealed_at,
                ],
            )
            .await?;
        Ok(n == 1)
    }
}
