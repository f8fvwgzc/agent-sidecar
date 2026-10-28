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
    AgentChange, AgentEntry, AgentFilter, AgentStatus, Approval, ApprovalFilter, ApprovalPut,
    ApprovalStatus, ChainFilter, ChainHead, ChainService, LedgerRecord, MAX_ALIASES, PENDING_MAX,
    QuarantineState, RegistryChange, RiskRow, SecOpsStore, SyncPlan, by_chain, check_alias,
    check_reason,
};
use crate::store::StoreEvent;
use crate::store::{Actor, ServiceKey, StoreError};
use agentsc_common::principal::AgentId;

const AGENT_SELECT: &str = "SELECT id, namespace, service, name, status, created_at, updated_at, \
     quarantined_at, quarantine_reason, quarantined_by FROM agents";

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
        quarantine: match (r.get::<_, Option<String>>(7), r.get(8), r.get(9)) {
            (Some(at), Some(reason), Some(by)) => Some(QuarantineState { at, reason, by }),
            _ => None,
        },
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

const APPROVAL_SELECT: &str = "SELECT id, namespace, service, agent, agent_id, tool, request_id, trace_id, args_sha256, status, requested_at, expires_at, decided_at, decided_by, decision_reason FROM approvals";

fn approval_of(r: &Row) -> Approval {
    let status: String = r.get(9);
    Approval {
        id: r.get(0),
        namespace: r.get(1),
        service: r.get(2),
        agent: r.get(3),
        agent_id: r.get(4),
        tool: r.get(5),
        request_id: r.get(6),
        trace_id: r.get(7),
        args_sha256: r.get(8),
        status: ApprovalStatus::parse(&status).unwrap_or(ApprovalStatus::Expired),
        requested_at: r.get(10),
        expires_at: r.get(11),
        decided_at: r.get(12),
        decided_by: r.get(13),
        reason: r.get(14),
    }
}

async fn approval_by_id<C: GenericClient + Sync>(c: &C, id: &str) -> Result<Approval, StoreError> {
    c.query_opt(&format!("{APPROVAL_SELECT} WHERE id = $1"), &[&id])
        .await?
        .map(|r| approval_of(&r))
        .ok_or(StoreError::NotFound)
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
    async fn quarantine_agent(
        &self,
        id: &str,
        reason: &str,
        actor: &Actor,
        at: &str,
    ) -> Result<AgentEntry, StoreError> {
        check_reason(reason)?;
        let mut client = self.client().await?;
        let tx = client.transaction().await?;
        tx.query_opt("SELECT id FROM agents WHERE id = $1 FOR UPDATE", &[&id])
            .await?
            .ok_or(StoreError::NotFound)?;
        if let Some(q) = agent_by_id(&tx, id).await?.quarantine {
            return Err(StoreError::Conflict { current: q.at });
        }
        tx.execute(
            "UPDATE agents SET quarantined_at = $2, quarantine_reason = $3, quarantined_by = $4 \
             WHERE id = $1",
            &[&id, &at, &reason, &actor.name],
        )
        .await?;
        let out = agent_by_id(&tx, id).await?;
        let event = StoreEvent::AgentsChanged {
            key: ServiceKey::new(&out.namespace, &out.service),
        };
        self.notify(&tx, &event).await?;
        tx.commit().await?;
        self.emit(event);
        Ok(out)
    }

    async fn release_agent(&self, id: &str) -> Result<AgentEntry, StoreError> {
        let mut client = self.client().await?;
        let tx = client.transaction().await?;
        tx.query_opt("SELECT id FROM agents WHERE id = $1 FOR UPDATE", &[&id])
            .await?
            .ok_or(StoreError::NotFound)?;
        if agent_by_id(&tx, id).await?.quarantine.is_none() {
            return Err(StoreError::Conflict {
                current: "not quarantined".into(),
            });
        }
        tx.execute(
            "UPDATE agents SET quarantined_at = NULL, quarantine_reason = NULL, quarantined_by = NULL \
             WHERE id = $1",
            &[&id],
        )
        .await?;
        let out = agent_by_id(&tx, id).await?;
        let event = StoreEvent::AgentsChanged {
            key: ServiceKey::new(&out.namespace, &out.service),
        };
        self.notify(&tx, &event).await?;
        tx.commit().await?;
        self.emit(event);
        Ok(out)
    }

    async fn risk_unscored(
        &self,
        quiet_before: &str,
        limit: usize,
    ) -> Result<Vec<String>, StoreError> {
        let client = self.client().await?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        Ok(client
            .query(
                "SELECT chain FROM ledger_heads WHERE NOT risk_scored AND entries > 0 AND updated_at <= $1 \
                 ORDER BY updated_at LIMIT $2",
                &[&quiet_before, &limit],
            )
            .await?
            .iter()
            .map(|r| r.get(0))
            .collect())
    }

    async fn risk_claim(&self, chain: &str) -> Result<bool, StoreError> {
        let client = self.client().await?;
        Ok(client
            .execute(
                "UPDATE ledger_heads SET risk_scored = true WHERE chain = $1 AND NOT risk_scored",
                &[&chain],
            )
            .await?
            == 1)
    }

    async fn get_baseline(&self, agent_id: &str) -> Result<Option<(u64, String)>, StoreError> {
        let client = self.client().await?;
        Ok(client
            .query_opt(
                "SELECT runs, state FROM agent_baselines WHERE agent_id = $1",
                &[&agent_id],
            )
            .await?
            .map(|r| (unsigned(r.get(0)), r.get(1))))
    }

    async fn put_baseline(
        &self,
        agent_id: &str,
        expected: Option<u64>,
        runs: u64,
        state: &str,
        at: &str,
    ) -> Result<bool, StoreError> {
        let client = self.client().await?;
        let n = match expected {
            None => {
                client
                    .execute(
                        "INSERT INTO agent_baselines (agent_id, runs, state, updated_at) VALUES ($1, $2, $3, $4) \
                         ON CONFLICT (agent_id) DO NOTHING",
                        &[&agent_id, &signed(runs)?, &state, &at],
                    )
                    .await?
            }
            Some(e) => {
                client
                    .execute(
                        "UPDATE agent_baselines SET runs = $2, state = $3, updated_at = $4 \
                         WHERE agent_id = $1 AND runs = $5",
                        &[&agent_id, &signed(runs)?, &state, &at, &signed(e)?],
                    )
                    .await?
            }
        };
        Ok(n == 1)
    }

    async fn put_risk(&self, r: &RiskRow) -> Result<(), StoreError> {
        let client = self.client().await?;
        client
            .execute(
                "INSERT INTO agent_risk (agent_id, chain, score, reasons, novelty, scored_at) \
                 VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (agent_id, chain) DO NOTHING",
                &[
                    &r.agent_id,
                    &r.chain,
                    &r.score,
                    &serde_json::to_string(&r.reasons).unwrap_or_default(),
                    &r.novelty,
                    &r.scored_at,
                ],
            )
            .await?;
        Ok(())
    }

    async fn latest_risk(&self, agent_id: &str) -> Result<Option<RiskRow>, StoreError> {
        let client = self.client().await?;
        Ok(client
            .query_opt(
                "SELECT agent_id, chain, score, reasons, novelty, scored_at FROM agent_risk \
                 WHERE agent_id = $1 ORDER BY scored_at DESC, chain DESC LIMIT 1",
                &[&agent_id],
            )
            .await?
            .map(|r| {
                let reasons: String = r.get(3);
                RiskRow {
                    agent_id: r.get(0),
                    chain: r.get(1),
                    score: r.get(2),
                    reasons: serde_json::from_str(&reasons).unwrap_or_default(),
                    novelty: r.get(4),
                    scored_at: r.get(5),
                }
            }))
    }

    async fn put_approval(&self, a: &Approval) -> Result<ApprovalPut, StoreError> {
        let mut client = self.client().await?;
        let tx = client.transaction().await?;
        // one agent's requests in turn, so the pending count holds across replicas
        tx.execute(
            "SELECT pg_advisory_xact_lock(hashtext('agentsc-approvals:' || $1 || '/' || $2 || '/' || $3))",
            &[&a.namespace, &a.service, &a.agent],
        )
        .await?;
        if let Ok(existing) = approval_by_id(&tx, &a.id).await {
            return Ok(ApprovalPut::Existing(existing));
        }
        let pending: i64 = tx
            .query_one(
                "SELECT count(*) FROM approvals WHERE namespace = $1 AND service = $2 AND agent = $3 \
                 AND status = 'pending'",
                &[&a.namespace, &a.service, &a.agent],
            )
            .await?
            .get(0);
        if pending as usize >= PENDING_MAX {
            return Ok(ApprovalPut::TooMany);
        }
        tx.execute(
            "INSERT INTO approvals (id, namespace, service, agent, agent_id, tool, request_id, \
             trace_id, args_sha256, status, requested_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', $10, $11)",
            &[
                &a.id,
                &a.namespace,
                &a.service,
                &a.agent,
                &a.agent_id,
                &a.tool,
                &a.request_id,
                &a.trace_id,
                &a.args_sha256,
                &a.requested_at,
                &a.expires_at,
            ],
        )
        .await?;
        let out = approval_by_id(&tx, &a.id).await?;
        tx.commit().await?;
        Ok(ApprovalPut::Stored(out))
    }

    async fn get_approval(&self, id: &str) -> Result<Approval, StoreError> {
        let client = self.client().await?;
        approval_by_id(&client, id).await
    }

    async fn list_approvals(&self, f: &ApprovalFilter) -> Result<Vec<Approval>, StoreError> {
        let client = self.client().await?;
        let limit = i64::try_from(f.limit).unwrap_or(i64::MAX);
        Ok(client
            .query(
                &format!(
                    "{APPROVAL_SELECT} WHERE ($1::text IS NULL OR status = $1) \
                     AND ($2::text IS NULL OR namespace = $2) AND ($3::text IS NULL OR service = $3) \
                     ORDER BY requested_at DESC, id LIMIT $4"
                ),
                &[&f.status.map(ApprovalStatus::as_str), &f.namespace, &f.service, &limit],
            )
            .await?
            .iter()
            .map(approval_of)
            .collect())
    }

    async fn decide_approval(
        &self,
        id: &str,
        approve: bool,
        by: &str,
        reason: Option<&str>,
        now: &str,
    ) -> Result<Approval, StoreError> {
        let mut client = self.client().await?;
        let tx = client.transaction().await?;
        let a = tx
            .query_opt(
                &format!("{APPROVAL_SELECT} WHERE id = $1 FOR UPDATE"),
                &[&id],
            )
            .await?
            .map(|r| approval_of(&r))
            .ok_or(StoreError::NotFound)?;
        if a.status != ApprovalStatus::Pending {
            return Err(StoreError::Conflict {
                current: a.status.as_str().into(),
            });
        }
        if now > a.expires_at.as_str() {
            tx.execute(
                "UPDATE approvals SET status = 'expired', decided_at = $2 WHERE id = $1",
                &[&id, &now],
            )
            .await?;
        } else {
            let status = if approve { "approved" } else { "denied" };
            tx.execute(
                "UPDATE approvals SET status = $2, decided_at = $3, decided_by = $4, decision_reason = $5 \
                 WHERE id = $1",
                &[&id, &status, &now, &by, &reason],
            )
            .await?;
        }
        let out = approval_by_id(&tx, id).await?;
        let event = StoreEvent::ApprovalDecided {
            key: ServiceKey::new(&out.namespace, &out.service),
            id: out.id.clone(),
        };
        self.notify(&tx, &event).await?;
        tx.commit().await?;
        self.emit(event);
        Ok(out)
    }

    async fn expire_approvals(
        &self,
        now: &str,
        agent: Option<(&str, &str, &str)>,
    ) -> Result<Vec<Approval>, StoreError> {
        let mut client = self.client().await?;
        let tx = client.transaction().await?;
        let (n, s, a) = agent.map_or((None, None, None), |(n, s, a)| (Some(n), Some(s), Some(a)));
        let rows = tx
            .query(
                &format!(
                    "UPDATE approvals SET status = 'expired', decided_at = $1 WHERE status = 'pending' AND \
                     (($2::text IS NULL AND expires_at < $1) OR (namespace = $2 AND service = $3 AND agent = $4)) \
                     RETURNING {}",
                    APPROVAL_SELECT.trim_start_matches("SELECT ").trim_end_matches(" FROM approvals")
                ),
                &[&now, &n, &s, &a],
            )
            .await?;
        let out: Vec<Approval> = rows.iter().map(approval_of).collect();
        let events: Vec<StoreEvent> = out
            .iter()
            .map(|a| StoreEvent::ApprovalDecided {
                key: ServiceKey::new(&a.namespace, &a.service),
                id: a.id.clone(),
            })
            .collect();
        self.notify_all(&tx, &events).await?;
        tx.commit().await?;
        for e in events {
            self.emit(e);
        }
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
