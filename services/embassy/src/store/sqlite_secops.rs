//! [`SecOpsStore`] on the SQLite store: the agent registry (migration 2, `schema_v2.sql`) and the
//! evidence ledger (migration 3, `schema_v3.sql`). Every call is one transaction under the
//! store's one lock, so syncs of one service and appends to one chain serialize.
use std::collections::BTreeSet;

use async_trait::async_trait;
use rusqlite::{OptionalExtension, Transaction, params};

use super::{SqliteStore, checked_key, now_ts};
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
        quarantine: match (r.get::<_, Option<String>>(7)?, r.get(8)?, r.get(9)?) {
            (Some(at), Some(reason), Some(by)) => Some(QuarantineState { at, reason, by }),
            _ => None,
        },
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

fn unsigned(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Io(format!("{v} does not fit the database")))
}

const HEAD_SELECT: &str = "SELECT chain, entries, head, sealed, updated_at FROM ledger_heads";

fn head_of(r: &rusqlite::Row<'_>) -> rusqlite::Result<ChainHead> {
    Ok(ChainHead {
        chain: r.get(0)?,
        entries: unsigned(r.get(1)?),
        head: r.get(2)?,
        sealed: unsigned(r.get(3)?),
        updated_at: r.get(4)?,
        services: Vec::new(),
    })
}

fn with_services(tx: &Transaction<'_>, mut h: ChainHead) -> Result<ChainHead, StoreError> {
    let mut stmt = tx.prepare_cached(
        "SELECT namespace, service FROM ledger_chain_services WHERE chain = ?1 \
         ORDER BY namespace, service",
    )?;
    h.services = stmt
        .query_map(params![h.chain], |r| {
            Ok(ChainService {
                namespace: r.get(0)?,
                service: r.get(1)?,
            })
        })?
        .collect::<Result<_, _>>()?;
    Ok(h)
}

fn heads(tx: &Transaction<'_>, rows: Vec<ChainHead>) -> Result<Vec<ChainHead>, StoreError> {
    rows.into_iter().map(|h| with_services(tx, h)).collect()
}

const APPROVAL_SELECT: &str = "SELECT id, namespace, service, agent, agent_id, tool, request_id, trace_id, args_sha256, status, requested_at, expires_at, decided_at, decided_by, decision_reason FROM approvals";

fn approval_of(r: &rusqlite::Row<'_>) -> rusqlite::Result<Approval> {
    let status: String = r.get(9)?;
    Ok(Approval {
        id: r.get(0)?,
        namespace: r.get(1)?,
        service: r.get(2)?,
        agent: r.get(3)?,
        agent_id: r.get(4)?,
        tool: r.get(5)?,
        request_id: r.get(6)?,
        trace_id: r.get(7)?,
        args_sha256: r.get(8)?,
        status: ApprovalStatus::parse(&status).unwrap_or(ApprovalStatus::Expired),
        requested_at: r.get(10)?,
        expires_at: r.get(11)?,
        decided_at: r.get(12)?,
        decided_by: r.get(13)?,
        reason: r.get(14)?,
    })
}

fn approval_by_id(tx: &Transaction<'_>, id: &str) -> Result<Approval, StoreError> {
    tx.query_row(
        &format!("{APPROVAL_SELECT} WHERE id = ?1"),
        params![id],
        approval_of,
    )
    .optional()?
    .ok_or(StoreError::NotFound)
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
    async fn quarantine_agent(
        &self,
        id: &str,
        reason: &str,
        actor: &Actor,
        at: &str,
    ) -> Result<AgentEntry, StoreError> {
        check_reason(reason)?;
        let (id, reason, by, at) = (
            id.to_string(),
            reason.to_string(),
            actor.name.clone(),
            at.to_string(),
        );
        let out = self
            .run(move |conn| {
                let tx = conn.transaction()?;
                let agent = agent_by_id(&tx, &id)?;
                if let Some(q) = agent.quarantine {
                    return Err(StoreError::Conflict { current: q.at });
                }
                tx.execute(
                    "UPDATE agents SET quarantined_at = ?2, quarantine_reason = ?3, quarantined_by = ?4 \
                     WHERE id = ?1",
                    params![id, at, reason, by],
                )?;
                let out = agent_by_id(&tx, &id)?;
                tx.commit()?;
                Ok(out)
            })
            .await?;
        self.emit(StoreEvent::AgentsChanged {
            key: ServiceKey::new(&out.namespace, &out.service),
        });
        Ok(out)
    }

    async fn release_agent(&self, id: &str) -> Result<AgentEntry, StoreError> {
        let id = id.to_string();
        let out = self
            .run(move |conn| {
                let tx = conn.transaction()?;
                if agent_by_id(&tx, &id)?.quarantine.is_none() {
                    return Err(StoreError::Conflict {
                        current: "not quarantined".into(),
                    });
                }
                tx.execute(
                    "UPDATE agents SET quarantined_at = NULL, quarantine_reason = NULL, \
                     quarantined_by = NULL WHERE id = ?1",
                    params![id],
                )?;
                let out = agent_by_id(&tx, &id)?;
                tx.commit()?;
                Ok(out)
            })
            .await?;
        self.emit(StoreEvent::AgentsChanged {
            key: ServiceKey::new(&out.namespace, &out.service),
        });
        Ok(out)
    }

    async fn risk_unscored(
        &self,
        quiet_before: &str,
        limit: usize,
    ) -> Result<Vec<String>, StoreError> {
        let q = quiet_before.to_string();
        self.run(move |conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT chain FROM ledger_heads WHERE risk_scored = 0 AND entries > 0 AND updated_at <= ?1 \
                 ORDER BY updated_at LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![q, limit as i64], |r| r.get(0))?.collect::<Result<_, _>>()?;
            Ok(rows)
        })
        .await
    }

    async fn risk_claim(&self, chain: &str) -> Result<bool, StoreError> {
        let chain = chain.to_string();
        self.run(move |conn| {
            Ok(conn.execute(
                "UPDATE ledger_heads SET risk_scored = 1 WHERE chain = ?1 AND risk_scored = 0",
                params![chain],
            )? == 1)
        })
        .await
    }

    async fn get_baseline(&self, agent_id: &str) -> Result<Option<(u64, String)>, StoreError> {
        let id = agent_id.to_string();
        self.run(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT runs, state FROM agent_baselines WHERE agent_id = ?1",
                    params![id],
                    |r| Ok((unsigned(r.get(0)?), r.get(1)?)),
                )
                .optional()?)
        })
        .await
    }

    async fn put_baseline(
        &self,
        agent_id: &str,
        expected: Option<u64>,
        runs: u64,
        state: &str,
        at: &str,
    ) -> Result<bool, StoreError> {
        let (id, state, at) = (agent_id.to_string(), state.to_string(), at.to_string());
        self.run(move |conn| {
            let n = match expected {
                None => conn.execute(
                    "INSERT INTO agent_baselines (agent_id, runs, state, updated_at) VALUES (?1, ?2, ?3, ?4) \
                     ON CONFLICT (agent_id) DO NOTHING",
                    params![id, signed(runs)?, state, at],
                )?,
                Some(e) => conn.execute(
                    "UPDATE agent_baselines SET runs = ?2, state = ?3, updated_at = ?4 \
                     WHERE agent_id = ?1 AND runs = ?5",
                    params![id, signed(runs)?, state, at, signed(e)?],
                )?,
            };
            Ok(n == 1)
        })
        .await
    }

    async fn put_risk(&self, row: &RiskRow) -> Result<(), StoreError> {
        let r = row.clone();
        self.run(move |conn| {
            conn.execute(
                "INSERT INTO agent_risk (agent_id, chain, score, reasons, novelty, scored_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT (agent_id, chain) DO NOTHING",
                params![
                    r.agent_id,
                    r.chain,
                    r.score,
                    serde_json::to_string(&r.reasons).unwrap_or_default(),
                    r.novelty,
                    r.scored_at
                ],
            )?;
            Ok(())
        })
        .await
    }

    async fn latest_risk(&self, agent_id: &str) -> Result<Option<RiskRow>, StoreError> {
        let id = agent_id.to_string();
        self.run(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT agent_id, chain, score, reasons, novelty, scored_at FROM agent_risk \
                     WHERE agent_id = ?1 ORDER BY scored_at DESC, chain DESC LIMIT 1",
                    params![id],
                    |r| {
                        let reasons: String = r.get(3)?;
                        Ok(RiskRow {
                            agent_id: r.get(0)?,
                            chain: r.get(1)?,
                            score: r.get(2)?,
                            reasons: serde_json::from_str(&reasons).unwrap_or_default(),
                            novelty: r.get(4)?,
                            scored_at: r.get(5)?,
                        })
                    },
                )
                .optional()?)
        })
        .await
    }

    async fn put_approval(&self, a: &Approval) -> Result<ApprovalPut, StoreError> {
        let a = a.clone();
        self.run(move |conn| {
            let tx = conn.transaction()?;
            if let Ok(existing) = approval_by_id(&tx, &a.id) {
                return Ok(ApprovalPut::Existing(existing));
            }
            let pending: i64 = tx.query_row(
                "SELECT count(*) FROM approvals WHERE namespace = ?1 AND service = ?2 AND agent = ?3 \
                 AND status = 'pending'",
                params![a.namespace, a.service, a.agent],
                |r| r.get(0),
            )?;
            if pending as usize >= PENDING_MAX {
                return Ok(ApprovalPut::TooMany);
            }
            tx.execute(
                "INSERT INTO approvals (id, namespace, service, agent, agent_id, tool, request_id, \
                 trace_id, args_sha256, status, requested_at, expires_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'pending', ?10, ?11)",
                params![a.id, a.namespace, a.service, a.agent, a.agent_id, a.tool, a.request_id,
                    a.trace_id, a.args_sha256, a.requested_at, a.expires_at],
            )?;
            let out = approval_by_id(&tx, &a.id)?;
            tx.commit()?;
            Ok(ApprovalPut::Stored(out))
        })
        .await
    }

    async fn get_approval(&self, id: &str) -> Result<Approval, StoreError> {
        let id = id.to_string();
        self.run(move |conn| {
            let tx = conn.transaction()?;
            approval_by_id(&tx, &id)
        })
        .await
    }

    async fn list_approvals(&self, filter: &ApprovalFilter) -> Result<Vec<Approval>, StoreError> {
        let f = filter.clone();
        self.run(move |conn| {
            let mut stmt = conn.prepare_cached(&format!(
                "{APPROVAL_SELECT} WHERE (?1 IS NULL OR status = ?1) AND (?2 IS NULL OR namespace = ?2) \
                 AND (?3 IS NULL OR service = ?3) ORDER BY requested_at DESC, id LIMIT ?4"
            ))?;
            let rows = stmt
                .query_map(
                    params![f.status.map(ApprovalStatus::as_str), f.namespace, f.service, f.limit as i64],
                    approval_of,
                )?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
    }

    async fn decide_approval(
        &self,
        id: &str,
        approve: bool,
        by: &str,
        reason: Option<&str>,
        now: &str,
    ) -> Result<Approval, StoreError> {
        let (id, by, reason, now) = (
            id.to_string(),
            by.to_string(),
            reason.map(str::to_string),
            now.to_string(),
        );
        let out = self
            .run(move |conn| {
                let tx = conn.transaction()?;
                let a = approval_by_id(&tx, &id)?;
                if a.status != ApprovalStatus::Pending {
                    return Err(StoreError::Conflict {
                        current: a.status.as_str().into(),
                    });
                }
                if now > a.expires_at {
                    tx.execute(
                        "UPDATE approvals SET status = 'expired', decided_at = ?2 WHERE id = ?1",
                        params![id, now],
                    )?;
                } else {
                    let status = if approve { "approved" } else { "denied" };
                    tx.execute(
                        "UPDATE approvals SET status = ?2, decided_at = ?3, decided_by = ?4, \
                         decision_reason = ?5 WHERE id = ?1",
                        params![id, status, now, by, reason],
                    )?;
                }
                let out = approval_by_id(&tx, &id)?;
                tx.commit()?;
                Ok(out)
            })
            .await?;
        self.emit(StoreEvent::ApprovalDecided {
            key: ServiceKey::new(&out.namespace, &out.service),
            id: out.id.clone(),
        });
        Ok(out)
    }

    async fn expire_approvals(
        &self,
        now: &str,
        agent: Option<(&str, &str, &str)>,
    ) -> Result<Vec<Approval>, StoreError> {
        let now = now.to_string();
        let agent = agent.map(|(n, s, a)| (n.to_string(), s.to_string(), a.to_string()));
        let out = self
            .run(move |conn| {
                let tx = conn.transaction()?;
                let ids: Vec<String> = {
                    let mut stmt = tx.prepare_cached(
                        "SELECT id FROM approvals WHERE status = 'pending' AND \
                         ((?2 IS NULL AND expires_at < ?1) OR (namespace = ?2 AND service = ?3 AND agent = ?4))",
                    )?;
                    let (n, s, a) = agent.clone().map_or((None, None, None), |(n, s, a)| (Some(n), Some(s), Some(a)));
                    stmt.query_map(params![now, n, s, a], |r| r.get(0))?
                        .collect::<Result<_, _>>()?
                };
                let mut out = Vec::new();
                for id in ids {
                    tx.execute(
                        "UPDATE approvals SET status = 'expired', decided_at = ?2 WHERE id = ?1",
                        params![id, now],
                    )?;
                    out.push(approval_by_id(&tx, &id)?);
                }
                tx.commit()?;
                Ok(out)
            })
            .await?;
        for a in &out {
            self.emit(StoreEvent::ApprovalDecided {
                key: ServiceKey::new(&a.namespace, &a.service),
                id: a.id.clone(),
            });
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
        let (at, groups) = (ingested_at.to_string(), by_chain(records));
        self.run(move |conn| {
            let tx = conn.transaction()?;
            let mut appended = 0u64;
            for (chain, recs) in groups {
                tx.execute(
                    "INSERT INTO ledger_heads (chain, updated_at) VALUES (?1, ?2) \
                     ON CONFLICT (chain) DO NOTHING",
                    params![chain, at],
                )?;
                let (entries, mut head): (i64, String) = tx.query_row(
                    "SELECT entries, head FROM ledger_heads WHERE chain = ?1",
                    params![chain],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;

                for (seq, r) in (unsigned(entries)..).zip(recs) {
                    let hash = agentsc_ledger::entry_hash(&head, &chain, seq, &at, &r.record)
                        .ok_or_else(|| StoreError::Io(format!("chain {chain}: a bad head")))?;
                    tx.execute(
                        "INSERT INTO ledger_entries (chain, seq, ingested_at, record, prev_hash, \
                         hash, namespace, service, agent_id, kind) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                        params![
                            chain,
                            signed(seq)?,
                            at,
                            agentsc_ledger::canonical_json(&r.record),
                            head,
                            hash,
                            r.namespace,
                            r.service,
                            r.agent_id,
                            r.kind
                        ],
                    )?;
                    tx.execute(
                        "INSERT INTO ledger_chain_services (chain, namespace, service) \
                         VALUES (?1, ?2, ?3) ON CONFLICT DO NOTHING",
                        params![chain, r.namespace, r.service],
                    )?;
                    head = hash;
                    appended += 1;
                }
            }
            tx.commit()?;
            Ok(appended)
        })
        .await
    }

    async fn ledger_head(&self, chain: &str) -> Result<ChainHead, StoreError> {
        let chain = chain.to_string();
        self.run(move |conn| {
            let tx = conn.transaction()?;
            let h = tx
                .query_row(
                    &format!("{HEAD_SELECT} WHERE chain = ?1 AND entries > 0"),
                    params![chain],
                    head_of,
                )
                .optional()?
                .ok_or(StoreError::NotFound)?;
            with_services(&tx, h)
        })
        .await
    }

    async fn ledger_chains(&self, filter: &ChainFilter) -> Result<Vec<ChainHead>, StoreError> {
        let filter = filter.clone();
        self.run(move |conn| {
            let tx = conn.transaction()?;
            let mut stmt = tx.prepare_cached(
                "SELECT chain, entries, head, sealed, updated_at FROM ledger_heads h \
                 WHERE entries > 0 AND (?1 IS NULL OR EXISTS (SELECT 1 FROM ledger_chain_services s \
                 WHERE s.chain = h.chain AND s.namespace = ?1 AND (?2 IS NULL OR s.service = ?2))) \
                 ORDER BY updated_at DESC, chain LIMIT ?3",
            )?;
            let rows = stmt
                .query_map(
                    params![filter.namespace, filter.service, filter.limit as i64],
                    head_of,
                )?
                .collect::<Result<Vec<_>, _>>()?;
            drop(stmt);
            heads(&tx, rows)
        })
        .await
    }

    async fn ledger_entries(&self, chain: &str) -> Result<Vec<agentsc_ledger::Entry>, StoreError> {
        let chain = chain.to_string();
        self.run(move |conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT seq, ingested_at, record, prev_hash, hash FROM ledger_entries \
                 WHERE chain = ?1 ORDER BY seq",
            )?;
            let rows = stmt
                .query_map(params![chain], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter()
                .map(|(seq, ingested_at, record, prev_hash, hash)| {
                    Ok(agentsc_ledger::Entry {
                        seq: unsigned(seq),
                        ingested_at,
                        record: serde_json::from_str(&record)
                            .map_err(|e| StoreError::Io(format!("ledger record: {e}")))?,
                        prev_hash,
                        hash,
                    })
                })
                .collect()
        })
        .await
    }

    async fn ledger_seals(&self, chain: &str) -> Result<Vec<agentsc_ledger::Seal>, StoreError> {
        let chain = chain.to_string();
        self.run(move |conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT statement, signature, kid FROM ledger_seals WHERE chain = ?1 ORDER BY entries",
            )?;
            let rows = stmt
                .query_map(params![chain], |r| {
                    Ok(agentsc_ledger::Seal {
                        statement: r.get(0)?,
                        signature: r.get(1)?,
                        kid: r.get(2)?,
                    })
                })?
                .collect::<Result<_, _>>()?;
            Ok(rows)
        })
        .await
    }

    async fn ledger_unsealed(
        &self,
        quiet_before: &str,
        limit: usize,
    ) -> Result<Vec<ChainHead>, StoreError> {
        let quiet_before = quiet_before.to_string();
        self.run(move |conn| {
            let tx = conn.transaction()?;
            let mut stmt = tx.prepare_cached(&format!(
                "{HEAD_SELECT} WHERE sealed < entries AND updated_at <= ?1 ORDER BY updated_at LIMIT ?2"
            ))?;
            let rows = stmt
                .query_map(params![quiet_before, limit as i64], head_of)?
                .collect::<Result<Vec<_>, _>>()?;
            drop(stmt);
            heads(&tx, rows)
        })
        .await
    }

    async fn ledger_put_seal(
        &self,
        chain: &str,
        entries: u64,
        sealed_at: &str,
        seal: &agentsc_ledger::Seal,
    ) -> Result<bool, StoreError> {
        let (chain, sealed_at, seal) = (chain.to_string(), sealed_at.to_string(), seal.clone());
        self.run(move |conn| {
            let n = conn.execute(
                "INSERT INTO ledger_seals (chain, entries, statement, signature, kid, sealed_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT (chain, entries) DO NOTHING",
                params![
                    chain,
                    signed(entries)?,
                    seal.statement,
                    seal.signature,
                    seal.kid,
                    sealed_at
                ],
            )?;
            Ok(n == 1)
        })
        .await
    }
}
