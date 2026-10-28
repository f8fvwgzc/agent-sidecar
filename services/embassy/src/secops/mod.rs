//! The control plane's AgentSecOps data (docs/design/agentsecops-merge.md §4, §6): the agent
//! registry ([`registry`], docs/design/agent-registry.md) and the evidence ledger ([`ledger`],
//! docs/design/evidence-ledger.md).
//!
//! It lives in the SQL stores only, each in its own migrations: the SQLite store (one process,
//! development) and the PostgreSQL store (many replicas). `--store file:<dir>` keeps it in a
//! SQLite database next to the charters (`<dir>/.secops.sqlite3`); `--store kubernetes` keeps it
//! where `--secops-store` says, and has none without it (the API then answers 503
//! `secops_unavailable`).
use std::collections::BTreeSet;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::store::{Actor, ServiceKey, StoreError};

pub mod ledger;
pub mod registry;

/// Whether an agent is declared by its service's stored charter now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    /// The stored charter declares it.
    Active,
    /// It was declared once and is not now (removed from the charter, or the service deleted).
    /// Its id stays its own: declared again, it is active again with the same id.
    Retired,
}

impl AgentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            AgentStatus::Active => "active",
            AgentStatus::Retired => "retired",
        }
    }

    pub fn parse(s: &str) -> Option<AgentStatus> {
        match s {
            "active" => Some(AgentStatus::Active),
            "retired" => Some(AgentStatus::Retired),
            _ => None,
        }
    }
}

/// One agent of the registry (CONTRACT.md §5.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentEntry {
    /// `agt_<uuidv7>`.
    pub id: String,
    /// `agent:agt_<uuidv7>`, the agent's principal as Tutela names it.
    pub principal: String,
    pub namespace: String,
    pub service: String,
    /// The agent's name in its service's charter.
    pub name: String,
    pub status: AgentStatus,
    /// RFC 3339, milliseconds, UTC: when the id was minted.
    pub created_at: String,
    /// When `status` last changed.
    pub updated_at: String,
    /// Other names of the agent (`agent://<workspace>/<name>` from nexc-engine), sorted.
    pub aliases: Vec<String>,
}

/// What [`SecOpsStore::sync_agents`] did to one agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryChange {
    /// A new agent: a fresh id.
    Registered,
    /// A retired agent declared again: active, with its old id.
    Reactivated,
    /// No longer declared.
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentChange {
    pub change: RegistryChange,
    pub entry: AgentEntry,
}

/// Which agents [`SecOpsStore::list_agents`] returns.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentFilter {
    pub namespace: Option<String>,
    pub service: Option<String>,
    pub status: Option<AgentStatus>,
}

/// What [`SecOpsStore::sync_agents`] must do for one service, from what the registry holds for it
/// (`existing`, every status) and the names its stored charter declares.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncPlan {
    /// Declared and never registered: mint an id.
    pub register: Vec<String>,
    /// Ids of retired agents declared again.
    pub reactivate: Vec<String>,
    /// Ids of active agents no longer declared.
    pub retire: Vec<String>,
}

impl SyncPlan {
    pub fn of(existing: &[AgentEntry], declared: &BTreeSet<String>) -> SyncPlan {
        let mut plan = SyncPlan::default();
        for name in declared {
            match existing.iter().find(|e| &e.name == name) {
                None => plan.register.push(name.clone()),
                Some(e) if e.status == AgentStatus::Retired => plan.reactivate.push(e.id.clone()),
                Some(_) => {}
            }
        }
        for e in existing {
            if e.status == AgentStatus::Active && !declared.contains(&e.name) {
                plan.retire.push(e.id.clone());
            }
        }
        plan
    }

    pub fn is_empty(&self) -> bool {
        self.register.is_empty() && self.reactivate.is_empty() && self.retire.is_empty()
    }
}

/// One audit record for the ledger ([`SecOpsStore::ledger_append`]).
#[derive(Debug, Clone, PartialEq)]
pub struct LedgerRecord {
    /// [`agentsc_ledger::chain_of`] the record.
    pub chain: String,
    pub namespace: String,
    pub service: String,
    pub agent_id: Option<String>,
    pub kind: String,
    /// The record as embassy took it in (service, namespace and `agent_id` filled).
    pub record: serde_json::Value,
}

/// A service a chain has records of.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ChainService {
    pub namespace: String,
    pub service: String,
}

/// Where a chain is (CONTRACT.md §6.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainHead {
    pub chain: String,
    /// How many entries it has.
    pub entries: u64,
    /// The last entry's hash (64 zeros while it has none).
    pub head: String,
    /// How many entries its newest seal covers (0: none).
    pub sealed: u64,
    /// When its last entry was taken in.
    pub updated_at: String,
    /// The services it has records of, sorted.
    pub services: Vec<ChainService>,
}

/// Which chains [`SecOpsStore::ledger_chains`] returns: those with records of the namespace (and
/// service), newest first, at most `limit`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChainFilter {
    pub namespace: Option<String>,
    pub service: Option<String>,
    pub limit: usize,
}

/// The longest alias, in bytes.
pub const MAX_ALIAS_BYTES: usize = 256;
/// The most aliases one agent has.
pub const MAX_ALIASES: usize = 16;

/// An alias is `<scheme>://<rest>`: a lowercase scheme (`agent://<workspace>/<name>` is
/// nexc-engine's), then at least one character, no whitespace or control character, at most
/// [`MAX_ALIAS_BYTES`] bytes. It is never a principal of its own (`agent:`, `workload:`).
pub fn check_alias(alias: &str) -> Result<(), String> {
    let bad = || {
        format!(
            "alias {alias:?} is not <scheme>://<name> (a lowercase scheme, no whitespace, at most {MAX_ALIAS_BYTES} bytes)"
        )
    };
    if alias.len() > MAX_ALIAS_BYTES || alias.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(bad());
    }
    let Some((scheme, rest)) = alias.split_once("://") else {
        return Err(bad());
    };
    let mut chars = scheme.chars();
    let scheme_ok = chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "+.-".contains(c));
    if !scheme_ok || rest.is_empty() {
        return Err(bad());
    }
    Ok(())
}

/// The AgentSecOps data a store keeps (module docs). Every method is one transaction.
#[async_trait]
pub trait SecOpsStore: Send + Sync {
    /// Make the registry's active agents of `key` exactly `declared` ([`SyncPlan`]): mint an id
    /// for each new agent, make retired ones that are declared again active (same id), and retire
    /// active ones that are gone. Concurrent calls for one service serialize, so of two replicas
    /// syncing the same change exactly one reports it. Returns what changed.
    async fn sync_agents(
        &self,
        key: &ServiceKey,
        declared: &BTreeSet<String>,
    ) -> Result<Vec<AgentChange>, StoreError>;

    /// Agents matching `filter`, by namespace, service and name.
    async fn list_agents(&self, filter: &AgentFilter) -> Result<Vec<AgentEntry>, StoreError>;

    /// One agent by its id (`agt_<uuidv7>`).
    async fn get_agent(&self, id: &str) -> Result<AgentEntry, StoreError>;

    /// The agent an alias names. [`StoreError::NotFound`] when none does.
    async fn resolve_alias(&self, alias: &str) -> Result<AgentEntry, StoreError>;

    /// Give agent `id` the alias ([`check_alias`]); a no-op when it has it already.
    /// [`StoreError::Conflict`] (with the other agent's id) when another agent has it,
    /// [`StoreError::Invalid`] when the agent has [`MAX_ALIASES`].
    async fn put_alias(
        &self,
        id: &str,
        alias: &str,
        actor: &Actor,
    ) -> Result<AgentEntry, StoreError>;

    /// Take the alias from agent `id`. [`StoreError::NotFound`] when it does not have it.
    async fn delete_alias(&self, id: &str, alias: &str) -> Result<AgentEntry, StoreError>;

    /// Append `records` to their chains, in order within each chain (chains in sorted order, so
    /// two replicas appending to the same chains never wait on each other in a cycle), all taken
    /// in at `ingested_at`. Each chain's head is locked while its entries are appended, so
    /// replicas appending to one chain serialize. Returns how many entries were appended.
    async fn ledger_append(
        &self,
        ingested_at: &str,
        records: &[LedgerRecord],
    ) -> Result<u64, StoreError>;

    /// One chain's head. [`StoreError::NotFound`] when it has no entry.
    async fn ledger_head(&self, chain: &str) -> Result<ChainHead, StoreError>;

    /// Chains matching `filter`, the most recently appended first.
    async fn ledger_chains(&self, filter: &ChainFilter) -> Result<Vec<ChainHead>, StoreError>;

    /// A chain's entries, in order (empty when it has none).
    async fn ledger_entries(&self, chain: &str) -> Result<Vec<agentsc_ledger::Entry>, StoreError>;

    /// A chain's seals, the fewest entries first.
    async fn ledger_seals(&self, chain: &str) -> Result<Vec<agentsc_ledger::Seal>, StoreError>;

    /// Chains with entries no seal covers whose last entry was taken in at or before
    /// `quiet_before`, oldest first, at most `limit`.
    async fn ledger_unsealed(
        &self,
        quiet_before: &str,
        limit: usize,
    ) -> Result<Vec<ChainHead>, StoreError>;

    /// Keep `seal`, which covers the first `entries` entries of `chain`. `false` when a seal of
    /// that many entries is kept already (another replica sealed first).
    async fn ledger_put_seal(
        &self,
        chain: &str,
        entries: u64,
        sealed_at: &str,
        seal: &agentsc_ledger::Seal,
    ) -> Result<bool, StoreError>;
}

/// `records` by chain (sorted), each chain's records in their order.
pub fn by_chain(records: &[LedgerRecord]) -> std::collections::BTreeMap<String, Vec<LedgerRecord>> {
    let mut out: std::collections::BTreeMap<String, Vec<LedgerRecord>> = Default::default();
    for r in records {
        out.entry(r.chain.clone()).or_default().push(r.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, name: &str, status: AgentStatus) -> AgentEntry {
        AgentEntry {
            id: id.into(),
            principal: format!("agent:{id}"),
            namespace: "shop".into(),
            service: "orders".into(),
            name: name.into(),
            status,
            created_at: String::new(),
            updated_at: String::new(),
            aliases: Vec::new(),
        }
    }

    #[test]
    fn the_plan_registers_reactivates_and_retires() {
        let existing = [
            entry("agt_a", "kept", AgentStatus::Active),
            entry("agt_b", "back", AgentStatus::Retired),
            entry("agt_c", "gone", AgentStatus::Active),
            entry("agt_d", "still-gone", AgentStatus::Retired),
        ];
        let declared: BTreeSet<String> = ["kept", "back", "new"].map(String::from).into();
        let plan = SyncPlan::of(&existing, &declared);
        assert_eq!(plan.register, ["new"]);
        assert_eq!(plan.reactivate, ["agt_b"]);
        assert_eq!(plan.retire, ["agt_c"]);
        assert!(SyncPlan::of(&existing[..1], &["kept".to_string()].into()).is_empty());
    }

    #[test]
    fn an_alias_is_a_scheme_and_a_name() {
        for ok in ["agent://acme/triage", "nexc://w/1", "a+b.c-d://x"] {
            check_alias(ok).unwrap();
        }
        for bad in [
            "",
            "agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102",
            "workload:spiffe://agentsc/ns/a/svc/b",
            "Agent://x",
            "agent://",
            "agent://a b",
            "agent://a\n",
            "1x://y",
        ] {
            assert!(check_alias(bad).is_err(), "{bad:?}");
        }
        assert!(check_alias(&format!("agent://{}", "x".repeat(MAX_ALIAS_BYTES))).is_err());
    }
}
