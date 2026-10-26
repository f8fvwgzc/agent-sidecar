//! The control-plane store (design §8.4): charters with history, memory, proposals and pending
//! adoptions, per service. Three implementations follow: `file:<dir>` (B3a, `store/file.rs`),
//! `sqlite:<path>` (`store/sqlite.rs`, docs/adr/0003-sqlite-store-schema.md) and `kubernetes`
//! (B3b, `k8s`).
//!
//! The store only persists. Every write reaching it has already passed, in order: the charter
//! validator → `policy` → role on the diff → the version-skew check (design §8.4). The store
//! enforces the optimistic-concurrency precondition and assigns versions: decimal strings of a
//! `u64` counter, monotonic per service and never reused, plus an `epoch` (a UUID; a new one when
//! a service's charter is deleted and recreated). Memory has its own version counter per service.
//!
//! Memory exists only for agents with learning enabled (design §3): a charter write that turns an
//! agent's learning off, or removes the agent, drops that agent's notes in the same change
//! ([`prune_memory`]; the store does it inside the critical section of the charter write and
//! emits [`StoreEvent::MemoryChanged`]).
use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::api::types::CpAuditRecord;
use crate::config::Role;

pub mod file;
pub mod sqlite;

/// The plain charter document inside a stored charter: `spec` for the custom-resource form
/// (`metadata` + `spec`), the document itself otherwise.
pub fn charter_doc(charter_json: &serde_json::Value) -> &serde_json::Value {
    match charter_json.get("spec") {
        Some(spec) if charter_json.get("metadata").is_some() => spec,
        _ => charter_json,
    }
}

/// The memory after a charter write: the notes of agents that the charter does not have, or
/// whose learning is off, removed (design §3). `None` when nothing changes; otherwise the new
/// document with the next memory version.
pub fn prune_memory(memory: &MemoryDoc, charter_json: &serde_json::Value) -> Option<MemoryDoc> {
    let keep =
        |agent: &str| AgentLearning::from_charter(charter_json, agent).is_some_and(|l| l.enabled);
    if memory.agents.keys().all(|a| keep(a)) {
        return None;
    }
    let next = memory.version.parse::<u64>().ok()?.checked_add(1)?;
    Some(MemoryDoc {
        version: next.to_string(),
        agents: memory
            .agents
            .iter()
            .filter(|(a, _)| keep(a))
            .map(|(a, n)| (a.clone(), n.clone()))
            .collect(),
    })
}

/// A service: `(namespace, service)`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ServiceKey {
    pub namespace: String,
    pub service: String,
}

impl ServiceKey {
    pub fn new(namespace: impl Into<String>, service: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            service: service.into(),
        }
    }
}

impl std::fmt::Display for ServiceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.namespace, self.service)
    }
}

/// The stored charter of one service (the API's `CharterDoc`).
#[derive(Debug, Clone, PartialEq)]
pub struct StoredCharter {
    pub epoch: String,
    pub version: String,
    /// The YAML text exactly as written.
    pub yaml: String,
    /// The same document as JSON (the YAML converted as written, no defaults filled in).
    pub charter_json: serde_json::Value,
}

/// The precondition of a write (`If-Match: "<version>"` or `If-None-Match: *`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Precondition {
    /// The current version must be this one (else [`StoreError::Conflict`]).
    Version(String),
    /// There must be no charter yet (else [`StoreError::Conflict`] with the current version).
    NotExists,
}

/// Who made a change (design §8.5 `actor`, `actor_kind`, `role`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    /// Token name, `sidecar:<spiffe id>/<pod>`, `k8s:<field manager>` or `system`.
    pub name: String,
    pub kind: ActorKind,
    /// Null for sidecars, Kubernetes managers and the system.
    pub role: Option<Role>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActorKind {
    Session,
    Token,
    Sidecar,
    K8s,
    System,
}

/// Where a charter version came from (the SSE `config` event's `source`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeSource {
    Api,
    Kubernetes,
    Adopt,
    Rollback,
    File,
}

/// A charter write: the new document, who wrote it and through what.
#[derive(Debug, Clone, PartialEq)]
pub struct CharterWrite {
    pub yaml: String,
    pub charter_json: serde_json::Value,
    pub actor: Actor,
    pub source: ChangeSource,
}

/// One stored version (`GET .../charter/history`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryEntry {
    pub version: String,
    pub ts: String,
    pub actor: String,
    /// SHA-256 (lowercase hex) of that version's YAML text.
    pub sha256: String,
}

/// A service's learned notes (`GET .../memory`), a full replacement on every write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryDoc {
    pub version: String,
    /// Agent name → its active notes, oldest first.
    pub agents: BTreeMap<String, Vec<Note>>,
}

/// One learned note: the proto `Note` (design §7) in JSON, empty strings as null.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Note {
    pub id: String,
    pub text: String,
    pub source: NoteSource,
    pub request_id: Option<String>,
    pub trace_id: Option<String>,
    /// Who approved it; null for `auto` notes.
    pub approved_by: Option<String>,
    pub ts: String,
    /// Set for `auto` notes (`ts + note_ttl_days`).
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NoteSource {
    /// An approved proposal.
    Review,
    /// Stored at once (learning mode `auto`); expires.
    Auto,
    /// Written with `PUT .../memory`.
    Manual,
}

/// A lesson an agent proposed (design §6.5, §7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    /// Assigned by the control plane (UUIDv4).
    pub id: String,
    pub namespace: String,
    pub service: String,
    pub agent: String,
    pub note: String,
    pub rationale: String,
    pub request_id: String,
    pub trace_id: String,
    pub ts: String,
    pub status: ProposalStatus,
    pub auto: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProposalStatus {
    Pending,
    Approved,
    Rejected,
}

/// Which proposals to list (`GET /proposals?status=&namespace=&service=`); `None` = any.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProposalFilter {
    pub status: Option<ProposalStatus>,
    pub namespace: Option<String>,
    pub service: Option<String>,
}

impl ProposalFilter {
    pub fn matches(&self, p: &Proposal) -> bool {
        self.status.is_none_or(|s| s == p.status)
            && self.namespace.as_ref().is_none_or(|n| *n == p.namespace)
            && self.service.as_ref().is_none_or(|s| *s == p.service)
    }
}

/// The outcome of [`Store::put_proposal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalPut {
    Stored,
    /// A proposal with the same `(namespace, service, dedup_key)` exists; nothing was written.
    Duplicate {
        existing_id: String,
    },
}

/// A sidecar's valid start-up charter for a service that has none (design §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAdoption {
    pub key: ServiceKey,
    /// SHA-256 (lowercase hex) of `yaml`.
    pub sha256: String,
    pub pod: String,
    pub ts: String,
    pub yaml: String,
}

/// A decision on a pending proposal ([`Store::approve_proposal`], [`Store::reject_proposal`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProposalVerdict {
    Approve,
    Reject,
}

/// An agent's `learning` settings as far as memory writes need them, with the charter defaults
/// (design §4: `max_notes` 20, `max_note_chars` 500).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AgentLearning {
    pub enabled: bool,
    pub max_notes: usize,
    pub max_note_chars: usize,
}

impl AgentLearning {
    pub const DEFAULT_MAX_NOTES: usize = 20;
    pub const DEFAULT_MAX_NOTE_CHARS: usize = 500;

    /// The `learning` of `agent` in a stored charter (`StoredCharter::charter_json`, plain or
    /// custom-resource form); `None` when the charter has no such agent.
    pub fn from_charter(charter_json: &serde_json::Value, agent: &str) -> Option<Self> {
        let doc = match charter_json.get("spec") {
            Some(spec) if charter_json.get("metadata").is_some() => spec,
            _ => charter_json,
        };
        let a = doc
            .get("agents")?
            .as_array()?
            .iter()
            .find(|a| a.get("name").and_then(|n| n.as_str()) == Some(agent))?;
        let l = a.get("learning");
        let num = |key: &str, default: usize| {
            l.and_then(|l| l.get(key))
                .and_then(serde_json::Value::as_u64)
                .and_then(|n| usize::try_from(n).ok())
                .unwrap_or(default)
        };
        Some(Self {
            enabled: l
                .and_then(|l| l.get("enabled"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            max_notes: num("max_notes", Self::DEFAULT_MAX_NOTES),
            max_note_chars: num("max_note_chars", Self::DEFAULT_MAX_NOTE_CHARS),
        })
    }
}

/// What a store reads, inside one critical section, to decide a proposal: the stored charter
/// (`None` when the service has none), the service's memory and the proposal.
#[derive(Debug, Clone, Copy)]
pub struct LearningState<'a> {
    pub charter: Option<&'a serde_json::Value>,
    pub memory: &'a MemoryDoc,
    pub proposal: &'a Proposal,
}

/// Decide a pending proposal: the pure part of [`Store::approve_proposal`] and
/// [`Store::reject_proposal`]. A store runs it inside the one critical section that also reads
/// `state` and writes the result (file store: its lock over the charter, memory and proposal
/// files; Kubernetes store: one `status` replace with the `resourceVersion` it read, since the
/// charter `spec`, the memory and the proposals are one Charter object, so a concurrent charter
/// change makes the replace fail).
///
/// In this order:
///
/// 1. the proposal must be pending, else [`StoreError::NotPending`] with its status (so of an
///    approve and a reject racing for the same proposal exactly one wins, and the loser learns
///    why);
/// 2. `if_match_memory` must be the memory version, else [`StoreError::Conflict`] with the
///    current memory version;
/// 3. approving only: the stored charter must enable learning for the agent (memory exists only
///    for agents with learning enabled, design §3), the agent must have fewer than
///    `learning.max_notes` notes (approving never evicts one: remove a note first) and the note
///    must be at most `learning.max_note_chars` characters (the charter may have lowered it
///    since the proposal), else [`StoreError::Invalid`]. Rejecting needs none of this: it
///    leaves the memory alone, so pending proposals of an agent whose learning was turned off
///    can still be rejected.
///
/// Approving appends the note (`source: review`, `approved_by` = the actor, id `note_id`, `ts`)
/// to the agent's notes and bumps the memory version; rejecting leaves the memory as it is.
/// Returns the new memory and the decided proposal.
pub fn decide_proposal(
    state: LearningState<'_>,
    verdict: ProposalVerdict,
    if_match_memory: &str,
    actor: &Actor,
    ts: &str,
    note_id: String,
) -> Result<(MemoryDoc, Proposal), StoreError> {
    let LearningState {
        charter,
        memory,
        proposal,
    } = state;
    if proposal.status != ProposalStatus::Pending {
        return Err(StoreError::NotPending {
            status: proposal.status,
        });
    }
    if if_match_memory != memory.version {
        return Err(StoreError::Conflict {
            current: memory.version.clone(),
        });
    }
    let mut decided = proposal.clone();
    let mut memory = memory.clone();
    match verdict {
        ProposalVerdict::Reject => decided.status = ProposalStatus::Rejected,
        ProposalVerdict::Approve => {
            let agent = &proposal.agent;
            let learning = charter.and_then(|c| AgentLearning::from_charter(c, agent));
            let Some(learning) = learning.filter(|l| l.enabled) else {
                return Err(StoreError::Invalid(vec![format!(
                    "{agent}: the stored charter does not enable learning for this agent \
                     (memory exists only for agents with learning enabled)"
                )]));
            };
            let notes = memory.agents.get(agent).map_or(0, Vec::len);
            let mut problems = Vec::new();
            if notes >= learning.max_notes {
                problems.push(format!(
                    "{agent}: already has {notes} notes and learning.max_notes is {}; \
                     remove a note before approving",
                    learning.max_notes
                ));
            }
            let chars = proposal.note.chars().count();
            if chars > learning.max_note_chars {
                problems.push(format!(
                    "{agent}: the note has {chars} characters and learning.max_note_chars is {}",
                    learning.max_note_chars
                ));
            }
            if !problems.is_empty() {
                return Err(StoreError::Invalid(problems));
            }
            decided.status = ProposalStatus::Approved;
            let next = memory
                .version
                .parse::<u64>()
                .ok()
                .and_then(|v| v.checked_add(1))
                .ok_or_else(|| {
                    StoreError::Io(format!(
                        "memory version {:?} is not a decimal u64 below u64::MAX",
                        memory.version
                    ))
                })?;
            memory.version = next.to_string();
            let non_empty = |s: &str| (!s.is_empty()).then(|| s.to_string());
            memory
                .agents
                .entry(proposal.agent.clone())
                .or_default()
                .push(Note {
                    id: note_id,
                    text: proposal.note.clone(),
                    source: NoteSource::Review,
                    request_id: non_empty(&proposal.request_id),
                    trace_id: non_empty(&proposal.trace_id),
                    approved_by: Some(actor.name.clone()),
                    ts: ts.to_string(),
                    expires_at: None,
                });
        }
    }
    Ok((memory, decided))
}

/// A change, broadcast to subscribers (the Connect streams push charters and memory from these;
/// the API turns them into SSE `config`, `proposal` and `cp_audit` events).
#[derive(Debug, Clone, PartialEq)]
pub enum StoreEvent {
    CharterChanged {
        key: ServiceKey,
        epoch: String,
        version: String,
        actor: Actor,
        source: ChangeSource,
    },
    ServiceDeleted {
        key: ServiceKey,
        actor: Actor,
    },
    MemoryChanged {
        key: ServiceKey,
        version: String,
    },
    ProposalChanged {
        key: ServiceKey,
        id: String,
    },
    AdoptionPending {
        key: ServiceKey,
        sha256: String,
    },
    /// A control-plane audit record the store produced itself — `cr_external_edit` (an external
    /// edit of a file-store charter, or a Charter CR changed with kubectl, actor
    /// `k8s:<manager>`) — after [`Store::append_cp_audit`] persisted it. The API sends it to
    /// admins as SSE `cp_audit`, like the records the API writes. Boxed: it is the largest
    /// event.
    CpAudit(Box<CpAuditRecord>),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    #[error("not found")]
    NotFound,
    /// The precondition failed; `current` is the current version (charter or memory).
    #[error("version conflict: the current version is {current}")]
    Conflict { current: String },
    /// A decision on a proposal that was already decided (API: 409 `not_pending`).
    #[error("the proposal is no longer pending: it is {status:?}")]
    NotPending { status: ProposalStatus },
    #[error("invalid: {}", .0.join("; "))]
    Invalid(Vec<String>),
    #[error("store: {0}")]
    Io(String),
}

/// The common interface of the file and Kubernetes stores (design §8.4).
#[async_trait]
pub trait Store: Send + Sync {
    /// Every service with a stored charter.
    async fn list_services(&self) -> Result<Vec<ServiceKey>, StoreError>;

    async fn get_charter(&self, key: &ServiceKey) -> Result<StoredCharter, StoreError>;

    /// Store a new version if `precondition` holds; returns what is now stored (new version,
    /// and a new epoch when the service had no charter). Records the version in the history,
    /// removes a pending adoption of the service, and, in the same critical section, drops the
    /// notes of agents the new charter does not let learn ([`prune_memory`]).
    ///
    /// `Precondition::Version` on a service without a charter is [`StoreError::NotFound`].
    async fn put_charter(
        &self,
        key: &ServiceKey,
        precondition: &Precondition,
        write: CharterWrite,
    ) -> Result<StoredCharter, StoreError>;

    /// Stored versions, newest first.
    async fn history(&self, key: &ServiceKey) -> Result<Vec<HistoryEntry>, StoreError>;

    /// The YAML of one stored version.
    async fn get_revision(&self, key: &ServiceKey, version: &str) -> Result<String, StoreError>;

    /// Delete the charter, history, memory and proposals of a service (`if_match` = the current
    /// charter version).
    async fn delete_service(
        &self,
        key: &ServiceKey,
        if_match: &str,
        actor: &Actor,
    ) -> Result<(), StoreError>;

    /// The service's memory; version `"0"` with no agents when nothing was ever written.
    async fn get_memory(&self, key: &ServiceKey) -> Result<MemoryDoc, StoreError>;

    /// Replace the service's memory if its version is `if_match`; returns the new document.
    async fn put_memory(
        &self,
        key: &ServiceKey,
        if_match: &str,
        agents: BTreeMap<String, Vec<Note>>,
        actor: &Actor,
    ) -> Result<MemoryDoc, StoreError>;

    /// Proposals matching `filter`, newest first.
    async fn list_proposals(&self, filter: &ProposalFilter) -> Result<Vec<Proposal>, StoreError>;

    async fn get_proposal(&self, id: &str) -> Result<Proposal, StoreError>;

    /// Insert a new proposal (with the sidecar's `dedup_key`) or, with `dedup_key: None`,
    /// replace the stored proposal with the same `id`. Decisions on pending proposals never use
    /// this: they go through [`Store::approve_proposal`] / [`Store::reject_proposal`].
    async fn put_proposal(
        &self,
        proposal: &Proposal,
        dedup_key: Option<&str>,
    ) -> Result<ProposalPut, StoreError>;

    /// Approve the pending proposal `id` of `key` atomically: in one critical section, read the
    /// stored charter, the memory and the proposal, decide with [`decide_proposal`] (pending,
    /// memory version, learning enabled for the agent in the stored charter, below
    /// `learning.max_notes`, note within `learning.max_note_chars`), then write the new memory
    /// and the approved proposal. The charter is read inside the same critical section as the
    /// write, so a concurrent charter write that turns learning off (which drops the agent's
    /// notes in the same change, design §3) is either seen or happens after the note is stored
    /// (and then drops it); an approve and a reject of the same proposal never both succeed.
    ///
    /// Errors: [`StoreError::NotFound`] (no such proposal for this service),
    /// [`StoreError::NotPending`] (already decided), [`StoreError::Conflict`] (stale memory
    /// version), [`StoreError::Invalid`] (learning off, at `max_notes`, note too long). Emits
    /// [`StoreEvent::MemoryChanged`] and [`StoreEvent::ProposalChanged`].
    async fn approve_proposal(
        &self,
        key: &ServiceKey,
        id: &str,
        if_match_memory: &str,
        actor: &Actor,
    ) -> Result<(MemoryDoc, Proposal), StoreError>;

    /// Reject the pending proposal `id` of `key` atomically ([`decide_proposal`]: pending and
    /// memory version are checked; learning need not be enabled any more); the memory is
    /// returned unchanged. Errors: [`StoreError::NotFound`], [`StoreError::NotPending`],
    /// [`StoreError::Conflict`]. Emits [`StoreEvent::ProposalChanged`].
    async fn reject_proposal(
        &self,
        key: &ServiceKey,
        id: &str,
        if_match_memory: &str,
        actor: &Actor,
    ) -> Result<(MemoryDoc, Proposal), StoreError>;

    async fn list_pending_adoptions(&self) -> Result<Vec<PendingAdoption>, StoreError>;

    /// Record (or replace) the pending adoption of a service.
    async fn put_pending_adoption(&self, adoption: PendingAdoption) -> Result<(), StoreError>;

    /// Remove and return the pending adoption of `key` whose hash is `sha256`.
    async fn take_pending_adoption(
        &self,
        key: &ServiceKey,
        sha256: &str,
    ) -> Result<PendingAdoption, StoreError>;

    /// Persist one control-plane audit record durably (design §8.5): the file store appends
    /// `.audit.jsonl`, the SQLite store inserts into `cp_audit`, the Kubernetes store appends to
    /// its ConfigMap segments in the control-plane namespace. There is no default: a store that
    /// cannot keep the audit must say so with an error, which [`crate::cp_audit::CpAudit`]
    /// logs and counts, never drop it. Records the store produces itself are also broadcast as
    /// [`StoreEvent::CpAudit`].
    async fn append_cp_audit(&self, record: &CpAuditRecord) -> Result<(), StoreError>;

    /// The newest `limit` control-plane audit records this store kept, oldest first (what
    /// [`Store::append_cp_audit`] wrote, and the records the store produced itself).
    async fn cp_audit(&self, limit: usize) -> Result<Vec<CpAuditRecord>, StoreError>;

    /// A store that writes the audit in the background (the Kubernetes store): once the records
    /// appended so far are written or given up. The others write in `append_cp_audit`.
    async fn flush_cp_audit(&self) {}

    /// Records `append_cp_audit` accepted that a background write lost later, and the last
    /// error ([`crate::cp_audit::CpAudit::health`] adds them to its own count).
    fn cp_audit_write_failures(&self) -> (u64, Option<String>) {
        (0, None)
    }

    /// Changes from now on. Lagging receivers lose events (`RecvError::Lagged`) and must resync.
    fn subscribe(&self) -> broadcast::Receiver<StoreEvent>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;

    /// What the test store keeps under its one lock: the stored charter, the memory and the
    /// proposals of one service.
    struct Learning {
        charter: Option<serde_json::Value>,
        memory: MemoryDoc,
        proposals: Vec<Proposal>,
    }

    /// The smallest store: one service; charter, memory and proposals in one mutex, decided with
    /// [`decide_proposal`] the way a real store does. Proves the trait is implementable and
    /// usable as `Arc<dyn Store>`.
    struct Empty {
        tx: broadcast::Sender<StoreEvent>,
        learning: std::sync::Mutex<Learning>,
        audit: std::sync::Mutex<Vec<CpAuditRecord>>,
    }

    /// support's charter: `support-agent` learns in review mode (at most `max_notes` notes of
    /// at most 400 characters), `faq` does not learn.
    fn support_charter(enabled: bool, max_notes: u64) -> serde_json::Value {
        json!({
            "apiVersion": "agentsc.io/v1alpha1", "kind": "Charter",
            "service": {"name": "support", "namespace": "agentsc-demo", "app_port": 8090},
            "agents": [
                {"name": "support-agent", "model": "claude-opus-5-5",
                 "learning": {"enabled": enabled, "mode": "review", "max_notes": max_notes, "max_note_chars": 400}},
                {"name": "faq", "model": "mock"}
            ]
        })
    }

    impl Empty {
        fn new(tx: broadcast::Sender<StoreEvent>, proposals: Vec<Proposal>) -> Self {
            Self {
                tx,
                learning: std::sync::Mutex::new(Learning {
                    charter: Some(support_charter(true, 20)),
                    memory: MemoryDoc {
                        version: "0".into(),
                        agents: BTreeMap::new(),
                    },
                    proposals,
                }),
                audit: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn lock(&self) -> Result<std::sync::MutexGuard<'_, Learning>, StoreError> {
            self.learning
                .lock()
                .map_err(|_| StoreError::Io("poisoned".into()))
        }

        fn decide(
            &self,
            key: &ServiceKey,
            id: &str,
            verdict: ProposalVerdict,
            if_match: &str,
            actor: &Actor,
        ) -> Result<(MemoryDoc, Proposal), StoreError> {
            let mut guard = self.lock()?;
            let Learning {
                charter,
                memory,
                proposals,
            } = &mut *guard;
            let slot = proposals
                .iter_mut()
                .find(|p| p.id == id && p.namespace == key.namespace && p.service == key.service)
                .ok_or(StoreError::NotFound)?;
            let (new_memory, decided) = decide_proposal(
                LearningState {
                    charter: charter.as_ref(),
                    memory,
                    proposal: slot,
                },
                verdict,
                if_match,
                actor,
                "2026-10-21T10:00:00.000Z",
                format!("note-for-{id}"),
            )?;
            let memory_changed = new_memory.version != memory.version;
            *memory = new_memory.clone();
            *slot = decided.clone();
            if memory_changed {
                let _ = self.tx.send(StoreEvent::MemoryChanged {
                    key: key.clone(),
                    version: new_memory.version.clone(),
                });
            }
            let _ = self.tx.send(StoreEvent::ProposalChanged {
                key: key.clone(),
                id: id.to_string(),
            });
            Ok((new_memory, decided))
        }

        /// A charter write that turns `support-agent`'s learning off, dropping its notes in the
        /// same change (design §3), under the same lock as the decisions.
        fn disable_learning(&self) -> Result<(), StoreError> {
            let mut guard = self.lock()?;
            guard.charter = Some(support_charter(false, 20));
            if guard.memory.agents.remove("support-agent").is_some() {
                let next = guard.memory.version.parse::<u64>().unwrap() + 1;
                guard.memory.version = next.to_string();
            }
            Ok(())
        }
    }

    #[async_trait]
    impl Store for Empty {
        async fn list_services(&self) -> Result<Vec<ServiceKey>, StoreError> {
            Ok(vec![])
        }
        async fn get_charter(&self, _: &ServiceKey) -> Result<StoredCharter, StoreError> {
            Err(StoreError::NotFound)
        }
        async fn put_charter(
            &self,
            _: &ServiceKey,
            p: &Precondition,
            _: CharterWrite,
        ) -> Result<StoredCharter, StoreError> {
            match p {
                Precondition::NotExists => Err(StoreError::Invalid(vec!["read-only".into()])),
                Precondition::Version(_) => Err(StoreError::NotFound),
            }
        }
        async fn history(&self, _: &ServiceKey) -> Result<Vec<HistoryEntry>, StoreError> {
            Err(StoreError::NotFound)
        }
        async fn get_revision(&self, _: &ServiceKey, _: &str) -> Result<String, StoreError> {
            Err(StoreError::NotFound)
        }
        async fn delete_service(
            &self,
            _: &ServiceKey,
            _: &str,
            _: &Actor,
        ) -> Result<(), StoreError> {
            Err(StoreError::NotFound)
        }
        async fn get_memory(&self, _: &ServiceKey) -> Result<MemoryDoc, StoreError> {
            Ok(self.lock()?.memory.clone())
        }
        async fn put_memory(
            &self,
            _: &ServiceKey,
            if_match: &str,
            _: BTreeMap<String, Vec<Note>>,
            _: &Actor,
        ) -> Result<MemoryDoc, StoreError> {
            if if_match == "0" {
                Err(StoreError::Io("read-only".into()))
            } else {
                Err(StoreError::Conflict {
                    current: "0".into(),
                })
            }
        }
        async fn list_proposals(&self, f: &ProposalFilter) -> Result<Vec<Proposal>, StoreError> {
            Ok(self
                .lock()?
                .proposals
                .iter()
                .filter(|p| f.matches(p))
                .cloned()
                .collect())
        }
        async fn get_proposal(&self, id: &str) -> Result<Proposal, StoreError> {
            self.lock()?
                .proposals
                .iter()
                .find(|p| p.id == id)
                .cloned()
                .ok_or(StoreError::NotFound)
        }
        async fn put_proposal(
            &self,
            _: &Proposal,
            _: Option<&str>,
        ) -> Result<ProposalPut, StoreError> {
            Err(StoreError::Io("read-only".into()))
        }
        async fn approve_proposal(
            &self,
            key: &ServiceKey,
            id: &str,
            if_match_memory: &str,
            actor: &Actor,
        ) -> Result<(MemoryDoc, Proposal), StoreError> {
            self.decide(key, id, ProposalVerdict::Approve, if_match_memory, actor)
        }
        async fn reject_proposal(
            &self,
            key: &ServiceKey,
            id: &str,
            if_match_memory: &str,
            actor: &Actor,
        ) -> Result<(MemoryDoc, Proposal), StoreError> {
            self.decide(key, id, ProposalVerdict::Reject, if_match_memory, actor)
        }
        async fn list_pending_adoptions(&self) -> Result<Vec<PendingAdoption>, StoreError> {
            Ok(vec![])
        }
        async fn put_pending_adoption(&self, _: PendingAdoption) -> Result<(), StoreError> {
            Err(StoreError::Io("read-only".into()))
        }
        async fn take_pending_adoption(
            &self,
            _: &ServiceKey,
            _: &str,
        ) -> Result<PendingAdoption, StoreError> {
            Err(StoreError::NotFound)
        }
        async fn append_cp_audit(&self, record: &CpAuditRecord) -> Result<(), StoreError> {
            self.audit
                .lock()
                .map_err(|_| StoreError::Io("poisoned".into()))?
                .push(record.clone());
            Ok(())
        }
        async fn cp_audit(&self, limit: usize) -> Result<Vec<CpAuditRecord>, StoreError> {
            let all = self
                .audit
                .lock()
                .map_err(|_| StoreError::Io("poisoned".into()))?;
            Ok(all[all.len().saturating_sub(limit)..].to_vec())
        }
        fn subscribe(&self) -> broadcast::Receiver<StoreEvent> {
            self.tx.subscribe()
        }
    }

    #[tokio::test]
    async fn the_trait_is_object_safe_and_usable() {
        let (tx, _) = broadcast::channel(4);
        let store: Arc<dyn Store> = Arc::new(Empty::new(tx.clone(), vec![]));
        let key = ServiceKey::new("agentsc-demo", "orders");
        assert_eq!(key.to_string(), "agentsc-demo/orders");
        assert_eq!(store.get_charter(&key).await, Err(StoreError::NotFound));
        assert_eq!(
            store
                .put_memory(
                    &key,
                    "7",
                    BTreeMap::new(),
                    &Actor {
                        name: "alice".into(),
                        kind: ActorKind::Session,
                        role: Some(Role::Editor),
                    }
                )
                .await,
            Err(StoreError::Conflict {
                current: "0".into()
            })
        );
        assert_eq!(store.get_memory(&key).await.unwrap().version, "0");
        // every store keeps the control-plane audit (no default that drops it) and reads it back
        let rec: CpAuditRecord = serde_json::from_value(serde_json::json!({
            "ts": "2026-10-21T10:00:00.000Z", "actor": "alice", "actor_kind": "session", "role": "admin",
            "action": "login", "namespace": null, "service": null, "agent": null, "from_version": null,
            "to_version": null, "sha256_before": null, "sha256_after": null, "result": "ok", "reason": null
        }))
        .unwrap();
        store.append_cp_audit(&rec).await.unwrap();
        let mut logout = rec.clone();
        logout.action = crate::api::types::CpAction::Logout;
        store.append_cp_audit(&logout).await.unwrap();
        assert_eq!(
            store.cp_audit(10).await.unwrap(),
            [rec.clone(), logout.clone()]
        );
        assert_eq!(store.cp_audit(1).await.unwrap(), [logout], "the newest");
        let mut rx = store.subscribe();
        tx.send(StoreEvent::MemoryChanged {
            key: key.clone(),
            version: "1".into(),
        })
        .unwrap();
        assert_eq!(
            rx.recv().await.unwrap(),
            StoreEvent::MemoryChanged {
                key,
                version: "1".into()
            }
        );
        // store-produced control-plane audit reaches subscribers
        let mut edit = rec.clone();
        edit.action = crate::api::types::CpAction::CrExternalEdit;
        edit.actor = "k8s:kubectl-edit".into();
        edit.actor_kind = ActorKind::K8s;
        edit.role = None;
        tx.send(StoreEvent::CpAudit(Box::new(edit.clone())))
            .unwrap();
        assert_eq!(
            rx.recv().await.unwrap(),
            StoreEvent::CpAudit(Box::new(edit))
        );
    }

    fn proposal(id: &str, status: ProposalStatus) -> Proposal {
        Proposal {
            id: id.into(),
            namespace: "agentsc-demo".into(),
            service: "support".into(),
            agent: "support-agent".into(),
            note: format!("note of {id}"),
            rationale: "r".into(),
            request_id: "q".into(),
            trace_id: String::new(),
            ts: "2026-10-21T09:59:38.130Z".into(),
            status,
            auto: false,
        }
    }

    fn alice() -> Actor {
        Actor {
            name: "alice".into(),
            kind: ActorKind::Session,
            role: Some(Role::Editor),
        }
    }

    #[test]
    fn deciding_a_proposal() {
        let charter = support_charter(true, 2);
        let memory = MemoryDoc {
            version: "4".into(),
            agents: BTreeMap::new(),
        };
        let p = proposal("p1", ProposalStatus::Pending);
        let ts = "2026-10-21T10:00:00.000Z";
        fn with<'a>(
            charter: &'a serde_json::Value,
            memory: &'a MemoryDoc,
            proposal: &'a Proposal,
        ) -> LearningState<'a> {
            LearningState {
                charter: Some(charter),
                memory,
                proposal,
            }
        }

        let (m, d) = decide_proposal(
            with(&charter, &memory, &p),
            ProposalVerdict::Approve,
            "4",
            &alice(),
            ts,
            "n1".into(),
        )
        .unwrap();
        assert_eq!(d.status, ProposalStatus::Approved);
        assert_eq!(m.version, "5");
        assert_eq!(
            m.agents["support-agent"],
            [Note {
                id: "n1".into(),
                text: "note of p1".into(),
                source: NoteSource::Review,
                request_id: Some("q".into()),
                trace_id: None,
                approved_by: Some("alice".into()),
                ts: ts.into(),
                expires_at: None,
            }]
        );

        let (m, d) = decide_proposal(
            with(&charter, &memory, &p),
            ProposalVerdict::Reject,
            "4",
            &alice(),
            ts,
            "unused".into(),
        )
        .unwrap();
        assert_eq!(d.status, ProposalStatus::Rejected);
        assert_eq!(m, memory, "rejecting leaves the memory alone");

        // stale memory version: a conflict naming the memory version
        for verdict in [ProposalVerdict::Approve, ProposalVerdict::Reject] {
            assert_eq!(
                decide_proposal(
                    with(&charter, &memory, &p),
                    verdict,
                    "3",
                    &alice(),
                    ts,
                    "n".into()
                ),
                Err(StoreError::Conflict {
                    current: "4".into()
                })
            );
        }
        // no longer pending: says so (with any If-Match), so a client knows reloading the
        // memory will not help
        for status in [ProposalStatus::Rejected, ProposalStatus::Approved] {
            let decided = proposal("p1", status);
            for verdict in [ProposalVerdict::Approve, ProposalVerdict::Reject] {
                for if_match in ["4", "3"] {
                    assert_eq!(
                        decide_proposal(
                            with(&charter, &memory, &decided),
                            verdict,
                            if_match,
                            &alice(),
                            ts,
                            "n".into()
                        ),
                        Err(StoreError::NotPending { status })
                    );
                }
            }
        }

        // approving needs learning enabled in the stored charter; rejecting does not
        let off = support_charter(false, 2);
        let mut faq = proposal("p2", ProposalStatus::Pending);
        faq.agent = "faq".into();
        let mut ghost = proposal("p3", ProposalStatus::Pending);
        ghost.agent = "ghost".into();
        for (charter, p) in [
            (Some(&off), &p),
            (Some(&charter), &faq),
            (Some(&charter), &ghost),
            (None, &p),
        ] {
            let s = LearningState {
                charter,
                memory: &memory,
                proposal: p,
            };
            let err = decide_proposal(s, ProposalVerdict::Approve, "4", &alice(), ts, "n".into())
                .unwrap_err();
            assert!(
                matches!(&err, StoreError::Invalid(d) if d[0].contains("does not enable learning")),
                "{err:?}"
            );
            let (m, d) =
                decide_proposal(s, ProposalVerdict::Reject, "4", &alice(), ts, "n".into()).unwrap();
            assert_eq!((m, d.status), (memory.clone(), ProposalStatus::Rejected));
        }

        // approving never goes past learning.max_notes (2 here) or max_note_chars (400)
        let full = MemoryDoc {
            version: "6".into(),
            agents: BTreeMap::from([(
                "support-agent".to_string(),
                vec![
                    Note {
                        id: "a".into(),
                        text: "a".into(),
                        source: NoteSource::Manual,
                        request_id: None,
                        trace_id: None,
                        approved_by: Some("alice".into()),
                        ts: ts.into(),
                        expires_at: None,
                    };
                    2
                ],
            )]),
        };
        let mut long = proposal("p4", ProposalStatus::Pending);
        long.note = "x".repeat(401);
        let err = decide_proposal(
            with(&charter, &full, &long),
            ProposalVerdict::Approve,
            "6",
            &alice(),
            ts,
            "n".into(),
        )
        .unwrap_err();
        let StoreError::Invalid(problems) = err else {
            panic!("{err:?}")
        };
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(
            problems[0].contains("learning.max_notes is 2"),
            "{problems:?}"
        );
        assert!(
            problems[1].contains("max_note_chars is 400"),
            "{problems:?}"
        );

        let broken = MemoryDoc {
            version: u64::MAX.to_string(),
            agents: BTreeMap::new(),
        };
        let v = broken.version.clone();
        assert!(matches!(
            decide_proposal(
                with(&charter, &broken, &p),
                ProposalVerdict::Approve,
                &v,
                &alice(),
                ts,
                "n".into()
            ),
            Err(StoreError::Io(_))
        ));
    }

    #[test]
    fn learning_settings_come_from_the_stored_charter() {
        let plain = support_charter(true, 7);
        assert_eq!(
            AgentLearning::from_charter(&plain, "support-agent"),
            Some(AgentLearning {
                enabled: true,
                max_notes: 7,
                max_note_chars: 400
            })
        );
        // no learning block: off, with the charter defaults
        assert_eq!(
            AgentLearning::from_charter(&plain, "faq"),
            Some(AgentLearning {
                enabled: false,
                max_notes: AgentLearning::DEFAULT_MAX_NOTES,
                max_note_chars: AgentLearning::DEFAULT_MAX_NOTE_CHARS
            })
        );
        assert_eq!(AgentLearning::from_charter(&plain, "ghost"), None);
        // the custom-resource form
        let mut spec = plain.clone();
        let spec_map = spec.as_object_mut().unwrap();
        spec_map.remove("apiVersion");
        spec_map.remove("kind");
        let cr = json!({
            "apiVersion": "agentsc.io/v1alpha1", "kind": "Charter",
            "metadata": {"name": "support", "namespace": "agentsc-demo"},
            "spec": spec
        });
        assert_eq!(
            AgentLearning::from_charter(&cr, "support-agent").map(|l| l.max_notes),
            Some(7)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn approve_and_reject_never_both_win() {
        let key = ServiceKey::new("agentsc-demo", "support");
        for round in 0..50 {
            let (tx, _) = broadcast::channel(16);
            let store: Arc<dyn Store> = Arc::new(Empty::new(
                tx,
                vec![proposal("p1", ProposalStatus::Pending)],
            ));
            let mut rx = store.subscribe();
            let (a, b) = (store.clone(), store.clone());
            let (k1, k2) = (key.clone(), key.clone());
            let approve =
                tokio::spawn(async move { a.approve_proposal(&k1, "p1", "0", &alice()).await });
            let reject =
                tokio::spawn(async move { b.reject_proposal(&k2, "p1", "0", &alice()).await });
            let (approve, reject) = (approve.await.unwrap(), reject.await.unwrap());
            assert!(
                approve.is_ok() != reject.is_ok(),
                "round {round}: exactly one decision wins: {approve:?} / {reject:?}"
            );
            let stored = store.get_proposal("p1").await.unwrap();
            let memory = store.get_memory(&key).await.unwrap();
            match (approve, reject) {
                (Ok((m, d)), Err(e)) => {
                    assert_eq!(stored.status, ProposalStatus::Approved);
                    assert_eq!((m.version.as_str(), &d), ("1", &stored));
                    assert_eq!(memory.agents["support-agent"].len(), 1);
                    // the loser learns that the proposal was decided
                    assert_eq!(
                        e,
                        StoreError::NotPending {
                            status: ProposalStatus::Approved
                        }
                    );
                    assert!(matches!(
                        rx.recv().await.unwrap(),
                        StoreEvent::MemoryChanged { .. }
                    ));
                }
                (Err(e), Ok((m, d))) => {
                    assert_eq!(stored.status, ProposalStatus::Rejected);
                    assert_eq!((m.version.as_str(), &d), ("0", &stored));
                    assert!(memory.agents.is_empty());
                    assert_eq!(
                        e,
                        StoreError::NotPending {
                            status: ProposalStatus::Rejected
                        }
                    );
                }
                _ => unreachable!(),
            }
            assert_eq!(
                rx.recv().await.unwrap(),
                StoreEvent::ProposalChanged {
                    key: key.clone(),
                    id: "p1".into()
                }
            );
        }
        // an unknown proposal, or one of another service
        let (tx, _) = broadcast::channel(4);
        let store = Empty::new(tx, vec![proposal("p1", ProposalStatus::Pending)]);
        let other = ServiceKey::new("agentsc-demo", "orders");
        assert_eq!(
            store.approve_proposal(&key, "p2", "0", &alice()).await,
            Err(StoreError::NotFound)
        );
        assert_eq!(
            store.reject_proposal(&other, "p1", "0", &alice()).await,
            Err(StoreError::NotFound)
        );
    }

    /// The learning check happens inside the store's critical section: a charter write that
    /// turns learning off for an agent without notes (so the memory version does not move)
    /// either comes first, and the approve is refused, or comes after, and drops the note the
    /// approve stored. Never a note for an agent whose learning is off.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn approve_never_outlives_learning_turned_off() {
        let key = ServiceKey::new("agentsc-demo", "support");
        let (mut refused, mut dropped) = (0, 0);
        for round in 0..50 {
            let (tx, _) = broadcast::channel(16);
            let store = Arc::new(Empty::new(
                tx,
                vec![proposal("p1", ProposalStatus::Pending)],
            ));
            let (a, b) = (store.clone(), store.clone());
            let k = key.clone();
            let approve =
                tokio::spawn(async move { a.approve_proposal(&k, "p1", "0", &alice()).await });
            let off = tokio::spawn(async move { b.disable_learning() });
            let approve = approve.await.unwrap();
            off.await.unwrap().unwrap();
            let memory = store.get_memory(&key).await.unwrap();
            assert!(
                !memory.agents.contains_key("support-agent"),
                "round {round}: a note survived learning turned off: {memory:?}"
            );
            match approve {
                Ok(_) => dropped += 1,
                Err(StoreError::Invalid(_)) => refused += 1,
                Err(e) => panic!("round {round}: {e:?}"),
            }
        }
        assert_eq!(refused + dropped, 50);
    }

    #[test]
    fn errors_name_the_current_version() {
        assert_eq!(
            StoreError::Conflict {
                current: "3".into()
            }
            .to_string(),
            "version conflict: the current version is 3"
        );
        assert_eq!(
            StoreError::Invalid(vec!["a".into(), "b".into()]).to_string(),
            "invalid: a; b"
        );
    }

    #[test]
    fn proposal_filters() {
        let p = Proposal {
            id: "1".into(),
            namespace: "agentsc-demo".into(),
            service: "orders".into(),
            agent: "ops-assistant".into(),
            note: "n".into(),
            rationale: "r".into(),
            request_id: "q".into(),
            trace_id: "t".into(),
            ts: "2026-10-21T10:00:00.000Z".into(),
            status: ProposalStatus::Pending,
            auto: false,
        };
        assert!(ProposalFilter::default().matches(&p));
        assert!(
            ProposalFilter {
                status: Some(ProposalStatus::Pending),
                namespace: Some("agentsc-demo".into()),
                service: Some("orders".into()),
            }
            .matches(&p)
        );
        assert!(
            !ProposalFilter {
                status: Some(ProposalStatus::Approved),
                ..Default::default()
            }
            .matches(&p)
        );
        assert!(
            !ProposalFilter {
                service: Some("inventory".into()),
                ..Default::default()
            }
            .matches(&p)
        );
    }
}
