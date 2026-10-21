//! The control-plane store (design §8.4): charters with history, memory, proposals and pending
//! adoptions, per service. Two implementations follow: `file:<dir>` (B3a, `store/file.rs`) and
//! `kubernetes` (B3b, `k8s`).
//!
//! The store only persists. Every write reaching it has already passed, in order: the charter
//! validator → `policy` → role on the diff → the version-skew check (design §8.4). The store
//! enforces the optimistic-concurrency precondition and assigns versions: decimal strings of a
//! `u64` counter, monotonic per service and never reused, plus an `epoch` (a UUID; a new one when
//! a service's charter is deleted and recreated). Memory has its own version counter per service.
use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::api::types::CpAuditRecord;
use crate::config::Role;

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

/// Decide a pending proposal against the service's memory: the pure part of
/// [`Store::approve_proposal`] and [`Store::reject_proposal`], which a store runs inside the one
/// critical section (file store: its lock; Kubernetes store: one `status` replace with the read
/// `resourceVersion`, since memory and proposals live in the same Charter status) that also
/// writes the result.
///
/// Refused with [`StoreError::Conflict`] (current = the memory version) when `if_match_memory` is
/// not the memory version or the proposal is no longer pending, so of an approve and a reject
/// racing for the same proposal exactly one wins. Approving appends the note (`source: review`,
/// `approved_by` = the actor, id `note_id`, `ts`) to the agent's notes and bumps the memory
/// version; rejecting leaves the memory as it is. Returns the new memory and the decided
/// proposal.
pub fn decide_proposal(
    memory: &MemoryDoc,
    proposal: &Proposal,
    verdict: ProposalVerdict,
    if_match_memory: &str,
    actor: &Actor,
    ts: &str,
    note_id: String,
) -> Result<(MemoryDoc, Proposal), StoreError> {
    let conflict = || StoreError::Conflict {
        current: memory.version.clone(),
    };
    if if_match_memory != memory.version || proposal.status != ProposalStatus::Pending {
        return Err(conflict());
    }
    let mut decided = proposal.clone();
    let mut memory = memory.clone();
    match verdict {
        ProposalVerdict::Reject => decided.status = ProposalStatus::Rejected,
        ProposalVerdict::Approve => {
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
    /// and a new epoch when the service had no charter). Records the version in the history.
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

    /// Approve the pending proposal `id` of `key` atomically: in one critical section, check
    /// that it is still pending and that the memory version is `if_match_memory`, add its note
    /// to the agent's memory (new memory version) and mark it approved ([`decide_proposal`]).
    /// An approve and a reject of the same proposal can therefore never both succeed. Errors:
    /// [`StoreError::NotFound`] (no such proposal for this service), [`StoreError::Conflict`]
    /// (stale memory version, or the proposal is no longer pending). Emits
    /// [`StoreEvent::MemoryChanged`] and [`StoreEvent::ProposalChanged`]. The caller has checked
    /// the stored charter first (learning still enabled for the agent, design §7).
    async fn approve_proposal(
        &self,
        key: &ServiceKey,
        id: &str,
        if_match_memory: &str,
        actor: &Actor,
    ) -> Result<(MemoryDoc, Proposal), StoreError>;

    /// Reject the pending proposal `id` of `key` atomically (same checks and errors as
    /// [`Store::approve_proposal`]); the memory is returned unchanged. Emits
    /// [`StoreEvent::ProposalChanged`].
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

    /// Persist one control-plane audit record (the file store appends `.audit.jsonl`; stores
    /// without an audit file keep the default, which writes nothing). Records the store
    /// produces itself are also broadcast as [`StoreEvent::CpAudit`].
    async fn append_cp_audit(&self, _record: &CpAuditRecord) -> Result<(), StoreError> {
        Ok(())
    }

    /// Changes from now on. Lagging receivers lose events (`RecvError::Lagged`) and must resync.
    fn subscribe(&self) -> broadcast::Receiver<StoreEvent>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// The smallest store: no charters; memory and proposals in one mutex, decided with
    /// [`decide_proposal`] the way a real store does. Proves the trait is implementable and
    /// usable as `Arc<dyn Store>`.
    struct Empty {
        tx: broadcast::Sender<StoreEvent>,
        learning: std::sync::Mutex<(MemoryDoc, Vec<Proposal>)>,
    }

    impl Empty {
        fn new(tx: broadcast::Sender<StoreEvent>, proposals: Vec<Proposal>) -> Self {
            Self {
                tx,
                learning: std::sync::Mutex::new((
                    MemoryDoc {
                        version: "0".into(),
                        agents: BTreeMap::new(),
                    },
                    proposals,
                )),
            }
        }

        fn decide(
            &self,
            key: &ServiceKey,
            id: &str,
            verdict: ProposalVerdict,
            if_match: &str,
            actor: &Actor,
        ) -> Result<(MemoryDoc, Proposal), StoreError> {
            let mut guard = self
                .learning
                .lock()
                .map_err(|_| StoreError::Io("poisoned".into()))?;
            let (memory, proposals) = &mut *guard;
            let slot = proposals
                .iter_mut()
                .find(|p| p.id == id && p.namespace == key.namespace && p.service == key.service)
                .ok_or(StoreError::NotFound)?;
            let (new_memory, decided) = decide_proposal(
                memory,
                slot,
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
            let guard = self
                .learning
                .lock()
                .map_err(|_| StoreError::Io("poisoned".into()))?;
            Ok(guard.0.clone())
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
            let guard = self
                .learning
                .lock()
                .map_err(|_| StoreError::Io("poisoned".into()))?;
            Ok(guard.1.iter().filter(|p| f.matches(p)).cloned().collect())
        }
        async fn get_proposal(&self, id: &str) -> Result<Proposal, StoreError> {
            let guard = self
                .learning
                .lock()
                .map_err(|_| StoreError::Io("poisoned".into()))?;
            guard
                .1
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
        fn subscribe(&self) -> broadcast::Receiver<StoreEvent> {
            self.tx.subscribe()
        }
    }

    #[tokio::test]
    async fn the_trait_is_object_safe_and_usable() {
        let (tx, _) = broadcast::channel(4);
        let store: Arc<dyn Store> = Arc::new(Empty::new(tx.clone(), vec![]));
        let key = ServiceKey::new("attache-demo", "orders");
        assert_eq!(key.to_string(), "attache-demo/orders");
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
        // the default `append_cp_audit` accepts and drops
        let rec: CpAuditRecord = serde_json::from_value(serde_json::json!({
            "ts": "2026-10-21T10:00:00.000Z", "actor": "alice", "actor_kind": "session", "role": "admin",
            "action": "login", "namespace": null, "service": null, "agent": null, "from_version": null,
            "to_version": null, "sha256_before": null, "sha256_after": null, "result": "ok", "reason": null
        }))
        .unwrap();
        store.append_cp_audit(&rec).await.unwrap();
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
            namespace: "attache-demo".into(),
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
        let memory = MemoryDoc {
            version: "4".into(),
            agents: BTreeMap::new(),
        };
        let p = proposal("p1", ProposalStatus::Pending);
        let ts = "2026-10-21T10:00:00.000Z";

        let (m, d) = decide_proposal(
            &memory,
            &p,
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
            &memory,
            &p,
            ProposalVerdict::Reject,
            "4",
            &alice(),
            ts,
            "unused".into(),
        )
        .unwrap();
        assert_eq!(d.status, ProposalStatus::Rejected);
        assert_eq!(m, memory, "rejecting leaves the memory alone");

        // stale memory version, or no longer pending: conflict naming the memory version
        for (p, if_match) in [
            (p.clone(), "3"),
            (proposal("p1", ProposalStatus::Rejected), "4"),
            (proposal("p1", ProposalStatus::Approved), "4"),
        ] {
            for verdict in [ProposalVerdict::Approve, ProposalVerdict::Reject] {
                assert_eq!(
                    decide_proposal(&memory, &p, verdict, if_match, &alice(), ts, "n".into()),
                    Err(StoreError::Conflict {
                        current: "4".into()
                    })
                );
            }
        }
        let broken = MemoryDoc {
            version: u64::MAX.to_string(),
            agents: BTreeMap::new(),
        };
        let v = broken.version.clone();
        assert!(matches!(
            decide_proposal(
                &broken,
                &p,
                ProposalVerdict::Approve,
                &v,
                &alice(),
                ts,
                "n".into()
            ),
            Err(StoreError::Io(_))
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn approve_and_reject_never_both_win() {
        let key = ServiceKey::new("attache-demo", "support");
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
                    // the loser was told the memory version that is current now
                    assert_eq!(
                        e,
                        StoreError::Conflict {
                            current: "1".into()
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
                        StoreError::Conflict {
                            current: "0".into()
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
        let other = ServiceKey::new("attache-demo", "orders");
        assert_eq!(
            store.approve_proposal(&key, "p2", "0", &alice()).await,
            Err(StoreError::NotFound)
        );
        assert_eq!(
            store.reject_proposal(&other, "p1", "0", &alice()).await,
            Err(StoreError::NotFound)
        );
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
            namespace: "attache-demo".into(),
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
                namespace: Some("attache-demo".into()),
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
