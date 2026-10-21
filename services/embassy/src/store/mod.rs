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

/// A change, broadcast to subscribers (the Connect streams push charters and memory from these;
/// the API turns them into SSE `config` and `proposal` events).
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
    /// replace the stored proposal with the same `id` (a status change).
    async fn put_proposal(
        &self,
        proposal: &Proposal,
        dedup_key: Option<&str>,
    ) -> Result<ProposalPut, StoreError>;

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
    /// without an audit file keep the default, which writes nothing).
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

    /// The smallest store: nothing stored, nothing accepted. Proves the trait is implementable
    /// and usable as `Arc<dyn Store>`.
    struct Empty(broadcast::Sender<StoreEvent>);

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
            Ok(MemoryDoc {
                version: "0".into(),
                agents: BTreeMap::new(),
            })
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
        async fn list_proposals(&self, _: &ProposalFilter) -> Result<Vec<Proposal>, StoreError> {
            Ok(vec![])
        }
        async fn get_proposal(&self, _: &str) -> Result<Proposal, StoreError> {
            Err(StoreError::NotFound)
        }
        async fn put_proposal(
            &self,
            _: &Proposal,
            _: Option<&str>,
        ) -> Result<ProposalPut, StoreError> {
            Err(StoreError::Io("read-only".into()))
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
            self.0.subscribe()
        }
    }

    #[tokio::test]
    async fn the_trait_is_object_safe_and_usable() {
        let (tx, _) = broadcast::channel(4);
        let store: Arc<dyn Store> = Arc::new(Empty(tx.clone()));
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
