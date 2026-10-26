//! Control-plane audit (docs/design/agent-platform.md §8.5).
//!
//! [`CpAudit::record`] writes every control-plane action three ways: one JSON line on stdout,
//! [`Store::append_cp_audit`] (the file store's `.audit.jsonl`, the SQLite store's `cp_audit`
//! table, the Kubernetes store's ConfigMap segments), and a broadcast that the API turns into
//! the admin-only SSE event `cp_audit` ([`CpAudit::subscribe`]). Records a store produces by
//! itself (`cr_external_edit`) reach subscribers of the store as
//! [`crate::store::StoreEvent::CpAudit`] instead.
//!
//! A store that refuses a record never stops the line, the broadcast or the action audited: the
//! refusal is logged, counted and reported on `GET /readyz` as `cp_audit` ([`CpAudit::health`]),
//! so a lost record is visible. Every store implements `append_cp_audit` (the trait has no
//! default); a process without a store writes stdout only and says so (`persisted: false`).
//!
//! **Refusals of unauthenticated requests** ([`CpAudit::record_unauthenticated`]: a login while
//! rate limited, an `IssueCertificate` refused before its credential was verified) cost nothing
//! to send, so a flood of them would push a store's records out (the Kubernetes store keeps the
//! newest 4 MiB). Each still writes its line on stdout; the store and subscribers get the first
//! of each kind per [`UNAUTHENTICATED_WINDOW`], whose `reason` counts the ones before it that
//! they did not get.
//!
//! The record type is [`CpAuditRecord`] of the API types (its JSON shape is the OpenAPI
//! `CpAuditRecord`), re-exported here with its enums.
use std::collections::HashMap;
use std::fmt;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{SecondsFormat, Utc};
use tokio::sync::broadcast;

pub use crate::api::types::{CpAction, CpAuditHealth, CpAuditRecord, CpResult};
use crate::store::{Actor, Store};

/// Records a slow SSE subscriber may fall behind before it loses some (`RecvError::Lagged`).
pub const SUBSCRIBER_CAPACITY: usize = 1024;
/// Refusals of unauthenticated requests of one kind reach the store once per window (module
/// docs).
pub const UNAUTHENTICATED_WINDOW: Duration = Duration::from_secs(60);
/// Kinds of unauthenticated refusals tracked at once; more start over the windows ended.
const MAX_UNAUTHENTICATED_KINDS: usize = 256;

/// One kind of unauthenticated refusal: when its window began, and how many the store did not
/// get since.
struct Window {
    since: Instant,
    held_back: u64,
}

/// The control-plane audit log.
pub struct CpAudit {
    store: Option<Arc<dyn Store>>,
    out: Mutex<Box<dyn Write + Send>>,
    tx: broadcast::Sender<Arc<CpAuditRecord>>,
    /// Records the store refused, and the last refusal.
    append_failures: AtomicU64,
    last_error: Mutex<Option<String>>,
    /// [`CpAudit::record_unauthenticated`], by kind, and its window.
    unauthenticated: Mutex<HashMap<String, Window>>,
    window: Duration,
}

impl fmt::Debug for CpAudit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CpAudit")
            .field("store", &self.store.is_some())
            .field("subscribers", &self.tx.receiver_count())
            .field(
                "append_failures",
                &self.append_failures.load(Ordering::Relaxed),
            )
            .finish()
    }
}

/// The audit timestamp format: RFC 3339 UTC with milliseconds (`2026-10-21T10:00:00.000Z`).
pub fn now_ts() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

impl CpAudit {
    /// Lines go to stdout; records are also persisted in `store` when there is one.
    pub fn new(store: Option<Arc<dyn Store>>) -> Self {
        Self::with_writer(store, Box::new(std::io::stdout()))
    }

    /// Like [`Self::new`], with the JSON lines written to `out` instead of stdout.
    pub fn with_writer(store: Option<Arc<dyn Store>>, out: Box<dyn Write + Send>) -> Self {
        let (tx, _) = broadcast::channel(SUBSCRIBER_CAPACITY);
        Self {
            store,
            out: Mutex::new(out),
            tx,
            append_failures: AtomicU64::new(0),
            last_error: Mutex::new(None),
            unauthenticated: Mutex::new(HashMap::new()),
            window: UNAUTHENTICATED_WINDOW,
        }
    }

    /// Another window for [`CpAudit::record_unauthenticated`] (tests).
    #[cfg(test)]
    pub fn with_unauthenticated_window(mut self, window: Duration) -> Self {
        self.window = window;
        self
    }

    /// Whether records are persisted, and the records the store refused or lost so far, at
    /// once or in a background write ([`Store::cp_audit_write_failures`]) (`GET /readyz`).
    pub fn health(&self) -> CpAuditHealth {
        let (lost, lost_error) = self
            .store
            .as_ref()
            .map_or((0, None), |s| s.cp_audit_write_failures());
        let refused = self
            .last_error
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        CpAuditHealth {
            persisted: self.store.is_some(),
            append_failures: self.append_failures.load(Ordering::Relaxed) + lost,
            last_error: lost_error.or(refused),
        }
    }

    /// Once the store has written the records so far ([`Store::flush_cp_audit`]).
    pub async fn flush(&self) {
        if let Some(store) = &self.store {
            store.flush_cp_audit().await;
        }
    }

    /// A record of `action` by `actor` with `result`, stamped now; the optional fields are
    /// unset for the caller to fill in.
    pub fn entry(action: CpAction, actor: &Actor, result: CpResult) -> CpAuditRecord {
        CpAuditRecord {
            ts: now_ts(),
            actor: actor.name.clone(),
            actor_kind: actor.kind,
            role: actor.role,
            action,
            namespace: None,
            service: None,
            agent: None,
            from_version: None,
            to_version: None,
            sha256_before: None,
            sha256_after: None,
            result,
            reason: None,
        }
    }

    /// Write `record`: one JSON line on stdout, then the store, then subscribers. A failure of
    /// one is logged (a store's also counted, [`CpAudit::health`]) and never stops the others or
    /// the caller.
    pub async fn record(&self, record: CpAuditRecord) {
        let record = Arc::new(record);
        self.write_line(&record);
        self.persist(record).await;
    }

    /// [`CpAudit::record`] for the refusal of a request nobody authenticated (module docs):
    /// `kind` names what was refused, without anything the caller chose.
    pub async fn record_unauthenticated(&self, kind: &str, mut record: CpAuditRecord) {
        self.write_line(&record);
        let now = Instant::now();
        let held_back = {
            let mut windows = self
                .unauthenticated
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            match windows.get_mut(kind) {
                Some(w) if now.duration_since(w.since) < self.window => {
                    w.held_back += 1;
                    return;
                }
                Some(w) => {
                    std::mem::replace(
                        w,
                        Window {
                            since: now,
                            held_back: 0,
                        },
                    )
                    .held_back
                }
                None => {
                    if windows.len() >= MAX_UNAUTHENTICATED_KINDS {
                        windows.retain(|_, w| now.duration_since(w.since) < self.window);
                    }
                    windows.insert(
                        kind.to_string(),
                        Window {
                            since: now,
                            held_back: 0,
                        },
                    );
                    0
                }
            }
        };
        if held_back > 0 {
            let note = format!(
                "{held_back} more refusals like this one since the last recorded are on stdout only"
            );
            record.reason = Some(match record.reason.take() {
                Some(r) => format!("{r}; {note}"),
                None => note,
            });
        }
        self.persist(Arc::new(record)).await;
    }

    /// The JSON line on stdout.
    fn write_line(&self, record: &CpAuditRecord) {
        match serde_json::to_string(record) {
            Ok(mut line) => {
                line.push('\n');
                // one write per line, under the lock, so concurrent records never interleave
                let mut out = self.out.lock().unwrap_or_else(|p| p.into_inner());
                if let Err(e) = out.write_all(line.as_bytes()).and_then(|()| out.flush()) {
                    tracing::warn!(error = %e, "writing a control-plane audit line failed");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "serializing a control-plane audit record failed")
            }
        }
    }

    /// The store, then subscribers.
    async fn persist(&self, record: Arc<CpAuditRecord>) {
        if let Some(store) = &self.store
            && let Err(e) = store.append_cp_audit(&record).await
        {
            let failures = self.append_failures.fetch_add(1, Ordering::Relaxed) + 1;
            *self.last_error.lock().unwrap_or_else(|p| p.into_inner()) = Some(e.to_string());
            tracing::error!(
                error = %e,
                action = ?record.action,
                failures,
                "persisting a control-plane audit record failed; it is only on stdout"
            );
        }
        // no subscriber is not an error
        let _ = self.tx.send(record);
    }

    /// Every record from now on, in order. A receiver more than [`SUBSCRIBER_CAPACITY`] records
    /// behind loses the oldest (`RecvError::Lagged`).
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<CpAuditRecord>> {
        self.tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Role;
    use crate::store::{
        ActorKind, CharterWrite, HistoryEntry, MemoryDoc, Note, PendingAdoption, Precondition,
        Proposal, ProposalFilter, ProposalPut, ServiceKey, StoreError, StoreEvent, StoredCharter,
    };
    use async_trait::async_trait;
    use std::collections::BTreeMap;

    /// A shared buffer standing in for stdout.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Capture {
        fn lines(&self) -> Vec<String> {
            String::from_utf8(self.0.lock().unwrap().clone())
                .unwrap()
                .lines()
                .map(str::to_string)
                .collect()
        }
    }

    /// A store that keeps audit records (or refuses them) and has nothing else.
    struct AuditOnly {
        records: Mutex<Vec<CpAuditRecord>>,
        fail: bool,
        tx: broadcast::Sender<StoreEvent>,
    }

    impl AuditOnly {
        fn new(fail: bool) -> Arc<Self> {
            Arc::new(Self {
                records: Mutex::new(Vec::new()),
                fail,
                tx: broadcast::channel(4).0,
            })
        }
    }

    #[async_trait]
    impl Store for AuditOnly {
        async fn list_services(&self) -> Result<Vec<ServiceKey>, StoreError> {
            Ok(Vec::new())
        }
        async fn get_charter(&self, _: &ServiceKey) -> Result<StoredCharter, StoreError> {
            Err(StoreError::NotFound)
        }
        async fn put_charter(
            &self,
            _: &ServiceKey,
            _: &Precondition,
            _: CharterWrite,
        ) -> Result<StoredCharter, StoreError> {
            Err(StoreError::NotFound)
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
            Err(StoreError::NotFound)
        }
        async fn put_memory(
            &self,
            _: &ServiceKey,
            _: &str,
            _: BTreeMap<String, Vec<Note>>,
            _: &Actor,
        ) -> Result<MemoryDoc, StoreError> {
            Err(StoreError::NotFound)
        }
        async fn list_proposals(&self, _: &ProposalFilter) -> Result<Vec<Proposal>, StoreError> {
            Ok(Vec::new())
        }
        async fn get_proposal(&self, _: &str) -> Result<Proposal, StoreError> {
            Err(StoreError::NotFound)
        }
        async fn put_proposal(
            &self,
            _: &Proposal,
            _: Option<&str>,
        ) -> Result<ProposalPut, StoreError> {
            Err(StoreError::NotFound)
        }
        async fn approve_proposal(
            &self,
            _: &ServiceKey,
            _: &str,
            _: &str,
            _: &Actor,
        ) -> Result<(MemoryDoc, Proposal), StoreError> {
            Err(StoreError::NotFound)
        }
        async fn reject_proposal(
            &self,
            _: &ServiceKey,
            _: &str,
            _: &str,
            _: &Actor,
        ) -> Result<(MemoryDoc, Proposal), StoreError> {
            Err(StoreError::NotFound)
        }
        async fn list_pending_adoptions(&self) -> Result<Vec<PendingAdoption>, StoreError> {
            Ok(Vec::new())
        }
        async fn put_pending_adoption(&self, _: PendingAdoption) -> Result<(), StoreError> {
            Err(StoreError::NotFound)
        }
        async fn take_pending_adoption(
            &self,
            _: &ServiceKey,
            _: &str,
        ) -> Result<PendingAdoption, StoreError> {
            Err(StoreError::NotFound)
        }
        async fn append_cp_audit(&self, record: &CpAuditRecord) -> Result<(), StoreError> {
            if self.fail {
                return Err(StoreError::Io("disk full".into()));
            }
            self.records.lock().unwrap().push(record.clone());
            Ok(())
        }
        async fn cp_audit(&self, limit: usize) -> Result<Vec<CpAuditRecord>, StoreError> {
            let all = self.records.lock().unwrap();
            Ok(all[all.len().saturating_sub(limit)..].to_vec())
        }
        fn subscribe(&self) -> broadcast::Receiver<StoreEvent> {
            self.tx.subscribe()
        }
    }

    fn alice() -> Actor {
        Actor {
            name: "alice".into(),
            kind: ActorKind::Token,
            role: Some(Role::Admin),
        }
    }

    fn charter_put() -> CpAuditRecord {
        let mut r = CpAudit::entry(CpAction::CharterPut, &alice(), CpResult::Ok);
        r.namespace = Some("shop".into());
        r.service = Some("orders".into());
        r.from_version = Some("6".into());
        r.to_version = Some("7".into());
        r
    }

    #[test]
    fn entry_fills_the_actor_and_a_millisecond_utc_timestamp() {
        let r = CpAudit::entry(CpAction::Login, &alice(), CpResult::Denied);
        assert_eq!(r.actor, "alice");
        assert_eq!(r.actor_kind, ActorKind::Token);
        assert_eq!(r.role, Some(Role::Admin));
        assert_eq!((r.action, r.result), (CpAction::Login, CpResult::Denied));
        assert!(r.namespace.is_none() && r.reason.is_none() && r.agent.is_none());
        // 2026-10-21T10:00:00.000Z
        assert_eq!(r.ts.len(), 24, "{}", r.ts);
        assert!(
            r.ts.ends_with('Z') && r.ts.as_bytes()[19] == b'.',
            "{}",
            r.ts
        );
        chrono::DateTime::parse_from_rfc3339(&r.ts).unwrap();
    }

    #[tokio::test]
    async fn record_writes_a_line_persists_and_broadcasts() {
        let out = Capture::default();
        let store = AuditOnly::new(false);
        let audit = CpAudit::with_writer(Some(store.clone()), Box::new(out.clone()));
        let mut rx = audit.subscribe();

        let rec = charter_put();
        audit.record(rec.clone()).await;
        let mut sidecar = CpAudit::entry(
            CpAction::ConnectDenied,
            &Actor {
                name: "sidecar:spiffe://agentsc/ns/shop/svc/orders/orders-0".into(),
                kind: ActorKind::Sidecar,
                role: None,
            },
            CpResult::Denied,
        );
        sidecar.reason = Some("Hello names another service".into());
        audit.record(sidecar.clone()).await;

        // stdout: one JSON object per line, the record exactly
        let lines = out.lines();
        assert_eq!(lines.len(), 2, "{lines:?}");
        let first: CpAuditRecord = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(first, rec);
        let v: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        assert_eq!(v["action"], "connect_denied");
        assert_eq!(v["actor_kind"], "sidecar");
        assert_eq!(v["result"], "denied");
        assert!(v["role"].is_null());

        // the store
        assert_eq!(
            *store.records.lock().unwrap(),
            [rec.clone(), sidecar.clone()]
        );

        // subscribers, in order
        assert_eq!(*rx.recv().await.unwrap(), rec);
        assert_eq!(*rx.recv().await.unwrap(), sidecar);
        assert!(format!("{audit:?}").contains("subscribers"));
    }

    #[tokio::test]
    async fn a_failing_store_does_not_stop_the_line_or_the_broadcast() {
        let out = Capture::default();
        let audit = CpAudit::with_writer(Some(AuditOnly::new(true)), Box::new(out.clone()));
        let mut rx = audit.subscribe();
        assert_eq!(
            audit.health(),
            CpAuditHealth {
                persisted: true,
                append_failures: 0,
                last_error: None
            }
        );
        audit.record(charter_put()).await;
        audit.record(charter_put()).await;
        assert_eq!(out.lines().len(), 2);
        assert_eq!(rx.recv().await.unwrap().action, CpAction::CharterPut);
        // the refusals are surfaced, not dropped
        let h = audit.health();
        assert_eq!(h.append_failures, 2);
        assert_eq!(h.last_error.as_deref(), Some("store: disk full"));
        assert!(format!("{audit:?}").contains("append_failures: 2"));
    }

    #[tokio::test]
    async fn without_a_store_or_subscribers() {
        let out = Capture::default();
        let audit = CpAudit::with_writer(None, Box::new(out.clone()));
        audit.record(charter_put()).await;
        let late = audit.subscribe();
        assert_eq!(out.lines().len(), 1);
        assert!(late.is_empty());
        // stdout only, and it says so
        assert!(!audit.health().persisted);
        // the stdout constructor builds
        let _ = CpAudit::new(None);
    }

    #[tokio::test]
    async fn concurrent_records_never_interleave() {
        let out = Capture::default();
        let audit = Arc::new(CpAudit::with_writer(None, Box::new(out.clone())));
        let mut tasks = Vec::new();
        for i in 0..32 {
            let audit = audit.clone();
            tasks.push(tokio::spawn(async move {
                let mut r = charter_put();
                r.reason = Some("x".repeat(i * 100));
                audit.record(r).await;
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        let lines = out.lines();
        assert_eq!(lines.len(), 32);
        for line in lines {
            serde_json::from_str::<CpAuditRecord>(&line).unwrap();
        }
    }

    /// The review finding: anyone can send refusals of unauthenticated requests (a login while
    /// rate limited, an IssueCertificate with a bad name), and one store record each let a flood
    /// push the store's records out. Every one is on stdout; the store and subscribers get the
    /// first of each kind per window, which counts the ones they did not get.
    #[tokio::test]
    async fn unauthenticated_refusals_reach_the_store_once_per_window() {
        let store = AuditOnly::new(false);
        let out = Capture::default();
        let audit = CpAudit::with_writer(Some(store.clone()), Box::new(out.clone()))
            .with_unauthenticated_window(Duration::from_millis(200));
        let mut rx = audit.subscribe();
        let refused = |reason: &str| {
            let mut r = CpAudit::entry(CpAction::LoginFailed, &alice(), CpResult::Denied);
            r.reason = Some(reason.into());
            r
        };
        for i in 0..5 {
            audit
                .record_unauthenticated("login rate limited", refused(&format!("flood {i}")))
                .await;
        }
        audit
            .record_unauthenticated("IssueCertificate InvalidArgument", refused("other kind"))
            .await;
        assert_eq!(out.lines().len(), 6, "every one on stdout");
        let kept = |s: &AuditOnly| -> Vec<String> {
            s.records
                .lock()
                .unwrap()
                .iter()
                .map(|r| r.reason.clone().unwrap())
                .collect()
        };
        assert_eq!(kept(&store), ["flood 0", "other kind"]);
        assert_eq!(rx.recv().await.unwrap().reason.as_deref(), Some("flood 0"));
        assert_eq!(
            rx.recv().await.unwrap().reason.as_deref(),
            Some("other kind")
        );
        assert!(rx.try_recv().is_err());
        // the next window: recorded, with the count of the ones held back
        tokio::time::sleep(Duration::from_millis(250)).await;
        audit
            .record_unauthenticated("login rate limited", refused("flood 5"))
            .await;
        assert_eq!(
            kept(&store).last().unwrap(),
            "flood 5; 4 more refusals like this one since the last recorded are on stdout only"
        );
        // record() is never held back
        for _ in 0..3 {
            audit.record(refused("authenticated")).await;
        }
        assert_eq!(kept(&store).len(), 6);
    }
}
