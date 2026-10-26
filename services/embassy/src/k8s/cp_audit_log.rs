//! The control-plane audit of the `kubernetes` store (design §8.5): a ring of [`SEGMENTS`]
//! ConfigMaps in the control-plane namespace (`--cp-namespace`).
//!
//! | What | Where |
//! | --- | --- |
//! | a segment | ConfigMap `agentsc-cp-audit-<slot>`, `slot` in `0..SEGMENTS` ([`segment_name`]) |
//! | its records | `data["records.jsonl"]`, one [`CpAuditRecord`] per line, in the order they were appended |
//! | its place in the ring | annotation [`SEQ_ANNOTATION`]: a decimal `u64`, +1 per new segment; the segment of sequence `n` is in slot `n % SEGMENTS` |
//!
//! **Append** ([`CpAuditLog::append`]) only queues the record: a write replaces a whole segment
//! (up to [`SEGMENT_BYTES`]) for records of a few hundred bytes, so no request handler and no
//! admission webhook waits for one. A writer task, started by the first record queued, writes
//! the queue, at most [`SEGMENT_BYTES`] of records per write, until it is empty, and waits
//! [`FLUSH_DELAY`] before each write (gathering what comes in meanwhile) unless a segment's worth
//! is waiting: at most one write per second and process however many records arrive, plus one
//! per full segment. The queue holds at most
//! [`MAX_QUEUED_BYTES`]; beyond that `append` refuses, for [`crate::cp_audit::CpAudit`] to log
//! and count. A write that fails is logged and its records are counted
//! ([`CpAuditLog::failures`], reported by `GET /readyz` as `cp_audit.append_failures`): nothing is
//! dropped silently, and every record is on stdout as well. [`CpAuditLog::flush`] waits for the
//! records queued so far; a read flushes first, and `embassy serve` flushes at shutdown.
//!
//! **Write.** Records go to the head (the segment with the highest sequence) while the head stays
//! within [`SEGMENT_BYTES`]; otherwise a new head (sequence + 1) replaces the oldest segment in
//! its slot. So the ring keeps the newest `SEGMENTS × SEGMENT_BYTES` (4 MiB) of records, and
//! writing never needs `list` or `delete`. Every write carries the `resourceVersion` it read:
//! embassy and embassy-ca (both audit, and embassy-ca may run more than one replica) never
//! overwrite each other's lines, and a conflict reads again and retries. A record whose line
//! alone is larger than [`SEGMENT_BYTES`] gets a segment of its own (the API server refuses a
//! ConfigMap above 1 MiB, and that write fails).
//!
//! **Read** ([`CpAuditLog::read`]): every slot, segments oldest first and lines in order, then
//! sorted by `ts` (stable): two processes may each append to the segment they last saw as the
//! head, so lines of the same second can sit in neighbouring segments.
//!
//! **RBAC** (`deploy/helm/agent-sidecar/templates/rbac.yaml`, Role `agentsc-embassy-cp-audit` in
//! the control-plane namespace, both service accounts): `get` and `update` on exactly the
//! [`SEGMENTS`] names, and `create` (Kubernetes cannot restrict `create` by name). No `list`,
//! `watch` or `delete`, and no access to any other ConfigMap. The segments are not owned by the
//! Helm release, so `helm uninstall` leaves the audit in place.
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use k8s_openapi::api::core::v1::ConfigMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use tokio::sync::{Notify, watch};

use super::client::{ApiError, CharterApi, FIELD_MANAGER};
use crate::api::types::CpAuditRecord;
use crate::store::StoreError;

/// Segments in the ring. The chart's RBAC names each of them (`until 16` in rbac.yaml).
pub const SEGMENTS: u64 = 16;
/// A segment takes no more records once its data reaches this size.
pub const SEGMENT_BYTES: usize = 256 * 1024;
/// The prefix of the segment names.
pub const SEGMENT_PREFIX: &str = "agentsc-cp-audit-";
/// The key of the records in a segment's `data`.
pub const RECORDS_KEY: &str = "records.jsonl";
/// The segment's sequence number.
pub const SEQ_ANNOTATION: &str = "agentsc.io/cp-audit-seq";
/// The label every segment carries (`kubectl get cm -l agentsc.io/cp-audit`).
pub const SEGMENT_LABEL: &str = "agentsc.io/cp-audit";
/// Reads and retries of one write after conflicts.
const MAX_ATTEMPTS: usize = 8;
/// How long the writer task gathers records before its first write: a burst is one write.
pub const FLUSH_DELAY: Duration = Duration::from_secs(1);
/// Records waiting to be written, at most: as much as the ring holds.
pub const MAX_QUEUED_BYTES: usize = SEGMENTS as usize * SEGMENT_BYTES;

/// `agentsc-cp-audit-<slot>`.
pub fn segment_name(slot: u64) -> String {
    format!("{SEGMENT_PREFIX}{slot}")
}

fn api_err(e: ApiError) -> StoreError {
    match e {
        ApiError::NotFound => StoreError::NotFound,
        ApiError::Refused(m) => StoreError::Invalid(vec![format!("control-plane audit: {m}")]),
        other => StoreError::Io(format!("kubernetes (control-plane audit): {other}")),
    }
}

/// The sequence number of a segment; `None` when the annotation is missing or not a number
/// (such a slot counts as the oldest and is the first replaced).
fn seq_of(cm: &ConfigMap) -> Option<u64> {
    cm.metadata
        .annotations
        .as_ref()?
        .get(SEQ_ANNOTATION)?
        .parse()
        .ok()
}

fn records_of(cm: &ConfigMap) -> &str {
    cm.data
        .as_ref()
        .and_then(|d| d.get(RECORDS_KEY))
        .map_or("", String::as_str)
}

/// The head as last read: its sequence number and the object (with its `resourceVersion`).
#[derive(Clone)]
struct Head {
    seq: u64,
    cm: ConfigMap,
}

/// The records appended and not yet written, oldest first.
#[derive(Default)]
struct Queue {
    lines: VecDeque<String>,
    bytes: usize,
    /// Records ever queued (what [`CpAuditLog::flush`] waits for).
    queued: u64,
    /// A writer task is running.
    writing: bool,
}

/// What the writer task and [`CpAuditLog`] share.
struct Shared {
    api: Arc<dyn CharterApi>,
    namespace: String,
    /// The head as last written or read (only the writer task uses it).
    head: tokio::sync::Mutex<Option<Head>>,
    queue: Mutex<Queue>,
    /// Records the writer is done with, written or not.
    done: watch::Sender<u64>,
    /// [`CpAuditLog::flush`]: write now instead of after the delay.
    now: Notify,
    /// The pause before each write ([`FLUSH_DELAY`]; tests set another).
    delay: Duration,
    /// Records the writer could not persist, and the last error.
    failures: AtomicU64,
    last_error: Mutex<Option<String>>,
}

/// See the module docs.
pub struct CpAuditLog {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for CpAuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CpAuditLog")
            .field("namespace", &self.shared.namespace)
            .finish_non_exhaustive()
    }
}

impl CpAuditLog {
    pub fn new(api: Arc<dyn CharterApi>, namespace: &str) -> Self {
        Self {
            shared: Arc::new(Shared {
                api,
                namespace: namespace.to_string(),
                head: tokio::sync::Mutex::new(None),
                queue: Mutex::new(Queue::default()),
                done: watch::Sender::new(0),
                now: Notify::new(),
                delay: FLUSH_DELAY,
                failures: AtomicU64::new(0),
                last_error: Mutex::new(None),
            }),
        }
    }

    /// Another pause before each write than [`FLUSH_DELAY`] (tests).
    #[cfg(test)]
    pub fn with_flush_delay(mut self, delay: Duration) -> Self {
        if let Some(shared) = Arc::get_mut(&mut self.shared) {
            shared.delay = delay;
        }
        self
    }

    pub fn namespace(&self) -> &str {
        &self.shared.namespace
    }

    /// Queue one record for the writer task (module docs). Refused only when [`MAX_QUEUED_BYTES`]
    /// are waiting already (the API server is slow or refuses the writes).
    pub fn append(&self, record: &CpAuditRecord) -> Result<(), StoreError> {
        let mut line = serde_json::to_string(record)
            .map_err(|e| StoreError::Io(format!("control-plane audit record: {e}")))?;
        line.push('\n');
        let mut q = lock(&self.shared.queue);
        if !q.lines.is_empty() && q.bytes + line.len() > MAX_QUEUED_BYTES {
            return Err(StoreError::Io(format!(
                "control-plane audit: {} KiB wait to be written already (the API server is slow \
                 or refuses the writes)",
                q.bytes / 1024
            )));
        }
        q.bytes += line.len();
        q.lines.push_back(line);
        q.queued += 1;
        if !q.writing {
            q.writing = true;
            tokio::spawn(self.shared.clone().write_queue());
        }
        Ok(())
    }

    /// Once every record queued before the call is written (or given up, and counted).
    pub async fn flush(&self) {
        let target = lock(&self.shared.queue).queued;
        self.shared.now.notify_one();
        let mut done = self.shared.done.subscribe();
        // the sender lives in `shared`, which `self` holds: never closed
        let _ = done.wait_for(|d| *d >= target).await;
    }

    /// Records the writer task could not persist so far, and the last error (`GET /readyz`).
    pub fn failures(&self) -> (u64, Option<String>) {
        (
            self.shared.failures.load(Ordering::Relaxed),
            lock(&self.shared.last_error).clone(),
        )
    }

    /// The newest `limit` records, oldest first (module docs), after the records queued so far
    /// are written. A line that does not parse (an edit by hand) is skipped and logged, not the
    /// whole segment.
    pub async fn read(&self, limit: usize) -> Result<Vec<CpAuditRecord>, StoreError> {
        self.flush().await;
        self.shared.read(limit).await
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Shared {
    /// The writer task: the queue in writes of at most [`SEGMENT_BYTES`] each, until it is
    /// empty, each after [`FLUSH_DELAY`] unless a segment's worth is waiting or a flush asks.
    async fn write_queue(self: Arc<Self>) {
        loop {
            // before every write, also the next one under sustained load: a write replaces a
            // whole segment, so it may come once per delay, or as soon as a segment's worth
            // is waiting (or a flush asks)
            if lock(&self.queue).bytes < SEGMENT_BYTES {
                tokio::select! {
                    () = tokio::time::sleep(self.delay) => {}
                    () = self.now.notified() => {}
                }
            }
            let (lines, n) = {
                let mut q = lock(&self.queue);
                let mut lines = String::new();
                let mut n = 0u64;
                while let Some(next) = q.lines.front() {
                    if n > 0 && lines.len() + next.len() > SEGMENT_BYTES {
                        break;
                    }
                    let next = q.lines.pop_front().unwrap_or_default();
                    q.bytes -= next.len();
                    lines.push_str(&next);
                    n += 1;
                }
                if n == 0 {
                    q.writing = false;
                    return;
                }
                (lines, n)
            };
            if let Err(e) = self.write(&lines).await {
                let failures = self.failures.fetch_add(n, Ordering::Relaxed) + n;
                *lock(&self.last_error) = Some(e.to_string());
                tracing::error!(
                    error = %e,
                    records = n,
                    failures,
                    "persisting control-plane audit records failed; they are only on stdout"
                );
            }
            self.done.send_modify(|d| *d += n);
        }
    }

    fn segment(&self, seq: u64, lines: String) -> ConfigMap {
        ConfigMap {
            metadata: ObjectMeta {
                name: Some(segment_name(seq % SEGMENTS)),
                namespace: Some(self.namespace.clone()),
                labels: Some(BTreeMap::from([
                    (SEGMENT_LABEL.to_string(), "segment".to_string()),
                    (
                        "app.kubernetes.io/managed-by".to_string(),
                        FIELD_MANAGER.to_string(),
                    ),
                ])),
                annotations: Some(BTreeMap::from([(
                    SEQ_ANNOTATION.to_string(),
                    seq.to_string(),
                )])),
                ..Default::default()
            },
            data: Some(BTreeMap::from([(RECORDS_KEY.to_string(), lines)])),
            ..Default::default()
        }
    }

    async fn get(&self, slot: u64) -> Result<Option<ConfigMap>, StoreError> {
        self.api
            .get_config_map(&self.namespace, &segment_name(slot))
            .await
            .map_err(api_err)
    }

    /// Every segment there is, oldest first.
    async fn segments(&self) -> Result<Vec<(Option<u64>, ConfigMap)>, StoreError> {
        let mut out = Vec::new();
        for slot in 0..SEGMENTS {
            if let Some(cm) = self.get(slot).await? {
                out.push((seq_of(&cm), cm));
            }
        }
        out.sort_by_key(|(seq, _)| *seq);
        Ok(out)
    }

    /// The head of the ring, read from the cluster.
    async fn find_head(&self) -> Result<Option<Head>, StoreError> {
        Ok(self
            .segments()
            .await?
            .into_iter()
            .filter_map(|(seq, cm)| seq.map(|seq| Head { seq, cm }))
            .next_back())
    }

    /// Write `lines` (whole records, at most [`SEGMENT_BYTES`] unless one record is larger) to
    /// the head, or to a new head when they do not fit (module docs).
    async fn write(&self, lines: &str) -> Result<(), StoreError> {
        let mut cached = self.head.lock().await;
        for _ in 0..MAX_ATTEMPTS {
            let head = match cached.clone() {
                Some(h) => Some(h),
                None => self.find_head().await?,
            };
            match head {
                Some(h) if records_of(&h.cm).len() + lines.len() <= SEGMENT_BYTES => {
                    let mut next = h.cm.clone();
                    next.data
                        .get_or_insert_with(BTreeMap::new)
                        .entry(RECORDS_KEY.to_string())
                        .or_default()
                        .push_str(lines);
                    match self.api.replace_config_map(&self.namespace, &next).await {
                        Ok(written) => {
                            *cached = Some(Head {
                                seq: h.seq,
                                cm: written,
                            });
                            return Ok(());
                        }
                        // someone else appended: read the slot again (it may have moved on)
                        Err(ApiError::Conflict(_) | ApiError::NotFound) => {
                            *cached = match self.get(h.seq % SEGMENTS).await? {
                                Some(cm) if seq_of(&cm) == Some(h.seq) => {
                                    Some(Head { seq: h.seq, cm })
                                }
                                _ => None,
                            };
                        }
                        Err(e) => {
                            *cached = None;
                            return Err(api_err(e));
                        }
                    }
                }
                // no segment yet, or the head is full: a new head in the next slot
                full => {
                    let seq = full.map_or(0, |h| h.seq + 1);
                    let fresh = self.segment(seq, lines.to_string());
                    let written = match self.get(seq % SEGMENTS).await? {
                        None => self.api.create_config_map(&self.namespace, &fresh).await,
                        Some(old) => match seq_of(&old) {
                            // another process started this segment first: append to it
                            Some(s) if s == seq => {
                                *cached = Some(Head { seq, cm: old });
                                continue;
                            }
                            // this process is behind the ring: find the head again
                            Some(s) if s > seq => {
                                *cached = None;
                                continue;
                            }
                            // the oldest segment: replaced, with the version read
                            _ => {
                                let mut next = fresh.clone();
                                next.metadata.resource_version = old.metadata.resource_version;
                                self.api.replace_config_map(&self.namespace, &next).await
                            }
                        },
                    };
                    match written {
                        Ok(cm) => {
                            *cached = Some(Head { seq, cm });
                            return Ok(());
                        }
                        Err(ApiError::Conflict(_) | ApiError::AlreadyExists(_)) => {
                            *cached = None;
                        }
                        Err(e) => {
                            *cached = None;
                            return Err(api_err(e));
                        }
                    }
                }
            }
        }
        Err(StoreError::Io(
            "control-plane audit: too many concurrent appends; try again".into(),
        ))
    }

    async fn read(&self, limit: usize) -> Result<Vec<CpAuditRecord>, StoreError> {
        let mut out: Vec<CpAuditRecord> = Vec::new();
        for (_, cm) in self.segments().await? {
            for (i, line) in records_of(&cm).lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str(line) {
                    Ok(r) => out.push(r),
                    Err(e) => tracing::warn!(
                        segment = cm.metadata.name.as_deref().unwrap_or(""),
                        line = i + 1,
                        error = %e,
                        "unreadable control-plane audit line"
                    ),
                }
            }
        }
        out.sort_by(|a, b| a.ts.cmp(&b.ts));
        let skip = out.len().saturating_sub(limit);
        Ok(out.split_off(skip))
    }
}
