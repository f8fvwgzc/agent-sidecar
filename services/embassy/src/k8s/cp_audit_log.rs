//! The control-plane audit of the `kubernetes` store (design §8.5): a ring of [`SEGMENTS`]
//! ConfigMaps in the control-plane namespace (`--cp-namespace`).
//!
//! | What | Where |
//! | --- | --- |
//! | a segment | ConfigMap `agentsc-cp-audit-<slot>`, `slot` in `0..SEGMENTS` ([`segment_name`]) |
//! | its records | `data["records.jsonl"]`, one [`CpAuditRecord`] per line, in the order they were appended |
//! | its place in the ring | annotation [`SEQ_ANNOTATION`]: a decimal `u64`, +1 per new segment; the segment of sequence `n` is in slot `n % SEGMENTS` |
//!
//! **Append** ([`CpAuditLog::append`]). A record goes to the head (the segment with the highest
//! sequence) while the head stays within [`SEGMENT_BYTES`]; otherwise a new head (sequence + 1)
//! replaces the oldest segment in its slot. So the ring keeps the newest `SEGMENTS ×
//! SEGMENT_BYTES` (4 MiB) of records, and appending never needs `list` or `delete`. Every write
//! carries the `resourceVersion` it read: embassy and embassy-ca (both audit, and embassy-ca may
//! run more than one replica) never overwrite each other's lines, and a conflict reads again and
//! retries; within one process appends are serialized. A record whose line alone is larger than
//! [`SEGMENT_BYTES`] gets a segment of its own (the API server refuses a ConfigMap above 1 MiB,
//! and the append then fails). A failure is returned, for [`crate::cp_audit::CpAudit`] to log
//! and count: nothing is dropped silently.
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
use std::collections::BTreeMap;
use std::sync::Arc;

use k8s_openapi::api::core::v1::ConfigMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

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
/// Reads and retries of one append after conflicts.
const MAX_ATTEMPTS: usize = 8;

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

/// See the module docs.
pub struct CpAuditLog {
    api: Arc<dyn CharterApi>,
    namespace: String,
    /// Serializes appends of this process; holds the head as last written or read.
    head: tokio::sync::Mutex<Option<Head>>,
}

impl std::fmt::Debug for CpAuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CpAuditLog")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl CpAuditLog {
    pub fn new(api: Arc<dyn CharterApi>, namespace: &str) -> Self {
        Self {
            api,
            namespace: namespace.to_string(),
            head: tokio::sync::Mutex::new(None),
        }
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
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

    /// Append one record (module docs).
    pub async fn append(&self, record: &CpAuditRecord) -> Result<(), StoreError> {
        let mut line = serde_json::to_string(record)
            .map_err(|e| StoreError::Io(format!("control-plane audit record: {e}")))?;
        line.push('\n');
        let mut cached = self.head.lock().await;
        for _ in 0..MAX_ATTEMPTS {
            let head = match cached.clone() {
                Some(h) => Some(h),
                None => self.find_head().await?,
            };
            match head {
                Some(h) if records_of(&h.cm).len() + line.len() <= SEGMENT_BYTES => {
                    let mut next = h.cm.clone();
                    next.data
                        .get_or_insert_with(BTreeMap::new)
                        .entry(RECORDS_KEY.to_string())
                        .or_default()
                        .push_str(&line);
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
                    let fresh = self.segment(seq, line.clone());
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

    /// The newest `limit` records, oldest first (module docs). A line that does not parse (an
    /// edit by hand) is skipped and logged, not the whole segment.
    pub async fn read(&self, limit: usize) -> Result<Vec<CpAuditRecord>, StoreError> {
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
