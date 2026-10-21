//! What managed mode sends to the control plane besides hello, heartbeats and acks (design §6.4,
//! §6.5): audit records, span starts and learning proposals. Each has its own bounded queue that
//! drops the oldest entry when full, so nothing here ever waits for the control plane; the
//! queues outlive a `Connect` stream and are drained by whichever stream is up.
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use agentsc_common::audit::{AuditRecord, Direction, Kind, now_rfc3339};
use agentsc_common::trace::TraceContext;
use agentsc_proto::{LearningProposal, SpanStart};
use tokio::sync::{Notify, broadcast};

/// Audit records queued at most (design §6.4).
pub const AUDIT_QUEUE_RECORDS: usize = 4096;
/// Bytes of audit JSON queued at most.
pub const AUDIT_QUEUE_BYTES: usize = 8 * 1024 * 1024;
/// An `AuditBatch` holds at most this many records (design §3) ...
pub const BATCH_RECORDS: usize = 256;
/// ... and this many bytes of JSON.
pub const BATCH_BYTES: usize = 1024 * 1024;
/// Span starts queued at most (design §6.4).
pub const SPAN_QUEUE: usize = 1024;
/// Learning proposals queued at most.
pub const PROPOSAL_QUEUE: usize = 256;

#[derive(Default)]
struct AuditQueue {
    items: VecDeque<(Instant, String)>,
    bytes: usize,
}

pub struct Outbox {
    enabled: bool,
    audit: Mutex<AuditQueue>,
    audit_notify: Notify,
    audit_dropped: AtomicU64,
    spans: Mutex<VecDeque<SpanStart>>,
    span_notify: Notify,
    spans_dropped: AtomicU64,
    proposals: Mutex<VecDeque<LearningProposal>>,
    proposal_notify: Notify,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Outbox {
    /// `enabled` = managed mode; a disabled outbox takes nothing.
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            audit: Mutex::new(AuditQueue::default()),
            audit_notify: Notify::new(),
            audit_dropped: AtomicU64::new(0),
            spans: Mutex::new(VecDeque::new()),
            span_notify: Notify::new(),
            spans_dropped: AtomicU64::new(0),
            proposals: Mutex::new(VecDeque::new()),
            proposal_notify: Notify::new(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Audit records dropped so far (queue overflow and broadcast lag), for heartbeats.
    pub fn audit_dropped(&self) -> u64 {
        self.audit_dropped.load(Ordering::Relaxed)
    }

    pub fn spans_dropped(&self) -> u64 {
        self.spans_dropped.load(Ordering::Relaxed)
    }

    pub fn count_audit_dropped(&self, n: u64) {
        self.audit_dropped.fetch_add(n, Ordering::Relaxed);
    }

    /// Queue one record (as JSON), dropping the oldest beyond the limits.
    pub fn push_audit(&self, json: String) {
        if !self.enabled {
            return;
        }
        {
            let mut q = lock(&self.audit);
            q.bytes += json.len();
            q.items.push_back((Instant::now(), json));
            while q.items.len() > AUDIT_QUEUE_RECORDS || q.bytes > AUDIT_QUEUE_BYTES {
                match q.items.pop_front() {
                    Some((_, old)) => {
                        q.bytes -= old.len();
                        self.audit_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    None => break,
                }
            }
        }
        self.audit_notify.notify_one();
    }

    pub fn audit_len(&self) -> usize {
        lock(&self.audit).items.len()
    }

    /// Take up to [`BATCH_RECORDS`] records / [`BATCH_BYTES`] bytes (at least one record).
    fn take_batch(&self) -> Vec<String> {
        let mut q = lock(&self.audit);
        let mut out = Vec::new();
        let mut bytes = 0;
        while let Some((_, front)) = q.items.front() {
            if !out.is_empty() && (out.len() >= BATCH_RECORDS || bytes + front.len() > BATCH_BYTES)
            {
                break;
            }
            let Some((_, json)) = q.items.pop_front() else {
                break;
            };
            q.bytes -= json.len();
            bytes += json.len();
            out.push(json);
        }
        out
    }

    /// The next `AuditBatch`: as soon as 256 records or 1 MiB are queued, or `flush` after the
    /// oldest queued record arrived.
    pub async fn next_audit_batch(&self, flush: Duration) -> Vec<String> {
        loop {
            let wait = {
                let q = lock(&self.audit);
                match q.items.front() {
                    None => None,
                    Some((first, _)) => {
                        if q.items.len() >= BATCH_RECORDS || q.bytes >= BATCH_BYTES {
                            Some(Duration::ZERO)
                        } else {
                            Some(flush.saturating_sub(first.elapsed()))
                        }
                    }
                }
            };
            match wait {
                Some(d) if d.is_zero() => {
                    let batch = self.take_batch();
                    if !batch.is_empty() {
                        return batch;
                    }
                }
                Some(d) => {
                    tokio::select! {
                        _ = self.audit_notify.notified() => {}
                        _ = tokio::time::sleep(d) => {
                            let batch = self.take_batch();
                            if !batch.is_empty() {
                                return batch;
                            }
                        }
                    }
                }
                None => self.audit_notify.notified().await,
            }
        }
    }

    /// Queue a span start (managed mode only), dropping the oldest beyond [`SPAN_QUEUE`].
    pub fn span_start(&self, s: SpanStart) {
        if !self.enabled {
            return;
        }
        {
            let mut q = lock(&self.spans);
            q.push_back(s);
            while q.len() > SPAN_QUEUE {
                q.pop_front();
                self.spans_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.span_notify.notify_one();
    }

    /// Every queued span start, waiting for one if none is queued.
    pub async fn next_spans(&self) -> Vec<SpanStart> {
        loop {
            let taken = self.take_spans();
            if !taken.is_empty() {
                return taken;
            }
            self.span_notify.notified().await;
        }
    }

    /// Every queued span start, now (maybe none).
    pub fn take_spans(&self) -> Vec<SpanStart> {
        lock(&self.spans).drain(..).collect()
    }

    pub fn propose(&self, p: LearningProposal) {
        if !self.enabled {
            return;
        }
        {
            let mut q = lock(&self.proposals);
            q.push_back(p);
            while q.len() > PROPOSAL_QUEUE {
                q.pop_front();
            }
        }
        self.proposal_notify.notify_one();
    }

    pub async fn next_proposals(&self) -> Vec<LearningProposal> {
        loop {
            let taken: Vec<LearningProposal> = lock(&self.proposals).drain(..).collect();
            if !taken.is_empty() {
                return taken;
            }
            self.proposal_notify.notified().await;
        }
    }
}

/// A span start for the timeline (design §6.4): the span the closing audit record will carry.
#[allow(clippy::too_many_arguments)]
pub fn span(
    kind: &str,
    request_id: &str,
    trace: &TraceContext,
    agent: &str,
    caller: &str,
    caller_agent: Option<&str>,
    callee: &str,
    direction: Direction,
) -> SpanStart {
    SpanStart {
        request_id: request_id.to_string(),
        trace_id: trace.trace_id.clone(),
        span_id: trace.span_id.clone(),
        parent_span_id: trace.parent_span_id.clone().unwrap_or_default(),
        kind: kind.to_string(),
        agent: agent.to_string(),
        caller: caller.to_string(),
        caller_agent: caller_agent.unwrap_or_default().to_string(),
        callee: callee.to_string(),
        direction: direction.as_str().to_string(),
        ts: now_rfc3339(),
    }
}

/// The record as it leaves the pod: as written (redacted, truncated), with `input` / `output`
/// set to null unless `payloads` (`telemetry.control_plane_payloads`); the hashes stay.
pub fn export_json(rec: &AuditRecord, payloads: bool) -> String {
    if payloads {
        return rec.to_json_line();
    }
    let mut r = rec.clone();
    r.input = serde_json::Value::Null;
    r.output = serde_json::Value::Null;
    r.to_json_line()
}

/// The `config` record of an applied charter.
fn charter_applied(rec: &AuditRecord) -> bool {
    rec.kind == Kind::Config
        && rec.callee == "charter"
        && rec.rule.as_deref() == Some(crate::reload::RULE_APPLIED)
}

/// Feed the audit queue from the writer for the life of the sidecar. `payloads` is the current
/// charter's `telemetry.control_plane_payloads`, `None` while no charter is loaded.
///
/// Records the writer published before the first charter's `config.applied` record were
/// redacted without any charter's `audit.redact` paths or `pii_redact` (the writer publishes in
/// order, and [`crate::audit::Audit::set_redaction`] waits for writes in progress): they leave
/// without payloads (design §15, rule 6), except `config` records, whose input is the
/// sidecar's own metadata.
pub async fn pump_audit(
    outbox: Arc<Outbox>,
    mut rx: broadcast::Receiver<Arc<AuditRecord>>,
    payloads: impl Fn() -> Option<bool>,
) {
    let mut configured = false;
    loop {
        match rx.recv().await {
            Ok(rec) => {
                configured = configured || charter_applied(&rec);
                let keep = if configured {
                    payloads().unwrap_or(false)
                } else {
                    rec.kind == Kind::Config
                };
                outbox.push_audit(export_json(&rec, keep));
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                outbox.count_audit_dropped(n);
                // where the stream stands is unknown now; a charter in force decides
                configured = configured || payloads().is_some();
            }
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn audit_queue_batches_drops_oldest_and_counts() {
        let o = Outbox::new(true);
        for i in 0..(AUDIT_QUEUE_RECORDS + 10) {
            o.push_audit(format!("{{\"n\":{i}}}"));
        }
        assert_eq!(o.audit_len(), AUDIT_QUEUE_RECORDS);
        assert_eq!(o.audit_dropped(), 10);
        let b = o.next_audit_batch(Duration::from_secs(60)).await;
        assert_eq!(b.len(), BATCH_RECORDS, "full batch at once");
        assert_eq!(b[0], "{\"n\":10}", "the oldest were dropped");

        // byte limits: 8 MiB in the queue, 1 MiB per batch
        let o = Outbox::new(true);
        let big = "x".repeat(600 * 1024);
        for _ in 0..20 {
            o.push_audit(big.clone());
        }
        assert_eq!(o.audit_len(), AUDIT_QUEUE_BYTES / big.len());
        assert_eq!(
            o.audit_dropped(),
            20 - (AUDIT_QUEUE_BYTES / big.len()) as u64
        );
        let b = o.next_audit_batch(Duration::from_secs(60)).await;
        assert_eq!(b.len(), 1, "two would pass 1 MiB");

        // a partial batch waits for the flush interval
        let o = Outbox::new(true);
        o.push_audit("{}".into());
        let started = Instant::now();
        let b = o.next_audit_batch(Duration::from_millis(200)).await;
        assert_eq!(b.len(), 1);
        assert!(started.elapsed() >= Duration::from_millis(150));

        // unmanaged: nothing is queued
        let off = Outbox::new(false);
        off.push_audit("{}".into());
        off.span_start(SpanStart::default());
        assert_eq!(off.audit_len(), 0);
    }

    #[tokio::test]
    async fn span_queue_is_bounded() {
        let o = Outbox::new(true);
        for i in 0..(SPAN_QUEUE + 5) {
            o.span_start(SpanStart {
                span_id: i.to_string(),
                ..Default::default()
            });
        }
        let got = o.next_spans().await;
        assert_eq!(got.len(), SPAN_QUEUE);
        assert_eq!(got[0].span_id, "5");
        assert_eq!(o.spans_dropped(), 5);
    }

    fn rec(kind: agentsc_common::audit::Kind, callee: &str, rule: Option<&str>) -> AuditRecord {
        let mut r = AuditRecord::new(
            kind,
            Direction::Internal,
            "r",
            &TraceContext::new_root(),
            None,
            "local",
            None,
            callee,
            serde_json::json!({"q": callee}),
            serde_json::Value::Null,
        );
        r.rule = rule.map(str::to_string);
        r
    }

    #[tokio::test]
    async fn records_from_before_the_first_charter_leave_without_payloads() {
        use agentsc_common::audit::Kind;
        let outbox = Arc::new(Outbox::new(true));
        let (tx, rx) = broadcast::channel(16);
        // a charter keeping payloads is in force by the time the pump sees these records
        let pump = tokio::spawn(pump_audit(outbox.clone(), rx, || Some(true)));
        for r in [
            rec(Kind::AgentInvocation, "early", Some("config.no_charter")),
            rec(Kind::Config, "certificate", Some("cert.issued")),
            rec(Kind::Config, "charter", Some("config.invalid")),
            rec(Kind::Config, "charter", Some("config.applied")),
            rec(Kind::AgentInvocation, "late", None),
        ] {
            tx.send(Arc::new(r)).unwrap();
        }
        drop(tx);
        pump.await.unwrap();
        let out: Vec<serde_json::Value> = outbox
            .next_audit_batch(Duration::ZERO)
            .await
            .iter()
            .map(|j| serde_json::from_str(j).unwrap())
            .collect();
        let inputs: Vec<&serde_json::Value> = out.iter().map(|v| &v["input"]).collect();
        assert!(inputs[0].is_null(), "no payload before the first charter");
        assert!(out[0]["input_sha256"].is_string(), "the hash stays");
        assert_eq!(
            inputs[1]["q"], "certificate",
            "config records keep their metadata"
        );
        assert_eq!(inputs[2]["q"], "charter");
        assert_eq!(inputs[3]["q"], "charter");
        assert_eq!(inputs[4]["q"], "late", "under the charter: its setting");
    }

    #[test]
    fn payloads_are_nulled_but_hashes_stay() {
        let rec = AuditRecord::new(
            agentsc_common::audit::Kind::ToolCall,
            Direction::Internal,
            "r",
            &TraceContext::new_root(),
            Some("a"),
            "local",
            None,
            "t",
            serde_json::json!({"q": 1}),
            serde_json::json!("out"),
        );
        let v: serde_json::Value = serde_json::from_str(&export_json(&rec, false)).unwrap();
        assert!(v["input"].is_null() && v["output"].is_null());
        assert!(v["input_sha256"].is_string() && v["output_sha256"].is_string());
        let v: serde_json::Value = serde_json::from_str(&export_json(&rec, true)).unwrap();
        assert_eq!(v["input"]["q"], 1);
    }
}
