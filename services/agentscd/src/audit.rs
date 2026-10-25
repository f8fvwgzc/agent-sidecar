//! The sidecar's handle on the audit writer (CONTRACT.md §6).
//!
//! [`Audit`] wraps [`AuditWriter`] and adds what the sidecar needs besides writing:
//!
//! - It keeps, per request, the values the writer scrubs from that request's later records (the
//!   values at `audit.redact` paths and the inputs a content guardrail withheld), so a lesson the
//!   runtime proposes for a run can be scrubbed the same way before it leaves the sidecar
//!   (design §6.5).
//! - Its sink can be pointed somewhere else once, when the first charter arrives in managed
//!   mode (the writer, and so its subscribers, stay the same).
//! - A change of the redaction settings waits for the writes in progress, so every record
//!   published after [`Audit::set_redaction`] returns was redacted with the new settings (the
//!   control-plane export relies on it to tell records written before the first charter).
//! - Sink failures are never silent (CONTRACT.md §6, docs/operations.md "Audit sink failures").
//!   The writer keeps what the sink did not take and retries it first (its module docs); this
//!   handle logs failures (the first at once, then at most one summary per [`LOG_EVERY`], and
//!   the recovery), retries the backlog every [`RETRY_EVERY`] ([`retry_loop`]) and on every
//!   `/readyz`, and reports [`Audit::health`] there. With `--audit-fail-closed`,
//!   [`Audit::check`] refuses new work with rule [`RULE_UNAVAILABLE`] from the first failed
//!   write or flush until the backlog is written and flushed again: the HTTP and gRPC
//!   invocations (`pipeline::invoke`), the mesh and the runtime's tool calls. A refusal writes
//!   its own record, so every refused call is also a retry of the sink. Records a call that
//!   already started owes are still written (or kept): fail-closed stops new work, it never
//!   discards records.
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use agentsc_charter::{AuditSink, AuditSpec};
use agentsc_common::audit::{
    AuditRecord, AuditWriter, Direction, Kind, MIN_SECRET_LEN, OnCancel, SinkHealth,
};
use agentsc_common::authz::Verdict;
use agentsc_common::trace::TraceContext;
use agentsc_proto::ToolContext;
use serde_json::Value;
use tokio::sync::broadcast;

/// How long values are kept per request (as the writer does).
const SECRET_TTL: Duration = Duration::from_secs(15 * 60);
/// The default file of `audit.sink: file` without `audit.file` (the validator requires one).
const DEFAULT_AUDIT_FILE: &str = "/var/log/agentsc/audit.jsonl";
/// The rule of work refused in fail-closed mode while the audit sink fails.
pub const RULE_UNAVAILABLE: &str = "audit.unavailable";
/// At most one warning per this long while the sink keeps failing (the first comes at once).
pub const LOG_EVERY: Duration = Duration::from_secs(10);
/// How often [`retry_loop`] retries an unhealthy sink.
pub const RETRY_EVERY: Duration = Duration::from_secs(1);

/// Where audit lines go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SinkTarget {
    Stdout,
    File(PathBuf),
}

impl SinkTarget {
    pub fn of(spec: &AuditSpec) -> Self {
        match spec.sink {
            AuditSink::Stdout => SinkTarget::Stdout,
            AuditSink::File => SinkTarget::File(PathBuf::from(
                spec.file.as_deref().unwrap_or(DEFAULT_AUDIT_FILE),
            )),
        }
    }

    fn open(&self) -> std::io::Result<Box<dyn Write + Send>> {
        match self {
            SinkTarget::Stdout => Ok(Box::new(std::io::stdout())),
            SinkTarget::File(path) => {
                if let Some(parent) = path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    std::fs::create_dir_all(parent)?;
                }
                let f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?;
                Ok(Box::new(f))
            }
        }
    }
}

/// A sink whose target can be replaced. Whole lines only reach the target, so a line is never
/// split between two targets.
///
/// It buffers like a `BufWriter`: a write is taken whole once the lines before it reached the
/// target (until then it fails, and the writer keeps the bytes), and a target failure after
/// that surfaces at `flush`, with the bytes the target did not take still buffered. So the
/// writer's accounting of what reached the sink stays exact.
#[derive(Clone)]
struct SwitchSink {
    inner: Arc<Mutex<SwitchInner>>,
}

struct SwitchInner {
    target: Box<dyn Write + Send>,
    line: Vec<u8>,
    /// The front of `line` is the rest of a line whose start the target took.
    partial: bool,
}

impl SwitchInner {
    /// Write the complete lines buffered to the target; what it took leaves the buffer.
    fn push_lines(&mut self) -> std::io::Result<()> {
        let Some(end) = self.line.iter().rposition(|b| *b == b'\n') else {
            return Ok(());
        };
        let mut done = 0;
        let result = loop {
            if done > end {
                break Ok(());
            }
            match self.target.write(&self.line[done..=end]) {
                Ok(0) => break Err(std::io::ErrorKind::WriteZero.into()),
                Ok(n) => done += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => break Err(e),
            }
        };
        if done > 0 {
            self.partial = self.line[done - 1] != b'\n';
            self.line.drain(..done);
        }
        result
    }

    /// Replace the target: the old one gets a last chance at the lines buffered; those it did
    /// not take go to the new one, except the rest of a line it took only the start of (that
    /// line would be cut in either place, so it is dropped and logged).
    fn switch(&mut self, target: Box<dyn Write + Send>) {
        let _ = self.push_lines();
        let _ = self.target.flush();
        if self.partial {
            let cut = self
                .line
                .iter()
                .position(|b| *b == b'\n')
                .map_or(self.line.len(), |i| i + 1);
            self.line.drain(..cut);
            self.partial = false;
            tracing::warn!(
                "the old audit sink took only part of a record; its rest was dropped at the switch"
            );
        }
        self.target = target;
    }
}

impl Write for SwitchSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        // the earlier lines first: until they are out, nothing new is taken
        inner.push_lines()?;
        inner.line.extend_from_slice(buf);
        // taken: a failure from here on is reported by `flush`, the bytes stay buffered
        let _ = inner.push_lines();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.push_lines()?;
        inner.target.flush()
    }
}

/// What the last log line about the sink said, for [`LOG_EVERY`].
#[derive(Default)]
struct Reported {
    at: Option<Instant>,
    write_errors: u64,
    dropped: u64,
    failing: bool,
}

pub struct Audit {
    writer: AuditWriter,
    sink: SwitchSink,
    target: Mutex<SinkTarget>,
    /// request_id → values scrubbed from that request's later records.
    secrets: Mutex<HashMap<String, (Instant, Vec<String>)>>,
    /// When `secrets` was last swept: a sweep visits every entry, so it runs at most once per
    /// [`PRUNE_EVERY`] instead of on every record.
    last_prune: Mutex<Instant>,
    /// Held shared by every write and exclusively by [`Audit::set_redaction`].
    gate: RwLock<()>,
    /// `--audit-fail-closed` (restart-only).
    fail_closed: bool,
    reported: Mutex<Reported>,
}

/// The `UNAVAILABLE` status of a refusal (`x-agentsc-rule` = the rule).
pub fn unavailable(v: Verdict) -> tonic::Status {
    crate::tools::status_with_rule(tonic::Code::Unavailable, &v.rule, &v.reason)
}

/// Retry an unhealthy sink every [`RETRY_EVERY`] and log what changed (module docs), so the
/// backlog drains and fail-closed mode ends without traffic.
pub async fn retry_loop(state: Arc<crate::state::AppState>) {
    let mut tick = tokio::time::interval(RETRY_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        state.audit.retry();
    }
}

const PRUNE_EVERY: Duration = Duration::from_secs(1);

/// Drop remembered values older than [`SECRET_TTL`], at most once per [`PRUNE_EVERY`].
fn prune_secrets(
    secrets: &mut HashMap<String, (Instant, Vec<String>)>,
    now: Instant,
    last: &Mutex<Instant>,
) {
    let mut last = last.lock().unwrap_or_else(PoisonError::into_inner);
    if now.duration_since(*last) < PRUNE_EVERY {
        return;
    }
    *last = now;
    secrets.retain(|_, (t, _)| now.duration_since(*t) < SECRET_TTL);
}

impl Audit {
    pub fn new(
        service: &str,
        namespace: &str,
        redact: Vec<String>,
        pii_redact: bool,
        target: SinkTarget,
    ) -> std::io::Result<Self> {
        let sink = SwitchSink {
            inner: Arc::new(Mutex::new(SwitchInner {
                target: target.open()?,
                line: Vec::new(),
                partial: false,
            })),
        };
        let writer = AuditWriter::with_sink(service, namespace, redact, Box::new(sink.clone()))
            .with_pii_redact(pii_redact);
        Ok(Self {
            writer,
            sink,
            target: Mutex::new(target),
            secrets: Mutex::new(HashMap::new()),
            last_prune: Mutex::new(Instant::now()),
            gate: RwLock::new(()),
            fail_closed: false,
            reported: Mutex::new(Reported::default()),
        })
    }

    /// `--audit-fail-closed`: refuse new work while the sink fails (module docs).
    pub fn with_fail_closed(mut self, on: bool) -> Self {
        self.fail_closed = on;
        self
    }

    pub fn fail_closed(&self) -> bool {
        self.fail_closed
    }

    /// Point the sink elsewhere (the first charter in managed mode names the audit sink). Lines
    /// the old target did not take go to the new one, except the rest of a line the old one
    /// took only the start of (it would be cut in either file).
    pub fn set_sink(&self, target: SinkTarget) -> std::io::Result<()> {
        let mut current = self.target.lock().unwrap_or_else(PoisonError::into_inner);
        if *current == target {
            return Ok(());
        }
        let opened = target.open()?;
        self.sink
            .inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .switch(opened);
        *current = target;
        Ok(())
    }

    /// Write to `writer` instead of the target's file or stdout (embedding, and the tests that
    /// make the sink fail). [`Audit::sink_target`] keeps naming the target; a later
    /// [`Audit::set_sink`] to another target replaces `writer`. Lines the old writer did not take
    /// go to `writer`.
    pub fn replace_writer(&self, writer: Box<dyn Write + Send>) {
        self.sink
            .inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .switch(writer);
    }

    pub fn sink_target(&self) -> SinkTarget {
        self.target
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn writer(&self) -> &AuditWriter {
        &self.writer
    }

    pub fn write(&self, record: AuditRecord) {
        self.remember_record(&record);
        {
            let _gate = self.gate.read().unwrap_or_else(PoisonError::into_inner);
            self.writer.write(record);
        }
        self.report();
    }

    /// The sink's state and whether fail-closed is on (`/readyz`).
    pub fn health(&self) -> SinkHealth {
        self.writer.health()
    }

    /// Write the backlog again if the sink is unhealthy, and log what changed; returns whether
    /// it is healthy now.
    pub fn retry(&self) -> bool {
        let healthy = self.writer.retry();
        self.report();
        healthy
    }

    /// Whether this sidecar takes new work as far as the audit sink goes: always without
    /// fail-closed, else while the sink is healthy. No I/O (readiness).
    pub fn serving(&self) -> bool {
        !self.fail_closed || self.writer.health().healthy
    }

    /// The fail-closed gate at the entry of every unit of new work (module docs): `Ok` without
    /// fail-closed or while the sink is healthy (an unhealthy one is retried first), else the
    /// [`RULE_UNAVAILABLE`] denial. The caller writes the refusal's record with it.
    pub fn check(&self) -> Result<(), Verdict> {
        if !self.fail_closed || self.retry() {
            return Ok(());
        }
        let h = self.writer.health();
        Err(Verdict::deny(
            RULE_UNAVAILABLE,
            format!(
                "the audit sink is failing ({}); with --audit-fail-closed no new work starts \
                 until a write succeeds again",
                h.last_error.as_deref().unwrap_or("unknown error")
            ),
        ))
    }

    /// [`Audit::check`] as the `UNAVAILABLE` status of a refusal, for gRPC handlers that write no
    /// record of their own when refused (`ProposeLesson`).
    pub fn gate(&self) -> Result<(), tonic::Status> {
        self.check().map_err(unavailable)
    }

    /// [`Audit::check`] for a runtime tool call: a refusal writes its `tool_call` record (rule
    /// [`RULE_UNAVAILABLE`]) and is `UNAVAILABLE` for the runtime.
    pub fn gate_tool(&self, ctx: Option<&ToolContext>) -> Result<(), tonic::Status> {
        let Err(v) = self.check() else {
            return Ok(());
        };
        let c = ctx.cloned().unwrap_or_default();
        let root = TraceContext::new_root();
        let valid = TraceContext::parse(&format!("00-{}-{}-01", c.trace_id, root.span_id));
        let trace = TraceContext {
            trace_id: valid.map_or(root.trace_id, |(t, _)| t),
            span_id: root.span_id,
            parent_span_id: (!c.span_id.is_empty()).then(|| c.span_id.clone()),
        };
        let agent = (!c.agent.is_empty()).then_some(c.agent.as_str());
        self.write(
            AuditRecord::new(
                Kind::ToolCall,
                Direction::Internal,
                &c.request_id,
                &trace,
                agent,
                agentsc_charter::LOCAL_IDENTITY,
                agent,
                &c.tool,
                Value::Null,
                Value::Null,
            )
            .verdict(&v),
        );
        Err(unavailable(v))
    }

    /// Log a failure at once, then at most one summary per [`LOG_EVERY`], and the recovery.
    /// Never under the sink lock; a report already in progress elsewhere is enough.
    fn report(&self) {
        let h = self.writer.health();
        let mut last = match self.reported.try_lock() {
            Ok(last) => last,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return,
        };
        let now = Instant::now();
        let new_errors = h.write_errors.saturating_sub(last.write_errors);
        let new_drops = h.dropped.saturating_sub(last.dropped);
        if (new_errors > 0 || new_drops > 0)
            && last.at.is_none_or(|at| now.duration_since(at) >= LOG_EVERY)
        {
            tracing::warn!(
                failed = new_errors,
                dropped = new_drops,
                pending_bytes = h.pending_bytes,
                error = h.last_error.as_deref().unwrap_or(""),
                fail_closed = self.fail_closed,
                sink = ?self.sink_target(),
                "audit sink write failed; unwritten records are kept and retried"
            );
            last.at = Some(now);
            last.write_errors = h.write_errors;
            last.dropped = h.dropped;
            last.failing = true;
        }
        if h.healthy && last.failing {
            tracing::info!(
                write_errors = h.write_errors,
                dropped = h.dropped,
                "audit sink recovered: the kept records are written"
            );
            *last = Reported {
                at: None,
                write_errors: h.write_errors,
                dropped: h.dropped,
                failing: false,
            };
        }
    }

    /// See [`AuditWriter::remember`].
    pub fn remember(&self, request_id: &str, side: &str, payload: &Value) {
        let paths = self.writer.redaction().0;
        let mut found = Vec::new();
        collect(&paths, side, payload, &mut found);
        self.keep(request_id, found);
        self.writer.remember(request_id, side, payload);
    }

    /// See [`AuditWriter::withhold`].
    pub fn withhold(&self, request_id: &str, values: impl IntoIterator<Item = String>) {
        let values: Vec<String> = values.into_iter().collect();
        self.keep(
            request_id,
            values
                .iter()
                .filter(|v| v.chars().count() >= MIN_SECRET_LEN)
                .cloned()
                .collect(),
        );
        self.writer.withhold(request_id, values);
    }

    /// See [`AuditWriter::on_cancel`].
    pub fn on_cancel(&self, records: Vec<AuditRecord>, started: Instant) -> OnCancel<'_> {
        for r in &records {
            self.remember_record(r);
        }
        self.writer.on_cancel(records, started)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<AuditRecord>> {
        self.writer.subscribe()
    }

    /// See [`AuditWriter::set_redaction`]; returns once every write in progress is published.
    pub fn set_redaction(&self, paths: Vec<String>, pii_redact: bool) {
        let _gate = self.gate.write().unwrap_or_else(PoisonError::into_inner);
        self.writer.set_redaction(paths, pii_redact);
    }

    pub fn redaction(&self) -> (Vec<String>, bool) {
        self.writer.redaction()
    }

    /// The values the writer scrubs from `request_id`'s records, longest first.
    pub fn scrub_values(&self, request_id: &str) -> Vec<String> {
        let mut secrets = self.secrets.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        prune_secrets(&mut secrets, now, &self.last_prune);
        secrets
            .get(request_id)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }

    /// Replace every value remembered for `request_id` in `text` with `[redacted]`.
    pub fn scrub_text(&self, request_id: &str, text: &str) -> String {
        let mut out = text.to_string();
        for secret in self.scrub_values(request_id) {
            if out.contains(secret.as_str()) {
                out = out.replace(secret.as_str(), "[redacted]");
            }
        }
        out
    }

    fn remember_record(&self, record: &AuditRecord) {
        if record.request_id.is_empty() {
            return;
        }
        let paths = self.writer.redaction().0;
        if paths.is_empty() {
            return;
        }
        let mut found = Vec::new();
        collect(&paths, "input", &record.input, &mut found);
        collect(&paths, "output", &record.output, &mut found);
        self.keep(&record.request_id, found);
    }

    fn keep(&self, request_id: &str, found: Vec<String>) {
        if found.is_empty() || request_id.is_empty() {
            return;
        }
        let mut secrets = self.secrets.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        prune_secrets(&mut secrets, now, &self.last_prune);
        let entry = secrets
            .entry(request_id.to_string())
            .or_insert_with(|| (now, Vec::new()));
        entry.0 = now;
        for f in found {
            if !entry.1.contains(&f) {
                entry.1.push(f);
            }
        }
        entry.1.sort_by_key(|s| std::cmp::Reverse(s.len()));
    }
}

/// The values at the `audit.redact` paths of `side` (`input` / `output`) in `payload`, as the
/// writer remembers them: strings and numbers of [`MIN_SECRET_LEN`]+ characters, arrays walked.
fn collect(paths: &[String], side: &str, payload: &Value, out: &mut Vec<String>) {
    let prefix = format!("{side}.");
    for p in paths {
        if let Some(rest) = p.strip_prefix(&prefix) {
            collect_path(payload, rest, out);
        } else if p == side {
            collect_leaves(payload, out);
        }
    }
}

fn collect_path(v: &Value, dotted: &str, out: &mut Vec<String>) {
    let (head, rest) = match dotted.split_once('.') {
        Some((h, r)) => (h, Some(r)),
        None => (dotted, None),
    };
    match v {
        Value::Array(items) => items.iter().for_each(|i| collect_path(i, dotted, out)),
        Value::Object(map) => {
            if let Some(next) = map.get(head) {
                match rest {
                    Some(r) => collect_path(next, r, out),
                    None => collect_leaves(next, out),
                }
            }
        }
        _ => {}
    }
}

fn collect_leaves(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) if s.chars().count() >= MIN_SECRET_LEN && s != "[redacted]" => {
            out.push(s.clone())
        }
        Value::Number(n) if n.to_string().len() >= MIN_SECRET_LEN => out.push(n.to_string()),
        Value::Array(items) => items.iter().for_each(|i| collect_leaves(i, out)),
        Value::Object(map) => map.values().for_each(|i| collect_leaves(i, out)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentsc_common::audit::{Direction, Kind};
    use agentsc_common::trace::TraceContext;
    use serde_json::json;

    fn audit(dir: &std::path::Path, redact: &[&str]) -> Audit {
        Audit::new(
            "orders",
            "shop",
            redact.iter().map(|s| s.to_string()).collect(),
            false,
            SinkTarget::File(dir.join("a.jsonl")),
        )
        .unwrap()
    }

    fn rec(request_id: &str, input: Value, output: Value) -> AuditRecord {
        AuditRecord::new(
            Kind::ToolCall,
            Direction::Internal,
            request_id,
            &TraceContext::new_root(),
            Some("a"),
            "local",
            None,
            "t",
            input,
            output,
        )
    }

    #[test]
    fn remembers_what_the_writer_scrubs_per_request() {
        let tmp = tempfile::tempdir().unwrap();
        let a = audit(tmp.path(), &["input.card", "output.body.token"]);
        a.remember("r1", "input", &json!({"input": "x", "card": "4111-2222"}));
        a.write(rec(
            "r1",
            Value::Null,
            json!({"body": {"token": "tok-SECRET", "n": 1}}),
        ));
        a.withhold("r1", ["api_key = sk-1".to_string(), "ab".to_string()]);
        a.write(rec("r2", json!({"card": "9999-0000"}), Value::Null));
        let note = "card 4111-2222 and tok-SECRET and api_key = sk-1 and ab";
        assert_eq!(
            a.scrub_text("r1", note),
            "card [redacted] and [redacted] and [redacted] and ab"
        );
        assert_eq!(a.scrub_text("r2", "9999-0000"), "[redacted]");
        assert_eq!(a.scrub_text("r3", note), note, "other requests untouched");
        // and the writer itself scrubbed the same values from r1's later records
        a.write(rec("r1", json!("asked with tok-SECRET"), Value::Null));
        let log = std::fs::read_to_string(tmp.path().join("a.jsonl")).unwrap();
        let last: Value = serde_json::from_str(log.lines().last().unwrap()).unwrap();
        assert_eq!(last["input"], "asked with [redacted]");
    }

    /// A writer that fails while `failing` is set (a full disk), or takes only `short` bytes of
    /// one write and then fails.
    #[derive(Clone, Default)]
    struct Flaky {
        out: Arc<Mutex<Vec<u8>>>,
        failing: Arc<std::sync::atomic::AtomicBool>,
        short: Arc<Mutex<Option<usize>>>,
    }

    impl Write for Flaky {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            use std::sync::atomic::Ordering::SeqCst;
            if self.failing.load(SeqCst) {
                return Err(std::io::Error::other("No space left on device"));
            }
            if let Some(n) = self.short.lock().unwrap().take() {
                self.out.lock().unwrap().extend_from_slice(&b[..n]);
                self.failing.store(true, SeqCst);
                return Ok(n);
            }
            self.out.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Flaky {
        fn fail(&self, on: bool) {
            self.failing.store(on, std::sync::atomic::Ordering::SeqCst);
        }
        fn records(&self) -> Vec<Value> {
            String::from_utf8(self.out.lock().unwrap().clone())
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        }
    }

    #[test]
    fn a_failing_target_keeps_its_lines_and_takes_them_when_it_recovers() {
        let tmp = tempfile::tempdir().unwrap();
        let a = audit(tmp.path(), &[]);
        let f = Flaky::default();
        a.replace_writer(Box::new(f.clone()));
        a.write(rec("r1", json!("one"), Value::Null));
        assert!(a.health().healthy);
        f.fail(true);
        a.write(rec("r2", json!("two"), Value::Null));
        a.write(rec("r3", json!("three"), Value::Null));
        let h = a.health();
        assert!(!h.healthy && h.write_errors >= 2, "{h:?}");
        assert!(!a.retry());
        f.fail(false);
        assert!(a.retry());
        let ids: Vec<Value> = f
            .records()
            .iter()
            .map(|r| r["request_id"].clone())
            .collect();
        assert_eq!(ids, ["r1", "r2", "r3"], "each once, in order");
        // replace_writer keeps the target's name
        assert_eq!(
            a.sink_target(),
            SinkTarget::File(tmp.path().join("a.jsonl"))
        );
    }

    #[test]
    fn a_line_the_old_target_cut_is_dropped_at_a_switch_and_never_split() {
        let tmp = tempfile::tempdir().unwrap();
        let a = audit(tmp.path(), &[]);
        let f = Flaky::default();
        a.replace_writer(Box::new(f.clone()));
        *f.short.lock().unwrap() = Some(10);
        a.write(rec("cut", json!("x"), Value::Null));
        assert!(!a.health().healthy);
        assert_eq!(f.out.lock().unwrap().len(), 10);
        let next = tmp.path().join("b.jsonl");
        a.set_sink(SinkTarget::File(next.clone())).unwrap();
        a.write(rec("next", json!("y"), Value::Null));
        assert!(a.health().healthy);
        let text = std::fs::read_to_string(next).unwrap();
        let lines: Vec<Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 1, "{text}");
        assert_eq!(lines[0]["request_id"], "next");
    }

    #[test]
    fn fail_closed_refuses_with_the_rule_until_a_write_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        let a = audit(tmp.path(), &[]).with_fail_closed(true);
        assert!(a.fail_closed());
        let f = Flaky::default();
        a.replace_writer(Box::new(f.clone()));
        f.fail(true);
        assert!(a.check().is_ok(), "healthy until a write fails");
        a.write(rec("r1", json!("in flight"), Value::Null));
        assert!(!a.serving());
        let v = a.check().unwrap_err();
        assert_eq!(v.rule, RULE_UNAVAILABLE);
        assert!(v.reason.contains("No space left on device"), "{}", v.reason);
        // a tool call is refused UNAVAILABLE and leaves its tool_call record
        let ctx = ToolContext {
            request_id: "r1".into(),
            trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".into(),
            span_id: "00f067aa0ba902b7".into(),
            agent: "ops-assistant".into(),
            tool: "check_stock".into(),
            depth: 0,
        };
        let st = a.gate_tool(Some(&ctx)).unwrap_err();
        assert_eq!(st.code(), tonic::Code::Unavailable);
        assert_eq!(
            st.metadata().get("x-agentsc-rule").unwrap(),
            RULE_UNAVAILABLE
        );
        // without fail-closed the same failure never refuses work
        let b = audit(&tmp.path().join("b"), &[]);
        b.replace_writer(Box::new(f.clone()));
        b.write(rec("r9", Value::Null, Value::Null));
        assert!(!b.health().healthy);
        assert!(b.check().is_ok() && b.serving() && b.gate_tool(Some(&ctx)).is_ok());

        // the disk has room again: the next check writes the backlog and lets work in
        f.fail(false);
        assert!(a.check().is_ok());
        assert!(a.serving());
        let records = f.records();
        let refused = records
            .iter()
            .find(|r| r["decision"] == "deny")
            .expect("the refusal was kept and written");
        assert_eq!(refused["kind"], "tool_call");
        assert_eq!(refused["rule"], RULE_UNAVAILABLE);
        assert_eq!(refused["callee"], "check_stock");
        assert_eq!(refused["agent"], "ops-assistant");
        assert_eq!(refused["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(refused["parent_span_id"], "00f067aa0ba902b7");
        assert_eq!(records[0]["request_id"], "r1", "the record in flight first");
    }

    #[test]
    fn the_sink_switches_without_a_new_writer() {
        let tmp = tempfile::tempdir().unwrap();
        let a = audit(tmp.path(), &[]);
        let mut rx = a.subscribe();
        a.write(rec("r1", json!("one"), Value::Null));
        let second = tmp.path().join("nested/b.jsonl");
        a.set_sink(SinkTarget::File(second.clone())).unwrap();
        assert_eq!(a.sink_target(), SinkTarget::File(second.clone()));
        a.write(rec("r2", json!("two"), Value::Null));
        let first = std::fs::read_to_string(tmp.path().join("a.jsonl")).unwrap();
        let next = std::fs::read_to_string(second).unwrap();
        assert_eq!(first.lines().count(), 1);
        assert!(first.contains("\"one\""));
        assert_eq!(next.lines().count(), 1);
        assert!(next.contains("\"two\""));
        assert_eq!(rx.try_recv().unwrap().request_id, "r1");
        assert_eq!(rx.try_recv().unwrap().request_id, "r2");
    }
}
