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
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use attache_charter::{AuditSink, AuditSpec};
use attache_common::audit::{AuditRecord, AuditWriter, MIN_SECRET_LEN, OnCancel};
use serde_json::Value;
use tokio::sync::broadcast;

/// How long values are kept per request (as the writer does).
const SECRET_TTL: Duration = Duration::from_secs(15 * 60);
/// The default file of `audit.sink: file` without `audit.file` (the validator requires one).
const DEFAULT_AUDIT_FILE: &str = "/var/log/attache/audit.jsonl";

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
#[derive(Clone)]
struct SwitchSink {
    inner: Arc<Mutex<SwitchInner>>,
}

struct SwitchInner {
    target: Box<dyn Write + Send>,
    line: Vec<u8>,
}

impl Write for SwitchSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.line.extend_from_slice(buf);
        if let Some(end) = inner.line.iter().rposition(|b| *b == b'\n') {
            let rest = inner.line.split_off(end + 1);
            let lines = std::mem::replace(&mut inner.line, rest);
            inner.target.write_all(&lines)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.target.flush()
    }
}

pub struct Audit {
    writer: AuditWriter,
    sink: SwitchSink,
    target: Mutex<SinkTarget>,
    /// request_id → values scrubbed from that request's later records.
    secrets: Mutex<HashMap<String, (Instant, Vec<String>)>>,
    /// Held shared by every write and exclusively by [`Audit::set_redaction`].
    gate: RwLock<()>,
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
            })),
        };
        let writer = AuditWriter::with_sink(service, namespace, redact, Box::new(sink.clone()))
            .with_pii_redact(pii_redact);
        Ok(Self {
            writer,
            sink,
            target: Mutex::new(target),
            secrets: Mutex::new(HashMap::new()),
            gate: RwLock::new(()),
        })
    }

    /// Point the sink elsewhere (the first charter in managed mode names the audit sink).
    pub fn set_sink(&self, target: SinkTarget) -> std::io::Result<()> {
        let mut current = self.target.lock().unwrap_or_else(PoisonError::into_inner);
        if *current == target {
            return Ok(());
        }
        let opened = target.open()?;
        let mut inner = self
            .sink
            .inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let _ = inner.target.flush();
        inner.target = opened;
        *current = target;
        Ok(())
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
        let _gate = self.gate.read().unwrap_or_else(PoisonError::into_inner);
        self.writer.write(record);
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
        secrets.retain(|_, (t, _)| now.duration_since(*t) < SECRET_TTL);
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
        secrets.retain(|_, (t, _)| now.duration_since(*t) < SECRET_TTL);
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
    use attache_common::audit::{Direction, Kind};
    use attache_common::trace::TraceContext;
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
