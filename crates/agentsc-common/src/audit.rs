//! The audit record (CONTRACT.md §6). Field order below is the wire order.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Instant;
use tokio::sync::broadcast;

pub const MAX_PAYLOAD_BYTES: usize = 8 * 1024;
/// Records a [`AuditWriter::subscribe`] receiver may fall behind by before it loses the oldest.
pub const SUBSCRIBE_CAPACITY: usize = 4096;

/// The kinds this build writes. A reader must keep a record of a kind it does not know and show
/// the kind as written (CONTRACT.md §6): parse `kind` as a string when reading other sidecars' logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    AgentInvocation,
    ModelCall,
    ToolCall,
    AgentCall,
    ServiceCall,
    HttpCall,
    Authz,
    Guardrail,
    Budget,
    /// A charter, memory or certificate change applied, refused or failed (`config.*`, `cert.*`).
    Config,
    /// A lesson an agent proposed (`learning.*`).
    Learning,
}

impl Kind {
    /// The wire name (`"agent_invocation"`, …, `"config"`, `"learning"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::AgentInvocation => "agent_invocation",
            Kind::ModelCall => "model_call",
            Kind::ToolCall => "tool_call",
            Kind::AgentCall => "agent_call",
            Kind::ServiceCall => "service_call",
            Kind::HttpCall => "http_call",
            Kind::Authz => "authz",
            Kind::Guardrail => "guardrail",
            Kind::Budget => "budget",
            Kind::Config => "config",
            Kind::Learning => "learning",
        }
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
    Internal,
}

impl Direction {
    /// The wire name (`"inbound"`, `"outbound"`, `"internal"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Inbound => "inbound",
            Direction::Outbound => "outbound",
            Direction::Internal => "internal",
        }
    }
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub ts: String,
    pub kind: Kind,
    pub request_id: String,
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub service: String,
    pub namespace: String,
    pub agent: Option<String>,
    pub caller: String,
    pub caller_agent: Option<String>,
    pub callee: String,
    pub direction: Direction,
    pub input: Value,
    pub output: Value,
    pub input_sha256: Option<String>,
    pub output_sha256: Option<String>,
    pub tokens: Option<Tokens>,
    pub cost_usd: Option<f64>,
    pub latency_ms: u64,
    pub decision: String,
    pub rule: Option<String>,
    pub reason: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Tokens {
    pub input: u32,
    pub output: u32,
}

/// An audit record as any version of the sidecar wrote it (design §5): what the CLI, embassy and
/// the OpenTelemetry exporter read when the record may come from another version.
///
/// - `kind`, `direction` and `decision` are strings, so a kind this build does not know
///   (`"teleport"`) is kept and shown as written, never rejected ([`AuditRecordView::known_kind`]
///   maps it to a [`Kind`] when there is one).
/// - `tokens` is [`TokensView`], which accepts and keeps fields it does not know.
/// - Unknown top-level fields are kept in `extra` and serialized again unchanged (after the
///   known fields, which keep the wire order of CONTRACT.md §6).
/// - The fields that identify a record (`ts`, `kind`, `request_id`, `trace_id`, `service`,
///   `caller`, `callee`, `direction`, `decision`) are required, so a JSON line that is not an
///   audit record (a sidecar diagnostic) does not parse; every other field defaults when absent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecordView {
    pub ts: String,
    pub kind: String,
    pub request_id: String,
    pub trace_id: String,
    #[serde(default)]
    pub span_id: String,
    #[serde(default)]
    pub parent_span_id: Option<String>,
    pub service: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub agent: Option<String>,
    pub caller: String,
    #[serde(default)]
    pub caller_agent: Option<String>,
    pub callee: String,
    pub direction: String,
    #[serde(default)]
    pub input: Value,
    #[serde(default)]
    pub output: Value,
    #[serde(default)]
    pub input_sha256: Option<String>,
    #[serde(default)]
    pub output_sha256: Option<String>,
    #[serde(default)]
    pub tokens: Option<TokensView>,
    #[serde(default)]
    pub cost_usd: Option<f64>,
    #[serde(default)]
    pub latency_ms: u64,
    pub decision: String,
    #[serde(default)]
    pub rule: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    /// Top-level fields this build does not know, kept as written.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// `tokens` of an [`AuditRecordView`]: `input` and `output` (0 when absent), and any other
/// count a newer writer adds, kept as written.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TokensView {
    #[serde(default)]
    pub input: u64,
    #[serde(default)]
    pub output: u64,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

impl AuditRecordView {
    /// Parse one JSON record (a line of an audit log, an `AuditBatch` entry).
    pub fn from_json(text: &str) -> serde_json::Result<AuditRecordView> {
        serde_json::from_str(text)
    }

    /// The record as one JSON line: the known fields in wire order, then `extra` unchanged.
    pub fn to_json_line(&self) -> String {
        serde_json::to_string(self)
            .unwrap_or_else(|e| format!("{{\"error\":\"serialize audit record: {e}\"}}"))
    }

    /// `kind` as a [`Kind`] this build knows, or `None` for any other kind.
    pub fn known_kind(&self) -> Option<Kind> {
        serde_json::from_value(Value::String(self.kind.clone())).ok()
    }
}

impl From<&AuditRecord> for AuditRecordView {
    fn from(r: &AuditRecord) -> Self {
        AuditRecordView {
            ts: r.ts.clone(),
            kind: r.kind.as_str().to_string(),
            request_id: r.request_id.clone(),
            trace_id: r.trace_id.clone(),
            span_id: r.span_id.clone(),
            parent_span_id: r.parent_span_id.clone(),
            service: r.service.clone(),
            namespace: r.namespace.clone(),
            agent: r.agent.clone(),
            caller: r.caller.clone(),
            caller_agent: r.caller_agent.clone(),
            callee: r.callee.clone(),
            direction: r.direction.as_str().to_string(),
            input: r.input.clone(),
            output: r.output.clone(),
            input_sha256: r.input_sha256.clone(),
            output_sha256: r.output_sha256.clone(),
            tokens: r.tokens.map(|t| TokensView {
                input: u64::from(t.input),
                output: u64::from(t.output),
                extra: serde_json::Map::new(),
            }),
            cost_usd: r.cost_usd,
            latency_ms: r.latency_ms,
            decision: r.decision.clone(),
            rule: r.rule.clone(),
            reason: r.reason.clone(),
            error: r.error.clone(),
            extra: serde_json::Map::new(),
        }
    }
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Serialise a payload for hashing: strings as-is, everything else as compact JSON.
pub fn payload_bytes(v: &Value) -> Vec<u8> {
    match v {
        Value::String(s) => s.as_bytes().to_vec(),
        Value::Null => Vec::new(),
        other => serde_json::to_vec(other).unwrap_or_default(),
    }
}

impl AuditRecord {
    /// A record with hashes computed from the full payloads; call `redact` before writing.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: Kind,
        direction: Direction,
        request_id: &str,
        trace: &crate::trace::TraceContext,
        agent: Option<&str>,
        caller: &str,
        caller_agent: Option<&str>,
        callee: &str,
        input: Value,
        output: Value,
    ) -> Self {
        let input_sha256 = (!input.is_null()).then(|| sha256_hex(&payload_bytes(&input)));
        let output_sha256 = (!output.is_null()).then(|| sha256_hex(&payload_bytes(&output)));
        Self {
            ts: now_rfc3339(),
            kind,
            request_id: request_id.to_string(),
            trace_id: trace.trace_id.clone(),
            span_id: trace.span_id.clone(),
            parent_span_id: trace.parent_span_id.clone(),
            service: String::new(),
            namespace: String::new(),
            agent: agent.map(str::to_string),
            caller: caller.to_string(),
            caller_agent: caller_agent.map(str::to_string),
            callee: callee.to_string(),
            direction,
            input,
            output,
            input_sha256,
            output_sha256,
            tokens: None,
            cost_usd: None,
            latency_ms: 0,
            decision: "allow".into(),
            rule: None,
            reason: None,
            error: None,
        }
    }

    pub fn verdict(mut self, v: &crate::authz::Verdict) -> Self {
        self.decision = v.decision().to_string();
        self.rule = Some(v.rule.clone());
        self.reason = (!v.reason.is_empty()).then(|| v.reason.clone());
        self
    }

    pub fn latency(mut self, started: Instant) -> Self {
        self.latency_ms = started.elapsed().as_millis() as u64;
        self
    }

    /// Replace `input` with `"[redacted:<rule>]"`, keeping the hash of the original: a payload a
    /// content guardrail denied is the one most likely to hold the secret it matched (CONTRACT.md §6).
    pub fn withhold_input(mut self, rule: &str) -> Self {
        self.ensure_hashes();
        if !self.input.is_null() {
            self.input = withheld(rule);
        }
        self
    }

    /// `withhold_input` for `output`.
    pub fn withhold_output(mut self, rule: &str) -> Self {
        self.ensure_hashes();
        if !self.output.is_null() {
            self.output = withheld(rule);
        }
        self
    }

    /// Recompute hashes (used when a record arrives from the runtime with payloads but no hashes).
    pub fn ensure_hashes(&mut self) {
        if self.input_sha256.is_none() && !self.input.is_null() {
            self.input_sha256 = Some(sha256_hex(&payload_bytes(&self.input)));
        }
        if self.output_sha256.is_none() && !self.output.is_null() {
            self.output_sha256 = Some(sha256_hex(&payload_bytes(&self.output)));
        }
    }

    /// Apply `audit.redact` dotted paths and size truncation to input/output.
    pub fn redact(&mut self, paths: &[String]) {
        self.redact_paths(paths);
        self.truncate_payloads();
    }

    pub fn truncate_payloads(&mut self) {
        truncate(&mut self.input);
        truncate(&mut self.output);
    }

    /// Apply `audit.redact` dotted paths to input/output.
    pub fn redact_paths(&mut self, paths: &[String]) {
        for p in paths {
            if let Some(rest) = p.strip_prefix("input.") {
                redact_path(&mut self.input, rest);
            } else if let Some(rest) = p.strip_prefix("output.") {
                redact_path(&mut self.output, rest);
            } else if p == "input" {
                self.input = Value::String("[redacted]".into());
            } else if p == "output" {
                self.output = Value::String("[redacted]".into());
            }
        }
    }

    pub fn to_json_line(&self) -> String {
        serde_json::to_string(self)
            .unwrap_or_else(|e| format!("{{\"error\":\"serialize audit record: {e}\"}}"))
    }
}

fn withheld(rule: &str) -> Value {
    Value::String(format!("[redacted:{rule}]"))
}

/// String values found at a dotted path (arrays are walked), for scrubbing them elsewhere.
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

/// Values shorter than this are not scrubbed from other records (too likely to hit unrelated text).
pub const MIN_SECRET_LEN: usize = 4;
const SECRET_TTL: std::time::Duration = std::time::Duration::from_secs(15 * 60);

fn scrub(v: &mut Value, secrets: &[String]) {
    match v {
        Value::String(s) => {
            for secret in secrets {
                if s.contains(secret.as_str()) {
                    *s = s.replace(secret.as_str(), "[redacted]");
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|i| scrub(i, secrets)),
        Value::Object(map) => map.values_mut().for_each(|i| scrub(i, secrets)),
        _ => {}
    }
}

fn redact_path(v: &mut Value, dotted: &str) {
    let mut cur = v;
    let parts: Vec<&str> = dotted.split('.').collect();
    for (i, part) in parts.iter().enumerate() {
        let last = i + 1 == parts.len();
        match cur {
            Value::Object(map) => {
                if last {
                    if map.contains_key(*part) {
                        map.insert(part.to_string(), Value::String("[redacted]".into()));
                    }
                    return;
                }
                match map.get_mut(*part) {
                    Some(next) => cur = next,
                    None => return,
                }
            }
            Value::Array(items) => {
                for item in items.iter_mut() {
                    redact_path(item, &parts[i..].join("."));
                }
                return;
            }
            _ => return,
        }
    }
}

/// Rewrite emails and phone numbers in every string of a JSON value.
pub fn redact_pii_value(v: &mut Value) {
    match v {
        Value::String(s) => {
            let (out, n) = crate::guardrails::redact_pii(s);
            if n > 0 {
                *s = out;
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact_pii_value),
        Value::Object(map) => map.values_mut().for_each(redact_pii_value),
        _ => {}
    }
}

fn truncate(v: &mut Value) {
    let bytes = payload_bytes(v);
    if bytes.len() > MAX_PAYLOAD_BYTES {
        let text = String::from_utf8_lossy(&bytes);
        let mut cut = MAX_PAYLOAD_BYTES;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        *v = Value::String(format!(
            "{}…(truncated, {} bytes)",
            &text[..cut],
            bytes.len()
        ));
    }
}

/// What [`AuditWriter::write`] redacts: the `audit.redact` paths and `guardrails.pii_redact`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Redaction {
    paths: Vec<String>,
    pii_redact: bool,
}

/// Writes records to stdout or a file, one line each, serialised, and publishes each written
/// record to [`AuditWriter::subscribe`] receivers.
pub struct AuditWriter {
    service: String,
    namespace: String,
    /// Swapped whole by [`AuditWriter::set_redaction`] (a charter hot reload); each write takes
    /// one snapshot, so a record is never redacted half with the old settings and half with the
    /// new ones.
    redaction: RwLock<Arc<Redaction>>,
    /// request_id → values found at `audit.redact` paths, scrubbed from every later record of that
    /// request (the same value reappears as text inside model prompts and tool results).
    secrets: Mutex<std::collections::HashMap<String, (std::time::Instant, Vec<String>)>>,
    sink: Mutex<Box<dyn Write + Send>>,
    published: broadcast::Sender<Arc<AuditRecord>>,
}

impl AuditWriter {
    pub fn stdout(service: &str, namespace: &str, redact: Vec<String>) -> Self {
        Self::with_sink(service, namespace, redact, Box::new(std::io::stdout()))
    }

    pub fn file(
        service: &str,
        namespace: &str,
        redact: Vec<String>,
        path: &str,
    ) -> std::io::Result<Self> {
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self::with_sink(service, namespace, redact, Box::new(f)))
    }

    pub fn with_sink(
        service: &str,
        namespace: &str,
        redact: Vec<String>,
        sink: Box<dyn Write + Send>,
    ) -> Self {
        Self {
            service: service.into(),
            namespace: namespace.into(),
            redaction: RwLock::new(Arc::new(Redaction {
                paths: redact,
                pii_redact: false,
            })),
            secrets: Mutex::new(std::collections::HashMap::new()),
            sink: Mutex::new(sink),
            published: broadcast::channel(SUBSCRIBE_CAPACITY).0,
        }
    }

    /// Every record written from now on, after redaction and truncation, exactly as written to
    /// the sink and in the same order (the OTel exporter and the control-plane client use it).
    /// A receiver more than [`SUBSCRIBE_CAPACITY`] records behind loses the oldest
    /// (`RecvError::Lagged`); the writer never waits for a receiver.
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<AuditRecord>> {
        self.published.subscribe()
    }

    /// With `guardrails.pii_redact`, emails and phone numbers are rewritten in every payload written.
    pub fn with_pii_redact(mut self, on: bool) -> Self {
        let redaction = self
            .redaction
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        Arc::make_mut(redaction).pii_redact = on;
        self
    }

    /// Replace the `audit.redact` paths and the `guardrails.pii_redact` switch, for a charter hot
    /// reload: every record written after this call uses the new settings. The writer stays the
    /// same, so its sink, its remembered values and its [`AuditWriter::subscribe`] receivers are
    /// unaffected.
    pub fn set_redaction(&self, paths: Vec<String>, pii_redact: bool) {
        let new = Arc::new(Redaction { paths, pii_redact });
        *self
            .redaction
            .write()
            .unwrap_or_else(PoisonError::into_inner) = new;
    }

    /// The `audit.redact` paths and the `guardrails.pii_redact` switch in force.
    pub fn redaction(&self) -> (Vec<String>, bool) {
        let r = self.snapshot();
        (r.paths.clone(), r.pii_redact)
    }

    fn snapshot(&self) -> Arc<Redaction> {
        self.redaction
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Remember the values at `audit.redact` paths of a payload (`side` = "input" | "output")
    /// so later records of the same request never carry them, even embedded in text.
    pub fn remember(&self, request_id: &str, side: &str, payload: &Value) {
        self.remember_with(&self.snapshot().paths, request_id, side, payload);
    }

    fn remember_with(&self, paths: &[String], request_id: &str, side: &str, payload: &Value) {
        if paths.is_empty() || request_id.is_empty() {
            return;
        }
        let mut found = Vec::new();
        let prefix = format!("{side}.");
        for p in paths {
            if let Some(rest) = p.strip_prefix(&prefix) {
                collect_path(payload, rest, &mut found);
            } else if p == side {
                collect_leaves(payload, &mut found);
            }
        }
        self.keep_secrets(request_id, found);
    }

    /// Scrub these values (whole payloads a guardrail denied) from every later record of the
    /// request: the same text comes back inside the calling agent's next prompt.
    pub fn withhold(&self, request_id: &str, values: impl IntoIterator<Item = String>) {
        let found = values
            .into_iter()
            .filter(|v| v.chars().count() >= MIN_SECRET_LEN)
            .collect();
        self.keep_secrets(request_id, found);
    }

    fn keep_secrets(&self, request_id: &str, found: Vec<String>) {
        if found.is_empty() || request_id.is_empty() {
            return;
        }
        let mut secrets = self.secrets.lock().unwrap_or_else(PoisonError::into_inner);
        let now = std::time::Instant::now();
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
        // longest first, so a value that contains another is replaced whole
        entry.1.sort_by_key(|s| std::cmp::Reverse(s.len()));
    }

    /// Stamp, hash (over the original payloads), redact paths, scrub remembered values, redact PII,
    /// then truncate — redaction always sees the whole payload (CONTRACT.md §6).
    pub fn write(&self, mut record: AuditRecord) {
        let redaction = self.snapshot();
        record.service = self.service.clone();
        record.namespace = self.namespace.clone();
        record.ensure_hashes();
        self.remember_with(&redaction.paths, &record.request_id, "input", &record.input);
        self.remember_with(
            &redaction.paths,
            &record.request_id,
            "output",
            &record.output,
        );
        record.redact_paths(&redaction.paths);
        if let Some((_, secrets)) = self
            .secrets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&record.request_id)
        {
            scrub(&mut record.input, secrets);
            scrub(&mut record.output, secrets);
        }
        if redaction.pii_redact {
            redact_pii_value(&mut record.input);
            redact_pii_value(&mut record.output);
        }
        record.truncate_payloads();
        let line = record.to_json_line();
        // A guard may write while a panic unwinds; a poisoned lock must not turn that into an abort.
        let mut sink = self.sink.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = writeln!(sink, "{line}");
        let _ = sink.flush();
        // Published under the sink lock, so receivers see the sink's order. `send` never blocks
        // (a full channel drops the oldest for lagging receivers) and fails only with none.
        if self.published.receiver_count() > 0 {
            let _ = self.published.send(Arc::new(record));
        }
    }

    /// Records owed for work about to be awaited. Dropped before `disarm` — the server dropped the
    /// handler because the client went away or its deadline passed — they are written with
    /// `error: "cancelled: …"`, so side effects that already ran are never left unaudited.
    pub fn on_cancel(&self, records: Vec<AuditRecord>, started: Instant) -> OnCancel<'_> {
        OnCancel {
            writer: self,
            records,
            started,
        }
    }
}

pub const CANCELLED: &str =
    "cancelled: the caller went away or its deadline passed before this finished";

/// See [`AuditWriter::on_cancel`].
#[must_use = "dropping the guard writes its records as cancelled"]
pub struct OnCancel<'a> {
    writer: &'a AuditWriter,
    records: Vec<AuditRecord>,
    started: Instant,
}

impl OnCancel<'_> {
    /// The work finished and wrote its own records.
    pub fn disarm(mut self) {
        self.records.clear();
    }
}

impl Drop for OnCancel<'_> {
    fn drop(&mut self) {
        // `ts` is a record's end time (CONTRACT.md §6): these were built before the work started.
        let now = now_rfc3339();
        for mut rec in self.records.drain(..) {
            rec = rec.latency(self.started);
            rec.ts = now.clone();
            rec.error = Some(CANCELLED.into());
            self.writer.write(rec);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::TraceContext;

    #[test]
    fn field_order_and_hashes() {
        let t = TraceContext::new_root();
        let rec = AuditRecord::new(
            Kind::AgentInvocation,
            Direction::Inbound,
            "req-1",
            &t,
            Some("ops-assistant"),
            "local",
            None,
            "ops-assistant",
            Value::String("hello".into()),
            Value::Null,
        );
        let line = rec.to_json_line();
        let ts_pos = line.find("\"ts\"").unwrap();
        let kind_pos = line.find("\"kind\"").unwrap();
        let dec_pos = line.find("\"decision\"").unwrap();
        assert!(ts_pos < kind_pos && kind_pos < dec_pos);
        assert_eq!(
            rec.input_sha256.as_deref(),
            Some(sha256_hex(b"hello").as_str())
        );
        assert!(rec.output_sha256.is_none());
        let back: AuditRecord = serde_json::from_str(&line).unwrap();
        assert_eq!(back.kind, Kind::AgentInvocation);
    }

    #[test]
    fn redaction_and_truncation() {
        let t = TraceContext::new_root();
        let input = serde_json::json!({"question": "x", "context": {"customer_email": "a@b.co", "items": [{"card": "4111"}]}});
        let mut rec = AuditRecord::new(
            Kind::ToolCall,
            Direction::Internal,
            "r",
            &t,
            None,
            "local",
            None,
            "t",
            input,
            Value::String("y".repeat(10_000)),
        );
        let before = rec.input_sha256.clone();
        rec.redact(&[
            "input.context.customer_email".into(),
            "input.context.items.card".into(),
        ]);
        assert_eq!(rec.input["context"]["customer_email"], "[redacted]");
        assert_eq!(rec.input["context"]["items"][0]["card"], "[redacted]");
        assert_eq!(rec.input["question"], "x");
        assert_eq!(rec.input_sha256, before, "hash is over the full payload");
        let out = rec.output.as_str().unwrap();
        assert!(out.ends_with("…(truncated, 10000 bytes)"));
        assert!(out.len() < 9000);
    }

    #[test]
    fn pii_is_redacted_in_payloads_but_hash_is_of_the_original() {
        let mut v =
            serde_json::json!({"messages": [{"content": "mail ops-lead@example.com"}], "n": 3});
        let before = sha256_hex(&payload_bytes(&v));
        redact_pii_value(&mut v);
        assert_eq!(v["messages"][0]["content"], "mail [redacted:email]");
        assert_eq!(v["n"], 3);
        assert_ne!(before, sha256_hex(&payload_bytes(&v)));
    }

    #[derive(Clone, Default)]
    struct Buf(std::sync::Arc<Mutex<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Buf {
        fn lines(&self) -> Vec<Value> {
            String::from_utf8(self.0.lock().unwrap().clone())
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        }
    }

    #[test]
    fn redacted_values_are_scrubbed_from_later_records_of_the_same_request() {
        let buf = Buf::default();
        let w = AuditWriter::with_sink(
            "orders",
            "ns",
            vec!["input.context.customer".into(), "output.body.card".into()],
            Box::new(buf.clone()),
        );
        let t = TraceContext::new_root();
        // the invocation input is remembered up front (its own record is written last)
        w.remember(
            "r1",
            "input",
            &serde_json::json!({"input": "hi", "context": {"customer": "cust-SECRET-99"}}),
        );
        let tool_out =
            serde_json::json!({"status": 200, "body": {"card": "4111-1111", "sku": "W-1"}});
        w.write(AuditRecord::new(
            Kind::ServiceCall,
            Direction::Internal,
            "r1",
            &t,
            None,
            "local",
            None,
            "x",
            Value::Null,
            tool_out,
        ));
        let prompt = serde_json::json!({"messages": [{"content": "hi <context>{\"customer\": \"cust-SECRET-99\"}</context>"}, {"content": "{\"card\":\"4111-1111\"}"}]});
        w.write(AuditRecord::new(
            Kind::ModelCall,
            Direction::Outbound,
            "r1",
            &t,
            None,
            "local",
            None,
            "mock",
            prompt,
            Value::Null,
        ));
        w.write(AuditRecord::new(
            Kind::ModelCall,
            Direction::Outbound,
            "r2",
            &t,
            None,
            "local",
            None,
            "mock",
            Value::String("cust-SECRET-99".into()),
            Value::Null,
        ));
        let lines = buf.lines();
        assert_eq!(lines[0]["output"]["body"]["card"], "[redacted]");
        assert_eq!(lines[0]["output"]["body"]["sku"], "W-1");
        let text = lines[1]["input"].to_string();
        assert!(
            !text.contains("cust-SECRET-99") && !text.contains("4111-1111"),
            "{text}"
        );
        assert_eq!(
            lines[2]["input"], "cust-SECRET-99",
            "other requests are untouched"
        );
    }

    #[test]
    fn withheld_payloads_keep_their_hash_and_leave_no_text_behind() {
        let buf = Buf::default();
        let w = AuditWriter::with_sink("s", "n", vec![], Box::new(buf.clone()));
        let t = TraceContext::new_root();
        let secret = "use api_key = sk-123 please";
        let rule = "guardrail.input_deny.no-secrets";
        w.withhold("r1", [secret.to_string(), "ab".to_string()]);
        w.write(
            AuditRecord::new(
                Kind::Guardrail,
                Direction::Internal,
                "r1",
                &t,
                None,
                "local",
                None,
                "a",
                Value::String(secret.into()),
                Value::Null,
            )
            .withhold_input(rule)
            .withhold_output(rule),
        );
        // the calling agent's next prompt quotes the denied input
        w.write(AuditRecord::new(
            Kind::ModelCall,
            Direction::Outbound,
            "r1",
            &t,
            None,
            "local",
            None,
            "mock",
            serde_json::json!({"messages": [{"content": format!("asked: {secret}")}, {"content": "ab"}]}),
            Value::Null,
        ));
        let lines = buf.lines();
        assert_eq!(lines[0]["input"], format!("[redacted:{rule}]"));
        assert_eq!(lines[0]["input_sha256"], sha256_hex(secret.as_bytes()));
        assert!(lines[0]["output"].is_null() && lines[0]["output_sha256"].is_null());
        assert_eq!(
            lines[1]["input"]["messages"][0]["content"],
            "asked: [redacted]"
        );
        assert_eq!(
            lines[1]["input"]["messages"][1]["content"], "ab",
            "too short to scrub"
        );
    }

    #[test]
    fn a_dropped_guard_writes_its_records_as_cancelled() {
        let buf = Buf::default();
        let w = AuditWriter::with_sink("s", "n", vec![], Box::new(buf.clone()));
        let t = TraceContext::new_root();
        let rec = |callee: &str| {
            AuditRecord::new(
                Kind::ToolCall,
                Direction::Internal,
                "r",
                &t,
                None,
                "local",
                None,
                callee,
                Value::String("args".into()),
                Value::Null,
            )
        };
        w.on_cancel(vec![rec("finished")], Instant::now()).disarm();
        drop(w.on_cancel(vec![rec("a"), rec("b")], Instant::now()));
        let lines = buf.lines();
        let callees: Vec<&str> = lines
            .iter()
            .map(|l| l["callee"].as_str().unwrap())
            .collect();
        assert_eq!(callees, ["a", "b"]);
        assert!(
            lines.iter().all(|l| l["error"] == CANCELLED
                && l["decision"] == "allow"
                && l["input"] == "args")
        );
    }

    #[test]
    fn pii_redaction_happens_before_truncation() {
        let buf = Buf::default();
        let w =
            AuditWriter::with_sink("s", "n", vec![], Box::new(buf.clone())).with_pii_redact(true);
        let t = TraceContext::new_root();
        // an email straddling the 8 KiB cut must not leak a partial address
        let text = format!(
            "{}someone.long.name@example.com tail",
            "x".repeat(MAX_PAYLOAD_BYTES - 10)
        );
        w.write(AuditRecord::new(
            Kind::ToolCall,
            Direction::Internal,
            "r",
            &t,
            None,
            "local",
            None,
            "t",
            Value::String(text),
            Value::Null,
        ));
        let out = buf.lines()[0]["input"].as_str().unwrap().to_string();
        assert!(!out.contains("someone.lo"), "{}", &out[out.len() - 80..]);
    }

    #[test]
    fn config_and_learning_kinds_have_their_wire_names() {
        for (kind, name) in [(Kind::Config, "config"), (Kind::Learning, "learning")] {
            assert_eq!(serde_json::to_value(kind).unwrap(), name);
            assert_eq!(kind.as_str(), name);
            assert_eq!(kind.to_string(), name);
            let back: Kind = serde_json::from_value(Value::String(name.into())).unwrap();
            assert_eq!(back, kind);
        }
        // as_str agrees with serde for every kind
        for kind in [
            Kind::AgentInvocation,
            Kind::ModelCall,
            Kind::ToolCall,
            Kind::AgentCall,
            Kind::ServiceCall,
            Kind::HttpCall,
            Kind::Authz,
            Kind::Guardrail,
            Kind::Budget,
        ] {
            assert_eq!(serde_json::to_value(kind).unwrap(), kind.as_str());
        }
    }

    #[test]
    fn subscribers_receive_each_record_as_written() {
        let buf = Buf::default();
        let w = AuditWriter::with_sink(
            "orders",
            "shop",
            vec!["input.card".into()],
            Box::new(buf.clone()),
        )
        .with_pii_redact(true);
        let mut rx = w.subscribe();
        let t = TraceContext::new_root();
        let mut rec = AuditRecord::new(
            Kind::Learning,
            Direction::Internal,
            "r1",
            &t,
            Some("support"),
            "local",
            None,
            "learning",
            serde_json::json!({"card": "4111-1111", "note": "mail ops@example.com"}),
            Value::String("z".repeat(MAX_PAYLOAD_BYTES + 100)),
        );
        rec.rule = Some("learning.proposed".into());
        w.write(rec);
        let got = rx.try_recv().expect("one record published");
        assert_eq!(got.kind, Kind::Learning);
        assert_eq!(got.service, "orders", "stamped");
        assert_eq!(got.input["card"], "[redacted]", "audit.redact applied");
        assert_eq!(got.input["note"], "mail [redacted:email]", "PII redacted");
        assert!(
            got.output.as_str().unwrap().contains("…(truncated, "),
            "truncated"
        );
        // exactly the line the sink got
        let line = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert_eq!(line.trim_end(), got.to_json_line());
        assert!(rx.try_recv().is_err(), "nothing else");
    }

    #[test]
    fn a_lagging_subscriber_never_blocks_the_writer() {
        let buf = Buf::default();
        let w = AuditWriter::with_sink("s", "n", vec![], Box::new(buf.clone()));
        let mut slow = w.subscribe();
        let t = TraceContext::new_root();
        let total = SUBSCRIBE_CAPACITY + 100;
        for i in 0..total {
            w.write(AuditRecord::new(
                Kind::Config,
                Direction::Internal,
                "",
                &t,
                None,
                "file",
                None,
                &format!("charter-{i}"),
                Value::Null,
                Value::Null,
            ));
        }
        assert_eq!(buf.lines().len(), total, "every record reached the sink");
        match slow.try_recv() {
            Err(broadcast::error::TryRecvError::Lagged(n)) => assert_eq!(n, 100),
            other => panic!("expected Lagged, got {other:?}"),
        }
        // after the lag it reads on from the oldest record still held
        assert_eq!(slow.try_recv().unwrap().callee, "charter-100");
        // a writer with no subscribers at all is fine too
        drop(slow);
        w.write(AuditRecord::new(
            Kind::Config,
            Direction::Internal,
            "",
            &t,
            None,
            "file",
            None,
            "last",
            Value::Null,
            Value::Null,
        ));
        assert_eq!(buf.lines().len(), total + 1);
    }

    #[test]
    fn subscribe_works_for_the_file_sink() {
        let dir = std::env::temp_dir().join(format!("agentsc-audit-{}", uuid::Uuid::new_v4()));
        let path = dir.join("audit.jsonl");
        let w = AuditWriter::file("s", "n", vec![], path.to_str().unwrap()).unwrap();
        let mut rx = w.subscribe();
        let t = TraceContext::new_root();
        w.write(AuditRecord::new(
            Kind::Config,
            Direction::Internal,
            "",
            &t,
            None,
            "control-plane",
            None,
            "charter",
            serde_json::json!({"source": "control-plane", "version": "7"}),
            Value::Null,
        ));
        let got = rx.try_recv().unwrap();
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk.trim_end(), got.to_json_line());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_cancel_guard_stamps_the_end_time() {
        let buf = Buf::default();
        let w = AuditWriter::with_sink("s", "n", vec![], Box::new(buf.clone()));
        let t = TraceContext::new_root();
        let mut rec = AuditRecord::new(
            Kind::ToolCall,
            Direction::Internal,
            "r",
            &t,
            None,
            "local",
            None,
            "t",
            Value::Null,
            Value::Null,
        );
        rec.ts = "2000-01-01T00:00:00.000Z".into(); // built long before the work ended
        drop(w.on_cancel(vec![rec], Instant::now()));
        let line = &buf.lines()[0];
        assert_ne!(line["ts"], "2000-01-01T00:00:00.000Z");
        assert!(line["ts"].as_str().unwrap().ends_with('Z'));
    }

    #[test]
    fn set_redaction_applies_to_later_records_and_keeps_subscribers() {
        let buf = Buf::default();
        let w = Arc::new(
            AuditWriter::with_sink(
                "orders",
                "shop",
                vec!["input.card".into()],
                Box::new(buf.clone()),
            )
            .with_pii_redact(false),
        );
        let mut rx = w.subscribe();
        let t = TraceContext::new_root();
        let rec = |request_id: &str| {
            AuditRecord::new(
                Kind::ToolCall,
                Direction::Internal,
                request_id,
                &t,
                None,
                "local",
                None,
                "t",
                serde_json::json!({"card": "4111-1111", "token": "tok-123456", "mail": "a@example.com"}),
                Value::Null,
            )
        };
        w.write(rec("r1"));
        assert_eq!(
            w.redaction(),
            (vec!["input.card".to_string()], false),
            "the settings it was built with"
        );
        // a hot reload: through a shared reference, no new writer
        w.set_redaction(vec!["input.token".into()], true);
        assert_eq!(w.redaction(), (vec!["input.token".to_string()], true));
        w.write(rec("r2"));

        let lines = buf.lines();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["input"]["card"], "[redacted]");
        assert_eq!(lines[0]["input"]["token"], "tok-123456");
        assert_eq!(lines[0]["input"]["mail"], "a@example.com");
        assert_eq!(lines[1]["input"]["card"], "4111-1111", "path removed");
        assert_eq!(lines[1]["input"]["token"], "[redacted]", "path added");
        assert_eq!(
            lines[1]["input"]["mail"], "[redacted:email]",
            "pii_redact on"
        );
        // the receiver subscribed before the reload gets both, exactly as written
        let first = rx.try_recv().expect("first record");
        let second = rx.try_recv().expect("second record");
        assert_eq!(serde_json::to_value(&*first).unwrap(), lines[0]);
        assert_eq!(serde_json::to_value(&*second).unwrap(), lines[1]);
        assert!(rx.try_recv().is_err());
        // values remembered under the new paths are scrubbed from later records of the request
        w.write(AuditRecord::new(
            Kind::ModelCall,
            Direction::Outbound,
            "r2",
            &t,
            None,
            "local",
            None,
            "mock",
            Value::String("the tool said tok-123456".into()),
            Value::Null,
        ));
        assert_eq!(buf.lines()[2]["input"], "the tool said [redacted]");
        // and switching pii_redact off again works the same way
        w.set_redaction(vec![], false);
        w.write(rec("r3"));
        let last = &buf.lines()[3];
        assert_eq!(last["input"]["mail"], "a@example.com");
        assert_eq!(last["input"]["token"], "tok-123456");
        assert_eq!(rx.try_recv().unwrap().request_id, "r2");
        assert_eq!(rx.try_recv().unwrap().request_id, "r3");
    }

    #[test]
    fn set_redaction_is_safe_while_other_threads_write() {
        let buf = Buf::default();
        let w = Arc::new(AuditWriter::with_sink(
            "s",
            "n",
            vec!["input.a".into()],
            Box::new(buf.clone()),
        ));
        let t = TraceContext::new_root();
        let writers: Vec<_> = (0..4)
            .map(|i| {
                let w = Arc::clone(&w);
                let t = t.clone();
                std::thread::spawn(move || {
                    for j in 0..200 {
                        w.write(AuditRecord::new(
                            Kind::ToolCall,
                            Direction::Internal,
                            &format!("r{i}-{j}"),
                            &t,
                            None,
                            "local",
                            None,
                            "t",
                            serde_json::json!({"a": "value-a", "b": "value-b"}),
                            Value::Null,
                        ));
                    }
                })
            })
            .collect();
        for k in 0..100 {
            let path = if k % 2 == 0 { "input.a" } else { "input.b" };
            w.set_redaction(vec![path.into()], k % 3 == 0);
        }
        for h in writers {
            h.join().unwrap();
        }
        let lines = buf.lines();
        assert_eq!(lines.len(), 800);
        // every record was redacted with one consistent snapshot: exactly one of a / b
        for l in &lines {
            let a = l["input"]["a"] == "[redacted]";
            let b = l["input"]["b"] == "[redacted]";
            assert!(a ^ b, "{l}");
        }
    }

    #[test]
    fn the_view_reads_any_kind_and_keeps_unknown_fields() {
        let line = r#"{"ts":"2026-10-21T10:00:02.000Z","kind":"teleport","request_id":"r10","trace_id":"dddd1111","span_id":"s","parent_span_id":null,"service":"orders","namespace":"shop","agent":"support","caller":"local","caller_agent":null,"callee":"mars","direction":"sideways","input":{"to":"mars"},"output":null,"input_sha256":"ab","output_sha256":null,"tokens":{"input":12,"output":3,"cache_read":40},"cost_usd":0.25,"latency_ms":1,"decision":"maybe","rule":"teleport.ok","reason":null,"error":null,"new_field":{"x":[1,2]},"z_last":"kept"}"#;
        let view = AuditRecordView::from_json(line).unwrap();
        assert_eq!(view.kind, "teleport");
        assert_eq!(view.known_kind(), None);
        assert_eq!(view.direction, "sideways");
        assert_eq!(view.decision, "maybe");
        let tokens = view.tokens.clone().unwrap();
        assert_eq!((tokens.input, tokens.output), (12, 3));
        assert_eq!(tokens.extra["cache_read"], 40);
        assert_eq!(view.extra["new_field"], serde_json::json!({"x": [1, 2]}));
        assert_eq!(view.extra["z_last"], "kept");
        // re-serialized unchanged: the same JSON value, unknown fields included
        let original: Value = serde_json::from_str(line).unwrap();
        let again: Value = serde_json::from_str(&view.to_json_line()).unwrap();
        assert_eq!(again, original);
        // and the known fields keep the wire order, the unknown ones follow
        let text = view.to_json_line();
        let pos = |k: &str| text.find(&format!("\"{k}\":")).unwrap();
        assert!(pos("ts") < pos("kind") && pos("kind") < pos("decision"));
        assert!(pos("error") < pos("new_field") && pos("new_field") < pos("z_last"));
        // a strict reader refuses the same line; the view is what other versions' records need
        assert!(serde_json::from_str::<AuditRecord>(line).is_err());
        // it round-trips through the view a second time too
        assert_eq!(AuditRecordView::from_json(&text).unwrap(), view);
    }

    #[test]
    fn the_view_of_this_builds_records() {
        let t = TraceContext::new_root();
        let mut rec = AuditRecord::new(
            Kind::Learning,
            Direction::Internal,
            "r1",
            &t,
            Some("support"),
            "local",
            None,
            "learning",
            serde_json::json!({"request_id_of_run": "r0"}),
            Value::Null,
        );
        rec.tokens = Some(Tokens {
            input: 5,
            output: 7,
        });
        rec.rule = Some("learning.proposed".into());
        let view = AuditRecordView::from(&rec);
        assert_eq!(view.known_kind(), Some(Kind::Learning));
        assert_eq!(view.direction, "internal");
        assert!(view.extra.is_empty());
        // the same JSON as the record itself
        assert_eq!(
            serde_json::to_value(&view).unwrap(),
            serde_json::to_value(&rec).unwrap()
        );
        assert_eq!(
            AuditRecordView::from_json(&rec.to_json_line()).unwrap(),
            view
        );
        for d in [Direction::Inbound, Direction::Outbound, Direction::Internal] {
            assert_eq!(serde_json::to_value(d).unwrap(), d.as_str());
            assert_eq!(d.to_string(), d.as_str());
        }
    }

    #[test]
    fn the_view_refuses_lines_that_are_not_records_and_defaults_the_rest() {
        // a diagnostic that happens to be JSON
        assert!(
            AuditRecordView::from_json(r#"{"timestamp":"x","level":"INFO","fields":{}}"#).is_err()
        );
        // the identifying fields are enough; the others default
        let v = AuditRecordView::from_json(
            r#"{"ts":"t","kind":"config","request_id":"","trace_id":"","service":"s","caller":"file","callee":"charter","direction":"internal","decision":"allow"}"#,
        )
        .unwrap();
        assert_eq!(v.latency_ms, 0);
        assert!(v.input.is_null() && v.tokens.is_none() && v.extra.is_empty());
        assert_eq!(v.known_kind(), Some(Kind::Config));
        // tokens without the usual counts still parse
        let v = AuditRecordView::from_json(
            r#"{"ts":"t","kind":"model_call","request_id":"r","trace_id":"x","service":"s","caller":"local","callee":"mock","direction":"outbound","decision":"allow","tokens":{"reasoning":9}}"#,
        )
        .unwrap();
        let tokens = v.tokens.unwrap();
        assert_eq!((tokens.input, tokens.output), (0, 0));
        assert_eq!(tokens.extra["reasoning"], 9);
    }

    #[test]
    fn writer_stamps_service() {
        let buf = std::sync::Arc::new(Mutex::new(Vec::<u8>::new()));
        struct Shared(std::sync::Arc<Mutex<Vec<u8>>>);
        impl Write for Shared {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let w = AuditWriter::with_sink(
            "orders",
            "agentsc-demo",
            vec![],
            Box::new(Shared(buf.clone())),
        );
        let t = TraceContext::new_root();
        w.write(AuditRecord::new(
            Kind::Authz,
            Direction::Inbound,
            "r",
            &t,
            None,
            "local",
            None,
            "x",
            Value::Null,
            Value::Null,
        ));
        let s = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        let v: Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(v["service"], "orders");
        assert_eq!(v["namespace"], "agentsc-demo");
    }
}
