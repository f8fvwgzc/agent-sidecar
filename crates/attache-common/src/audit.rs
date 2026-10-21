//! The audit record (CONTRACT.md §6). Field order below is the wire order.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

pub const MAX_PAYLOAD_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
    Internal,
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

/// Writes records to stdout or a file, one line each, serialised.
pub struct AuditWriter {
    service: String,
    namespace: String,
    redact: Vec<String>,
    pii_redact: bool,
    /// request_id → values found at `audit.redact` paths, scrubbed from every later record of that
    /// request (the same value reappears as text inside model prompts and tool results).
    secrets: Mutex<std::collections::HashMap<String, (std::time::Instant, Vec<String>)>>,
    sink: Mutex<Box<dyn Write + Send>>,
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
            redact,
            pii_redact: false,
            secrets: Mutex::new(std::collections::HashMap::new()),
            sink: Mutex::new(sink),
        }
    }

    /// With `guardrails.pii_redact`, emails and phone numbers are rewritten in every payload written.
    pub fn with_pii_redact(mut self, on: bool) -> Self {
        self.pii_redact = on;
        self
    }

    /// Remember the values at `audit.redact` paths of a payload (`side` = "input" | "output")
    /// so later records of the same request never carry them, even embedded in text.
    pub fn remember(&self, request_id: &str, side: &str, payload: &Value) {
        if self.redact.is_empty() || request_id.is_empty() {
            return;
        }
        let mut found = Vec::new();
        let prefix = format!("{side}.");
        for p in &self.redact {
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
        record.service = self.service.clone();
        record.namespace = self.namespace.clone();
        record.ensure_hashes();
        self.remember(&record.request_id, "input", &record.input);
        self.remember(&record.request_id, "output", &record.output);
        record.redact_paths(&self.redact);
        if let Some((_, secrets)) = self
            .secrets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&record.request_id)
        {
            scrub(&mut record.input, secrets);
            scrub(&mut record.output, secrets);
        }
        if self.pii_redact {
            redact_pii_value(&mut record.input);
            redact_pii_value(&mut record.output);
        }
        record.truncate_payloads();
        let line = record.to_json_line();
        // A guard may write while a panic unwinds; a poisoned lock must not turn that into an abort.
        let mut sink = self.sink.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = writeln!(sink, "{line}");
        let _ = sink.flush();
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
        for mut rec in self.records.drain(..) {
            rec = rec.latency(self.started);
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
            "attache-demo",
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
        assert_eq!(v["namespace"], "attache-demo");
    }
}
