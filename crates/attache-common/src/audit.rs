//! The audit record (CONTRACT.md §6). Field order below is the wire order.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::sync::Mutex;

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

    pub fn latency(mut self, started: std::time::Instant) -> Self {
        self.latency_ms = started.elapsed().as_millis() as u64;
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
        truncate(&mut self.input);
        truncate(&mut self.output);
    }

    pub fn to_json_line(&self) -> String {
        serde_json::to_string(self)
            .unwrap_or_else(|e| format!("{{\"error\":\"serialize audit record: {e}\"}}"))
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
            sink: Mutex::new(sink),
        }
    }

    /// With `guardrails.pii_redact`, emails and phone numbers are rewritten in every payload written.
    pub fn with_pii_redact(mut self, on: bool) -> Self {
        self.pii_redact = on;
        self
    }

    pub fn write(&self, mut record: AuditRecord) {
        record.service = self.service.clone();
        record.namespace = self.namespace.clone();
        record.ensure_hashes();
        record.redact(&self.redact);
        if self.pii_redact {
            redact_pii_value(&mut record.input);
            redact_pii_value(&mut record.output);
        }
        let line = record.to_json_line();
        let mut sink = self.sink.lock().unwrap();
        let _ = writeln!(sink, "{line}");
        let _ = sink.flush();
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
