//! Runs for the agent timeline (design §10.1.1, §11.1): per trace, the span starts sidecars
//! sent (`SpanStart`) and the audit records the ring holds, turned into spans.
//!
//! - A span per record of kind `agent_invocation`, `agent_call`, `service_call`, `http_call`,
//!   `model_call` or `tool_call`, keyed by its `span_id`; records of any other kind attach to the
//!   span whose `span_id` they carry, as `events`.
//! - `start` comes from the `SpanStart` when one arrived, else `ts − latency_ms`; `end` is the
//!   record's `ts`. A start without a record is a running span, closed with `status: error` and
//!   `rule: span.timeout` [`SPAN_TIMEOUT`] after its start.
//! - `call_index` numbers repeated calls from the same caller agent to the same callee within
//!   the trace (1, 2, 3, ... by start).
//! - Namespace scope and payload visibility apply: spans outside the caller's namespaces are
//!   left out, and only callers that see payloads get the root invocation's input as the title.
//!
//! The store keeps at most [`MAX_TRACES`] traces (the least recently updated go first); a
//! trace's records leave it when the ring evicts them.
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};

use crate::api::ids;
use crate::api::types::{
    AuditRecord, Segment, Span, SpanEvent, SpanStatus, TraceDoc, TraceSummary,
};
use crate::graph::callee_node;

/// How long a started span may run before it is shown as failed.
pub const SPAN_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// Traces kept.
pub const MAX_TRACES: usize = 10_000;
/// Span starts kept per trace.
const MAX_STARTS_PER_TRACE: usize = 5_000;
/// Traces evicted at once when [`MAX_TRACES`] is reached.
const EVICT_BATCH: usize = 100;
/// The kinds that are spans.
pub const SPAN_KINDS: [&str; 6] = [
    "agent_invocation",
    "agent_call",
    "service_call",
    "http_call",
    "model_call",
    "tool_call",
];
/// Title length for callers that see payloads.
const TITLE_CHARS: usize = 120;

/// A `SpanStart` as received, with the stream's identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartInfo {
    pub namespace: String,
    pub service: String,
    pub request_id: String,
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub kind: String,
    pub agent: Option<String>,
    pub caller: String,
    pub caller_agent: Option<String>,
    pub callee: String,
    pub direction: String,
    /// RFC 3339 start time.
    pub ts: String,
}

impl StartInfo {
    pub fn agent_node(&self) -> Option<String> {
        self.agent
            .as_deref()
            .map(|a| ids::agent(&self.namespace, &self.service, a))
    }

    pub fn callee_node(&self) -> Option<String> {
        callee_node(
            &self.kind,
            &self.namespace,
            &self.service,
            self.agent.as_deref(),
            &self.callee,
            &self.direction,
        )
    }
}

#[derive(Debug, Default)]
struct Trace {
    starts: HashMap<String, StartInfo>,
    records: Vec<Arc<AuditRecord>>,
    touched: u64,
}

#[derive(Debug, Default)]
struct Inner {
    traces: HashMap<String, Trace>,
    tick: u64,
}

/// What a caller may see.
pub struct Visibility<'a> {
    pub allows: &'a (dyn Fn(&str) -> bool + Send + Sync),
    pub payloads: bool,
}

/// `GET /traces` filters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TraceFilter {
    pub namespace: Option<String>,
    pub service: Option<String>,
    /// An agent name or agent node id.
    pub agent: Option<String>,
    pub status: Option<SpanStatus>,
}

/// The traces; see the module docs.
#[derive(Debug, Default)]
pub struct TraceStore {
    inner: Mutex<Inner>,
}

pub fn parse_ts(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

pub fn fmt_ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn segment(kind: &str) -> Segment {
    match kind {
        "model_call" => Segment::Thinking,
        "agent_call" => Segment::Waiting,
        "agent_invocation" => Segment::Invocation,
        _ => Segment::Tool,
    }
}

fn status_of(rec: &AuditRecord) -> SpanStatus {
    if rec.decision == "deny" {
        SpanStatus::Denied
    } else if rec.error.is_some() {
        SpanStatus::Error
    } else {
        SpanStatus::Ok
    }
}

/// The key `call_index` counts by: the same caller agent and the same callee.
fn call_key(
    kind: &str,
    agent_node: Option<&str>,
    caller: &str,
    caller_agent: Option<&str>,
    callee: &str,
) -> String {
    if kind == "agent_invocation" {
        format!(
            "inv|{caller}|{}|{}",
            caller_agent.unwrap_or(""),
            agent_node.unwrap_or("")
        )
    } else {
        format!("{kind}|{}|{callee}", agent_node.unwrap_or(""))
    }
}

fn attempt_of(rec: &AuditRecord) -> (u32, bool) {
    if rec.kind != "model_call" {
        return (1, false);
    }
    let attempt = rec
        .input
        .get("attempt")
        .and_then(serde_json::Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n >= 1)
        .unwrap_or(1);
    let fallback = rec
        .input
        .get("fallback")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    (attempt, fallback)
}

/// The text of an invocation's input: a string, or the `input` string of `{input, context}`.
fn input_text(input: &serde_json::Value) -> Option<String> {
    match input {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Null => None,
        v => match v.get("input") {
            Some(serde_json::Value::String(s)) => Some(s.clone()),
            _ => Some(v.to_string()),
        },
    }
}

/// A built span with the record it came from.
struct Built {
    span: Span,
    record: Option<Arc<AuditRecord>>,
    start: DateTime<Utc>,
}

fn build(
    trace: &Trace,
    allows: &(dyn Fn(&str) -> bool + Send + Sync),
    now: DateTime<Utc>,
) -> Vec<Built> {
    let mut by_span: BTreeMap<&str, &Arc<AuditRecord>> = BTreeMap::new();
    let mut events: HashMap<&str, Vec<&Arc<AuditRecord>>> = HashMap::new();
    for r in &trace.records {
        if r.span_id.is_empty() {
            continue;
        }
        if SPAN_KINDS.contains(&r.kind.as_str()) {
            by_span.insert(r.span_id.as_str(), r);
        } else {
            events.entry(r.span_id.as_str()).or_default().push(r);
        }
    }
    let mut ids: Vec<&str> = by_span.keys().copied().collect();
    for k in trace.starts.keys() {
        if !by_span.contains_key(k.as_str()) {
            ids.push(k.as_str());
        }
    }
    let timeout =
        chrono::Duration::from_std(SPAN_TIMEOUT).unwrap_or_else(|_| chrono::Duration::minutes(15));
    let mut out = Vec::new();
    for id in ids {
        let rec = by_span.get(id).copied();
        let start = trace.starts.get(id);
        let (ns, svc) = match (rec, start) {
            (Some(r), _) => (r.namespace.as_str(), r.service.as_str()),
            (None, Some(s)) => (s.namespace.as_str(), s.service.as_str()),
            (None, None) => continue,
        };
        if !allows(ns) {
            continue;
        }
        let span = match (rec, start) {
            (Some(r), s) => {
                let Some(end) = parse_ts(&r.ts) else { continue };
                let latency = i64::try_from(r.latency_ms).unwrap_or(i64::MAX);
                let begin = s
                    .and_then(|s| parse_ts(&s.ts))
                    .unwrap_or_else(|| end - chrono::Duration::milliseconds(latency));
                let (attempt, fallback) = attempt_of(r);
                let agent_node = r.agent.as_deref().map(|a| ids::agent(ns, svc, a));
                let mut evs: Vec<SpanEvent> = events
                    .get(id)
                    .map(|v| {
                        v.iter()
                            .map(|e| SpanEvent {
                                kind: e.kind.clone(),
                                rule: e.rule.clone(),
                                decision: e.decision.clone(),
                                ts: e.ts.clone(),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                evs.sort_by(|a, b| a.ts.cmp(&b.ts));
                Built {
                    start: begin,
                    record: Some(r.clone()),
                    span: Span {
                        span_id: id.to_string(),
                        parent_span_id: r.parent_span_id.clone(),
                        kind: r.kind.clone(),
                        callee_node: callee_node(
                            &r.kind,
                            ns,
                            svc,
                            r.agent.as_deref(),
                            &r.callee,
                            &r.direction,
                        ),
                        agent: agent_node,
                        namespace: ns.to_string(),
                        service: svc.to_string(),
                        callee: r.callee.clone(),
                        start: fmt_ts(begin),
                        end: Some(fmt_ts(end)),
                        latency_ms: Some(r.latency_ms),
                        status: status_of(r),
                        decision: Some(r.decision.clone()),
                        rule: r.rule.clone(),
                        request_id: r.request_id.clone(),
                        caller: r.caller.clone(),
                        caller_agent: r.caller_agent.clone(),
                        tokens_in: r.tokens.as_ref().map_or(0, |t| t.input),
                        tokens_out: r.tokens.as_ref().map_or(0, |t| t.output),
                        cost_usd: r
                            .cost_usd
                            .filter(|c| c.is_finite() && *c > 0.0)
                            .unwrap_or(0.0),
                        call_index: 0,
                        segment: segment(&r.kind),
                        attempt,
                        fallback,
                        events: evs,
                    },
                }
            }
            (None, Some(s)) => {
                let begin = parse_ts(&s.ts).unwrap_or(now);
                let timed_out = now - begin >= timeout;
                let mut evs: Vec<SpanEvent> = events
                    .get(id)
                    .map(|v| {
                        v.iter()
                            .map(|e| SpanEvent {
                                kind: e.kind.clone(),
                                rule: e.rule.clone(),
                                decision: e.decision.clone(),
                                ts: e.ts.clone(),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                evs.sort_by(|a, b| a.ts.cmp(&b.ts));
                Built {
                    start: begin,
                    record: None,
                    span: Span {
                        span_id: id.to_string(),
                        parent_span_id: s.parent_span_id.clone(),
                        kind: s.kind.clone(),
                        agent: s.agent_node(),
                        namespace: ns.to_string(),
                        service: svc.to_string(),
                        callee: s.callee.clone(),
                        callee_node: s.callee_node(),
                        start: fmt_ts(begin),
                        end: timed_out.then(|| fmt_ts(begin + timeout)),
                        latency_ms: timed_out.then(|| SPAN_TIMEOUT.as_millis() as u64),
                        status: if timed_out {
                            SpanStatus::Error
                        } else {
                            SpanStatus::Running
                        },
                        decision: None,
                        rule: timed_out.then(|| "span.timeout".to_string()),
                        request_id: s.request_id.clone(),
                        caller: s.caller.clone(),
                        caller_agent: s.caller_agent.clone(),
                        tokens_in: 0,
                        tokens_out: 0,
                        cost_usd: 0.0,
                        call_index: 0,
                        segment: segment(&s.kind),
                        attempt: 1,
                        fallback: false,
                        events: evs,
                    },
                }
            }
            (None, None) => continue,
        };
        out.push(span);
    }
    out.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| a.span.span_id.cmp(&b.span.span_id))
    });
    let mut counts: HashMap<String, u32> = HashMap::new();
    for b in &mut out {
        let s = &b.span;
        let key = call_key(
            &s.kind,
            s.agent.as_deref(),
            &s.caller,
            s.caller_agent.as_deref(),
            &s.callee,
        );
        let n = counts.entry(key).or_insert(0);
        *n += 1;
        b.span.call_index = *n;
    }
    out
}

fn summarize(trace_id: &str, built: &[Built], payloads: bool) -> Option<TraceSummary> {
    let ids: HashSet<&str> = built.iter().map(|b| b.span.span_id.as_str()).collect();
    let is_root = |b: &&Built| {
        b.span.kind == "agent_invocation"
            && b.span
                .parent_span_id
                .as_deref()
                .is_none_or(|p| !ids.contains(p))
    };
    let root = built
        .iter()
        .filter(is_root)
        .min_by_key(|b| b.start)
        .or_else(|| built.iter().min_by_key(|b| b.start))?;
    let started = built.iter().map(|b| b.start).min()?;
    let root_agent = root
        .span
        .agent
        .clone()
        .or_else(|| root.span.callee_node.clone())
        .unwrap_or_default();
    let agent_name = root_agent.rsplit('/').next().unwrap_or("").to_string();
    let short: String = trace_id.chars().take(8).collect();
    let fallback_title = format!("{agent_name} · {short}");
    let title = if payloads {
        root.record
            .as_ref()
            .filter(|r| r.kind == "agent_invocation")
            .and_then(|r| input_text(&r.input))
            .map(|t| t.chars().take(TITLE_CHARS).collect::<String>())
            .filter(|t| !t.trim().is_empty())
            .unwrap_or(fallback_title)
    } else {
        fallback_title
    };
    let ended = match root.span.status {
        SpanStatus::Running => None,
        _ => root.span.end.as_deref().and_then(parse_ts),
    };
    let count = |kind: &str| {
        u32::try_from(built.iter().filter(|b| b.span.kind == kind).count()).unwrap_or(u32::MAX)
    };
    let agents: HashSet<&str> = built
        .iter()
        .filter_map(|b| b.span.agent.as_deref())
        .collect();
    let models = built.iter().filter(|b| b.span.kind == "model_call");
    let (mut tin, mut tout, mut cost) = (0u64, 0u64, 0f64);
    for m in models {
        tin += m.span.tokens_in;
        tout += m.span.tokens_out;
        cost += m.span.cost_usd;
    }
    Some(TraceSummary {
        trace_id: trace_id.to_string(),
        title,
        root_agent,
        root_request_id: root.span.request_id.clone(),
        started_at: fmt_ts(started),
        ended_at: ended.map(fmt_ts),
        duration_ms: ended.map(|e| u64::try_from((e - started).num_milliseconds()).unwrap_or(0)),
        status: root.span.status,
        agents: u32::try_from(agents.len()).unwrap_or(u32::MAX),
        invocations: count("agent_invocation"),
        model_calls: count("model_call"),
        tool_calls: count("tool_call"),
        tokens_in: tin,
        tokens_out: tout,
        cost_usd: (cost * 1e6).round() / 1e6,
    })
}

impl TraceStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn touch<'a>(inner: &'a mut Inner, trace_id: &str) -> &'a mut Trace {
        inner.tick += 1;
        let tick = inner.tick;
        if !inner.traces.contains_key(trace_id) && inner.traces.len() >= MAX_TRACES {
            // the least recently updated go, a batch at a time
            let mut touched: Vec<u64> = inner.traces.values().map(|t| t.touched).collect();
            let n = EVICT_BATCH.min(touched.len().saturating_sub(1));
            let (_, cut, _) = touched.select_nth_unstable(n);
            let cut = *cut;
            inner.traces.retain(|_, t| t.touched > cut);
        }
        let t = inner.traces.entry(trace_id.to_string()).or_default();
        t.touched = tick;
        t
    }

    /// Keep a record (it is in the ring).
    pub fn add_record(&self, rec: Arc<AuditRecord>) {
        if rec.trace_id.is_empty() {
            return;
        }
        let mut inner = self.lock();
        let t = Self::touch(&mut inner, &rec.trace_id.clone());
        t.records.push(rec);
    }

    /// Keep a span start; returns its `call_index`.
    pub fn add_start(&self, start: StartInfo) -> u32 {
        if start.trace_id.is_empty() || start.span_id.is_empty() {
            return 1;
        }
        let mut inner = self.lock();
        let t = Self::touch(&mut inner, &start.trace_id.clone());
        let key = call_key(
            &start.kind,
            start.agent_node().as_deref(),
            &start.caller,
            start.caller_agent.as_deref(),
            &start.callee,
        );
        let mut seen: HashSet<&str> = HashSet::new();
        for r in &t.records {
            if SPAN_KINDS.contains(&r.kind.as_str()) && r.span_id != start.span_id {
                let agent = r
                    .agent
                    .as_deref()
                    .map(|a| ids::agent(&r.namespace, &r.service, a));
                if call_key(
                    &r.kind,
                    agent.as_deref(),
                    &r.caller,
                    r.caller_agent.as_deref(),
                    &r.callee,
                ) == key
                {
                    seen.insert(r.span_id.as_str());
                }
            }
        }
        for (id, s) in &t.starts {
            if *id != start.span_id
                && call_key(
                    &s.kind,
                    s.agent_node().as_deref(),
                    &s.caller,
                    s.caller_agent.as_deref(),
                    &s.callee,
                ) == key
            {
                seen.insert(id.as_str());
            }
        }
        let index = u32::try_from(seen.len()).unwrap_or(u32::MAX - 1) + 1;
        if t.starts.len() < MAX_STARTS_PER_TRACE || t.starts.contains_key(&start.span_id) {
            t.starts.insert(start.span_id.clone(), start);
        }
        index
    }

    /// Records the ring evicted leave their traces; empty traces go.
    pub fn forget(&self, evicted: &[Arc<AuditRecord>]) {
        if evicted.is_empty() {
            return;
        }
        let mut inner = self.lock();
        for rec in evicted {
            let Some(t) = inner.traces.get_mut(&rec.trace_id) else {
                continue;
            };
            t.records.retain(|r| !Arc::ptr_eq(r, rec));
            if t.records.is_empty() && t.starts.is_empty() {
                inner.traces.remove(&rec.trace_id);
            }
        }
    }

    /// Traces kept.
    pub fn len(&self) -> usize {
        self.lock().traces.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `GET /traces`: newest first.
    pub fn summaries(
        &self,
        vis: &Visibility<'_>,
        filter: &TraceFilter,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Vec<TraceSummary> {
        if let Some(ns) = &filter.namespace
            && !(vis.allows)(ns)
        {
            return Vec::new();
        }
        let inner = self.lock();
        let mut out: Vec<TraceSummary> = Vec::new();
        for (id, t) in &inner.traces {
            let built = build(t, vis.allows, now);
            if built.is_empty() {
                continue;
            }
            let spans: Vec<&Span> = built.iter().map(|b| &b.span).collect();
            if let Some(ns) = &filter.namespace
                && !spans.iter().any(|s| &s.namespace == ns)
            {
                continue;
            }
            if let Some(svc) = &filter.service
                && !spans.iter().any(|s| {
                    &s.service == svc
                        && filter
                            .namespace
                            .as_ref()
                            .is_none_or(|ns| &s.namespace == ns)
                })
            {
                continue;
            }
            if let Some(agent) = &filter.agent
                && !spans.iter().any(|s| {
                    s.agent
                        .as_deref()
                        .is_some_and(|a| a == agent || a.rsplit('/').next() == Some(agent.as_str()))
                })
            {
                continue;
            }
            let Some(summary) = summarize(id, &built, vis.payloads) else {
                continue;
            };
            if filter.status.is_some_and(|s| s != summary.status) {
                continue;
            }
            out.push(summary);
        }
        drop(inner);
        out.sort_by(|a, b| {
            b.started_at
                .cmp(&a.started_at)
                .then_with(|| b.trace_id.cmp(&a.trace_id))
        });
        out.truncate(limit);
        out
    }

    /// `GET /traces/{trace_id}`: `None` when no span is visible.
    pub fn trace(
        &self,
        trace_id: &str,
        vis: &Visibility<'_>,
        now: DateTime<Utc>,
    ) -> Option<TraceDoc> {
        let inner = self.lock();
        let t = inner.traces.get(trace_id)?;
        let built = build(t, vis.allows, now);
        if built.is_empty() {
            return None;
        }
        Some(TraceDoc {
            trace_id: trace_id.to_string(),
            spans: built.into_iter().map(|b| b.span).collect(),
        })
    }

    /// The summary of one trace (the SSE side uses it to tell new runs).
    pub fn summary(
        &self,
        trace_id: &str,
        vis: &Visibility<'_>,
        now: DateTime<Utc>,
    ) -> Option<TraceSummary> {
        let inner = self.lock();
        let t = inner.traces.get(trace_id)?;
        summarize(trace_id, &build(t, vis.allows, now), vis.payloads)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const T: &str = "6e2d9ff960031afca28de8fa28704004";

    fn rec(v: serde_json::Value) -> Arc<AuditRecord> {
        let mut base = json!({
            "ts": "2026-10-21T10:00:05.000Z", "kind": "model_call", "request_id": "q1",
            "trace_id": T, "span_id": "m1", "parent_span_id": "inv", "service": "orders",
            "namespace": "shop", "agent": "ops", "caller": "local", "caller_agent": null,
            "callee": "anthropic:claude-opus-5-5", "direction": "outbound", "decision": "allow",
            "latency_ms": 1000
        });
        if let (Some(b), Some(o)) = (base.as_object_mut(), v.as_object()) {
            for (k, x) in o {
                b.insert(k.clone(), x.clone());
            }
        }
        Arc::new(serde_json::from_value(base).unwrap())
    }

    fn start(span: &str, kind: &str, ts: &str, callee: &str, parent: Option<&str>) -> StartInfo {
        StartInfo {
            namespace: "shop".into(),
            service: "orders".into(),
            request_id: "q1".into(),
            trace_id: T.into(),
            span_id: span.into(),
            parent_span_id: parent.map(str::to_string),
            kind: kind.into(),
            agent: Some("ops".into()),
            caller: "local".into(),
            caller_agent: None,
            callee: callee.into(),
            direction: "outbound".into(),
            ts: ts.into(),
        }
    }

    fn all(_: &str) -> bool {
        true
    }

    fn now() -> DateTime<Utc> {
        "2026-10-21T10:00:20.000Z".parse().unwrap()
    }

    #[test]
    fn spans_from_span_starts_and_audit_records() {
        let store = TraceStore::default();
        // the invocation starts; an agent_call starts under its tool_call
        assert_eq!(
            store.add_start(start(
                "inv",
                "agent_invocation",
                "2026-10-21T10:00:00.000Z",
                "ops",
                None
            )),
            1
        );
        // model calls: two attempts, then the fallback
        store.add_record(rec(json!({"span_id": "m1", "ts": "2026-10-21T10:00:02.000Z", "latency_ms": 2000, "error": "overloaded", "input": {"attempt": 1}})));
        store.add_record(rec(json!({"span_id": "m2", "ts": "2026-10-21T10:00:04.000Z", "latency_ms": 1500, "input": {"attempt": 2}, "tokens": {"input": 100, "output": 7}, "cost_usd": 0.01})));
        store.add_record(rec(json!({"span_id": "m3", "ts": "2026-10-21T10:00:06.000Z", "latency_ms": 1000, "callee": "anthropic:claude-haiku-5-5", "input": {"attempt": 3, "fallback": true}, "tokens": {"input": 50, "output": 5}, "cost_usd": 0.002})));
        store.add_record(rec(json!({"kind": "tool_call", "span_id": "tc1", "callee": "stock_analyst", "direction": "internal", "ts": "2026-10-21T10:00:09.000Z", "latency_ms": 2500})));
        assert_eq!(
            store.add_start(start(
                "ac1",
                "agent_call",
                "2026-10-21T10:00:06.600Z",
                "inventory/stock-analyst",
                Some("tc1")
            )),
            1
        );
        // a guardrail record attaches to the invocation span
        store.add_record(rec(json!({"kind": "guardrail", "span_id": "inv", "rule": "guardrail.pii_redact", "ts": "2026-10-21T10:00:10.000Z", "direction": "internal"})));
        let vis = Visibility {
            allows: &all,
            payloads: true,
        };
        let doc = store.trace(T, &vis, now()).unwrap();
        let by: HashMap<&str, &Span> = doc.spans.iter().map(|s| (s.span_id.as_str(), s)).collect();
        // the running invocation and agent_call
        let inv = by["inv"];
        assert_eq!(
            (inv.status, inv.end.as_deref(), inv.segment),
            (SpanStatus::Running, None, Segment::Invocation)
        );
        assert_eq!(inv.events.len(), 1);
        assert_eq!(inv.events[0].rule.as_deref(), Some("guardrail.pii_redact"));
        assert_eq!(by["ac1"].segment, Segment::Waiting);
        assert_eq!(
            by["ac1"].callee_node.as_deref(),
            Some("agent:shop/inventory/stock-analyst")
        );
        // model calls: start = ts - latency; attempts, fallback, call_index
        let m1 = by["m1"];
        assert_eq!(m1.start, "2026-10-21T10:00:00.000Z");
        assert_eq!(
            (m1.status, m1.attempt, m1.fallback, m1.call_index),
            (SpanStatus::Error, 1, false, 1)
        );
        assert_eq!((by["m2"].attempt, by["m2"].call_index), (2, 2));
        let m3 = by["m3"];
        assert_eq!(
            (m3.attempt, m3.fallback, m3.call_index),
            (3, true, 1),
            "another model: index 1"
        );
        assert_eq!(m3.segment, Segment::Thinking);
        assert_eq!(m3.callee_node.as_deref(), Some("model:anthropic"));
        assert_eq!(by["tc1"].segment, Segment::Tool);
        // spans in start order
        let starts: Vec<&str> = doc.spans.iter().map(|s| s.start.as_str()).collect();
        let mut sorted = starts.clone();
        sorted.sort();
        assert_eq!(starts, sorted);

        // the invocation ends: start from the SpanStart, end from the record
        store.add_record(rec(json!({"kind": "agent_invocation", "span_id": "inv", "parent_span_id": null,
            "ts": "2026-10-21T10:00:12.000Z", "latency_ms": 11000, "direction": "inbound", "callee": "ops",
            "input": {"input": "How many WIDGET-1 are in stock?", "context": {}}, "tokens": {"input": 999, "output": 9}})));
        let doc = store.trace(T, &vis, now()).unwrap();
        let inv = doc.spans.iter().find(|s| s.span_id == "inv").unwrap();
        assert_eq!(inv.start, "2026-10-21T10:00:00.000Z");
        assert_eq!(inv.end.as_deref(), Some("2026-10-21T10:00:12.000Z"));
        assert_eq!(inv.status, SpanStatus::Ok);
        let sum = store.summary(T, &vis, now()).unwrap();
        assert_eq!(sum.title, "How many WIDGET-1 are in stock?");
        assert_eq!(sum.root_agent, "agent:shop/orders/ops");
        assert_eq!(sum.status, SpanStatus::Ok);
        assert_eq!(sum.duration_ms, Some(12_000));
        assert_eq!(
            (sum.invocations, sum.model_calls, sum.tool_calls, sum.agents),
            (1, 3, 1, 1)
        );
        assert_eq!(
            (sum.tokens_in, sum.tokens_out),
            (150, 12),
            "model calls only"
        );
        // without payloads: the agent and the short trace id
        let hidden = Visibility {
            allows: &all,
            payloads: false,
        };
        assert_eq!(
            store.summary(T, &hidden, now()).unwrap().title,
            "ops · 6e2d9ff9"
        );
        // namespace scope
        let none = |_: &str| false;
        let scoped = Visibility {
            allows: &none,
            payloads: true,
        };
        assert!(store.trace(T, &scoped, now()).is_none());
        assert!(
            store
                .summaries(&scoped, &TraceFilter::default(), 10, now())
                .is_empty()
        );
    }

    #[test]
    fn the_least_recently_updated_traces_go_first() {
        let store = TraceStore::default();
        let start_of = |i: usize| StartInfo {
            trace_id: format!("{i:032x}"),
            ..start(
                "aaaaaaaaaaaaaaaa",
                "agent_invocation",
                "2026-10-21T10:00:00.000Z",
                "ops",
                None,
            )
        };
        for i in 0..MAX_TRACES {
            store.add_start(start_of(i));
        }
        // trace 0 is updated again: it stays
        store.add_start(start_of(0));
        store.add_start(start_of(MAX_TRACES));
        assert!(store.len() <= MAX_TRACES);
        assert!(store.len() >= MAX_TRACES - EVICT_BATCH - 1);
        let vis = Visibility {
            allows: &all,
            payloads: true,
        };
        assert!(store.trace(&format!("{:032x}", 0), &vis, now()).is_some());
        assert!(
            store
                .trace(&format!("{:032x}", MAX_TRACES), &vis, now())
                .is_some()
        );
        assert!(store.trace(&format!("{:032x}", 1), &vis, now()).is_none());
    }

    #[test]
    fn running_spans_time_out_after_fifteen_minutes() {
        let store = TraceStore::default();
        store.add_start(start(
            "inv",
            "agent_invocation",
            "2026-10-21T10:00:00.000Z",
            "ops",
            None,
        ));
        let vis = Visibility {
            allows: &all,
            payloads: true,
        };
        let s = store.summaries(&vis, &TraceFilter::default(), 10, now());
        assert_eq!(s[0].status, SpanStatus::Running);
        assert_eq!(s[0].ended_at, None);
        let later: DateTime<Utc> = "2026-10-21T10:15:00.000Z".parse().unwrap();
        let doc = store.trace(T, &vis, later).unwrap();
        let inv = &doc.spans[0];
        assert_eq!(inv.status, SpanStatus::Error);
        assert_eq!(inv.rule.as_deref(), Some("span.timeout"));
        assert_eq!(inv.end.as_deref(), Some("2026-10-21T10:15:00.000Z"));
        assert_eq!(inv.latency_ms, Some(900_000));
        let sum = store.summary(T, &vis, later).unwrap();
        assert_eq!(sum.status, SpanStatus::Error);
    }

    #[test]
    fn filters_limits_and_eviction() {
        let store = TraceStore::default();
        for i in 0..3 {
            let t = format!("{i:032x}");
            store.add_record(Arc::new(serde_json::from_value(json!({
                "ts": format!("2026-10-21T10:00:0{i}.000Z"), "kind": "agent_invocation", "request_id": "q",
                "trace_id": t, "span_id": format!("s{i}"), "service": if i == 0 { "orders" } else { "support" },
                "namespace": "shop", "agent": "ops", "caller": "local", "callee": "ops", "direction": "inbound",
                "decision": if i == 2 { "deny" } else { "allow" }, "latency_ms": 10
            })).unwrap()));
        }
        let vis = Visibility {
            allows: &all,
            payloads: true,
        };
        let all3 = store.summaries(&vis, &TraceFilter::default(), 10, now());
        assert_eq!(all3.len(), 3);
        assert!(all3[0].started_at > all3[1].started_at, "newest first");
        assert_eq!(
            store
                .summaries(&vis, &TraceFilter::default(), 1, now())
                .len(),
            1
        );
        let f = TraceFilter {
            service: Some("support".into()),
            ..Default::default()
        };
        assert_eq!(store.summaries(&vis, &f, 10, now()).len(), 2);
        let f = TraceFilter {
            status: Some(SpanStatus::Denied),
            ..Default::default()
        };
        assert_eq!(store.summaries(&vis, &f, 10, now()).len(), 1);
        let f = TraceFilter {
            agent: Some("agent:shop/orders/ops".into()),
            ..Default::default()
        };
        assert_eq!(store.summaries(&vis, &f, 10, now()).len(), 1);
        let f = TraceFilter {
            agent: Some("ops".into()),
            ..Default::default()
        };
        assert_eq!(store.summaries(&vis, &f, 10, now()).len(), 3);
        let f = TraceFilter {
            agent: Some("other".into()),
            ..Default::default()
        };
        assert!(store.summaries(&vis, &f, 10, now()).is_empty());
        // the ring evicts a record: its trace goes
        let doc = store.trace(&format!("{:032x}", 0), &vis, now()).unwrap();
        assert_eq!(doc.spans.len(), 1);
        let inner_rec = {
            let inner = store.lock();
            inner.traces[&format!("{:032x}", 0)].records[0].clone()
        };
        store.forget(&[inner_rec]);
        assert_eq!(store.len(), 2);
    }
}
