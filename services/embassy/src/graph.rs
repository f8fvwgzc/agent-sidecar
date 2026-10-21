//! The node graph of `GET /graph` (design §10.1): nodes and declared edges from the stored
//! charters, instances from the registry, stats from the audit records over a sliding 15 minutes
//! in one-minute buckets, undeclared edges from traffic (at most 200 per service, oldest
//! evicted), and the graph `version`, which increases whenever topology or stats change.
//!
//! **Record → edge mapping** ([`map_record`]; one animating record per hop):
//!
//! | Record | Animates | Stats |
//! | --- | --- | --- |
//! | `agent_invocation`, caller `local`, no `caller_agent` | `invoke` edge app→agent | agent node + edge |
//! | `agent_invocation`, caller `local`, with `caller_agent` | nothing | agent node |
//! | `agent_invocation`, caller a peer | nothing | agent node |
//! | `agent_call` (caller side) | tool edge agent→agent `#<tool>` | edge |
//! | `service_call` outbound or internal | tool edge agent→app `#<tool>` | edge |
//! | `service_call` inbound (callee side) | nothing | callee app node |
//! | `http_call` | tool edge agent→external `#<tool>` | edge |
//! | `model_call` | `model` edge agent→provider (provider from the callee) | edge |
//! | `tool_call`, `guardrail`, `budget`, `authz`, `config`, `learning`, `load_skill` | nothing | node counters only |
//!
//! The `#<tool>` of an `agent_call`, `service_call` or `http_call` is the `callee` of the
//! `tool_call` whose `span_id` is the record's `parent_span_id` (the sidecar writes that
//! `tool_call` first).
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use attache_charter::{Charter, LOCAL_IDENTITY, ToolType as CharterToolType};
use chrono::{DateTime, Utc};
use tokio::sync::Notify;

use crate::api::ids;
use crate::api::types::{
    AgentNode, AgentStats, AgentStatus, AgentType, AppNode, AppStats, AuditRecord, Disconnected,
    Edge, EdgeKind, EdgeStats, ExternalNode, Graph, LearningMode, LearningSummary,
    ModelProviderNode, Node, PlaceholderNode, PlaceholderType, Ports, ServiceNode, ServiceStatus,
    ToolRef, ToolType, True,
};
use crate::registry::{Connected, Registry};
use crate::store::{ProposalFilter, ProposalStatus, ServiceKey, Store, StoreError, StoredCharter};

/// The stats window, in one-minute buckets.
pub const WINDOW_MINUTES: i64 = 15;
/// Undeclared edges kept per service.
pub const MAX_UNDECLARED_PER_SERVICE: usize = 200;
/// `tool_call` span ids remembered to name the tool of the call records that follow.
const MAX_TOOL_SPANS: usize = 100_000;
/// Latencies kept per agent and minute (for p50/p95).
const MAX_LATENCIES: usize = 10_000;

// ---- node ids of record targets ---------------------------------------------------------------

/// The agent an `agent_call` reaches: `callee` is `<service>/<agent>` or a local `<agent>`.
pub fn agent_call_target(namespace: &str, own_service: &str, callee: &str) -> Option<String> {
    let (svc, agent) = match callee.rsplit_once('/') {
        Some((s, a)) if !s.is_empty() => (s, a),
        Some((_, a)) => (own_service, a),
        None => (own_service, callee),
    };
    (!agent.is_empty()).then(|| ids::agent(namespace, svc, agent))
}

/// The app a `service_call` reaches: `callee` is `<service> <METHOD> <path>`.
pub fn service_call_target(namespace: &str, callee: &str) -> Option<String> {
    let svc = callee.split_whitespace().next()?;
    Some(ids::app(namespace, svc))
}

/// `scheme://host[:port]` of a URL (default ports left out), http and https only.
pub fn origin_of(url: &str) -> Option<String> {
    let u = url::Url::parse(url).ok()?;
    if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none() {
        return None;
    }
    Some(u.origin().ascii_serialization())
}

/// The external node an `http_call` reaches: `callee` is `<METHOD> <url>` (or the URL).
pub fn http_call_target(callee: &str) -> Option<String> {
    let url = callee.split_whitespace().last()?;
    origin_of(url).map(|o| ids::external(&o))
}

/// The node a span reaches (design §10.1.1 `callee_node`).
pub fn callee_node(
    rec_kind: &str,
    namespace: &str,
    service: &str,
    agent: Option<&str>,
    callee: &str,
    direction: &str,
) -> Option<String> {
    match rec_kind {
        "agent_invocation" => agent.map(|a| ids::agent(namespace, service, a)),
        "agent_call" => agent_call_target(namespace, service, callee),
        "service_call" if direction == "inbound" => Some(ids::app(namespace, service)),
        "service_call" => service_call_target(namespace, callee),
        "http_call" => http_call_target(callee),
        "model_call" => Some(ids::model_for_callee(callee).to_string()),
        _ => None,
    }
}

/// An edge a record maps to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeRef {
    pub id: String,
    pub kind: EdgeKind,
    pub source: String,
    pub source_port: String,
    pub target: String,
    pub target_port: String,
}

impl EdgeRef {
    fn new(
        kind: EdgeKind,
        source: String,
        source_port: &str,
        target: String,
        target_port: &str,
        tool: Option<&str>,
    ) -> Self {
        Self {
            id: ids::edge(kind, &source, &target, tool),
            kind,
            source,
            source_port: source_port.to_string(),
            target,
            target_port: target_port.to_string(),
        }
    }
}

/// The edge a record animates (design §10.1 mapping). `tool` is the name of the tool whose
/// `tool_call` is the record's parent.
pub fn map_record(rec: &AuditRecord, tool: Option<&str>) -> Option<EdgeRef> {
    let agent = rec.agent.as_deref()?;
    let (ns, svc) = (rec.namespace.as_str(), rec.service.as_str());
    let me = ids::agent(ns, svc, agent);
    match rec.kind.as_str() {
        "agent_invocation" => {
            (rec.caller == LOCAL_IDENTITY && rec.caller_agent.is_none()).then(|| {
                EdgeRef::new(
                    EdgeKind::Invoke,
                    ids::app(ns, svc),
                    "invoke",
                    me,
                    "invoke",
                    None,
                )
            })
        }
        "model_call" => Some(EdgeRef::new(
            EdgeKind::Model,
            me,
            "model",
            ids::model_for_callee(&rec.callee).to_string(),
            "model",
            None,
        )),
        "agent_call" => {
            let tool = tool?;
            let target = agent_call_target(ns, svc, &rec.callee)?;
            Some(EdgeRef::new(
                EdgeKind::Tool,
                me,
                tool,
                target,
                "invoke",
                Some(tool),
            ))
        }
        "service_call" if rec.direction != "inbound" => {
            let tool = tool?;
            let target = service_call_target(ns, &rec.callee)?;
            Some(EdgeRef::new(
                EdgeKind::Tool,
                me,
                tool,
                target,
                "service",
                Some(tool),
            ))
        }
        "http_call" => {
            let tool = tool?;
            let target = http_call_target(&rec.callee)?;
            Some(EdgeRef::new(
                EdgeKind::Tool,
                me,
                tool,
                target,
                "http",
                Some(tool),
            ))
        }
        _ => None,
    }
}

// ---- stats windows ---------------------------------------------------------------------------

/// The minute (unix minutes) of a record's `ts`; `now` when it does not parse or is ahead.
pub fn minute_of(ts: &str, now: DateTime<Utc>) -> i64 {
    let now_min = now.timestamp().div_euclid(60);
    DateTime::parse_from_rfc3339(ts)
        .map(|t| t.timestamp().div_euclid(60).min(now_min))
        .unwrap_or(now_min)
}

#[derive(Debug, Clone)]
struct Window<T> {
    slots: Vec<(i64, T)>,
}

impl<T: Default> Default for Window<T> {
    fn default() -> Self {
        Self {
            slots: (0..WINDOW_MINUTES)
                .map(|_| (i64::MIN, T::default()))
                .collect(),
        }
    }
}

impl<T: Default> Window<T> {
    /// Add to minute `m` (ignored when it is outside the window ending at `now_min`).
    fn add(&mut self, m: i64, now_min: i64, f: impl FnOnce(&mut T)) -> bool {
        if m <= now_min - WINDOW_MINUTES || m > now_min {
            return false;
        }
        let idx = usize::try_from(m.rem_euclid(WINDOW_MINUTES)).unwrap_or(0);
        let Some(slot) = self.slots.get_mut(idx) else {
            return false;
        };
        if slot.0 != m {
            *slot = (m, T::default());
        }
        f(&mut slot.1);
        true
    }

    fn live(&self, now_min: i64) -> impl Iterator<Item = &T> {
        self.slots
            .iter()
            .filter(move |(m, _)| *m > now_min - WINDOW_MINUTES && *m <= now_min)
            .map(|(_, t)| t)
    }

    fn any_live(&self, now_min: i64) -> bool {
        self.live(now_min).next().is_some()
    }
}

#[derive(Debug, Clone, Default)]
struct AgentBucket {
    invocations: u64,
    denied: u64,
    errors: u64,
    latencies: Vec<u64>,
    tokens_in: u64,
    tokens_out: u64,
    cost_usd: f64,
}

#[derive(Debug, Clone, Default)]
struct CallBucket {
    calls: u64,
    denied: u64,
    errors: u64,
    sum_ms: u64,
}

#[derive(Debug, Default)]
struct EdgeEntry {
    window: Window<CallBucket>,
    last_ts: Option<String>,
}

#[derive(Debug, Default)]
struct StatsInner {
    agents: HashMap<String, Window<AgentBucket>>,
    edges: HashMap<String, EdgeEntry>,
    apps: HashMap<String, Window<CallBucket>>,
    declared: HashSet<String>,
    /// Per service (of the record), oldest first.
    undeclared: BTreeMap<ServiceKey, VecDeque<EdgeRef>>,
    tool_spans: HashMap<(String, String, String), String>,
    tool_order: VecDeque<(String, String, String)>,
    /// The newest minute that holds stats (for the rollover bump).
    newest_minute: i64,
}

/// What [`GraphState::observe`] found for one record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// The edge the record animates (`audit` event `edge_id`), if any.
    pub edge_id: Option<String>,
    /// A new undeclared edge (topology changed).
    pub new_edge: bool,
}

/// Stats, undeclared edges and the graph version; see the module docs.
#[derive(Debug)]
pub struct GraphState {
    inner: Mutex<StatsInner>,
    version: AtomicU64,
    /// Woken on every version change (the `graph` SSE throttle waits on it).
    pub changed: Notify,
}

impl Default for GraphState {
    fn default() -> Self {
        Self {
            inner: Mutex::new(StatsInner {
                newest_minute: i64::MIN,
                ..Default::default()
            }),
            version: AtomicU64::new(1),
            changed: Notify::new(),
        }
    }
}

fn is_error(rec: &AuditRecord) -> bool {
    rec.error.is_some()
}

fn is_denied(rec: &AuditRecord) -> bool {
    rec.decision == "deny"
}

impl GraphState {
    fn lock(&self) -> std::sync::MutexGuard<'_, StatsInner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The current graph version.
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }

    /// Topology or stats changed: a new version.
    pub fn bump(&self) -> u64 {
        let v = self.version.fetch_add(1, Ordering::SeqCst) + 1;
        self.changed.notify_one();
        v
    }

    /// The edges the stored charters declare (recomputed on every charter change).
    pub fn set_declared(&self, declared: HashSet<String>) {
        self.lock().declared = declared;
    }

    /// Account one audit record; see the module docs.
    pub fn observe(&self, rec: &AuditRecord, now: DateTime<Utc>) -> Observation {
        let now_min = now.timestamp().div_euclid(60);
        let minute = minute_of(&rec.ts, now);
        let mut inner = self.lock();
        let (ns, svc) = (rec.namespace.clone(), rec.service.clone());
        if rec.kind == "tool_call" && !rec.span_id.is_empty() {
            let key = (ns.clone(), svc.clone(), rec.span_id.clone());
            if inner
                .tool_spans
                .insert(key.clone(), rec.callee.clone())
                .is_none()
            {
                inner.tool_order.push_back(key);
            }
            while inner.tool_order.len() > MAX_TOOL_SPANS {
                if let Some(old) = inner.tool_order.pop_front() {
                    inner.tool_spans.remove(&old);
                }
            }
        }
        let tool = rec
            .parent_span_id
            .as_ref()
            .and_then(|p| inner.tool_spans.get(&(ns.clone(), svc.clone(), p.clone())))
            .cloned();
        let edge = map_record(rec, tool.as_deref());
        let mut changed = false;
        let agent_id = rec.agent.as_deref().map(|a| ids::agent(&ns, &svc, a));
        match (rec.kind.as_str(), &agent_id) {
            ("agent_invocation", Some(id)) => {
                changed |= inner
                    .agents
                    .entry(id.clone())
                    .or_default()
                    .add(minute, now_min, |b| {
                        b.invocations += 1;
                        if b.latencies.len() < MAX_LATENCIES {
                            b.latencies.push(rec.latency_ms);
                        }
                        b.denied += u64::from(is_denied(rec));
                        b.errors += u64::from(is_error(rec));
                    });
            }
            ("tool_call", Some(id)) if is_denied(rec) || is_error(rec) => {
                changed |= inner
                    .agents
                    .entry(id.clone())
                    .or_default()
                    .add(minute, now_min, |b| {
                        b.denied += u64::from(is_denied(rec));
                        b.errors += u64::from(is_error(rec));
                    });
            }
            ("model_call", Some(id)) => {
                changed |= inner
                    .agents
                    .entry(id.clone())
                    .or_default()
                    .add(minute, now_min, |b| {
                        if let Some(t) = &rec.tokens {
                            b.tokens_in += t.input;
                            b.tokens_out += t.output;
                        }
                        b.cost_usd += rec
                            .cost_usd
                            .filter(|c| c.is_finite() && *c > 0.0)
                            .unwrap_or(0.0);
                    });
            }
            ("service_call", _) if rec.direction == "inbound" => {
                let app = ids::app(&ns, &svc);
                changed |= inner
                    .apps
                    .entry(app)
                    .or_default()
                    .add(minute, now_min, |b| {
                        b.calls += 1;
                        b.denied += u64::from(is_denied(rec));
                        b.errors += u64::from(is_error(rec));
                        b.sum_ms = b.sum_ms.saturating_add(rec.latency_ms);
                    });
            }
            _ => {}
        }
        let mut new_edge = false;
        if let Some(e) = &edge {
            let entry = inner.edges.entry(e.id.clone()).or_default();
            changed |= entry.window.add(minute, now_min, |b| {
                b.calls += 1;
                b.denied += u64::from(is_denied(rec));
                b.errors += u64::from(is_error(rec));
                b.sum_ms = b.sum_ms.saturating_add(rec.latency_ms);
            });
            if entry.last_ts.as_deref().is_none_or(|l| rec.ts.as_str() > l) {
                entry.last_ts = Some(rec.ts.clone());
                changed = true;
            }
            let key = ServiceKey::new(&ns, &svc);
            let known = inner.declared.contains(&e.id)
                || inner
                    .undeclared
                    .get(&key)
                    .is_some_and(|l| l.iter().any(|u| u.id == e.id));
            if !known {
                let list = inner.undeclared.entry(key).or_default();
                list.push_back(e.clone());
                while list.len() > MAX_UNDECLARED_PER_SERVICE {
                    list.pop_front();
                }
                new_edge = true;
            }
        }
        if changed {
            inner.newest_minute = inner.newest_minute.max(minute);
        }
        drop(inner);
        if changed || new_edge {
            self.bump();
        }
        Observation {
            edge_id: edge.map(|e| e.id),
            new_edge,
        }
    }

    /// Called every minute: a new version when stats left the window (the newest stats are at
    /// most [`WINDOW_MINUTES`] old).
    pub fn tick(&self, now: DateTime<Utc>) -> bool {
        let now_min = now.timestamp().div_euclid(60);
        let mut inner = self.lock();
        let newest = inner.newest_minute;
        let live = newest != i64::MIN && newest > now_min - WINDOW_MINUTES - 1;
        // forget what left the window, except the last use of declared and undeclared edges
        inner.agents.retain(|_, w| w.any_live(now_min));
        inner.apps.retain(|_, w| w.any_live(now_min));
        let kept: HashSet<String> = inner
            .undeclared
            .values()
            .flatten()
            .map(|e| e.id.clone())
            .chain(inner.declared.iter().cloned())
            .collect();
        inner
            .edges
            .retain(|id, e| e.window.any_live(now_min) || kept.contains(id));
        drop(inner);
        if live {
            self.bump();
        }
        live
    }

    /// Stats entries held (agents, apps, edges), for tests.
    pub fn entries(&self) -> (usize, usize, usize) {
        let inner = self.lock();
        (inner.agents.len(), inner.apps.len(), inner.edges.len())
    }

    fn agent_stats(&self, inner: &StatsInner, id: &str, now_min: i64) -> AgentStats {
        let Some(w) = inner.agents.get(id) else {
            return AgentStats::default();
        };
        let mut s = AgentStats::default();
        let mut lat: Vec<u64> = Vec::new();
        for b in w.live(now_min) {
            s.invocations += b.invocations;
            s.denied += b.denied;
            s.errors += b.errors;
            s.tokens_in += b.tokens_in;
            s.tokens_out += b.tokens_out;
            s.cost_usd += b.cost_usd;
            lat.extend_from_slice(&b.latencies);
        }
        s.cost_usd = (s.cost_usd * 1e6).round() / 1e6;
        lat.sort_unstable();
        s.p50_ms = percentile(&lat, 50);
        s.p95_ms = percentile(&lat, 95);
        s
    }

    fn call_stats(w: &Window<CallBucket>, now_min: i64) -> (u64, u64, u64, u64) {
        let (mut c, mut d, mut e, mut ms) = (0u64, 0u64, 0u64, 0u64);
        for b in w.live(now_min) {
            c += b.calls;
            d += b.denied;
            e += b.errors;
            ms = ms.saturating_add(b.sum_ms);
        }
        (c, d, e, ms.checked_div(c).unwrap_or(0))
    }

    fn edge_stats(&self, inner: &StatsInner, id: &str, now_min: i64) -> EdgeStats {
        let Some(e) = inner.edges.get(id) else {
            return EdgeStats::default();
        };
        let (calls, denied, errors, avg_ms) = Self::call_stats(&e.window, now_min);
        EdgeStats {
            calls,
            denied,
            errors,
            avg_ms,
            last_ts: e.last_ts.clone(),
        }
    }

    fn app_stats(&self, inner: &StatsInner, id: &str, now_min: i64) -> AppStats {
        let Some(w) = inner.apps.get(id) else {
            return AppStats::default();
        };
        let (calls, denied, errors, avg_ms) = Self::call_stats(w, now_min);
        AppStats {
            calls,
            denied,
            errors,
            avg_ms,
        }
    }

    /// Whether any stats are inside the window (tests).
    pub fn has_live_stats(&self, now: DateTime<Utc>) -> bool {
        let now_min = now.timestamp().div_euclid(60);
        let inner = self.lock();
        inner.agents.values().any(|w| w.any_live(now_min))
            || inner.edges.values().any(|e| e.window.any_live(now_min))
            || inner.apps.values().any(|w| w.any_live(now_min))
    }
}

/// Nearest-rank percentile of sorted values.
fn percentile(sorted: &[u64], p: u64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let n = sorted.len() as u64;
    let rank = (p * n).div_ceil(100).max(1);
    sorted
        .get(usize::try_from(rank - 1).unwrap_or(0))
        .copied()
        .unwrap_or(0)
}

fn agent_status(s: &AgentStats) -> AgentStatus {
    if s.errors > 0 {
        AgentStatus::Errors
    } else if s.denied > 0 {
        AgentStatus::Denied
    } else if s.invocations > 0 {
        AgentStatus::Ok
    } else {
        AgentStatus::Idle
    }
}

/// The status of a service (OpenAPI `ServiceStatus`).
pub fn service_status(stored_version: Option<&str>, instances: &[Connected]) -> ServiceStatus {
    match (stored_version, instances.is_empty()) {
        (None, _) => ServiceStatus::NoCharter,
        (Some(_), true) => ServiceStatus::Disconnected,
        (Some(v), false) => {
            let lagging = instances.iter().any(|i| {
                i.info.ack_error.is_some()
                    || i.info.acked_version.as_deref() != Some(v)
                    || !i.info.runtime_ready
            });
            if lagging {
                ServiceStatus::Degraded
            } else {
                ServiceStatus::Connected
            }
        }
    }
}

/// Whether the `identity: local` caller rules admit `agent`.
fn admitted_locally(c: &Charter, agent: &str) -> bool {
    c.authz
        .callers
        .iter()
        .any(|r| r.identity == LOCAL_IDENTITY && r.agents.iter().any(|a| a == "*" || a == agent))
}

/// The node a declared tool reaches (design §10.1).
pub fn tool_target(
    namespace: &str,
    service: &str,
    t: &attache_charter::ToolSpec,
) -> Option<String> {
    match t.tool_type {
        CharterToolType::Agent => Some(ids::agent(
            namespace,
            t.service.as_deref().unwrap_or(service),
            t.agent.as_deref()?,
        )),
        CharterToolType::Service => Some(ids::app(namespace, t.service.as_deref()?)),
        CharterToolType::Http => t
            .url
            .as_deref()
            .and_then(attache_charter::http_origin)
            .map(|o| ids::external(&o)),
    }
}

fn tool_type(t: CharterToolType) -> ToolType {
    match t {
        CharterToolType::Agent => ToolType::Agent,
        CharterToolType::Service => ToolType::Service,
        CharterToolType::Http => ToolType::Http,
    }
}

fn tool_port(t: CharterToolType) -> &'static str {
    match t {
        CharterToolType::Agent => "invoke",
        CharterToolType::Service => "service",
        CharterToolType::Http => "http",
    }
}

/// The declared edges of one stored charter.
pub fn declared_edges(key: &ServiceKey, c: &Charter) -> Vec<EdgeRef> {
    let (ns, svc) = (key.namespace.as_str(), key.service.as_str());
    let mut out = Vec::new();
    for a in &c.agents {
        let me = ids::agent(ns, svc, &a.name);
        if admitted_locally(c, &a.name) {
            out.push(EdgeRef::new(
                EdgeKind::Invoke,
                ids::app(ns, svc),
                "invoke",
                me.clone(),
                "invoke",
                None,
            ));
        }
        for t in &a.tools {
            if let Some(target) = tool_target(ns, svc, t) {
                out.push(EdgeRef::new(
                    EdgeKind::Tool,
                    me.clone(),
                    &t.name,
                    target,
                    tool_port(t.tool_type),
                    Some(&t.name),
                ));
            }
        }
        out.push(EdgeRef::new(
            EdgeKind::Model,
            me.clone(),
            "model",
            ids::model_for_agent_model(&a.model).to_string(),
            "model",
            None,
        ));
    }
    out
}

/// A stored charter, parsed (`None` when it no longer validates).
pub fn parse_stored(c: &StoredCharter) -> Option<Charter> {
    Charter::from_yaml(&c.yaml).ok()
}

/// Every declared edge id of every stored charter.
pub async fn all_declared(store: &dyn Store) -> HashSet<String> {
    let mut out = HashSet::new();
    let Ok(keys) = store.list_services().await else {
        return out;
    };
    for key in keys {
        if let Ok(stored) = store.get_charter(&key).await
            && let Some(c) = parse_stored(&stored)
        {
            out.extend(declared_edges(&key, &c).into_iter().map(|e| e.id));
        }
    }
    out
}

fn ports(inputs: &[&str], outputs: &[&str]) -> Ports {
    Ports {
        inputs: inputs.iter().map(|s| s.to_string()).collect(),
        outputs: outputs.iter().map(|s| s.to_string()).collect(),
    }
}

/// Splits `agent:<ns>/<svc>/<agent>` / `app:<ns>/<svc>` into parts.
fn split_node(id: &str) -> Option<(&str, Vec<&str>)> {
    let (kind, rest) = id.split_once(':')?;
    Some((kind, rest.split('/').collect()))
}

/// Builds a [`Graph`]; see [`build`].
struct Builder {
    nodes: Vec<Node>,
    index: HashMap<String, usize>,
}

impl Builder {
    fn has(&self, id: &str) -> bool {
        self.index.contains_key(id)
    }

    fn push(&mut self, n: Node) {
        if !self.has(n.id()) {
            self.index.insert(n.id().to_string(), self.nodes.len());
            self.nodes.push(n);
        }
    }

    /// Make sure `id` is a node: providers, externals, or placeholders for unknown peers.
    fn ensure(&mut self, id: &str, target_port: &str) {
        if let Some(&i) = self.index.get(id) {
            // a real app reached by an undeclared service edge gets the input port
            if let Some(Node::App(a)) = self.nodes.get_mut(i)
                && !target_port.is_empty()
                && !a.ports.inputs.iter().any(|p| p == target_port)
            {
                a.ports.inputs.push(target_port.to_string());
            }
            return;
        }
        if id == ids::MODEL_ANTHROPIC || id == ids::MODEL_MOCK {
            self.push(Node::ModelProvider(ModelProviderNode {
                id: id.to_string(),
                label: if id == ids::MODEL_MOCK {
                    "Mock"
                } else {
                    "Anthropic"
                }
                .into(),
                ports: ports(&["model"], &[]),
            }));
            return;
        }
        if let Some(origin) = id.strip_prefix("external:") {
            let label = origin
                .split_once("://")
                .map_or(origin, |(_, h)| h)
                .to_string();
            self.push(Node::External(ExternalNode {
                id: id.to_string(),
                label,
                ports: ports(&["http"], &[]),
            }));
            return;
        }
        let Some((kind, parts)) = split_node(id) else {
            return;
        };
        let (ns, svc) = match parts.as_slice() {
            [ns, svc, ..] => (*ns, *svc),
            _ => return,
        };
        let svc_id = ids::service(ns, svc);
        if !self.has(&svc_id) {
            self.push(Node::Placeholder(PlaceholderNode {
                id: svc_id.clone(),
                node_type: PlaceholderType::Service,
                parent: None,
                label: svc.to_string(),
                placeholder: True,
                status: Disconnected::Disconnected,
                ports: ports(&[], &[]),
            }));
        }
        match (kind, parts.as_slice()) {
            ("agent", [_, _, agent]) => self.push(Node::Placeholder(PlaceholderNode {
                id: id.to_string(),
                node_type: PlaceholderType::Agent,
                parent: Some(svc_id),
                label: agent.to_string(),
                placeholder: True,
                status: Disconnected::Disconnected,
                ports: ports(&["invoke"], &[]),
            })),
            ("app", [_, _]) => self.push(Node::Placeholder(PlaceholderNode {
                id: id.to_string(),
                node_type: PlaceholderType::App,
                parent: Some(svc_id),
                label: format!("{svc} app"),
                placeholder: True,
                status: Disconnected::Disconnected,
                ports: ports(
                    &[if target_port.is_empty() {
                        "service"
                    } else {
                        target_port
                    }],
                    &["invoke"],
                ),
            })),
            _ => {}
        }
    }
}

/// Everything [`build`] reads about one service.
struct ServiceData {
    key: ServiceKey,
    stored: Option<StoredCharter>,
    charter: Option<Charter>,
    instances: Vec<Connected>,
    notes: BTreeMap<String, usize>,
}

/// The graph as the caller may see it: services in the namespaces `allows` admits.
pub async fn build(
    store: &dyn Store,
    registry: &Registry,
    state: &GraphState,
    allows: &(dyn Fn(&str) -> bool + Send + Sync),
    now: DateTime<Utc>,
) -> Result<Graph, StoreError> {
    let version = state.version();
    let mut keys: BTreeSet<ServiceKey> = store.list_services().await?.into_iter().collect();
    keys.extend(registry.services());
    keys.retain(|k| allows(&k.namespace));
    let pending: Vec<_> = store
        .list_proposals(&ProposalFilter {
            status: Some(ProposalStatus::Pending),
            ..Default::default()
        })
        .await?;
    let mut data = Vec::new();
    for key in keys {
        let stored = match store.get_charter(&key).await {
            Ok(c) => Some(c),
            Err(StoreError::NotFound) => None,
            Err(e) => return Err(e),
        };
        let charter = stored.as_ref().and_then(parse_stored);
        let notes = match &stored {
            Some(_) => store
                .get_memory(&key)
                .await?
                .agents
                .iter()
                .map(|(a, n)| (a.clone(), n.len()))
                .collect(),
            None => BTreeMap::new(),
        };
        data.push(ServiceData {
            instances: registry.instances(&key),
            key,
            stored,
            charter,
            notes,
        });
    }

    let now_min = now.timestamp().div_euclid(60);
    let inner = state.lock();
    let mut b = Builder {
        nodes: Vec::new(),
        index: HashMap::new(),
    };
    let mut edges: Vec<(EdgeRef, bool)> = Vec::new();
    let mut declared_ids = HashSet::new();
    for d in &data {
        let (ns, svc) = (d.key.namespace.as_str(), d.key.service.as_str());
        b.push(Node::Service(ServiceNode {
            id: ids::service(ns, svc),
            label: svc.to_string(),
            namespace: ns.to_string(),
            service: svc.to_string(),
            status: service_status(d.stored.as_ref().map(|c| c.version.as_str()), &d.instances),
            instances: u32::try_from(d.instances.len()).unwrap_or(u32::MAX),
            charter_version: d.stored.as_ref().map(|c| c.version.clone()),
        }));
        let app_id = ids::app(ns, svc);
        let port = d
            .charter
            .as_ref()
            .map(|c| c.service.app_port)
            .or_else(|| registry.app_port(&d.key));
        b.push(Node::App(AppNode {
            id: app_id.clone(),
            parent: ids::service(ns, svc),
            label: format!("{svc} app"),
            port,
            ports: ports(&[], &["invoke"]),
            stats: state.app_stats(&inner, &app_id, now_min),
        }));
        let Some(c) = &d.charter else { continue };
        let allowed_tools = |a: &attache_charter::AgentSpec| c.allowed_tools(a);
        for a in &c.agents {
            let id = ids::agent(ns, svc, &a.name);
            let stats = state.agent_stats(&inner, &id, now_min);
            let allowed = allowed_tools(a);
            let tools: Vec<ToolRef> = a
                .tools
                .iter()
                .filter_map(|t| {
                    Some(ToolRef {
                        name: t.name.clone(),
                        tool_type: tool_type(t.tool_type),
                        target: tool_target(ns, svc, t)?,
                        allowed: allowed.iter().any(|x| x == &t.name),
                    })
                })
                .collect();
            let mut out: Vec<String> = a.tools.iter().map(|t| t.name.clone()).collect();
            out.push("model".into());
            let learning = a.learning_or_default();
            let pending_n = pending
                .iter()
                .filter(|p| p.namespace == ns && p.service == svc && p.agent == a.name)
                .count();
            b.push(Node::Agent(AgentNode {
                id: id.clone(),
                parent: ids::service(ns, svc),
                label: a.name.clone(),
                agent_type: match a.agent_type {
                    attache_charter::AgentType::Agent => AgentType::Agent,
                    attache_charter::AgentType::Orchestrator => AgentType::Orchestrator,
                },
                model: a.model.clone(),
                skills: a.skills.clone(),
                status: agent_status(&stats),
                ports: Ports {
                    inputs: vec!["invoke".into()],
                    outputs: out,
                },
                tools,
                learning: LearningSummary {
                    enabled: learning.enabled,
                    mode: match learning.mode {
                        attache_charter::LearningMode::Review => LearningMode::Review,
                        attache_charter::LearningMode::Auto => LearningMode::Auto,
                    },
                    notes: if learning.enabled {
                        u32::try_from(d.notes.get(&a.name).copied().unwrap_or(0))
                            .unwrap_or(u32::MAX)
                    } else {
                        0
                    },
                    pending: u32::try_from(pending_n).unwrap_or(u32::MAX),
                },
                stats,
            }));
        }
        for e in declared_edges(&d.key, c) {
            declared_ids.insert(e.id.clone());
            edges.push((e, true));
        }
    }
    // undeclared edges of the services in scope
    for d in &data {
        if let Some(list) = inner.undeclared.get(&d.key) {
            for e in list {
                if !declared_ids.contains(&e.id) && !edges.iter().any(|(x, _)| x.id == e.id) {
                    edges.push((e.clone(), false));
                }
            }
        }
    }
    // every endpoint is a node; a declared service tool gives its app the "service" input
    for (e, declared) in &edges {
        if *declared
            && e.target_port == "service"
            && let Some(&i) = b.index.get(&e.target)
            && let Some(Node::App(a)) = b.nodes.get_mut(i)
            && !a.ports.inputs.iter().any(|p| p == "service")
        {
            a.ports.inputs.push("service".into());
        }
    }
    let mut placeholders: Vec<(String, String)> = Vec::new();
    for (e, _) in &edges {
        placeholders.push((e.source.clone(), String::new()));
        placeholders.push((e.target.clone(), e.target_port.clone()));
    }
    // providers and externals go last, in a stable order
    let (late, early): (Vec<_>, Vec<_>) = placeholders
        .into_iter()
        .partition(|(id, _)| id.starts_with("model:") || id.starts_with("external:"));
    for (id, port) in early {
        b.ensure(&id, &port);
    }
    let mut late: Vec<_> = late;
    late.sort();
    late.dedup();
    for (id, port) in late {
        b.ensure(&id, &port);
    }
    let edges = edges
        .into_iter()
        .map(|(e, declared)| Edge {
            stats: state.edge_stats(&inner, &e.id, now_min),
            id: e.id,
            kind: e.kind,
            source: e.source,
            source_port: e.source_port,
            target: e.target,
            target_port: e.target_port,
            declared,
        })
        .collect();
    drop(inner);
    Ok(Graph {
        version: version.to_string(),
        generated_at: now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        nodes: b.nodes,
        edges,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rec(v: serde_json::Value) -> AuditRecord {
        let mut base = json!({
            "ts": "2026-10-21T10:00:00.000Z", "kind": "model_call", "request_id": "r",
            "trace_id": "t", "span_id": "s1", "parent_span_id": null, "service": "orders",
            "namespace": "shop", "agent": "ops", "caller": "local", "caller_agent": null,
            "callee": "anthropic:claude-opus-5-5", "direction": "outbound", "decision": "allow",
            "latency_ms": 100
        });
        if let (Some(b), Some(o)) = (base.as_object_mut(), v.as_object()) {
            for (k, x) in o {
                b.insert(k.clone(), x.clone());
            }
        }
        serde_json::from_value(base).unwrap()
    }

    #[test]
    fn targets() {
        assert_eq!(
            agent_call_target("shop", "orders", "inventory/stock-analyst").as_deref(),
            Some("agent:shop/inventory/stock-analyst")
        );
        assert_eq!(
            agent_call_target("shop", "orders", "order-triage").as_deref(),
            Some("agent:shop/orders/order-triage")
        );
        assert_eq!(
            service_call_target("shop", "inventory GET /stock/1").as_deref(),
            Some("app:shop/inventory")
        );
        assert_eq!(
            http_call_target("GET https://api.partner.example:443/eta?x=1").as_deref(),
            Some("external:https://api.partner.example")
        );
        assert_eq!(
            http_call_target("https://h.example:8443/x").as_deref(),
            Some("external:https://h.example:8443")
        );
        assert_eq!(http_call_target("GET ftp://x/y"), None);
        assert_eq!(percentile(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 50), 5);
        assert_eq!(percentile(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 95), 10);
        assert_eq!(percentile(&[7], 95), 7);
        assert_eq!(percentile(&[], 50), 0);
    }

    /// Every row of the record → edge table (design §10.1).
    #[test]
    fn the_mapping_table() {
        let invoke =
            rec(json!({"kind": "agent_invocation", "direction": "inbound", "callee": "ops"}));
        assert_eq!(
            map_record(&invoke, None).map(|e| e.id).as_deref(),
            Some("edge:invoke:app:shop/orders->agent:shop/orders/ops")
        );
        let local_orch =
            rec(json!({"kind": "agent_invocation", "caller_agent": "boss", "callee": "ops"}));
        assert_eq!(map_record(&local_orch, None), None);
        let peer = rec(
            json!({"kind": "agent_invocation", "caller": "spiffe://attache/ns/shop/svc/x", "caller_agent": "a"}),
        );
        assert_eq!(map_record(&peer, None), None);
        let call = rec(json!({"kind": "agent_call", "callee": "inventory/stock-analyst"}));
        assert_eq!(
            map_record(&call, None),
            None,
            "no tool_call parent, no edge"
        );
        assert_eq!(
            map_record(&call, Some("stock_analyst")).map(|e| (e.id, e.target_port)),
            Some((
                "edge:tool:agent:shop/orders/ops->agent:shop/inventory/stock-analyst#stock_analyst"
                    .into(),
                "invoke".into()
            ))
        );
        for dir in ["outbound", "internal"] {
            let sc = rec(
                json!({"kind": "service_call", "direction": dir, "callee": "orders GET /orders/1"}),
            );
            assert_eq!(
                map_record(&sc, Some("lookup_order"))
                    .map(|e| e.id)
                    .as_deref(),
                Some("edge:tool:agent:shop/orders/ops->app:shop/orders#lookup_order")
            );
        }
        let inbound = rec(
            json!({"kind": "service_call", "direction": "inbound", "callee": "orders POST /x"}),
        );
        assert_eq!(map_record(&inbound, Some("t")), None);
        let http =
            rec(json!({"kind": "http_call", "callee": "GET https://api.partner.example/eta"}));
        assert_eq!(
            map_record(&http, Some("partner_eta"))
                .map(|e| e.id)
                .as_deref(),
            Some(
                "edge:tool:agent:shop/orders/ops->external:https://api.partner.example#partner_eta"
            )
        );
        let mock = rec(json!({"kind": "model_call", "callee": "mock"}));
        assert_eq!(
            map_record(&mock, None).map(|e| e.id).as_deref(),
            Some("edge:model:agent:shop/orders/ops->model:mock")
        );
        let claude = rec(json!({"kind": "model_call"}));
        assert_eq!(
            map_record(&claude, None).map(|e| e.id).as_deref(),
            Some("edge:model:agent:shop/orders/ops->model:anthropic")
        );
        for kind in [
            "tool_call",
            "guardrail",
            "budget",
            "authz",
            "config",
            "learning",
            "teleport",
        ] {
            assert_eq!(
                map_record(&rec(json!({"kind": kind})), Some("t")),
                None,
                "{kind}"
            );
        }
        let no_agent = rec(json!({"kind": "model_call", "agent": null}));
        assert_eq!(map_record(&no_agent, None), None);
    }

    fn now() -> DateTime<Utc> {
        "2026-10-21T10:00:30.000Z".parse().unwrap()
    }

    #[test]
    fn observing_names_the_tool_from_the_parent_tool_call_and_counts() {
        let g = GraphState::default();
        let v0 = g.version();
        let tool = rec(
            json!({"kind": "tool_call", "span_id": "t1", "callee": "lookup_order", "direction": "internal"}),
        );
        assert_eq!(g.observe(&tool, now()).edge_id, None);
        let sc = rec(
            json!({"kind": "service_call", "span_id": "s2", "parent_span_id": "t1",
            "direction": "internal", "callee": "orders GET /orders/1", "latency_ms": 40, "decision": "deny"}),
        );
        let o = g.observe(&sc, now());
        assert_eq!(
            o.edge_id.as_deref(),
            Some("edge:tool:agent:shop/orders/ops->app:shop/orders#lookup_order")
        );
        assert!(o.new_edge, "undeclared until a charter declares it");
        assert!(g.version() > v0);
        // the same edge again is not new
        assert!(!g.observe(&sc, now()).new_edge);
        let inner = g.lock();
        let s = g.edge_stats(
            &inner,
            o.edge_id.as_deref().unwrap(),
            now().timestamp() / 60,
        );
        assert_eq!((s.calls, s.denied, s.avg_ms), (2, 2, 40));
        assert_eq!(s.last_ts.as_deref(), Some("2026-10-21T10:00:00.000Z"));
    }

    #[test]
    fn declared_edges_are_not_undeclared_and_the_cap_holds() {
        let g = GraphState::default();
        let declared = "edge:model:agent:shop/orders/ops->model:anthropic".to_string();
        g.set_declared(HashSet::from([declared.clone()]));
        let o = g.observe(&rec(json!({})), now());
        assert_eq!(o.edge_id.as_deref(), Some(declared.as_str()));
        assert!(!o.new_edge);
        for i in 0..(MAX_UNDECLARED_PER_SERVICE + 5) {
            let r = rec(json!({"kind": "model_call", "agent": format!("a{i}")}));
            assert!(g.observe(&r, now()).new_edge);
        }
        let inner = g.lock();
        let list = &inner.undeclared[&ServiceKey::new("shop", "orders")];
        assert_eq!(list.len(), MAX_UNDECLARED_PER_SERVICE);
        assert!(
            list[0].id.contains("/a5->"),
            "oldest evicted: {}",
            list[0].id
        );
    }

    #[test]
    fn agent_stats_use_fifteen_one_minute_buckets() {
        let g = GraphState::default();
        let at = |ts: &str, kind: &str, extra: serde_json::Value| {
            let mut v = json!({"ts": ts, "kind": kind});
            if let (Some(m), Some(e)) = (v.as_object_mut(), extra.as_object()) {
                m.extend(e.clone());
            }
            rec(v)
        };
        // in the window
        g.observe(
            &at(
                "2026-10-21T09:50:00.000Z",
                "agent_invocation",
                json!({"latency_ms": 100, "caller_agent": "x"}),
            ),
            now(),
        );
        g.observe(
            &at(
                "2026-10-21T09:59:00.000Z",
                "agent_invocation",
                json!({"latency_ms": 300, "error": "boom", "caller_agent": "x"}),
            ),
            now(),
        );
        g.observe(
            &at(
                "2026-10-21T09:59:10.000Z",
                "tool_call",
                json!({"decision": "deny"}),
            ),
            now(),
        );
        g.observe(
            &at(
                "2026-10-21T09:59:20.000Z",
                "model_call",
                json!({"tokens": {"input": 10, "output": 2}, "cost_usd": 0.5}),
            ),
            now(),
        );
        // 16 minutes old: outside
        g.observe(
            &at(
                "2026-10-21T09:44:00.000Z",
                "agent_invocation",
                json!({"latency_ms": 9000, "caller_agent": "x"}),
            ),
            now(),
        );
        let inner = g.lock();
        let s = g.agent_stats(&inner, "agent:shop/orders/ops", now().timestamp() / 60);
        assert_eq!(s.invocations, 2);
        assert_eq!((s.denied, s.errors), (1, 1));
        assert_eq!((s.p50_ms, s.p95_ms), (100, 300));
        assert_eq!((s.tokens_in, s.tokens_out), (10, 2));
        assert!((s.cost_usd - 0.5).abs() < 1e-9);
        assert_eq!(agent_status(&s), AgentStatus::Errors);
        // later, everything has left the window
        let later: DateTime<Utc> = "2026-10-21T10:20:00.000Z".parse().unwrap();
        let s = g.agent_stats(&inner, "agent:shop/orders/ops", later.timestamp() / 60);
        assert_eq!(s, AgentStats::default());
        assert_eq!(agent_status(&s), AgentStatus::Idle);
        drop(inner);
        assert!(g.has_live_stats(now()) && !g.has_live_stats(later));
        assert!(g.tick(now()));
        assert_eq!(g.entries().0, 1);
        // a tick after the window forgets the stats (undeclared edges keep their last use)
        assert!(!g.tick(later));
        assert_eq!(g.entries().0, 0);
        assert_eq!(
            g.entries().2,
            1,
            "the undeclared model edge keeps its last use"
        );
    }

    #[test]
    fn inbound_service_calls_count_on_the_app() {
        let g = GraphState::default();
        let r = rec(
            json!({"kind": "service_call", "direction": "inbound", "callee": "orders POST /admin/reset",
            "agent": "boss", "decision": "deny", "latency_ms": 3}),
        );
        assert_eq!(g.observe(&r, now()).edge_id, None);
        let inner = g.lock();
        let s = g.app_stats(&inner, "app:shop/orders", now().timestamp() / 60);
        assert_eq!((s.calls, s.denied, s.avg_ms), (1, 1, 3));
    }
}
