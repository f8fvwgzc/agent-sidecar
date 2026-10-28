//! Every JSON shape of the REST/SSE API (`docs/api/openapi.yaml`; schema names match). The
//! golden data in `ui/fixtures/` deserializes into these types and serializes back to equal
//! JSON (`tests/fixtures.rs`).
//!
//! Structs refuse unknown fields, except [`AuditRecord`] and its [`Tokens`]: records come from
//! sidecars, which may be one minor version newer or older than the control plane (design §7,
//! version skew), so they are read with the lenient view of design §5 — `kind`, `direction` and
//! `decision` are open strings, only the fields that identify a record are required, `tokens`
//! keeps counters it does not know, and unknown top-level fields are kept and served again
//! unchanged (except to a caller that does not see payloads, [`AuditRecordExt::without_payloads`]).
//! Charter objects (`CharterDoc::charter`, `AgentView::agent`) are plain JSON values: their
//! schema is the charter's (`schemas/charter.schema.json`).
use std::collections::{BTreeMap, BTreeSet};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

pub use crate::config::Role;
pub use crate::store::{
    ActorKind, ChangeSource, HistoryEntry, MemoryDoc, Note, NoteSource, Proposal, ProposalStatus,
};

// ---- errors and small bodies --------------------------------------------------------------------

/// The error codes (`Error.error`) and their HTTP statuses (design §10, Errors).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorCode {
    #[serde(rename = "invalid")]
    Invalid,
    #[serde(rename = "config.restart_required")]
    RestartRequired,
    #[serde(rename = "version_skew")]
    VersionSkew,
    #[serde(rename = "unauthenticated")]
    Unauthenticated,
    #[serde(rename = "forbidden")]
    Forbidden,
    #[serde(rename = "not_found")]
    NotFound,
    #[serde(rename = "version_conflict")]
    VersionConflict,
    #[serde(rename = "in_use")]
    InUse,
    /// A decision on a proposal that is no longer pending (`details` name its status).
    #[serde(rename = "not_pending")]
    NotPending,
    #[serde(rename = "misdirected_request")]
    MisdirectedRequest,
    #[serde(rename = "rate_limited")]
    RateLimited,
    #[serde(rename = "internal")]
    Internal,
    /// This embassy keeps no AgentSecOps data (a Kubernetes store without `--secops-store`).
    #[serde(rename = "secops_unavailable")]
    SecopsUnavailable,
}

impl ErrorCode {
    pub fn http_status(self) -> u16 {
        match self {
            ErrorCode::Invalid | ErrorCode::RestartRequired | ErrorCode::VersionSkew => 400,
            ErrorCode::Unauthenticated => 401,
            ErrorCode::Forbidden => 403,
            ErrorCode::NotFound => 404,
            ErrorCode::VersionConflict | ErrorCode::InUse | ErrorCode::NotPending => 409,
            ErrorCode::MisdirectedRequest => 421,
            ErrorCode::RateLimited => 429,
            ErrorCode::Internal => 500,
            ErrorCode::SecopsUnavailable => 503,
        }
    }
}

/// `{"error": "<code>", "details": [...], "current_version": "<v>"?}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiError {
    pub error: ErrorCode,
    pub details: Vec<String>,
    /// Only with `version_conflict`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_version: Option<String>,
}

impl ApiError {
    pub fn new(error: ErrorCode, details: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            error,
            details: details.into_iter().map(Into::into).collect(),
            current_version: None,
        }
    }

    pub fn version_conflict(current: impl Into<String>) -> Self {
        let current = current.into();
        Self {
            error: ErrorCode::VersionConflict,
            details: vec![format!(
                "If-Match does not match the current version {current}"
            )],
            current_version: Some(current),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    pub token: String,
}

/// `GET /whoami`, and the body of a successful `POST /login`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WhoAmI {
    pub name: String,
    pub role: Role,
    pub namespaces: Vec<String>,
    pub payloads: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionResult {
    pub version: String,
}

/// `{yaml}`: the body of `PUT .../charter` and `POST .../charter/validate`, and the response of
/// `GET .../charter/history/{version}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CharterYaml {
    pub yaml: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackRequest {
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdoptRequest {
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadyStatus {
    pub ready: bool,
    pub components: BTreeMap<String, bool>,
    /// The control-plane audit's persistence (design §8.5); it never changes `ready`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_audit: Option<CpAuditHealth>,
}

/// Whether control-plane audit records reach the store (`GET /readyz`, `cp_audit`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpAuditHealth {
    /// This process persists records in a store (`--store`); else stdout only.
    pub persisted: bool,
    /// Records the store refused since start (each was still written to stdout and sent to
    /// subscribers).
    pub append_failures: u64,
    /// The last refusal (kept after later successes).
    pub last_error: Option<String>,
}

// ---- graph (design §10.1) ------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Graph {
    pub version: String,
    pub generated_at: String,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
}

/// A graph node. On the wire every node has a `type` (`service`, `app`, `agent`,
/// `model_provider`, `external`); placeholder nodes (unknown peers) carry `type` too, plus
/// `placeholder: true` and `status: disconnected`.
#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    Service(ServiceNode),
    App(AppNode),
    Agent(AgentNode),
    ModelProvider(ModelProviderNode),
    External(ExternalNode),
    Placeholder(PlaceholderNode),
}

impl Node {
    pub fn id(&self) -> &str {
        match self {
            Node::Service(n) => &n.id,
            Node::App(n) => &n.id,
            Node::Agent(n) => &n.id,
            Node::ModelProvider(n) => &n.id,
            Node::External(n) => &n.id,
            Node::Placeholder(n) => &n.id,
        }
    }

    pub fn ports(&self) -> Option<&Ports> {
        match self {
            Node::Service(_) => None,
            Node::App(n) => Some(&n.ports),
            Node::Agent(n) => Some(&n.ports),
            Node::ModelProvider(n) => Some(&n.ports),
            Node::External(n) => Some(&n.ports),
            Node::Placeholder(n) => Some(&n.ports),
        }
    }
}

/// The non-placeholder nodes, tagged by `type`.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum TaggedNode<S, A, G, M, E> {
    Service(S),
    App(A),
    Agent(G),
    ModelProvider(M),
    External(E),
}

impl Serialize for Node {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        type Ref<'a> = TaggedNode<
            &'a ServiceNode,
            &'a AppNode,
            &'a AgentNode,
            &'a ModelProviderNode,
            &'a ExternalNode,
        >;
        match self {
            Node::Service(n) => Ref::Service(n).serialize(s),
            Node::App(n) => Ref::App(n).serialize(s),
            Node::Agent(n) => Ref::Agent(n).serialize(s),
            Node::ModelProvider(n) => Ref::ModelProvider(n).serialize(s),
            Node::External(n) => Ref::External(n).serialize(s),
            Node::Placeholder(n) => n.serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for Node {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        type Owned = TaggedNode<ServiceNode, AppNode, AgentNode, ModelProviderNode, ExternalNode>;
        let v = Value::deserialize(d)?;
        if v.get("placeholder").is_some() {
            return serde_json::from_value(v)
                .map(Node::Placeholder)
                .map_err(D::Error::custom);
        }
        Ok(
            match serde_json::from_value::<Owned>(v).map_err(D::Error::custom)? {
                TaggedNode::Service(n) => Node::Service(n),
                TaggedNode::App(n) => Node::App(n),
                TaggedNode::Agent(n) => Node::Agent(n),
                TaggedNode::ModelProvider(n) => Node::ModelProvider(n),
                TaggedNode::External(n) => Node::External(n),
            },
        )
    }
}

/// Port names (see `Ports` in the OpenAPI document for which node gets which).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ports {
    #[serde(rename = "in")]
    pub inputs: Vec<String>,
    #[serde(rename = "out")]
    pub outputs: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceStatus {
    Connected,
    Degraded,
    Disconnected,
    NoCharter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceNode {
    pub id: String,
    pub label: String,
    pub namespace: String,
    pub service: String,
    pub status: ServiceStatus,
    pub instances: u32,
    pub charter_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppNode {
    pub id: String,
    pub parent: String,
    pub label: String,
    pub port: Option<u16>,
    pub ports: Ports,
    pub stats: AppStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Ok,
    Errors,
    Denied,
    Idle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentType {
    Agent,
    Orchestrator,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentNode {
    pub id: String,
    pub parent: String,
    pub label: String,
    pub agent_type: AgentType,
    pub model: String,
    pub skills: Vec<String>,
    pub status: AgentStatus,
    pub ports: Ports,
    pub tools: Vec<ToolRef>,
    pub learning: LearningSummary,
    pub stats: AgentStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolType {
    Agent,
    Service,
    Http,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRef {
    pub name: String,
    #[serde(rename = "type")]
    pub tool_type: ToolType,
    /// The node id the tool reaches.
    pub target: String,
    /// False when `guardrails.allowed_tools` excludes it.
    pub allowed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LearningMode {
    Review,
    Auto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearningSummary {
    pub enabled: bool,
    pub mode: LearningMode,
    /// Active notes.
    pub notes: u32,
    /// Pending proposals.
    pub pending: u32,
}

/// Over a sliding 15 minutes (see `AgentStats` in the OpenAPI document).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentStats {
    pub invocations: u64,
    pub denied: u64,
    pub errors: u64,
    pub p50_ms: u64,
    pub p95_ms: u64,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub cost_usd: f64,
}

/// Inbound (callee-side) service calls from peers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppStats {
    pub calls: u64,
    pub denied: u64,
    pub errors: u64,
    pub avg_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelProviderNode {
    pub id: String,
    pub label: String,
    pub ports: Ports,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalNode {
    pub id: String,
    pub label: String,
    pub ports: Ports,
}

/// The `type` a placeholder stands in for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaceholderType {
    Service,
    App,
    Agent,
}

/// A node for a peer the control plane does not know (an agent tool naming a service without a
/// charter or instances), so that every edge endpoint is a node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlaceholderNode {
    pub id: String,
    #[serde(rename = "type")]
    pub node_type: PlaceholderType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    pub label: String,
    pub placeholder: True,
    pub status: Disconnected,
    pub ports: Ports,
}

/// The JSON literal `true` (and nothing else).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct True;

impl Serialize for True {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bool(true)
    }
}

impl<'de> Deserialize<'de> for True {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if bool::deserialize(d)? {
            Ok(True)
        } else {
            Err(D::Error::custom("expected true"))
        }
    }
}

/// The string `"disconnected"` (a placeholder's only status).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disconnected {
    #[default]
    Disconnected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Invoke,
    Tool,
    Model,
}

impl EdgeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EdgeKind::Invoke => "invoke",
            EdgeKind::Tool => "tool",
            EdgeKind::Model => "model",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    /// [`super::ids::edge`].
    pub id: String,
    pub kind: EdgeKind,
    pub source: String,
    pub source_port: String,
    pub target: String,
    pub target_port: String,
    /// False for edges seen only in traffic (not derived from a stored charter).
    pub declared: bool,
    pub stats: EdgeStats,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeStats {
    pub calls: u64,
    pub denied: u64,
    pub errors: u64,
    pub avg_ms: u64,
    pub last_ts: Option<String>,
}

// ---- services --------------------------------------------------------------------------------------

/// One row of `GET /services`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSummary {
    pub namespace: String,
    pub service: String,
    pub status: ServiceStatus,
    pub epoch: Option<String>,
    pub charter_version: Option<String>,
    pub memory_version: Option<String>,
    pub pending_adoption: Option<PendingAdoption>,
    pub instances: Vec<Instance>,
}

/// A pending adoption as the API shows it (the store keeps the YAML too).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingAdoption {
    pub sha256: String,
    pub pod: String,
    pub ts: String,
}

impl From<&crate::store::PendingAdoption> for PendingAdoption {
    fn from(p: &crate::store::PendingAdoption) -> Self {
        Self {
            sha256: p.sha256.clone(),
            pod: p.pod.clone(),
            ts: p.ts.clone(),
        }
    }
}

/// One connected `Connect` stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Instance {
    pub instance_id: String,
    pub pod: String,
    pub sidecar_version: String,
    pub connected_at: String,
    pub last_heartbeat: Option<String>,
    pub runtime_ready: bool,
    pub acked_version: Option<String>,
    pub ack_error: Option<String>,
    pub cert_expires_in_s: Option<i64>,
    pub audit_dropped: u64,
}

// ---- charter ---------------------------------------------------------------------------------------

/// `GET .../charter`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CharterDoc {
    pub epoch: String,
    pub version: String,
    pub yaml: String,
    pub charter: Value,
}

impl From<crate::store::StoredCharter> for CharterDoc {
    fn from(c: crate::store::StoredCharter) -> Self {
        Self {
            epoch: c.epoch,
            version: c.version,
            yaml: c.yaml,
            charter: c.charter_json,
        }
    }
}

/// `POST .../charter/validate`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidateResult {
    pub charter: Value,
    pub needs_role: Role,
    /// Dotted paths of changes that reduce protection (design §5).
    pub weakened: Vec<String>,
}

// ---- agents, skills, links -------------------------------------------------------------------------

/// An agent with the policy around it (design §10). On input, a missing `callers` means "add the
/// agent to the `identity: local` caller rule"; missing `allowed_*` mean "no entry".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentView {
    /// The charter's `agents[]` entry.
    pub agent: Value,
    #[serde(default)]
    pub allowed_tools: Option<Vec<String>>,
    #[serde(default)]
    pub allowed_services: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callers: Option<Vec<CallerRef>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerRef {
    pub identity: String,
    pub caller_agents: Option<Vec<String>>,
}

/// A top-level charter skill (design §4): the body of `PUT .../skills/{skill}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Skill {
    pub name: String,
    pub description: String,
    pub instructions: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<String>>,
}

/// `POST /links`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkRequest {
    /// The calling orchestrator's node id.
    pub from: String,
    /// The target agent's node id.
    pub to: String,
    pub tool: LinkTool,
    /// `"<ns>/<svc>"` → the charter version the caller saw.
    pub if_match: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkTool {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkResult {
    pub applied: Vec<LinkApplied>,
    /// `"<ns>/<svc>"` → why that charter's write failed.
    pub failed: BTreeMap<String, ApiError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkApplied {
    /// `<ns>/<svc>`.
    pub service: String,
    pub version: String,
}

// ---- memory and proposals ------------------------------------------------------------------------

/// `PUT .../memory`: the service's notes after the write, per agent (a full replacement: agents
/// and stored notes left out are removed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryPut {
    pub agents: BTreeMap<String, Vec<NoteEntry>>,
}

/// One entry of [`MemoryPut`]: a stored note to keep, or a new note.
///
/// - A full [`Note`], exactly as `GET .../memory` returned it, keeps that stored note.
/// - A [`NoteInput`] `{id?, text}` is a new note: the server assigns its id (a fresh UUIDv4),
///   `source: manual`, `ts` (now) and `approved_by` (the caller). The input's `id`, when the
///   client sends one (the draft id a form used, say), is never used as the note's id and is
///   not checked; a client never keeps a note with the short form.
///
/// Provenance always comes from the store, never from the client: a kept note whose fields
/// differ from the stored one is refused (notes are not edited in place; remove and add).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum NoteEntry {
    Note(Note),
    Input(NoteInput),
}

impl<'de> Deserialize<'de> for NoteEntry {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // An object with any key besides `id` and `text` is a full note; parsing it as one gives
        // a precise error ("missing field `ts`", "unknown field `colour`") instead of serde's
        // "did not match any variant".
        let v = Value::deserialize(d)?;
        let short = v
            .as_object()
            .is_some_and(|m| m.keys().all(|k| k == "id" || k == "text"));
        if short {
            serde_json::from_value(v)
                .map(NoteEntry::Input)
                .map_err(D::Error::custom)
        } else {
            serde_json::from_value(v)
                .map(NoteEntry::Note)
                .map_err(D::Error::custom)
        }
    }
}

/// A new note written with `PUT .../memory` (see [`NoteEntry`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoteInput {
    /// Optional and never used as the note's id: the server assigns a fresh one. Any string is
    /// accepted (a client may send the draft id it used while editing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub text: String,
}

impl MemoryPut {
    /// The notes to store: the kept notes as stored (in stored order, so the oldest stay first),
    /// then the new notes in the order given, stamped with `author` and `ts` and an id from
    /// `new_id`. Agents left with no notes are left out. Every problem is reported, as
    /// `agents.<agent>[<index>]: ...`.
    ///
    /// This checks the entries against `stored` only. The caller checks them against the stored
    /// charter (agents exist and have learning enabled, at most `learning.max_notes` notes of at
    /// most `learning.max_note_chars` characters each, design §3) and the If-Match version.
    pub fn resolve(
        &self,
        stored: &MemoryDoc,
        author: &str,
        ts: &str,
        mut new_id: impl FnMut() -> String,
    ) -> Result<BTreeMap<String, Vec<Note>>, Vec<String>> {
        let mut errs = Vec::new();
        let mut out = BTreeMap::new();
        for (agent, entries) in &self.agents {
            let current: &[Note] = stored.agents.get(agent).map_or(&[], Vec::as_slice);
            let mut keep = BTreeSet::new();
            let mut added = Vec::new();
            for (i, entry) in entries.iter().enumerate() {
                let at = format!("agents.{agent}[{i}]");
                match entry {
                    NoteEntry::Input(n) => {
                        if n.text.trim().is_empty() {
                            errs.push(format!("{at}: text is empty"));
                            continue;
                        }
                        added.push(Note {
                            id: new_id(),
                            text: n.text.clone(),
                            source: NoteSource::Manual,
                            request_id: None,
                            trace_id: None,
                            approved_by: Some(author.to_string()),
                            ts: ts.to_string(),
                            expires_at: None,
                        });
                    }
                    NoteEntry::Note(n) => {
                        let id = n.id.as_str();
                        let Some(stored_note) = current.iter().find(|s| s.id == id) else {
                            errs.push(format!("{at}: {agent} has no stored note {id}"));
                            continue;
                        };
                        if n != stored_note {
                            errs.push(format!(
                                "{at}: note {id} differs from the stored note (notes are not edited in place; remove it and add a new one)"
                            ));
                        }
                        if !keep.insert(id) {
                            errs.push(format!("{at}: note {id} is listed twice"));
                        }
                    }
                }
            }
            let mut notes: Vec<Note> = current
                .iter()
                .filter(|n| keep.contains(n.id.as_str()))
                .cloned()
                .collect();
            notes.append(&mut added);
            if !notes.is_empty() {
                out.insert(agent.clone(), notes);
            }
        }
        if errs.is_empty() { Ok(out) } else { Err(errs) }
    }
}

/// `POST /proposals/{id}/approve|reject`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalDecision {
    pub proposal: Proposal,
    pub memory_version: String,
}

// ---- audit ---------------------------------------------------------------------------------------

/// The `direction` values this build knows (an [`AuditRecord`] keeps any string).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
    Internal,
}

impl Direction {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "inbound" => Some(Self::Inbound),
            "outbound" => Some(Self::Outbound),
            "internal" => Some(Self::Internal),
            _ => None,
        }
    }
}

/// The `decision` values this build knows (an [`AuditRecord`] keeps any string).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
}

impl Decision {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }
}

/// A sidecar audit record (CONTRACT.md §6) as the API serves it: the shared lenient view of
/// design §5, `agentsc_common::audit::AuditRecordView`, which the CLI and the OpenTelemetry
/// exporter read too.
///
/// - `kind`, `direction` and `decision` are any string.
/// - Only the fields that identify a record are required (`ts`, `kind`, `request_id`,
///   `trace_id`, `service`, `caller`, `callee`, `direction`, `decision`): every other field
///   defaults when absent (empty string, null, 0) and is then served with that default.
/// - [`Tokens`] keeps counters it does not know.
/// - Top-level fields this build does not know are kept in `extra` and serialized again
///   unchanged, so a record from a newer sidecar is served as it arrived — except to a caller
///   that does not see payloads ([`AuditRecordExt::without_payloads`]).
pub use agentsc_common::audit::AuditRecordView as AuditRecord;
/// Token usage of a record (`agentsc_common::audit::TokensView`): `input` and `output` (0 when
/// absent), and any counter a newer sidecar adds, kept and served again as written.
pub use agentsc_common::audit::TokensView as Tokens;

/// What the API does with an [`AuditRecord`] (a trait: the record type is the shared one).
pub trait AuditRecordExt: Sized {
    /// The record as a caller that does not see payloads sees it (a token without
    /// `payloads: true`, or `?payloads=false`; design §8.3): `input` and `output` null (the
    /// hashes stay), and none of the top-level fields this build does not know, since a field a
    /// newer sidecar added may carry a payload. `tokens` keeps its unknown counters (usage, not
    /// payload).
    fn without_payloads(self) -> Self;

    /// The direction, when it is one this build knows.
    fn known_direction(&self) -> Option<Direction>;

    /// The decision, when it is one this build knows.
    fn known_decision(&self) -> Option<Decision>;
}

impl AuditRecordExt for AuditRecord {
    fn without_payloads(mut self) -> Self {
        self.input = Value::Null;
        self.output = Value::Null;
        self.extra.clear();
        self
    }

    fn known_direction(&self) -> Option<Direction> {
        Direction::parse(&self.direction)
    }

    fn known_decision(&self) -> Option<Decision> {
        Decision::parse(&self.decision)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CpAction {
    Login,
    LoginFailed,
    Logout,
    CharterPut,
    AgentPost,
    AgentPut,
    AgentDelete,
    SkillPut,
    SkillDelete,
    LinkPost,
    Rollback,
    DeleteService,
    AdoptPending,
    AdoptApprove,
    ProposalApprove,
    ProposalReject,
    MemoryPut,
    NoteAuto,
    CertIssue,
    CertDenied,
    Connect,
    ConnectDenied,
    CrExternalEdit,
    /// The agent registry minted an id for a new agent (`reason`: its principal).
    AgentRegistered,
    /// A retired agent was declared again and is active with its old id.
    AgentReactivated,
    /// An agent is no longer declared by its service's charter.
    AgentRetired,
    /// An alias was given to an agent (`reason`: `<principal> <alias>`).
    AgentAliasPut,
    /// An alias was taken from an agent.
    AgentAliasDelete,
    /// A run's evidence bundle was exported (`reason`: the run, its entries and seals).
    LedgerExport,
    /// An agent was quarantined (`reason`: `<principal>: <why>`).
    AgentQuarantined,
    /// An agent's quarantine was lifted.
    AgentReleased,
    /// A tool call was approved (`reason`: `<tool> in run <request_id>[: why]`).
    ApprovalApprove,
    /// A tool call was denied.
    ApprovalDeny,
    /// Old ledger chains were purged (`reason`: how many, and the cut-off).
    LedgerPurge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CpResult {
    Ok,
    Denied,
    Invalid,
    Error,
}

/// One control-plane audit line (design §8.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpAuditRecord {
    pub ts: String,
    pub actor: String,
    pub actor_kind: ActorKind,
    pub role: Option<Role>,
    pub action: CpAction,
    pub namespace: Option<String>,
    pub service: Option<String>,
    pub agent: Option<String>,
    pub from_version: Option<String>,
    pub to_version: Option<String>,
    pub sha256_before: Option<String>,
    pub sha256_after: Option<String>,
    pub result: CpResult,
    pub reason: Option<String>,
}

// ---- traces (design §10.1.1) ----------------------------------------------------------------------

/// The state of a span, and of a whole run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanStatus {
    /// Started (a `SpanStart` arrived) and not ended yet.
    Running,
    Ok,
    Denied,
    Error,
}

/// How the timeline draws a span (design §11.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Segment {
    /// `model_call`.
    Thinking,
    /// `service_call`, `http_call`, `tool_call` (incl. `load_skill`).
    Tool,
    /// `agent_call`: the caller waits on the sub-agent.
    Waiting,
    /// `agent_invocation`.
    Invocation,
}

/// One run (one trace) in `GET /traces`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceSummary {
    pub trace_id: String,
    /// The root invocation's input (first 120 characters) for callers that see payloads,
    /// otherwise `<root agent> · <first 8 characters of the trace id>`.
    pub title: String,
    /// The root invocation's agent node id.
    pub root_agent: String,
    pub root_request_id: String,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub duration_ms: Option<u64>,
    pub status: SpanStatus,
    /// Distinct agents that took part.
    pub agents: u32,
    pub invocations: u32,
    pub model_calls: u32,
    pub tool_calls: u32,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub cost_usd: f64,
}

/// A record of another kind (`guardrail`, `budget`, `authz`, `config`, `learning`, ...)
/// attached to the span whose `span_id` it carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpanEvent {
    pub kind: String,
    pub rule: Option<String>,
    pub decision: String,
    pub ts: String,
}

/// One span of a run (`GET /traces/{trace_id}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Span {
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub kind: String,
    /// The agent node id, null when the record names no agent.
    pub agent: Option<String>,
    pub namespace: String,
    pub service: String,
    pub callee: String,
    /// The node the call reaches, when there is one.
    pub callee_node: Option<String>,
    /// From the `SpanStart` when one arrived, else `ts − latency_ms` of the record.
    pub start: String,
    /// The record's `ts`; null while running.
    pub end: Option<String>,
    pub latency_ms: Option<u64>,
    pub status: SpanStatus,
    pub decision: Option<String>,
    pub rule: Option<String>,
    pub request_id: String,
    pub caller: String,
    pub caller_agent: Option<String>,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub cost_usd: f64,
    /// Repeated calls from the same caller agent to the same callee within the trace: 1, 2, ...
    pub call_index: u32,
    pub segment: Segment,
    /// `model_call`: `input.attempt` (1-based); 1 otherwise.
    pub attempt: u32,
    /// `model_call`: `input.fallback`.
    pub fallback: bool,
    pub events: Vec<SpanEvent>,
}

/// `GET /traces/{trace_id}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceDoc {
    pub trace_id: String,
    pub spans: Vec<Span>,
}

// ---- SSE events (design §10.2) --------------------------------------------------------------------

/// `event: span_start`: an invocation or a tool call started (the matching `audit` event closes
/// the span).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpanStartEvent {
    pub namespace: String,
    pub service: String,
    pub request_id: String,
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub kind: String,
    pub agent: Option<String>,
    pub agent_node: Option<String>,
    pub caller: String,
    pub caller_agent: Option<String>,
    pub callee: String,
    pub callee_node: Option<String>,
    pub ts: String,
    pub call_index: u32,
}

/// `event: audit`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub record: AuditRecord,
    pub edge_id: Option<String>,
    pub animate: bool,
}

/// `event: graph`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphEvent {
    pub version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryStatus {
    Connected,
    Disconnected,
}

/// `event: registry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryEvent {
    pub namespace: String,
    pub service: String,
    pub instance_id: String,
    pub pod: String,
    pub status: RegistryStatus,
}

/// `event: config`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigEvent {
    pub namespace: String,
    pub service: String,
    pub version: String,
    pub actor: String,
    pub source: ChangeSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AckKind {
    Charter,
    Memory,
}

/// `event: ack`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckEvent {
    pub namespace: String,
    pub service: String,
    pub instance_id: String,
    pub pod: String,
    pub kind: AckKind,
    pub version: String,
    pub applied: bool,
    pub error: Option<String>,
}

/// `event: lagged`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaggedEvent {
    pub dropped: u64,
}

/// `event: reset` (data `{}`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResetEvent {}

/// One SSE event: the `event:` name and the `data:` JSON.
#[derive(Debug, Clone, PartialEq)]
pub enum SseEvent {
    /// Boxed: an audit record is several times larger than the other events.
    Audit(Box<AuditEvent>),
    Graph(GraphEvent),
    Registry(RegistryEvent),
    Config(ConfigEvent),
    Ack(AckEvent),
    Proposal(Proposal),
    SpanStart(SpanStartEvent),
    /// Sent to admins only.
    CpAudit(CpAuditRecord),
    Lagged(LaggedEvent),
    Reset(ResetEvent),
    /// An approval of a tool call was asked for, decided or expired (CONTRACT.md §5.4).
    Approval(crate::secops::Approval),
}

impl SseEvent {
    /// Every event name, in the order of design §10.2.
    pub const NAMES: [&'static str; 11] = [
        "audit",
        "graph",
        "registry",
        "config",
        "ack",
        "proposal",
        "span_start",
        "cp_audit",
        "lagged",
        "reset",
        "approval",
    ];

    /// The SSE `event:` field.
    pub fn name(&self) -> &'static str {
        match self {
            SseEvent::Audit(_) => "audit",
            SseEvent::Graph(_) => "graph",
            SseEvent::Registry(_) => "registry",
            SseEvent::Config(_) => "config",
            SseEvent::Ack(_) => "ack",
            SseEvent::Proposal(_) => "proposal",
            SseEvent::SpanStart(_) => "span_start",
            SseEvent::CpAudit(_) => "cp_audit",
            SseEvent::Lagged(_) => "lagged",
            SseEvent::Reset(_) => "reset",
            SseEvent::Approval(_) => "approval",
        }
    }

    /// The SSE `data:` field (one line of JSON).
    pub fn data(&self) -> serde_json::Result<String> {
        match self {
            SseEvent::Audit(e) => serde_json::to_string(e),
            SseEvent::Graph(e) => serde_json::to_string(e),
            SseEvent::Registry(e) => serde_json::to_string(e),
            SseEvent::Config(e) => serde_json::to_string(e),
            SseEvent::Ack(e) => serde_json::to_string(e),
            SseEvent::Proposal(e) => serde_json::to_string(e),
            SseEvent::SpanStart(e) => serde_json::to_string(e),
            SseEvent::CpAudit(e) => serde_json::to_string(e),
            SseEvent::Lagged(e) => serde_json::to_string(e),
            SseEvent::Reset(e) => serde_json::to_string(e),
            SseEvent::Approval(e) => serde_json::to_string(e),
        }
    }

    /// Parse an event from its `event:` name and `data:` JSON.
    pub fn parse(name: &str, data: &str) -> serde_json::Result<Self> {
        Ok(match name {
            "approval" => SseEvent::Approval(serde_json::from_str(data)?),
            "audit" => SseEvent::Audit(serde_json::from_str(data)?),
            "graph" => SseEvent::Graph(serde_json::from_str(data)?),
            "registry" => SseEvent::Registry(serde_json::from_str(data)?),
            "config" => SseEvent::Config(serde_json::from_str(data)?),
            "ack" => SseEvent::Ack(serde_json::from_str(data)?),
            "proposal" => SseEvent::Proposal(serde_json::from_str(data)?),
            "span_start" => SseEvent::SpanStart(serde_json::from_str(data)?),
            "cp_audit" => SseEvent::CpAudit(serde_json::from_str(data)?),
            "lagged" => SseEvent::Lagged(serde_json::from_str(data)?),
            "reset" => SseEvent::Reset(serde_json::from_str(data)?),
            other => {
                return Err(serde_json::Error::custom(format!(
                    "unknown SSE event {other:?}"
                )));
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn error_codes_map_to_statuses() {
        let e = ApiError::version_conflict("3");
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["error"], "version_conflict");
        assert_eq!(v["current_version"], "3");
        assert_eq!(e.error.http_status(), 409);
        let e = ApiError::new(ErrorCode::RestartRequired, ["service.app_port"]);
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(
            v,
            json!({"error": "config.restart_required", "details": ["service.app_port"]})
        );
        assert_eq!(e.error.http_status(), 400);
        assert_eq!(ErrorCode::NotPending.http_status(), 409);
        assert_eq!(
            serde_json::to_value(ErrorCode::NotPending).unwrap(),
            "not_pending"
        );
        assert_eq!(ErrorCode::MisdirectedRequest.http_status(), 421);
        assert_eq!(ErrorCode::RateLimited.http_status(), 429);
    }

    #[test]
    fn nodes_round_trip_and_refuse_unknown_fields() {
        let agent = json!({
            "id": "agent:shop/orders/ops-assistant", "type": "agent", "parent": "svc:shop/orders",
            "label": "ops-assistant", "agent_type": "orchestrator", "model": "claude-opus-5-5",
            "skills": ["triage"], "status": "ok",
            "ports": {"in": ["invoke"], "out": ["stock_analyst", "model"]},
            "tools": [{"name": "stock_analyst", "type": "agent", "target": "agent:shop/inventory/stock-analyst", "allowed": true}],
            "learning": {"enabled": true, "mode": "review", "notes": 3, "pending": 1},
            "stats": {"invocations": 120, "denied": 3, "errors": 1, "p50_ms": 840, "p95_ms": 2900, "tokens_in": 51200, "tokens_out": 9100, "cost_usd": 0.41}
        });
        let n: Node = serde_json::from_value(agent.clone()).unwrap();
        assert!(matches!(n, Node::Agent(_)));
        assert_eq!(n.id(), "agent:shop/orders/ops-assistant");
        assert_eq!(serde_json::to_value(&n).unwrap(), agent);

        let mut bad = agent.clone();
        bad["colour"] = json!("red");
        let err = serde_json::from_value::<Node>(bad).unwrap_err().to_string();
        assert!(err.contains("colour"), "{err}");

        let placeholder = json!({
            "id": "agent:shop/billing/payer", "type": "agent", "parent": "svc:shop/billing",
            "label": "payer", "placeholder": true, "status": "disconnected",
            "ports": {"in": ["invoke"], "out": []}
        });
        let n: Node = serde_json::from_value(placeholder.clone()).unwrap();
        assert!(matches!(n, Node::Placeholder(_)));
        assert_eq!(serde_json::to_value(&n).unwrap(), placeholder);

        let mut not_true = placeholder.clone();
        not_true["placeholder"] = json!(false);
        assert!(serde_json::from_value::<Node>(not_true).is_err());
        let mut connected = placeholder;
        connected["status"] = json!("connected");
        assert!(serde_json::from_value::<Node>(connected).is_err());
        assert!(serde_json::from_value::<Node>(json!({"id": "x", "type": "planet"})).is_err());
    }

    fn record() -> Value {
        json!({
            "ts": "2026-10-21T10:00:00.000Z", "kind": "config", "request_id": "r", "trace_id": "t",
            "span_id": "s", "parent_span_id": null, "service": "orders", "namespace": "agentsc-demo",
            "agent": null, "caller": "control-plane", "caller_agent": null, "callee": "charter",
            "direction": "internal", "input": {"version": "3"}, "output": null, "input_sha256": null,
            "output_sha256": null, "tokens": null, "cost_usd": null, "latency_ms": 0,
            "decision": "allow", "rule": "config.applied", "reason": null, "error": null
        })
    }

    #[test]
    fn audit_records_read_known_values() {
        let r: AuditRecord = serde_json::from_value(record()).unwrap();
        assert_eq!(r.known_direction(), Some(Direction::Internal));
        assert_eq!(r.known_decision(), Some(Decision::Allow));
        assert!(r.extra.is_empty());
        assert_eq!(serde_json::to_value(&r).unwrap(), record());
        let r = r.without_payloads();
        assert!(r.input.is_null() && r.output.is_null());
    }

    #[test]
    fn audit_records_are_lenient_and_keep_unknown_fields() {
        // a record from a later sidecar: new kind, direction and decision values, a new token
        // counter and new top-level fields
        let mut rec = record();
        rec["kind"] = json!("telepathy");
        rec["direction"] = json!("sideways");
        rec["decision"] = json!("shadow");
        rec["tokens"] = json!({"input": 10, "output": 2, "cache_read": 7});
        rec["added_in_v0_3"] = json!({"nested": [1, 2]});
        rec["also_new"] = json!(null);
        let r: AuditRecord = serde_json::from_value(rec.clone()).unwrap();
        assert_eq!(r.kind, "telepathy");
        assert_eq!(r.direction, "sideways");
        assert_eq!(r.known_direction(), None);
        assert_eq!(r.known_decision(), None);
        let tokens = r.tokens.clone().unwrap();
        assert_eq!((tokens.input, tokens.output), (10, 2));
        assert_eq!(tokens.extra["cache_read"], json!(7));
        assert_eq!(r.extra.len(), 2);
        // re-served unchanged, the unknown token counter included
        assert_eq!(serde_json::to_value(&r).unwrap(), rec);
        // inside an SSE audit event too
        let e = AuditEvent {
            record: r.clone(),
            edge_id: None,
            animate: false,
        };
        let back: AuditEvent = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(back, e);
        assert_eq!(
            back.record.extra["added_in_v0_3"],
            json!({"nested": [1, 2]})
        );
        // the fields that identify a record are still required
        for field in [
            "ts",
            "kind",
            "request_id",
            "trace_id",
            "service",
            "caller",
            "callee",
            "direction",
            "decision",
        ] {
            let mut missing = record();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<AuditRecord>(missing).is_err(),
                "{field} is required"
            );
        }
        // a caller without payloads gets neither the payloads nor the fields this build does
        // not know (one may carry a payload); token counters stay
        let hidden = serde_json::to_value(r.without_payloads()).unwrap();
        let mut want = rec;
        want["input"] = Value::Null;
        want["output"] = Value::Null;
        let m = want.as_object_mut().unwrap();
        m.remove("added_in_v0_3");
        m.remove("also_new");
        assert_eq!(hidden, want);
        assert_eq!(hidden["tokens"]["cache_read"], json!(7));
    }

    /// The shape `agentsc_common::audit::AuditRecordView` (A1) has: what the CLI and the
    /// OpenTelemetry exporter accept, embassy accepts and serves the same way. This must keep
    /// passing when `AuditRecord` becomes that type.
    #[test]
    fn audit_records_parse_like_the_shared_view() {
        // only the identifying fields: every other field defaults
        let minimal = json!({
            "ts": "2026-10-21T10:00:00.000Z", "kind": "model_call", "request_id": "r",
            "trace_id": "t", "service": "orders", "caller": "local", "callee": "mock",
            "direction": "outbound", "decision": "allow"
        });
        let r: AuditRecord = serde_json::from_value(minimal).unwrap();
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            json!({
                "ts": "2026-10-21T10:00:00.000Z", "kind": "model_call", "request_id": "r",
                "trace_id": "t", "span_id": "", "parent_span_id": null, "service": "orders",
                "namespace": "", "agent": null, "caller": "local", "caller_agent": null,
                "callee": "mock", "direction": "outbound", "input": null, "output": null,
                "input_sha256": null, "output_sha256": null, "tokens": null, "cost_usd": null,
                "latency_ms": 0, "decision": "allow", "rule": null, "reason": null, "error": null
            }),
            "absent fields are served with their defaults, known fields in wire order"
        );
        // tokens: absent counters are 0
        let mut rec = record();
        rec["tokens"] = json!({"output": 3});
        let r: AuditRecord = serde_json::from_value(rec).unwrap();
        assert_eq!(
            serde_json::to_value(r.tokens).unwrap(),
            json!({"input": 0, "output": 3})
        );
        // a JSON line that is not an audit record does not parse
        assert!(
            serde_json::from_value::<AuditRecord>(json!({"level": "info", "msg": "listening"}))
                .is_err()
        );
    }

    fn note(id: &str, text: &str) -> Note {
        Note {
            id: id.into(),
            text: text.into(),
            source: NoteSource::Review,
            request_id: Some("q".into()),
            trace_id: Some("t".into()),
            approved_by: Some("bob".into()),
            ts: "2026-10-20T17:02:31.118Z".into(),
            expires_at: None,
        }
    }

    #[test]
    fn memory_put_takes_full_notes_and_note_inputs() {
        let n1 = note("n1", "first");
        let put: MemoryPut = serde_json::from_value(json!({"agents": {"support-agent": [
            serde_json::to_value(&n1).unwrap(),
            {"id": "draft-2", "text": "second"},
            {"text": "a new one"}
        ]}}))
        .unwrap();
        let entries = &put.agents["support-agent"];
        assert_eq!(entries[0], NoteEntry::Note(n1.clone()));
        assert_eq!(
            entries[1],
            NoteEntry::Input(NoteInput {
                id: Some("draft-2".into()),
                text: "second".into()
            })
        );
        assert_eq!(
            entries[2],
            NoteEntry::Input(NoteInput {
                id: None,
                text: "a new one".into()
            })
        );
        // serializes back to what was sent
        assert_eq!(
            serde_json::to_value(&put).unwrap()["agents"]["support-agent"][2],
            json!({"text": "a new one"})
        );
        // precise errors
        for (bad, want) in [
            (json!({"id": "n1"}), "text"),
            (json!({"text": "x", "colour": "red"}), "colour"),
            (json!({"id": "n1", "text": "x", "source": "manual"}), "ts"),
            (json!({"text": "x", "source": "telepathy"}), "telepathy"),
        ] {
            let err = serde_json::from_value::<MemoryPut>(json!({"agents": {"a": [bad]}}))
                .unwrap_err()
                .to_string();
            assert!(err.contains(want), "{err}");
        }
    }

    #[test]
    fn memory_put_resolves_against_the_stored_notes() {
        let stored = MemoryDoc {
            version: "4".into(),
            agents: BTreeMap::from([
                (
                    "support-agent".to_string(),
                    vec![note("n1", "first"), note("n2", "second")],
                ),
                ("faq".to_string(), vec![note("n3", "third")]),
            ]),
        };
        // keep n2 and n1 (full notes, listed out of order), add two (one with a client-side
        // id, one without); faq is dropped
        let put: MemoryPut = serde_json::from_value(json!({"agents": {
            "support-agent": [
                {"text": "new"}, note_json("n2", "second"), note_json("n1", "first"),
                {"id": "draft-7", "text": "newer"}
            ],
            "faq": []
        }}))
        .unwrap();
        let mut ids = 0;
        let out = put
            .resolve(&stored, "alice", "2026-10-21T10:00:00.000Z", || {
                ids += 1;
                format!("new-{ids}")
            })
            .unwrap();
        assert_eq!(out.keys().collect::<Vec<_>>(), ["support-agent"]);
        let notes = &out["support-agent"];
        assert_eq!(
            notes.iter().map(|n| n.id.as_str()).collect::<Vec<_>>(),
            ["n1", "n2", "new-1", "new-2"],
            "stored order, then the new notes in the order given; the server assigns every new id"
        );
        assert_eq!(notes[0], stored.agents["support-agent"][0]);
        assert_eq!(
            notes[2],
            Note {
                id: "new-1".into(),
                text: "new".into(),
                source: NoteSource::Manual,
                request_id: None,
                trace_id: None,
                approved_by: Some("alice".into()),
                ts: "2026-10-21T10:00:00.000Z".into(),
                expires_at: None,
            }
        );
        assert_eq!(
            (notes[3].text.as_str(), notes[3].source),
            ("newer", NoteSource::Manual)
        );

        // a NoteInput is always a new note, even when its id is a stored note's: that note is
        // not kept (it is not listed as a full note), and a manual note with the text is added
        let put: MemoryPut = serde_json::from_value(json!({"agents": {
            "support-agent": [{"id": "n2", "text": "second"}]
        }}))
        .unwrap();
        let out = put
            .resolve(&stored, "alice", "2026-10-21T10:00:00.000Z", || {
                "fresh".to_string()
            })
            .unwrap();
        assert_eq!(out["support-agent"].len(), 1);
        assert_eq!(out["support-agent"][0].id, "fresh");
        assert_eq!(out["support-agent"][0].source, NoteSource::Manual);
        assert_eq!(
            out["support-agent"][0].approved_by.as_deref(),
            Some("alice")
        );

        // every problem is reported
        let mut forged = note("n1", "first");
        forged.approved_by = Some("mallory".into());
        let mut edited = note("n2", "second");
        edited.text = "edited".into();
        let put = MemoryPut {
            agents: BTreeMap::from([
                (
                    "support-agent".to_string(),
                    vec![
                        NoteEntry::Note(forged),
                        NoteEntry::Note(edited),
                        NoteEntry::Note(note("n3", "third")),
                        NoteEntry::Input(NoteInput {
                            id: None,
                            text: "  ".into(),
                        }),
                        NoteEntry::Note(note("n2", "second")),
                    ],
                ),
                ("ghost".to_string(), vec![NoteEntry::Note(note("n9", "x"))]),
            ]),
        };
        let errs = put
            .resolve(&stored, "alice", "2026-10-21T10:00:00.000Z", || {
                "never".to_string()
            })
            .unwrap_err();
        let all = errs.join("\n");
        for want in [
            "agents.support-agent[0]: note n1 differs from the stored note",
            "agents.support-agent[1]: note n2 differs from the stored note",
            "agents.support-agent[2]: support-agent has no stored note n3",
            "agents.support-agent[3]: text is empty",
            "agents.support-agent[4]: note n2 is listed twice",
            "agents.ghost[0]: ghost has no stored note n9",
        ] {
            assert!(all.contains(want), "missing {want:?} in\n{all}");
        }
        assert_eq!(errs.len(), 6, "{all}");
    }

    fn note_json(id: &str, text: &str) -> Value {
        serde_json::to_value(note(id, text)).unwrap()
    }

    #[test]
    fn sse_events_parse_by_name() {
        for name in SseEvent::NAMES {
            let data = match name {
                "graph" => r#"{"version":"7"}"#,
                "lagged" => r#"{"dropped":1187}"#,
                "reset" => "{}",
                _ => continue,
            };
            let e = SseEvent::parse(name, data).unwrap();
            assert_eq!(e.name(), name);
            assert_eq!(e.data().unwrap(), data);
        }
        assert!(SseEvent::parse("gossip", "{}").is_err());
        assert!(SseEvent::parse("reset", r#"{"x":1}"#).is_err());
        assert!(SseEvent::parse("lagged", r#"{"dropped":-1}"#).is_err());
    }

    #[test]
    fn span_start_events_and_traces_round_trip() {
        let data = json!({
            "namespace": "shop", "service": "orders", "request_id": "q", "trace_id": "t",
            "span_id": "s", "parent_span_id": null, "kind": "agent_call", "agent": "ops",
            "agent_node": "agent:shop/orders/ops", "caller": "local", "caller_agent": null,
            "callee": "inventory/stock", "callee_node": "agent:shop/inventory/stock",
            "ts": "2026-10-21T10:00:00.000Z", "call_index": 2
        })
        .to_string();
        let e = SseEvent::parse("span_start", &data).unwrap();
        assert_eq!(e.name(), "span_start");
        assert_eq!(
            serde_json::from_str::<Value>(&e.data().unwrap()).unwrap(),
            serde_json::from_str::<Value>(&data).unwrap()
        );
        let span = json!({
            "span_id": "s", "parent_span_id": "p", "kind": "model_call",
            "agent": "agent:shop/orders/ops", "namespace": "shop", "service": "orders",
            "callee": "mock", "callee_node": "model:mock", "start": "2026-10-21T10:00:00.000Z",
            "end": null, "latency_ms": null, "status": "running", "decision": null, "rule": null,
            "request_id": "q", "caller": "local", "caller_agent": null, "tokens_in": 0,
            "tokens_out": 0, "cost_usd": 0.0, "call_index": 1, "segment": "thinking",
            "attempt": 2, "fallback": true,
            "events": [{"kind": "guardrail", "rule": null, "decision": "allow", "ts": "2026-10-21T10:00:00.000Z"}]
        });
        let doc: TraceDoc =
            serde_json::from_value(json!({"trace_id": "t", "spans": [span.clone()]})).unwrap();
        assert_eq!(doc.spans[0].segment, Segment::Thinking);
        assert_eq!(serde_json::to_value(&doc.spans[0]).unwrap(), span);
        let mut bad = span;
        bad["segment"] = json!("dancing");
        assert!(serde_json::from_value::<Span>(bad).is_err());
    }

    #[test]
    fn agent_view_inputs_may_omit_policy() {
        let v: AgentView =
            serde_json::from_value(json!({"agent": {"name": "a", "model": "mock"}})).unwrap();
        assert!(v.callers.is_none() && v.allowed_tools.is_none());
        let back = serde_json::to_value(&v).unwrap();
        assert_eq!(
            back,
            json!({"agent": {"name": "a", "model": "mock"}, "allowed_tools": null, "allowed_services": null})
        );
    }
}
