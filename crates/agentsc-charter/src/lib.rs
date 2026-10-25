//! `charter.yaml` — the agent and policy spec. CONTRACT.md §3 is normative.
//!
//! Every struct uses `deny_unknown_fields`, so a typo or a field from a newer
//! version is a load error with the YAML path, not a silently ignored key.
//!
//! A charter is read in either of two forms: the plain document (`apiVersion`, `kind`,
//! `service`, …) or the Kubernetes custom resource ([`resource::CharterResource`]: `metadata`
//! plus `spec`). [`diff`] compares two charters (restart-only fields, weakened protection, the
//! role a change needs) and [`crd`] builds the `charters.agentsc.io` CustomResourceDefinition.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub mod crd;
pub mod diff;
pub mod resource;

pub use resource::{CharterResource, CharterSpec, ObjectMeta, ResourceServiceSpec};

pub const API_VERSION: &str = "agentsc.io/v1alpha1";
pub const KIND: &str = "Charter";
pub const LOCAL_IDENTITY: &str = "local";
pub const DEFAULT_MESH_PORT: u16 = 50002;
/// Largest `max_tokens` any current Claude model accepts.
pub const MAX_TOKENS_PER_CALL_LIMIT: u32 = 128_000;
/// The charter schema level this build understands: 1 = v0.1 fields only, 2 = v0.2
/// (`skills`, `telemetry`, `service.service_accounts`, `agents[].skills/harness/learning`),
/// 3 = taint policy (`agents[].taint`, `tools[].label`, `tools[].effect`), 4 = the taint rule
/// for inbound service calls (`authz.taint`).
pub const CHARTER_SCHEMA_LEVEL: u32 = 4;
/// A charter is at most this many bytes, measured the same way whatever form it arrived in
/// ([`Charter::validate`]): its JSON serialization and its plain YAML ([`Charter::to_yaml`], the
/// text `CharterUpdate.charter_yaml` and the file store carry) are each at most this size, so a
/// charter accepted in one form is accepted in every form it is converted to. A plain charter's
/// YAML text, comments included, is also refused beyond this size before it is parsed. In the
/// custom resource form the limit applies to the charter `spec` describes, never to `status` or
/// `metadata`.
pub const MAX_CHARTER_BYTES: usize = 256 * 1024;
/// A custom resource document (`spec` plus `metadata` and the `status` embassy writes, which
/// holds the service's memory and proposals) is not even parsed beyond this many bytes: the
/// Kubernetes API server's own request limit.
pub const MAX_RESOURCE_BYTES: usize = 3 * 1024 * 1024;
/// At most this many entries in the top-level `skills`.
pub const MAX_SKILLS: usize = 64;
/// `agents[].system` is at most this many bytes.
pub const MAX_SYSTEM_BYTES: usize = 32 * 1024;
/// A skill's `instructions` are 1 to this many bytes.
pub const MAX_SKILL_INSTRUCTIONS_BYTES: usize = 32 * 1024;
/// A skill's `description` is 1 to this many characters.
pub const MAX_SKILL_DESCRIPTION_CHARS: usize = 1024;
/// The memory of one service is at most this many characters (design §3), so the
/// `max_notes × max_note_chars` of the agents with learning enabled must add up to no more.
/// Agents with learning off hold no memory at all.
pub const MAX_MEMORY_CHARS: usize = 262_144;
/// The former name of [`MAX_MEMORY_CHARS`], kept for code written against it. The limit counts
/// characters, not bytes; new code uses `MAX_MEMORY_CHARS`.
pub const MAX_MEMORY_BYTES: usize = MAX_MEMORY_CHARS;
/// A skill whose instructions are shorter than this (bytes) goes into the system prompt; a
/// longer one is loaded on demand with the `load_skill` tool.
pub const INLINE_SKILL_MAX_BYTES: usize = 2048;
/// The tool the runtime offers for skills that are not inline; no charter tool may use the name.
pub const LOAD_SKILL_TOOL: &str = "load_skill";
/// A DNS-1123 label, as JSON Schema `pattern`.
pub const DNS_LABEL_PATTERN: &str = "^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$";
/// `http(s)://host[:port]` with at most a `/` after it and no whitespace or control character
/// anywhere, as JSON Schema `pattern` ([`check_otlp_endpoint`] is the full rule).
pub const OTLP_ENDPOINT_PATTERN: &str = r"^https?://[^/?#@\s\x00-\x1f\x7f-\x9f]+/?$";
/// A tool name (the model API's tool-name rule), as JSON Schema `pattern`.
pub const TOOL_NAME_PATTERN: &str = "^[a-zA-Z0-9_-]{1,64}$";
/// `model` and `harness.fallback_model` are at most this many bytes.
pub const MAX_MODEL_BYTES: usize = 128;
/// A model id: not empty, no whitespace or control characters, as JSON Schema `pattern` (the
/// schema adds `maxLength` 128; the validator counts [`MAX_MODEL_BYTES`] bytes).
pub const MODEL_PATTERN: &str = r"^[^\s\x00-\x1f\x7f-\x9f]+$";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Charter {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub service: ServiceSpec,
    #[serde(default)]
    pub mesh: MeshSpec,
    /// Skills agents can use (`agents[].skills`), by name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 64))]
    pub skills: Vec<SkillSpec>,
    #[serde(default)]
    pub agents: Vec<AgentSpec>,
    #[serde(default)]
    pub guardrails: Guardrails,
    #[serde(default)]
    pub authz: Authz,
    #[serde(default)]
    pub audit: AuditSpec,
    /// OpenTelemetry export and what audit leaves the pod. Absent = the defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry: Option<TelemetrySpec>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceSpec {
    /// DNS-1123 label; also the `svc/<name>` segment of the pod's SPIFFE ID.
    pub name: String,
    pub namespace: String,
    /// Port the app container listens on (localhost), target of inbound service invocations.
    pub app_port: u16,
    /// Kubernetes service accounts whose pods may obtain this identity, besides `<service.name>`
    /// (default: `[<service.name>]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(inner(pattern(DNS_LABEL_PATTERN)))]
    pub service_accounts: Vec<String>,
}

impl ServiceSpec {
    /// The service accounts allowed to obtain this identity: `service.name` plus `service_accounts`.
    pub fn allowed_service_accounts(&self) -> Vec<String> {
        let mut out = vec![self.name.clone()];
        for sa in &self.service_accounts {
            if !out.contains(sa) {
                out.push(sa.clone());
            }
        }
        out
    }
}

/// A named set of instructions agents can use (`agents[].skills`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillSpec {
    /// DNS-1123 label, unique among skills.
    #[schemars(pattern(DNS_LABEL_PATTERN))]
    pub name: String,
    /// What the skill is for (1 to 1024 characters); the model sees it before it loads the skill.
    #[schemars(length(min = 1, max = 1024))]
    pub description: String,
    /// What the agent should do (1 to 32768 bytes).
    #[schemars(length(min = 1, max = 32768))]
    pub instructions: String,
    /// Tools the instructions use; each must be allowed for every agent that uses the skill.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<String>,
}

/// `telemetry` (design §4, §9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySpec {
    /// OTLP/HTTP endpoint, `http(s)://host[:port]` with no path, query or fragment. Honoured only
    /// when the sidecar allows it (`--otlp-endpoint-allow`); changing it needs a restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(pattern(OTLP_ENDPOINT_PATTERN))]
    pub otlp_endpoint: Option<String>,
    #[serde(default = "d_true")]
    pub traces: bool,
    #[serde(default = "d_true")]
    pub metrics: bool,
    /// Spans carry inputs and outputs only if true.
    #[serde(default)]
    pub export_payloads: bool,
    /// Audit records sent to the control plane keep their (redacted, truncated) input/output.
    #[serde(default = "d_true")]
    pub control_plane_payloads: bool,
}

fn d_true() -> bool {
    true
}

impl Default for TelemetrySpec {
    fn default() -> Self {
        Self {
            otlp_endpoint: None,
            traces: true,
            metrics: true,
            export_payloads: false,
            control_plane_payloads: true,
        }
    }
}

/// `agents[].harness`: how the runtime retries and bounds model and tool calls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HarnessSpec {
    /// Retries of a model call after a retryable failure, 0..=10.
    #[serde(default = "d_max_retries")]
    #[schemars(range(max = 10))]
    pub max_retries: u32,
    /// SDK timeout of each attempt, 1..=600 seconds.
    #[serde(default = "d_request_timeout_seconds")]
    #[schemars(range(min = 1, max = 600))]
    pub request_timeout_seconds: u32,
    /// Model tried once after the last retryable failure; a valid model id other than `model`
    /// (the `model` rules: not empty, no whitespace or control characters, at most 128 bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(pattern(MODEL_PATTERN), length(max = 128))]
    pub fallback_model: Option<String>,
    /// Tool results are cut to this many characters, 100..=200000.
    #[serde(default = "d_tool_result_max_chars")]
    #[schemars(range(min = 100, max = 200000))]
    pub tool_result_max_chars: u32,
}
fn d_max_retries() -> u32 {
    2
}
fn d_request_timeout_seconds() -> u32 {
    120
}
fn d_tool_result_max_chars() -> u32 {
    20_000
}
impl Default for HarnessSpec {
    fn default() -> Self {
        Self {
            max_retries: d_max_retries(),
            request_timeout_seconds: d_request_timeout_seconds(),
            fallback_model: None,
            tool_result_max_chars: d_tool_result_max_chars(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum LearningMode {
    /// A proposed lesson waits for an editor's decision.
    #[default]
    Review,
    /// A proposed lesson becomes a note at once and expires after `note_ttl_days`.
    Auto,
}

/// `agents[].learning`: governed learning (design §4, §6.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(extend(
    "if" = {"properties": {"mode": {"const": "auto"}}, "required": ["mode"]},
    "then" = {"properties": {"enabled": {"const": true}}, "required": ["enabled"]}
))]
pub struct LearningSpec {
    #[serde(default)]
    pub enabled: bool,
    /// `auto` requires `enabled: true`.
    #[serde(default)]
    pub mode: LearningMode,
    /// Active notes kept for the agent, 1..=200.
    #[serde(default = "d_max_notes")]
    #[schemars(range(min = 1, max = 200))]
    pub max_notes: u32,
    /// Longest note, 50..=4000 characters.
    #[serde(default = "d_max_note_chars")]
    #[schemars(range(min = 50, max = 4000))]
    pub max_note_chars: u32,
    /// Lifetime of an `auto` note, 1..=365 days.
    #[serde(default = "d_note_ttl_days")]
    #[schemars(range(min = 1, max = 365))]
    pub note_ttl_days: u32,
    /// Also reflect on invocations whose caller is a peer service.
    #[serde(default)]
    pub from_peers: bool,
    /// Lessons the agent may propose per hour, 1..=100.
    #[serde(default = "d_max_proposals_per_hour")]
    #[schemars(range(min = 1, max = 100))]
    pub max_proposals_per_hour: u32,
}
fn d_max_notes() -> u32 {
    20
}
fn d_max_note_chars() -> u32 {
    500
}
fn d_note_ttl_days() -> u32 {
    7
}
fn d_max_proposals_per_hour() -> u32 {
    10
}
impl Default for LearningSpec {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: LearningMode::Review,
            max_notes: d_max_notes(),
            max_note_chars: d_max_note_chars(),
            note_ttl_days: d_note_ttl_days(),
            from_peers: false,
            max_proposals_per_hour: d_max_proposals_per_hour(),
        }
    }
}

/// An active memory note as the runtime receives it (`agent_spec_json.memory`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeNote {
    pub id: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeshSpec {
    #[serde(default = "default_mesh_port")]
    pub port: u16,
    /// service name → `host:port` override of `<service>.<namespace>.svc.cluster.local:50002`.
    #[serde(default)]
    pub peers: BTreeMap<String, String>,
}

fn default_mesh_port() -> u16 {
    DEFAULT_MESH_PORT
}

impl Default for MeshSpec {
    fn default() -> Self {
        Self {
            port: DEFAULT_MESH_PORT,
            peers: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AgentType {
    Agent,
    Orchestrator,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentSpec {
    pub name: String,
    #[serde(rename = "type", default = "default_agent_type")]
    pub agent_type: AgentType,
    /// A Claude model id (e.g. `claude-opus-5-5`) or `mock`: not empty, no whitespace or control
    /// characters, at most 128 bytes.
    #[schemars(pattern(MODEL_PATTERN), length(max = 128))]
    pub model: String,
    /// System prompt, at most 32768 bytes.
    #[serde(default)]
    #[schemars(length(max = 32768))]
    pub system: String,
    #[serde(default)]
    pub tools: Vec<ToolSpec>,
    #[serde(default)]
    pub budgets: Budgets,
    /// Names of top-level `skills` this agent uses, each at most once.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(extend("uniqueItems" = true), inner(pattern(DNS_LABEL_PATTERN)))]
    pub skills: Vec<String>,
    /// Retries, timeouts and the fallback model. Absent = the defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<HarnessSpec>,
    /// Governed learning. Absent = off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub learning: Option<LearningSpec>,
    /// Taint-aware policy (docs/design/taint-policy.md). Absent = off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taint: Option<TaintSpec>,
}

/// Where a run's data came from. A run carries every label it has read.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum TaintLabel {
    /// Data the service vouches for (its own records, the authenticated caller's request).
    Trusted,
    /// Text a third party controls (emails, tickets, web pages, uploaded files): it may carry
    /// instructions aimed at the model.
    Untrusted,
    /// Data that must not leave the organisation (PII, account and health records).
    Sensitive,
}

impl TaintLabel {
    pub fn as_str(self) -> &'static str {
        match self {
            TaintLabel::Trusted => "trusted",
            TaintLabel::Untrusted => "untrusted",
            TaintLabel::Sensitive => "sensitive",
        }
    }
}

/// What a tool call does to the world.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ToolEffect {
    Read,
    Write,
}

/// `enforce` denies a call a rule forbids; `audit` allows it and records what would have been
/// denied (rule `taint.would_deny.<rule>`), for trying a policy on real traffic first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum TaintMode {
    #[default]
    Enforce,
    Audit,
}

/// Taint-aware policy of one agent: once a run has read untrusted data it may not call tools that
/// write; once it has read sensitive data it may not call `http` tools (data leaving).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaintSpec {
    #[serde(default)]
    pub mode: TaintMode,
    /// Label of the invocation's own input. `trusted` (the default) for an authenticated
    /// caller's request; `untrusted` when the input itself is third-party text.
    #[serde(default = "default_taint_input")]
    pub input: TaintLabel,
}

fn default_taint_input() -> TaintLabel {
    TaintLabel::Trusted
}

impl AgentSpec {
    /// `harness` with the defaults filled.
    pub fn harness_or_default(&self) -> HarnessSpec {
        self.harness.clone().unwrap_or_default()
    }

    /// `learning` with the defaults filled.
    pub fn learning_or_default(&self) -> LearningSpec {
        self.learning.clone().unwrap_or_default()
    }

    /// Is learning on for this agent?
    pub fn learning_enabled(&self) -> bool {
        self.learning.as_ref().is_some_and(|l| l.enabled)
    }
}

fn default_agent_type() -> AgentType {
    AgentType::Agent
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ToolType {
    Service,
    Agent,
    Http,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolSpec {
    /// The name the model sees, unique per agent: `^[a-zA-Z0-9_-]{1,64}$`, and never
    /// `load_skill` (the runtime's tool for skills).
    #[schemars(pattern(TOOL_NAME_PATTERN), extend("not" = {"const": "load_skill"}))]
    pub name: String,
    pub description: String,
    #[serde(rename = "type")]
    pub tool_type: ToolType,
    /// JSON Schema object describing the tool input. Defaults per CONTRACT.md §3.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
    /// `service` tools: target service. `agent` tools: remote service (omit for local).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Label of what this tool returns (taint policy). Default: `untrusted` for `http` tools,
    /// `trusted` for `service` and `agent` tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<TaintLabel>,
    /// What the call does (taint policy). Default from the method: GET, HEAD and OPTIONS read,
    /// everything else writes; `agent` tools read (the callee's sidecar enforces its own policy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<ToolEffect>,
}

impl ToolSpec {
    /// [`ToolSpec::label`] with its default.
    pub fn effective_label(&self) -> TaintLabel {
        self.label.unwrap_or(match self.tool_type {
            ToolType::Http => TaintLabel::Untrusted,
            ToolType::Service | ToolType::Agent => TaintLabel::Trusted,
        })
    }

    /// [`ToolSpec::effect`] with its default.
    pub fn effective_effect(&self) -> ToolEffect {
        if let Some(e) = self.effect {
            return e;
        }
        match self.tool_type {
            ToolType::Agent => ToolEffect::Read,
            ToolType::Service | ToolType::Http => {
                match self
                    .method
                    .as_deref()
                    .map(str::to_ascii_uppercase)
                    .as_deref()
                {
                    Some("GET" | "HEAD" | "OPTIONS") => ToolEffect::Read,
                    _ => ToolEffect::Write,
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Budgets {
    #[serde(default = "d_max_tokens")]
    pub max_tokens_per_call: u32,
    #[serde(default = "d_max_calls")]
    pub max_calls_per_minute: u32,
    #[serde(default = "d_max_cost")]
    pub max_cost_usd_per_day: f64,
    #[serde(default = "d_max_steps")]
    pub max_steps: u32,
}
fn d_max_tokens() -> u32 {
    1024
}
fn d_max_calls() -> u32 {
    60
}
fn d_max_cost() -> f64 {
    10.0
}
fn d_max_steps() -> u32 {
    8
}
impl Default for Budgets {
    fn default() -> Self {
        Self {
            max_tokens_per_call: d_max_tokens(),
            max_calls_per_minute: d_max_calls(),
            max_cost_usd_per_day: d_max_cost(),
            max_steps: d_max_steps(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Guardrails {
    #[serde(default = "d_max_input_bytes")]
    pub max_input_bytes: usize,
    #[serde(default)]
    pub pii_redact: bool,
    #[serde(default)]
    pub input_deny: Vec<RegexRule>,
    #[serde(default)]
    pub output_deny: Vec<RegexRule>,
    /// agent → tool names it may use (default: every tool it declares).
    #[serde(default)]
    pub allowed_tools: BTreeMap<String, Vec<String>>,
    /// agent → services it may call (default: every service its tools name).
    #[serde(default)]
    pub allowed_services: BTreeMap<String, Vec<String>>,
}
fn d_max_input_bytes() -> usize {
    16 * 1024
}

// A charter without a `guardrails:` block gets the same defaults as an empty one.
impl Default for Guardrails {
    fn default() -> Self {
        Self {
            max_input_bytes: d_max_input_bytes(),
            pii_redact: false,
            input_deny: Vec::new(),
            output_deny: Vec::new(),
            allowed_tools: BTreeMap::new(),
            allowed_services: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegexRule {
    pub name: String,
    pub regex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    #[default]
    Deny,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Authz {
    #[serde(default)]
    pub default: Decision,
    #[serde(default)]
    pub callers: Vec<CallerRule>,
    #[serde(default)]
    pub services: Vec<ServiceRule>,
    /// The taint rule for inbound service calls (docs/design/taint-policy.md): a peer's call
    /// whose run read untrusted data (its sidecar's `x-agentsc-taint`) may not write to this
    /// service. Absent = off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taint: Option<InboundTaintSpec>,
}

/// `authz.taint`: `enforce` refuses a write (any method but GET, HEAD and OPTIONS) from a peer
/// run that read untrusted data; `audit` lets it through and records what it would refuse.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboundTaintSpec {
    #[serde(default)]
    pub mode: TaintMode,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallerRule {
    /// `local` (the app container) or a SPIFFE ID.
    pub identity: String,
    /// Agent names, or `"*"`.
    pub agents: Vec<String>,
    /// Calling agents (the `x-agentsc-agent` claim of the caller's sidecar) this rule admits.
    /// Empty = any calling agent, including a direct call by the caller's app.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caller_agents: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceRule {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// Target service (this service's own name when evaluated inbound).
    pub service: String,
    /// `"<METHOD|*> <path>"`, optional trailing `*` on the path.
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuditSink {
    #[default]
    Stdout,
    File,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditSpec {
    #[serde(default)]
    pub sink: AuditSink,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Dotted paths inside `input`/`output` replaced by "[redacted]".
    #[serde(default)]
    pub redact: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum CharterError {
    #[error("cannot read charter: {0}")]
    Io(#[from] std::io::Error),
    #[error("charter is not valid YAML or has unknown fields: {0}")]
    Parse(#[from] serde_yaml_ng::Error),
    #[error("charter has unknown fields or wrong types: {0}")]
    Json(#[from] serde_json::Error),
    #[error("charter is invalid:\n{}", .0.iter().map(|e| format!("  - {e}")).collect::<Vec<_>>().join("\n"))]
    Invalid(Vec<String>),
}

impl Charter {
    /// Parse and validate a charter, plain or in the custom resource form (`metadata` + `spec`).
    ///
    /// Size: the charter is measured by [`Charter::validate`] (its JSON serialization and its
    /// plain YAML, each at most [`MAX_CHARTER_BYTES`]), the same in both forms. In the resource
    /// form that is the charter `spec` describes, not `status` (embassy keeps the service's
    /// memory and proposals there) or `metadata`; the whole document is at most
    /// [`MAX_RESOURCE_BYTES`]. A plain charter's text is also at most [`MAX_CHARTER_BYTES`], and
    /// a bigger text that cannot be the resource form ([`resource::may_be_resource_text`]) is
    /// refused before it is parsed.
    pub fn from_yaml(text: &str) -> Result<Charter, CharterError> {
        if text.len() > MAX_RESOURCE_BYTES {
            return Err(too_big("charter", text.len(), MAX_RESOURCE_BYTES));
        }
        if text.len() > MAX_CHARTER_BYTES && !resource::may_be_resource_text(text) {
            return Err(too_big("charter", text.len(), MAX_CHARTER_BYTES));
        }
        // Parsed twice: once to see which form it is, then typed from the text, so that errors
        // keep their YAML path ("guardrails: unknown field …").
        let doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(text)?;
        let charter = if resource::is_resource_yaml(&doc) {
            serde_yaml_ng::from_str::<CharterResource>(text)?.into_charter()?
        } else if text.len() > MAX_CHARTER_BYTES {
            return Err(too_big("charter", text.len(), MAX_CHARTER_BYTES));
        } else {
            serde_yaml_ng::from_str::<Charter>(text)?
        };
        charter.validate()?;
        Ok(charter)
    }

    /// [`Charter::from_yaml`] for a JSON value (e.g. a custom resource read from the API server).
    /// The size limit is [`Charter::validate`]'s, as in `from_yaml`: in the resource form it
    /// applies to the charter `spec` describes only.
    pub fn from_value(value: &serde_json::Value) -> Result<Charter, CharterError> {
        let charter = if resource::is_resource(value) {
            CharterResource::deserialize(value)?.into_charter()?
        } else {
            Charter::deserialize(value)?
        };
        charter.validate()?;
        Ok(charter)
    }

    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Charter, CharterError> {
        let text = std::fs::read_to_string(path)?;
        Self::from_yaml(&text)
    }

    /// The plain YAML document (the form `CharterUpdate.charter_yaml` carries).
    pub fn to_yaml(&self) -> Result<String, CharterError> {
        Ok(serde_yaml_ng::to_string(self)?)
    }

    /// The custom resource form: `metadata: {name, namespace}` from `service`, `spec` = the rest.
    pub fn to_resource(&self) -> CharterResource {
        CharterResource::from_charter(self)
    }

    pub fn agent(&self, name: &str) -> Option<&AgentSpec> {
        self.agents.iter().find(|a| a.name == name)
    }

    pub fn skill(&self, name: &str) -> Option<&SkillSpec> {
        self.skills.iter().find(|s| s.name == name)
    }

    /// `telemetry` with the defaults filled.
    pub fn telemetry_or_default(&self) -> TelemetrySpec {
        self.telemetry.clone().unwrap_or_default()
    }

    /// The fields above v0.1 the charter uses, as `(path, level)`: level 2 for the v0.2 fields
    /// (`skills`, `telemetry`, `service.service_accounts`, `agents[].skills`, `harness`,
    /// `learning`), 3 for the taint fields (`agents[].taint`, `tools[].label`, `tools[].effect`),
    /// 4 for `authz.taint`. Empty lists count as unused: they are left out when the charter is
    /// serialized.
    pub fn level_fields(&self) -> Vec<(String, u32)> {
        let mut out = Vec::new();
        if self.authz.taint.is_some() {
            out.push(("authz.taint".to_string(), 4));
        }
        if !self.skills.is_empty() {
            out.push(("skills".to_string(), 2));
        }
        if self.telemetry.is_some() {
            out.push(("telemetry".into(), 2));
        }
        if !self.service.service_accounts.is_empty() {
            out.push(("service.service_accounts".into(), 2));
        }
        for a in &self.agents {
            if !a.skills.is_empty() {
                out.push((format!("agents.{}.skills", a.name), 2));
            }
            if a.harness.is_some() {
                out.push((format!("agents.{}.harness", a.name), 2));
            }
            if a.learning.is_some() {
                out.push((format!("agents.{}.learning", a.name), 2));
            }
            if a.taint.is_some() {
                out.push((format!("agents.{}.taint", a.name), 3));
            }
            for t in &a.tools {
                if t.label.is_some() || t.effect.is_some() {
                    out.push((format!("agents.{}.tools.{}", a.name, t.name), 3));
                }
            }
        }
        out
    }

    /// The lowest `charter_schema_level` that can load this charter: the highest level in
    /// [`Charter::level_fields`], 1 when there is none.
    pub fn schema_level(&self) -> u32 {
        self.level_fields()
            .into_iter()
            .map(|(_, l)| l)
            .max()
            .unwrap_or(1)
    }

    /// `ExecuteRequest.agent_spec_json` for `agent` (design §4 "What the runtime receives"): the
    /// agent's entry after `guardrails.allowed_tools` (exactly [`Charter::agent_for_runtime`]),
    /// with `skills` resolved to `[{name, description, instructions, inline}]` (`inline` when the
    /// instructions are shorter than [`INLINE_SKILL_MAX_BYTES`]), `harness` and `learning` with
    /// the defaults filled, and `memory` = `[{id, text}]` (the active notes, oldest first).
    /// Memory exists only for agents with learning enabled (design §3): for any other agent
    /// `memory` is `[]`, whatever notes are passed in. `Value::Null` for an agent the charter does
    /// not declare.
    pub fn runtime_spec(&self, agent: &str, memory: &[RuntimeNote]) -> serde_json::Value {
        use serde_json::{Value, json};
        let Some(a) = self.agent(agent) else {
            return Value::Null;
        };
        let mut spec = serde_json::to_value(self.agent_for_runtime(a)).unwrap_or(Value::Null);
        if let Value::Object(map) = &mut spec {
            let skills = a
                .skills
                .iter()
                .filter_map(|name| self.skill(name))
                .map(|s| {
                    json!({
                        "name": s.name,
                        "description": s.description,
                        "instructions": s.instructions,
                        "inline": s.instructions.len() < INLINE_SKILL_MAX_BYTES,
                    })
                })
                .collect();
            map.insert("skills".into(), Value::Array(skills));
            map.insert(
                "harness".into(),
                serde_json::to_value(a.harness_or_default()).unwrap_or(Value::Null),
            );
            map.insert(
                "learning".into(),
                serde_json::to_value(a.learning_or_default()).unwrap_or(Value::Null),
            );
            // the taint policy is the sidecar's: the runtime never sees it
            map.remove("taint");
            if let Some(Value::Array(tools)) = map.get_mut("tools") {
                for t in tools.iter_mut() {
                    if let Value::Object(t) = t {
                        t.remove("label");
                        t.remove("effect");
                    }
                }
            }
            let memory: &[RuntimeNote] = if a.learning_enabled() { memory } else { &[] };
            map.insert(
                "memory".into(),
                serde_json::to_value(memory).unwrap_or(Value::Null),
            );
        }
        spec
    }

    /// `spiffe://agentsc/ns/<namespace>/svc/<service>`
    pub fn spiffe_id(&self) -> String {
        spiffe_id(&self.service.namespace, &self.service.name)
    }

    /// Mesh address of a peer service (CONTRACT.md §2).
    pub fn peer_address(&self, service: &str) -> String {
        self.mesh.peers.get(service).cloned().unwrap_or_else(|| {
            format!(
                "{service}.{}.svc.cluster.local:{}",
                self.service.namespace, self.mesh.port
            )
        })
    }

    /// Tool names an agent may use (guardrails.allowed_tools or all declared).
    pub fn allowed_tools(&self, agent: &AgentSpec) -> Vec<String> {
        match self.guardrails.allowed_tools.get(&agent.name) {
            Some(list) => list.clone(),
            None => agent.tools.iter().map(|t| t.name.clone()).collect(),
        }
    }

    /// Services an agent may call (guardrails.allowed_services or every service its tools name).
    pub fn allowed_services(&self, agent: &AgentSpec) -> Vec<String> {
        match self.guardrails.allowed_services.get(&agent.name) {
            Some(list) => list.clone(),
            None => {
                let mut out: Vec<String> = agent
                    .tools
                    .iter()
                    .filter_map(|t| t.service.clone())
                    .collect();
                out.sort();
                out.dedup();
                out
            }
        }
    }

    /// The agent entry the runtime receives: tools filtered by allowed_tools.
    pub fn agent_for_runtime(&self, agent: &AgentSpec) -> AgentSpec {
        let allowed = self.allowed_tools(agent);
        let mut spec = agent.clone();
        spec.tools.retain(|t| allowed.iter().any(|a| a == &t.name));
        spec
    }

    pub fn validate(&self) -> Result<(), CharterError> {
        let mut errs = Vec::new();
        if self.api_version != API_VERSION {
            errs.push(format!(
                "apiVersion must be {API_VERSION}, got {:?}",
                self.api_version
            ));
        }
        if self.kind != KIND {
            errs.push(format!("kind must be {KIND}, got {:?}", self.kind));
        }
        if !is_dns_label(&self.service.name) {
            errs.push(format!(
                "service.name {:?} is not a DNS-1123 label",
                self.service.name
            ));
        }
        if !is_dns_label(&self.service.namespace) {
            errs.push(format!(
                "service.namespace {:?} is not a DNS-1123 label",
                self.service.namespace
            ));
        }
        if self.service.app_port == 0 {
            errs.push("service.app_port must be > 0".into());
        }
        for (i, sa) in self.service.service_accounts.iter().enumerate() {
            if !is_dns_label(sa) {
                errs.push(format!(
                    "service.service_accounts[{i}] {sa:?} is not a DNS-1123 label"
                ));
            }
        }
        self.validate_skills(&mut errs);
        let mut seen = std::collections::BTreeSet::new();
        for (i, agent) in self.agents.iter().enumerate() {
            let at = format!("agents[{i}] ({})", agent.name);
            if !is_dns_label(&agent.name) {
                errs.push(format!("{at}: name is not a DNS-1123 label"));
            }
            if !seen.insert(agent.name.clone()) {
                errs.push(format!("{at}: duplicate agent name"));
            }
            if let Err(e) = check_model(&agent.model) {
                errs.push(format!("{at}: model {e}"));
            }
            if agent.system.len() > MAX_SYSTEM_BYTES {
                errs.push(format!(
                    "{at}: system is {} bytes, more than {MAX_SYSTEM_BYTES}",
                    agent.system.len()
                ));
            }
            self.validate_agent_v02(agent, &at, &mut errs);
            if agent.budgets.max_tokens_per_call == 0
                || agent.budgets.max_calls_per_minute == 0
                || agent.budgets.max_steps == 0
                || agent.budgets.max_cost_usd_per_day.partial_cmp(&0.0)
                    != Some(std::cmp::Ordering::Greater)
            {
                errs.push(format!("{at}: every budget must be > 0"));
            }
            if agent.budgets.max_tokens_per_call > MAX_TOKENS_PER_CALL_LIMIT {
                errs.push(format!(
                    "{at}: budgets.max_tokens_per_call must be <= {MAX_TOKENS_PER_CALL_LIMIT}"
                ));
            }
            let mut tool_names = std::collections::BTreeSet::new();
            for (j, tool) in agent.tools.iter().enumerate() {
                let tt = format!("{at}.tools[{j}] ({})", tool.name);
                if tool.name.trim().is_empty()
                    || tool.name.len() > 64
                    || !tool
                        .name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                {
                    errs.push(format!(
                        "{tt}: tool name must match ^[a-zA-Z0-9_-]{{1,64}}$"
                    ));
                }
                if !tool_names.insert(tool.name.clone()) {
                    errs.push(format!("{tt}: duplicate tool name"));
                }
                if tool.name == LOAD_SKILL_TOOL {
                    errs.push(format!(
                        "{tt}: the tool name {LOAD_SKILL_TOOL} is reserved for skills"
                    ));
                }
                if tool.description.trim().is_empty() {
                    errs.push(format!("{tt}: description is required"));
                }
                if let Some(p) = &tool.parameters
                    && !p.is_object()
                {
                    errs.push(format!("{tt}: parameters must be a JSON Schema object"));
                }
                match tool.tool_type {
                    ToolType::Service => {
                        if tool.service.is_none() || tool.method.is_none() || tool.path.is_none() {
                            errs.push(format!("{tt}: service tools need service, method and path"));
                        }
                        if tool.agent.is_some() || tool.url.is_some() {
                            errs.push(format!("{tt}: service tools may not set agent or url"));
                        }
                        if let Some(p) = &tool.path
                            && let Err(e) = PathTemplate::parse(p)
                        {
                            errs.push(format!("{tt}: path {p:?}: {e}"));
                        }
                    }
                    ToolType::Agent => {
                        if agent.agent_type != AgentType::Orchestrator {
                            errs.push(format!(
                                "{tt}: only type: orchestrator agents may declare agent tools"
                            ));
                        }
                        match &tool.agent {
                            None => errs.push(format!("{tt}: agent tools need agent")),
                            Some(target) => {
                                let local = match &tool.service {
                                    None => true,
                                    Some(s) => s == &self.service.name,
                                };
                                if local {
                                    if target == &agent.name {
                                        errs.push(format!("{tt}: an agent may not call itself"));
                                    } else if !self.agents.iter().any(|a| &a.name == target) {
                                        errs.push(format!("{tt}: local agent {target:?} is not declared in this charter"));
                                    }
                                }
                            }
                        }
                        if tool.method.is_some() || tool.path.is_some() || tool.url.is_some() {
                            errs.push(format!("{tt}: agent tools may not set method, path or url"));
                        }
                    }
                    ToolType::Http => {
                        if tool.method.is_none() || tool.url.is_none() {
                            errs.push(format!("{tt}: http tools need method and url"));
                        }
                        if let Some(u) = &tool.url {
                            if http_origin(u).is_none() {
                                errs.push(format!(
                                    "{tt}: url must be http(s)://host[:port]/… with no {{param}} in the scheme, host or port"
                                ));
                            } else if let Err(e) = PathTemplate::parse(http_url_path(u)) {
                                errs.push(format!("{tt}: url {u:?}: {e}"));
                            }
                        }
                        if tool.service.is_some() || tool.agent.is_some() || tool.path.is_some() {
                            errs.push(format!(
                                "{tt}: http tools may not set service, agent or path"
                            ));
                        }
                    }
                }
                if let Some(m) = &tool.method
                    && !is_method(m)
                {
                    errs.push(format!("{tt}: method {m:?} is not an HTTP method"));
                }
            }
        }
        for (agent_name, tools) in &self.guardrails.allowed_tools {
            match self.agent(agent_name) {
                None => errs.push(format!(
                    "guardrails.allowed_tools.{agent_name}: unknown agent"
                )),
                Some(a) => {
                    for t in tools {
                        if !a.tools.iter().any(|x| &x.name == t) {
                            errs.push(format!(
                                "guardrails.allowed_tools.{agent_name}: tool {t:?} is not declared"
                            ));
                        }
                    }
                }
            }
        }
        for (agent_name, services) in &self.guardrails.allowed_services {
            match self.agent(agent_name) {
                None => errs.push(format!(
                    "guardrails.allowed_services.{agent_name}: unknown agent"
                )),
                Some(a) => {
                    for s in services {
                        if !a.tools.iter().any(|x| x.service.as_deref() == Some(s)) {
                            errs.push(format!("guardrails.allowed_services.{agent_name}: no tool of this agent targets service {s:?}"));
                        }
                    }
                }
            }
        }
        for (i, r) in self
            .guardrails
            .input_deny
            .iter()
            .chain(self.guardrails.output_deny.iter())
            .enumerate()
        {
            if let Err(e) = regex::Regex::new(&r.regex) {
                errs.push(format!("guardrails regex rule #{i} ({}): {e}", r.name));
            }
        }
        for (i, c) in self.authz.callers.iter().enumerate() {
            if c.identity != LOCAL_IDENTITY && !c.identity.starts_with("spiffe://") {
                errs.push(format!(
                    "authz.callers[{i}]: identity must be `local` or a spiffe:// URI"
                ));
            }
            if c.agents.is_empty() {
                errs.push(format!("authz.callers[{i}]: agents must not be empty"));
            }
            for a in &c.agents {
                if a != "*" && self.agent(a).is_none() {
                    errs.push(format!("authz.callers[{i}]: unknown agent {a:?}"));
                }
            }
        }
        let mut rule_names = std::collections::BTreeSet::new();
        for (i, r) in self.authz.services.iter().enumerate() {
            let at = format!("authz.services[{i}] ({})", r.name);
            if r.name.trim().is_empty() || !rule_names.insert(r.name.clone()) {
                errs.push(format!("{at}: name must be unique and non-empty"));
            }
            if let Some(id) = &r.identity
                && id != LOCAL_IDENTITY
                && !id.starts_with("spiffe://")
            {
                errs.push(format!("{at}: identity must be `local` or a spiffe:// URI"));
            }
            if r.allow.is_empty() && r.deny.is_empty() {
                errs.push(format!("{at}: needs allow or deny patterns"));
            }
            for p in r.allow.iter().chain(r.deny.iter()) {
                if let Err(e) = PathPattern::parse(p) {
                    errs.push(format!("{at}: bad pattern {p:?}: {e}"));
                }
            }
        }
        if self.audit.sink == AuditSink::File && self.audit.file.is_none() {
            errs.push("audit.sink: file requires audit.file".into());
        }
        if let Some(TelemetrySpec {
            otlp_endpoint: Some(e),
            ..
        }) = &self.telemetry
            && let Err(why) = check_otlp_endpoint(e)
        {
            errs.push(format!("telemetry.otlp_endpoint {e:?}: {why}"));
        }
        // Only agents with learning enabled have memory (design §3).
        let memory: u64 = self
            .agents
            .iter()
            .filter(|a| a.learning_enabled())
            .map(|a| a.learning_or_default())
            .map(|l| u64::from(l.max_notes) * u64::from(l.max_note_chars))
            .sum();
        if memory > MAX_MEMORY_CHARS as u64 {
            errs.push(format!(
                "learning: the agents with learning enabled may keep {memory} characters of notes \
                 (max_notes × max_note_chars), more than the {MAX_MEMORY_CHARS} characters a \
                 service's memory holds"
            ));
        }
        if let Err(e) = self.check_size() {
            errs.push(e);
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(CharterError::Invalid(errs))
        }
    }

    /// Rule 7, the charter's size, measured on the parsed charter so that every form agrees:
    /// its JSON serialization and its plain YAML ([`Charter::to_yaml`], what sidecars receive in
    /// `CharterUpdate.charter_yaml` and the file store keeps) are each at most
    /// [`MAX_CHARTER_BYTES`]. YAML block scalars indent every line of a system prompt or a
    /// skill's instructions, so the YAML can be the bigger of the two; bounding both means a
    /// charter accepted as a resource or as JSON is never refused when it arrives as YAML.
    fn check_size(&self) -> Result<(), String> {
        let json = serde_json::to_vec(self)
            .map_err(|e| format!("charter cannot be serialized: {e}"))?
            .len();
        if json > MAX_CHARTER_BYTES {
            return Err(format!(
                "charter is {json} bytes serialized, more than the {MAX_CHARTER_BYTES} allowed"
            ));
        }
        let yaml = self
            .to_yaml()
            .map_err(|e| format!("charter cannot be serialized: {e}"))?
            .len();
        if yaml > MAX_CHARTER_BYTES {
            return Err(format!(
                "charter is {yaml} bytes serialized as plain YAML (the form sidecars receive), \
                 more than the {MAX_CHARTER_BYTES} allowed"
            ));
        }
        Ok(())
    }

    /// Top-level `skills`: names, uniqueness, sizes (design §4 rules 1 and 7).
    fn validate_skills(&self, errs: &mut Vec<String>) {
        if self.skills.len() > MAX_SKILLS {
            errs.push(format!(
                "skills: at most {MAX_SKILLS} skills, got {}",
                self.skills.len()
            ));
        }
        let mut names = BTreeSet::new();
        for (i, s) in self.skills.iter().enumerate() {
            let at = format!("skills[{i}] ({})", s.name);
            if !is_dns_label(&s.name) {
                errs.push(format!("{at}: name is not a DNS-1123 label"));
            }
            if !names.insert(s.name.as_str()) {
                errs.push(format!("{at}: duplicate skill name"));
            }
            let chars = s.description.chars().count();
            if s.description.trim().is_empty() || chars > MAX_SKILL_DESCRIPTION_CHARS {
                errs.push(format!(
                    "{at}: description must be 1 to {MAX_SKILL_DESCRIPTION_CHARS} characters, got {chars}"
                ));
            }
            if s.instructions.trim().is_empty()
                || s.instructions.len() > MAX_SKILL_INSTRUCTIONS_BYTES
            {
                errs.push(format!(
                    "{at}: instructions must be 1 to {MAX_SKILL_INSTRUCTIONS_BYTES} bytes, got {}",
                    s.instructions.len()
                ));
            }
        }
    }

    /// An agent's `skills`, `harness` and `learning` (design §4 rules 1, 2, 4 and 6).
    fn validate_agent_v02(&self, agent: &AgentSpec, at: &str, errs: &mut Vec<String>) {
        let allowed = self.allowed_tools(agent);
        let mut used = BTreeSet::new();
        for name in &agent.skills {
            if !used.insert(name.as_str()) {
                errs.push(format!("{at}: skill {name:?} is listed twice"));
                continue;
            }
            let Some(skill) = self.skill(name) else {
                errs.push(format!("{at}: unknown skill {name:?}"));
                continue;
            };
            for t in &skill.tools {
                if !allowed.contains(t) {
                    errs.push(format!(
                        "{at}: skill {name:?} uses tool {t:?}, which this agent does not declare or may not use (guardrails.allowed_tools)"
                    ));
                }
            }
        }
        if let Some(h) = &agent.harness {
            if h.max_retries > 10 {
                errs.push(format!("{at}: harness.max_retries must be 0..=10"));
            }
            if !(1..=600).contains(&h.request_timeout_seconds) {
                errs.push(format!(
                    "{at}: harness.request_timeout_seconds must be 1..=600"
                ));
            }
            if !(100..=200_000).contains(&h.tool_result_max_chars) {
                errs.push(format!(
                    "{at}: harness.tool_result_max_chars must be 100..=200000"
                ));
            }
            if let Some(f) = &h.fallback_model {
                if let Err(e) = check_model(f) {
                    errs.push(format!("{at}: harness.fallback_model {e}"));
                } else if f == &agent.model {
                    errs.push(format!(
                        "{at}: harness.fallback_model must differ from model"
                    ));
                }
            }
        }
        if let Some(l) = &agent.learning {
            for (field, value, range) in [
                ("max_notes", l.max_notes, 1..=200),
                ("max_note_chars", l.max_note_chars, 50..=4000),
                ("note_ttl_days", l.note_ttl_days, 1..=365),
                ("max_proposals_per_hour", l.max_proposals_per_hour, 1..=100),
            ] {
                if !range.contains(&value) {
                    errs.push(format!(
                        "{at}: learning.{field} must be {}..={}",
                        range.start(),
                        range.end()
                    ));
                }
            }
            if l.mode == LearningMode::Auto && !l.enabled {
                errs.push(format!(
                    "{at}: learning.mode: auto requires learning.enabled: true"
                ));
            }
        }
    }
}

fn too_big(what: &str, len: usize, max: usize) -> CharterError {
    CharterError::Invalid(vec![format!(
        "{what} is {len} bytes, more than the {max} allowed"
    )])
}

/// Whitespace (Unicode `White_Space`, plus U+FEFF, which JSON Schema's ECMA-262 `\s` also
/// counts) or a control character: never part of a model id or an endpoint.
fn is_space_or_control(c: char) -> bool {
    c.is_whitespace() || c.is_control() || c == '\u{feff}'
}

/// The `model` rules, shared by `harness.fallback_model`: a model id (or `mock`) — not empty, no
/// whitespace or control characters, at most 128 bytes ([`MODEL_PATTERN`] and `maxLength` in the
/// JSON Schema).
fn check_model(model: &str) -> Result<(), &'static str> {
    if model.trim().is_empty() {
        return Err("is required");
    }
    if model.len() > MAX_MODEL_BYTES || model.chars().any(is_space_or_control) {
        return Err("is not a model id (no whitespace, at most 128 bytes)");
    }
    Ok(())
}

/// `telemetry.otlp_endpoint`: an `http`/`https` URL with a host, no userinfo, and no path (other
/// than `/`), query or fragment. Whitespace and control characters are refused before the URL is
/// parsed: the URL parser would quietly drop them (a trailing space, a tab inside the host), so
/// the endpoint used would not be the text that was checked. [`OTLP_ENDPOINT_PATTERN`] agrees.
pub fn check_otlp_endpoint(endpoint: &str) -> Result<(), String> {
    if endpoint.chars().any(is_space_or_control) {
        return Err("may not contain whitespace or control characters".into());
    }
    if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
        return Err("must be an http:// or https:// URL".into());
    }
    let url = url::Url::parse(endpoint).map_err(|e| format!("is not a URL: {e}"))?;
    if url.host_str().is_none_or(str::is_empty) {
        return Err("has no host".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("may not carry credentials".into());
    }
    if url.query().is_some() || endpoint.contains('?') {
        return Err("may not have a query".into());
    }
    if url.fragment().is_some() || endpoint.contains('#') {
        return Err("may not have a fragment".into());
    }
    // `Url` turns an empty path into `/` and resolves dot segments; the raw text must not have
    // more than a `/` after the authority either.
    let after_authority = endpoint
        .split_once("://")
        .map_or("", |(_, rest)| rest.find('/').map_or("", |i| &rest[i..]));
    if url.path() != "/" || !(after_authority.is_empty() || after_authority == "/") {
        return Err("may not have a path (other than /)".into());
    }
    Ok(())
}

pub fn spiffe_id(namespace: &str, service: &str) -> String {
    format!("spiffe://agentsc/ns/{namespace}/svc/{service}")
}

pub fn is_dns_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

/// `scheme://authority` of an http(s) URL template, if it has no `{param}` before the path.
pub fn http_origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains(['{', '}', '@']) {
        return None;
    }
    Some(format!("{scheme}://{}", authority.to_ascii_lowercase()))
}

/// The path and query of an http(s) URL template (`https://h/v1/{id}?q=1` → `/v1/{id}?q=1`);
/// `/` when it has no path.
pub fn http_url_path(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let rest = rest.split('#').next().unwrap_or(rest);
    match rest.find(['/', '?']) {
        Some(i) if rest[i..].starts_with('/') => &rest[i..],
        _ => "/",
    }
}

pub fn is_method(m: &str) -> bool {
    matches!(
        m,
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
    )
}

/// RFC 3986 `pchar` without `%` and `;`: what a canonical path segment is written in. A
/// canonical path has no literal `;` (path parameters are refused, CONTRACT.md §5.1), so a
/// pattern or template that needs one could never match.
fn is_path_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "-._~!$&'()*+,=:@".contains(c)
}

/// The percent-escapes of a URL path made canonical (RFC 3986 §6.2.2): an escaped unreserved
/// character is decoded (`%61` → `a`, `%2E` → `.`), any other escape gets uppercase hex. An
/// escaped `/`, `\` or NUL, which a server may turn back into a separator, is an error, and so
/// is a `%` that does not start an escape.
pub fn normalize_percent_escapes(path: &str) -> Result<String, String> {
    let mut out = String::with_capacity(path.len());
    let mut rest = path;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let byte = rest
            .get(i + 1..i + 3)
            .filter(|h| h.bytes().all(|b| b.is_ascii_hexdigit()))
            .and_then(|h| u8::from_str_radix(h, 16).ok())
            .ok_or("has a % that does not start a %XX escape")?;
        match byte {
            b'/' | b'\\' | 0 => return Err("contains an encoded slash, backslash or NUL".into()),
            b if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') => {
                out.push(b as char)
            }
            b => out.push_str(&format!("%{b:02X}")),
        }
        rest = &rest[i + 3..];
    }
    out.push_str(rest);
    Ok(out)
}

/// `"<METHOD|*> <path>"` with an optional trailing `*` on the path, matched against the
/// canonical method and path (CONTRACT.md §5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathPattern {
    pub method: Option<String>,
    /// Canonical: unreserved escapes decoded, no trailing `/` unless the pattern is `/` or ends in `/*`.
    pub prefix: String,
    pub wildcard: bool,
}

impl PathPattern {
    pub fn parse(s: &str) -> Result<PathPattern, String> {
        let (m, p) = s
            .trim()
            .split_once(' ')
            .ok_or("expected \"<METHOD|*> <path>\"")?;
        let method = if m == "*" {
            None
        } else if is_method(m) {
            Some(m.to_string())
        } else {
            return Err(format!("{m:?} is not an HTTP method or *"));
        };
        let p = p.trim();
        if !p.starts_with('/') {
            return Err("path must start with /".into());
        }
        let (prefix, wildcard) = match p.strip_suffix('*') {
            Some(pre) => (pre, true),
            None => (p, false),
        };
        if prefix.contains('*') {
            return Err("only a trailing * is supported".into());
        }
        // A pattern only ever meets canonical paths, so one that could never match is an error.
        if let Some(c) = prefix
            .chars()
            .find(|&c| !is_path_char(c) && c != '/' && c != '%')
        {
            return Err(format!("{c:?} never appears in a canonical path"));
        }
        let mut prefix = normalize_percent_escapes(prefix)?;
        if prefix.contains("//") || prefix.split('/').any(|s| s == "." || s == "..") {
            return Err("empty, . and .. segments never appear in a canonical path".into());
        }
        if !wildcard && prefix.len() > 1 && prefix.ends_with('/') {
            prefix.pop();
        }
        Ok(PathPattern {
            method,
            prefix,
            wildcard,
        })
    }

    /// Exact match, as `allow` patterns use it: a case variant of an allowed path is not allowed.
    /// A `GET` pattern also matches `HEAD`, and one trailing `/` on the path is ignored.
    pub fn matches(&self, method: &str, path: &str) -> bool {
        self.matches_with(method, path, false)
    }

    /// [`PathPattern::matches`], but ignoring ASCII case in the path, as `deny` patterns use it:
    /// `/ADMIN` meets `* /admin`, because many routers ignore case.
    pub fn matches_ignore_case(&self, method: &str, path: &str) -> bool {
        self.matches_with(method, path, true)
    }

    fn matches_with(&self, method: &str, path: &str, ignore_case: bool) -> bool {
        if let Some(m) = &self.method
            && !m.eq_ignore_ascii_case(method)
            && !(m == "GET" && method.eq_ignore_ascii_case("HEAD"))
        {
            return false;
        }
        let path = path.split('?').next().unwrap_or(path);
        let path = match path.strip_suffix('/') {
            Some(p) if !p.is_empty() => p,
            _ => path,
        };
        let (p, pre) = (path.as_bytes(), self.prefix.as_bytes());
        let eq = |a: &[u8], b: &[u8]| {
            if ignore_case {
                a.eq_ignore_ascii_case(b)
            } else {
                a == b
            }
        };
        if self.wildcard {
            p.len() > pre.len() && eq(&p[..pre.len()], pre)
        } else {
            eq(p, pre)
        }
    }
}

/// A tool's path template, `/orders/{order_id}` or `/stock/{sku?}`, as the sidecar checks a call
/// against it (CONTRACT.md §3.1). A `{param}` stands for a non-empty segment, or a non-empty part
/// of one (`/files/{name}.json`); `{param?}`, only as the whole last segment, may also be left out
/// together with its `/`. The query (from `?` on) is not part of the template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathTemplate {
    segments: Vec<Vec<TemplatePart>>,
    optional_last: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TemplatePart {
    Literal(String),
    Param,
}

impl PathTemplate {
    pub fn parse(template: &str) -> Result<PathTemplate, String> {
        // the query starts at the first `?` outside `{…}` (`{sku?}` is a param, not a query)
        let mut depth = 0usize;
        let end = template
            .char_indices()
            .find(|&(_, c)| {
                match c {
                    '{' => depth += 1,
                    '}' => depth = depth.saturating_sub(1),
                    _ => {}
                }
                c == '?' && depth == 0
            })
            .map_or(template.len(), |(i, _)| i);
        let path = template[..end]
            .strip_prefix('/')
            .ok_or("must start with /")?;
        let raw: Vec<&str> = path.split('/').collect();
        let mut segments = Vec::with_capacity(raw.len());
        let mut optional_last = false;
        for (i, seg) in raw.iter().enumerate() {
            let last = i + 1 == raw.len();
            if let Some(name) = seg.strip_prefix('{').and_then(|s| s.strip_suffix("?}")) {
                if !last {
                    return Err(format!("{{{name}?}} may only be the last segment"));
                }
                param_name(name)?;
                optional_last = true;
                break;
            }
            if seg.is_empty() && !last {
                return Err("has an empty segment (//)".into());
            }
            let parts = template_segment(seg)?;
            if let [TemplatePart::Literal(l)] = parts.as_slice()
                && (l == "." || l == "..")
            {
                return Err("has a . or .. segment".into());
            }
            segments.push(parts);
        }
        Ok(PathTemplate {
            segments,
            optional_last,
        })
    }

    /// Does the canonical `path` (its query ignored) fit this template?
    pub fn matches(&self, path: &str) -> bool {
        let path = path.split('?').next().unwrap_or(path);
        let Some(path) = path.strip_prefix('/') else {
            return false;
        };
        let segs: Vec<&str> = path.split('/').collect();
        if segs.iter().any(|s| *s == "." || *s == "..") {
            return false;
        }
        let n = self.segments.len();
        let fixed: &[&str] = if segs.len() == n {
            &segs
        } else if self.optional_last && segs.len() == n + 1 && !segs[n].is_empty() {
            &segs[..n]
        } else if self.optional_last && n == 0 && segs == [""] {
            &[] // `/{param?}` left out is `/`
        } else {
            return false;
        };
        self.segments
            .iter()
            .zip(fixed)
            .all(|(parts, s)| segment_fits(parts, s))
    }
}

fn param_name(name: &str) -> Result<(), String> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(format!(
            "{{{name}}} is not a parameter: names match ^[a-zA-Z0-9_]+$, and an optional {{name?}} is a whole last segment"
        ));
    }
    Ok(())
}

fn template_segment(seg: &str) -> Result<Vec<TemplatePart>, String> {
    let mut parts = Vec::new();
    let mut rest = seg;
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix('{') {
            let end = after.find('}').ok_or("has a { without }")?;
            param_name(&after[..end])?;
            parts.push(TemplatePart::Param);
            rest = &after[end + 1..];
            continue;
        }
        let end = rest.find(['{', '}']).unwrap_or(rest.len());
        let lit = &rest[..end];
        if lit.is_empty() {
            return Err("has a } without {".into());
        }
        if let Some(c) = lit.chars().find(|&c| !is_path_char(c) && c != '%') {
            return Err(format!("{c:?} never appears in a canonical path"));
        }
        parts.push(TemplatePart::Literal(normalize_percent_escapes(lit)?));
        rest = &rest[end..];
    }
    Ok(parts)
}

/// A param takes one or more characters; literals must be equal.
fn segment_fits(parts: &[TemplatePart], s: &str) -> bool {
    match parts.split_first() {
        None => s.is_empty(),
        Some((TemplatePart::Literal(l), rest)) => s
            .strip_prefix(l.as_str())
            .is_some_and(|r| segment_fits(rest, r)),
        Some((TemplatePart::Param, rest)) => (1..=s.len())
            .filter(|&i| s.is_char_boundary(i))
            .any(|i| segment_fits(rest, &s[i..])),
    }
}

/// JSON Schema of `Charter` (== schemas/charter.schema.json).
pub fn json_schema() -> serde_json::Value {
    let mut schema = schemars::schema_for!(Charter);
    schema.insert(
        "$id".into(),
        serde_json::Value::String("https://agentsc.io/schemas/v1alpha1/charter.schema.json".into()),
    );
    schema.insert(
        "title".into(),
        serde_json::Value::String("agentsc Charter (agentsc.io/v1alpha1)".into()),
    );
    schema.to_value()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORDERS: &str = include_str!("../../../examples/charters/orders.charter.yaml");
    const INVENTORY: &str = include_str!("../../../examples/charters/inventory.charter.yaml");

    #[test]
    fn example_charters_are_valid() {
        let c = Charter::from_yaml(ORDERS).expect("orders charter valid");
        assert_eq!(c.spiffe_id(), "spiffe://agentsc/ns/agentsc-demo/svc/orders");
        assert_eq!(
            c.peer_address("inventory"),
            "inventory.agentsc-demo.svc.cluster.local:50002"
        );
        let inv = Charter::from_yaml(INVENTORY).expect("inventory charter valid");
        assert!(inv.agent("stock-analyst").is_some());
    }

    #[test]
    fn unknown_field_is_rejected_with_path() {
        let bad = ORDERS.replace(
            "pii_redact: true",
            "pii_redact: true\n  pii_redaction: true",
        );
        let err = Charter::from_yaml(&bad).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown field `pii_redaction`"), "{msg}");
        assert!(msg.contains("guardrails"), "{msg}");
    }

    #[test]
    fn top_level_unknown_field_is_rejected() {
        let bad = format!("{ORDERS}\nextra: 1\n");
        let err = Charter::from_yaml(&bad).unwrap_err();
        assert!(err.to_string().contains("unknown field `extra`"));
    }

    #[test]
    fn semantic_errors_are_collected() {
        let mut c = Charter::from_yaml(ORDERS).unwrap();
        c.agents[0].agent_type = AgentType::Agent; // orchestrator with agent tools → error
        c.authz.callers.push(CallerRule {
            identity: "nobody".into(),
            agents: vec!["ghost".into()],
            caller_agents: vec![],
        });
        c.agents[0].budgets.max_steps = 0;
        let err = c.validate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("only type: orchestrator"), "{msg}");
        assert!(
            msg.contains("identity must be `local` or a spiffe:// URI"),
            "{msg}"
        );
        assert!(msg.contains("unknown agent \"ghost\""), "{msg}");
        assert!(msg.contains("every budget must be > 0"), "{msg}");
    }

    #[test]
    fn missing_guardrails_block_gets_defaults() {
        let text = "apiVersion: agentsc.io/v1alpha1\nkind: Charter\nservice: {name: a, namespace: b, app_port: 1}\nagents: [{name: x, model: mock}]\n";
        let c = Charter::from_yaml(text).unwrap();
        assert_eq!(c.guardrails.max_input_bytes, 16 * 1024);
        assert_eq!(c.agents[0].budgets.max_steps, 8);
    }

    #[test]
    fn caller_agents_and_limits() {
        let inv = Charter::from_yaml(INVENTORY).unwrap();
        let rule = inv
            .authz
            .callers
            .iter()
            .find(|r| r.identity.ends_with("/svc/orders"))
            .unwrap();
        assert_eq!(rule.caller_agents, vec!["ops-assistant".to_string()]);
        let too_big = ORDERS.replace("max_tokens_per_call: 2048", "max_tokens_per_call: 200000");
        assert!(
            Charter::from_yaml(&too_big)
                .unwrap_err()
                .to_string()
                .contains("<= 128000")
        );
    }

    #[test]
    fn http_tool_urls_and_own_service_agent_tools() {
        assert_eq!(
            http_origin("https://api.example.com:8443/v1/{id}"),
            Some("https://api.example.com:8443".into())
        );
        assert_eq!(http_origin("http://{host}/x"), None);
        assert_eq!(http_origin("ftp://x/y"), None);
        assert_eq!(http_origin("https://user@evil/x"), None);
        let mut c = Charter::from_yaml(ORDERS).unwrap();
        // an agent tool naming this service is local: the target must exist and may not be the caller
        let t = c.agents[0]
            .tools
            .iter_mut()
            .find(|t| t.name == "order_triage")
            .unwrap();
        t.service = Some("orders".into());
        t.agent = Some("ops-assistant".into());
        assert!(
            c.validate()
                .unwrap_err()
                .to_string()
                .contains("may not call itself")
        );
    }

    #[test]
    fn path_patterns() {
        let p = PathPattern::parse("GET /stock/*").unwrap();
        assert!(p.matches("GET", "/stock/WIDGET-1"));
        assert!(p.matches("GET", "/stock/a/b?x=1"));
        assert!(!p.matches("GET", "/stock"));
        assert!(!p.matches("POST", "/stock/x"));
        let any = PathPattern::parse("* /admin*").unwrap();
        assert!(any.matches("POST", "/admin/reset"));
        assert!(any.matches("GET", "/administrator"));
        assert!(!any.matches("GET", "/admin"));
        let exact = PathPattern::parse("* /admin").unwrap();
        assert!(exact.matches("DELETE", "/admin"));
        assert!(PathPattern::parse("FETCH /x").is_err());
        assert!(PathPattern::parse("GET x").is_err());
        assert!(PathPattern::parse("GET /a/*/b").is_err());
    }

    #[test]
    fn path_patterns_trailing_slash_head_and_case() {
        // one trailing slash on the path is ignored: /x/ is /x, for /x and /x/* alike
        let exact = PathPattern::parse("* /admin").unwrap();
        assert!(exact.matches("POST", "/admin/"));
        assert!(!exact.matches("POST", "/admin//"));
        let sub = PathPattern::parse("* /admin/*").unwrap();
        assert!(sub.matches("POST", "/admin/reset/"));
        assert!(!sub.matches("POST", "/admin/"), "like /admin, not under it");
        assert_eq!(PathPattern::parse("GET /stock/").unwrap().prefix, "/stock");
        assert!(PathPattern::parse("GET /").unwrap().matches("GET", "/"));
        assert!(!PathPattern::parse("GET /*").unwrap().matches("GET", "/"));
        // GET rules cover HEAD; a HEAD rule covers only HEAD; request methods are compared uppercased
        let get = PathPattern::parse("GET /export/*").unwrap();
        assert!(get.matches("HEAD", "/export/x"));
        assert!(get.matches("get", "/export/x"));
        assert!(!get.matches("POST", "/export/x"));
        let head = PathPattern::parse("HEAD /export/*").unwrap();
        assert!(!head.matches("GET", "/export/x"));
        // case: allow-style matching is exact, deny-style ignores ASCII case
        assert!(!exact.matches("GET", "/ADMIN"));
        assert!(exact.matches_ignore_case("GET", "/ADMIN"));
        assert!(sub.matches_ignore_case("GET", "/Admin/Reset/"));
        assert!(!sub.matches_ignore_case("GET", "/Administrator"));
        // escapes in a pattern are canonical too; anything a canonical path never holds is refused
        assert_eq!(
            PathPattern::parse("* /%61dmin/%3a*").unwrap().prefix,
            "/admin/%3A"
        );
        assert_eq!(PathPattern::parse("* /a%3bb").unwrap().prefix, "/a%3Bb");
        for bad in [
            "* /admin;x",
            "* /admin;*",
            "* /a b",
            "* /a?x=1",
            "* /a#b",
            "* /a\\b",
            "* //a",
            "* /a/../b",
            "* /a/./*",
            "* /a%2Fb",
            "* /a%",
            "* /ä",
        ] {
            assert!(PathPattern::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn path_templates() {
        let t = PathTemplate::parse("/orders/{order_id}").unwrap();
        assert!(t.matches("/orders/1001"));
        assert!(t.matches("/orders/a%20b?x=1"), "the query is not checked");
        assert!(!t.matches("/orders"), "a required param cannot be left out");
        assert!(!t.matches("/orders/"));
        assert!(!t.matches("/orders/1/cancel"));
        assert!(!t.matches("/admin/reset"));
        assert!(!t.matches("/Orders/1"));
        assert!(!t.matches("/orders/.."));
        let cancel = PathTemplate::parse("/orders/{id}/cancel").unwrap();
        assert!(cancel.matches("/orders/7/cancel"));
        assert!(!cancel.matches("/orders/cancel"));
        assert!(!cancel.matches("/cancel"));
        let opt = PathTemplate::parse("/stock/{sku?}").unwrap();
        assert!(opt.matches("/stock"));
        assert!(opt.matches("/stock/WIDGET-1"));
        assert!(!opt.matches("/stock/"));
        assert!(!opt.matches("/stock/a/b"));
        assert!(!opt.matches("/"));
        let root_opt = PathTemplate::parse("/{x?}").unwrap();
        assert!(root_opt.matches("/") && root_opt.matches("/a") && !root_opt.matches("/a/b"));
        let mixed = PathTemplate::parse("/v{version}/files/{name}.json?raw={raw}").unwrap();
        assert!(mixed.matches("/v2/files/report.json"));
        assert!(
            !mixed.matches("/v/files/report.json"),
            "a param takes at least one character"
        );
        assert!(!mixed.matches("/v2/files/.json"));
        assert!(!mixed.matches("/v2/files/report.xml"));
        let slash = PathTemplate::parse("/orders/").unwrap();
        assert!(slash.matches("/orders/") && !slash.matches("/orders"));
        assert!(PathTemplate::parse("/").unwrap().matches("/"));
        assert!(PathTemplate::parse("/%61pi/x").unwrap().matches("/api/x"));
        for bad in [
            "orders/{id}",
            "/orders//{id}",
            "/a/../b",
            "/a/%2E/b",
            "/stock/{sku?}/history",
            "/stock/x{sku?}",
            "/stock/{}",
            "/stock/{a-b}",
            "/stock/{sku",
            "/stock/sku}",
            "/a b/{x}",
            "/a%2Fb/{x}",
            "/items;v=2/{x}",
            "/items/{x};v=2",
        ] {
            assert!(PathTemplate::parse(bad).is_err(), "{bad}");
        }
        // a `;` as data is %3B, in a literal or a value; the query is not a path
        let semi = PathTemplate::parse("/a%3bb/{x}?q=1;2").unwrap();
        assert!(semi.matches("/a%3Bb/c%3Bd"));
        assert_eq!(
            http_url_path("https://h:8443/v1/{id}?q=1#f"),
            "/v1/{id}?q=1"
        );
        assert_eq!(http_url_path("https://h"), "/");
        assert_eq!(http_url_path("https://h?q=1"), "/");
    }

    #[test]
    fn tool_templates_are_validated() {
        let mut c = Charter::from_yaml(INVENTORY).unwrap();
        c.agents[0].tools[0].path = Some("/stock/{sku?}/history".into());
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("may only be the last segment"), "{err}");
        let mut c = Charter::from_yaml(ORDERS).unwrap();
        c.agents[0].tools.push(ToolSpec {
            name: "partner".into(),
            description: "d".into(),
            tool_type: ToolType::Http,
            parameters: None,
            service: None,
            method: Some("GET".into()),
            path: None,
            agent: None,
            url: Some("https://api.example.com/v1//items/{id}".into()),
            label: None,
            effect: None,
        });
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("empty segment"), "{err}");
    }

    #[test]
    fn allowed_tools_filter_reaches_runtime_spec() {
        let c = Charter::from_yaml(ORDERS).unwrap();
        let a = c.agent("ops-assistant").unwrap();
        let spec = c.agent_for_runtime(a);
        let allowed = c.allowed_tools(a);
        assert_eq!(spec.tools.len(), allowed.len());
    }

    #[test]
    fn schema_file_is_in_sync() {
        let on_disk: serde_json::Value =
            serde_json::from_str(include_str!("../../../schemas/charter.schema.json")).unwrap();
        assert_eq!(
            on_disk,
            json_schema(),
            "run `agentsc charter schema > schemas/charter.schema.json`"
        );
    }
}
