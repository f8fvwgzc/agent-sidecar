//! `charter.yaml` — the agent and policy spec. CONTRACT.md §3 is normative.
//!
//! Every struct uses `deny_unknown_fields`, so a typo or a field from a newer
//! version is a load error with the YAML path, not a silently ignored key.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const API_VERSION: &str = "attache.io/v1alpha1";
pub const KIND: &str = "Charter";
pub const LOCAL_IDENTITY: &str = "local";
pub const DEFAULT_MESH_PORT: u16 = 50002;
/// Largest `max_tokens` any current Claude model accepts.
pub const MAX_TOKENS_PER_CALL_LIMIT: u32 = 128_000;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Charter {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub service: ServiceSpec,
    #[serde(default)]
    pub mesh: MeshSpec,
    #[serde(default)]
    pub agents: Vec<AgentSpec>,
    #[serde(default)]
    pub guardrails: Guardrails,
    #[serde(default)]
    pub authz: Authz,
    #[serde(default)]
    pub audit: AuditSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceSpec {
    /// DNS-1123 label; also the `svc/<name>` segment of the pod's SPIFFE ID.
    pub name: String,
    pub namespace: String,
    /// Port the app container listens on (localhost), target of inbound service invocations.
    pub app_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentSpec {
    pub name: String,
    #[serde(rename = "type", default = "default_agent_type")]
    pub agent_type: AgentType,
    /// A Claude model id (e.g. `claude-opus-5-5`) or `mock`.
    pub model: String,
    #[serde(default)]
    pub system: String,
    #[serde(default)]
    pub tools: Vec<ToolSpec>,
    #[serde(default)]
    pub budgets: Budgets,
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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolSpec {
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
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Authz {
    #[serde(default)]
    pub default: Decision,
    #[serde(default)]
    pub callers: Vec<CallerRule>,
    #[serde(default)]
    pub services: Vec<ServiceRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallerRule {
    /// `local` (the app container) or a SPIFFE ID.
    pub identity: String,
    /// Agent names, or `"*"`.
    pub agents: Vec<String>,
    /// Calling agents (the `x-attache-agent` claim of the caller's sidecar) this rule admits.
    /// Empty = any calling agent, including a direct call by the caller's app.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caller_agents: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
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
    #[error("charter is invalid:\n{}", .0.iter().map(|e| format!("  - {e}")).collect::<Vec<_>>().join("\n"))]
    Invalid(Vec<String>),
}

impl Charter {
    pub fn from_yaml(text: &str) -> Result<Charter, CharterError> {
        let charter: Charter = serde_yaml_ng::from_str(text)?;
        charter.validate()?;
        Ok(charter)
    }

    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Charter, CharterError> {
        let text = std::fs::read_to_string(path)?;
        Self::from_yaml(&text)
    }

    pub fn agent(&self, name: &str) -> Option<&AgentSpec> {
        self.agents.iter().find(|a| a.name == name)
    }

    /// `spiffe://attache/ns/<namespace>/svc/<service>`
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
        let mut seen = std::collections::BTreeSet::new();
        for (i, agent) in self.agents.iter().enumerate() {
            let at = format!("agents[{i}] ({})", agent.name);
            if !is_dns_label(&agent.name) {
                errs.push(format!("{at}: name is not a DNS-1123 label"));
            }
            if !seen.insert(agent.name.clone()) {
                errs.push(format!("{at}: duplicate agent name"));
            }
            if agent.model.trim().is_empty() {
                errs.push(format!("{at}: model is required"));
            }
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
        if errs.is_empty() {
            Ok(())
        } else {
            Err(CharterError::Invalid(errs))
        }
    }
}

pub fn spiffe_id(namespace: &str, service: &str) -> String {
    format!("spiffe://attache/ns/{namespace}/svc/{service}")
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

/// RFC 3986 `pchar` without `%`: what a canonical path segment is written in.
fn is_path_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "-._~!$&'()*+,;=:@".contains(c)
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
        serde_json::Value::String("https://attache.io/schemas/v1alpha1/charter.schema.json".into()),
    );
    schema.insert(
        "title".into(),
        serde_json::Value::String("attache Charter (attache.io/v1alpha1)".into()),
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
        assert_eq!(c.spiffe_id(), "spiffe://attache/ns/attache-demo/svc/orders");
        assert_eq!(
            c.peer_address("inventory"),
            "inventory.attache-demo.svc.cluster.local:50002"
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
        let text = "apiVersion: attache.io/v1alpha1\nkind: Charter\nservice: {name: a, namespace: b, app_port: 1}\nagents: [{name: x, model: mock}]\n";
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
        for bad in [
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
        ] {
            assert!(PathTemplate::parse(bad).is_err(), "{bad}");
        }
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
            "run `attache charter schema > schemas/charter.schema.json`"
        );
    }
}
