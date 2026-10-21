//! Comparing a stored charter with a new one (design §4 "Restart-only fields", §5 `weakened`,
//! §8.3 roles on the diff).
//!
//! Every function returns human-readable field paths, so the control plane can put them into a
//! 400 / 403 `details` list and the sidecar into the `config` audit record.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    AgentSpec, CallerRule, Charter, Decision, LOCAL_IDENTITY, LearningMode, RegexRule, ToolType,
    http_origin,
};

/// The roles of the control-plane API, lowest first (`Role::Viewer < Role::Editor < Role::Admin`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Viewer,
    Editor,
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Editor => "editor",
            Role::Admin => "admin",
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Fields a hot reload may not change (design §4): `service.name`, `service.namespace`,
/// `service.app_port`, `mesh.port`, `audit.sink`, `audit.file`, `telemetry.otlp_endpoint`.
/// Returns the ones that differ, in that order; empty = the change can be applied live.
pub fn restart_required(old: &Charter, new: &Charter) -> Vec<String> {
    let (ot, nt) = (old.telemetry_or_default(), new.telemetry_or_default());
    [
        ("service.name", old.service.name != new.service.name),
        (
            "service.namespace",
            old.service.namespace != new.service.namespace,
        ),
        (
            "service.app_port",
            old.service.app_port != new.service.app_port,
        ),
        ("mesh.port", old.mesh.port != new.mesh.port),
        ("audit.sink", old.audit.sink != new.audit.sink),
        ("audit.file", old.audit.file != new.audit.file),
        (
            "telemetry.otlp_endpoint",
            ot.otlp_endpoint != nt.otlp_endpoint,
        ),
    ]
    .into_iter()
    .filter(|(_, changed)| *changed)
    .map(|(field, _)| field.to_string())
    .collect()
}

/// Changes that reduce protection (design §5), as paths: a removed `audit.redact` path
/// (`audit.redact[<path>]`), `guardrails.pii_redact` true → false, `telemetry.export_payloads`
/// false → true, `authz.default` deny → allow, and a removed `input_deny` / `output_deny` rule
/// (`guardrails.input_deny[<name>]`; a rule whose regex changed counts as removed).
pub fn weakened(old: &Charter, new: &Charter) -> Vec<String> {
    let mut out = Vec::new();
    for p in &old.audit.redact {
        if !new.audit.redact.contains(p) {
            out.push(format!("audit.redact[{p}]"));
        }
    }
    if old.guardrails.pii_redact && !new.guardrails.pii_redact {
        out.push("guardrails.pii_redact".into());
    }
    if !old.telemetry_or_default().export_payloads && new.telemetry_or_default().export_payloads {
        out.push("telemetry.export_payloads".into());
    }
    if old.authz.default == Decision::Deny && new.authz.default == Decision::Allow {
        out.push("authz.default".into());
    }
    let removed = |field: &str, old: &[RegexRule], new: &[RegexRule], out: &mut Vec<String>| {
        for r in old {
            if !new.iter().any(|n| n.name == r.name && n.regex == r.regex) {
                out.push(format!("guardrails.{field}[{}]", r.name));
            }
        }
    };
    removed(
        "input_deny",
        &old.guardrails.input_deny,
        &new.guardrails.input_deny,
        &mut out,
    );
    removed(
        "output_deny",
        &old.guardrails.output_deny,
        &new.guardrails.output_deny,
        &mut out,
    );
    out
}

/// The role a write from `old` (the stored charter) to `new` needs (design §8.3), and, when that
/// is admin, one `"<field> requires admin"` reason per field that needs it. Any write needs at
/// least editor. Editors may change agents' `system`, `model`, `skills`, `harness`, `budgets`,
/// `learning` (except setting `mode: auto`) and tools of type `service` and `agent`; top-level
/// `skills`; the `guardrails.allowed_tools` / `allowed_services` entries; the agent names in
/// `authz.callers` rules whose identity is `local`; and create and delete agents (removing a
/// deleted agent's name from any `authz.callers` rule, and dropping a rule left empty, is part of
/// deleting it). Everything else needs admin: `service`, `mesh`, `audit`, `telemetry`, the
/// `guardrails` rules, `authz.default`, `authz.services`, any non-local `authz.callers` rule added,
/// changed or removed, an agent's `type`, `learning.mode: auto`, and a new `http` tool origin.
///
/// A service without a stored charter has nothing to diff against; creating its first charter
/// is an admin write (callers decide that case before calling this).
pub fn required_role(old: &Charter, new: &Charter) -> (Role, Vec<String>) {
    let mut admin: Vec<String> = Vec::new();
    let mut need = |changed: bool, field: &str| {
        if changed {
            admin.push(format!("{field} requires admin"));
        }
    };

    // service, mesh, audit, telemetry: admin only
    let (os, ns) = (&old.service, &new.service);
    need(os.name != ns.name, "service.name");
    need(os.namespace != ns.namespace, "service.namespace");
    need(os.app_port != ns.app_port, "service.app_port");
    need(
        sorted(&os.service_accounts) != sorted(&ns.service_accounts),
        "service.service_accounts",
    );
    need(old.mesh.port != new.mesh.port, "mesh.port");
    need(old.mesh.peers != new.mesh.peers, "mesh.peers");
    need(old.audit.sink != new.audit.sink, "audit.sink");
    need(old.audit.file != new.audit.file, "audit.file");
    need(old.audit.redact != new.audit.redact, "audit.redact");
    let (ot, nt) = (old.telemetry_or_default(), new.telemetry_or_default());
    need(
        ot.otlp_endpoint != nt.otlp_endpoint,
        "telemetry.otlp_endpoint",
    );
    need(ot.traces != nt.traces, "telemetry.traces");
    need(ot.metrics != nt.metrics, "telemetry.metrics");
    need(
        ot.export_payloads != nt.export_payloads,
        "telemetry.export_payloads",
    );
    need(
        ot.control_plane_payloads != nt.control_plane_payloads,
        "telemetry.control_plane_payloads",
    );

    // guardrails: the rules are admin; allowed_tools / allowed_services entries are editor
    let (og, ng) = (&old.guardrails, &new.guardrails);
    need(
        og.max_input_bytes != ng.max_input_bytes,
        "guardrails.max_input_bytes",
    );
    need(og.pii_redact != ng.pii_redact, "guardrails.pii_redact");
    need(
        rules(&og.input_deny) != rules(&ng.input_deny),
        "guardrails.input_deny",
    );
    need(
        rules(&og.output_deny) != rules(&ng.output_deny),
        "guardrails.output_deny",
    );

    // authz: default and services are admin; callers per the local / non-local split
    need(old.authz.default != new.authz.default, "authz.default");
    need(old.authz.services != new.authz.services, "authz.services");
    let deleted: BTreeSet<&str> = old
        .agents
        .iter()
        .map(|a| a.name.as_str())
        .filter(|n| new.agent(n).is_none())
        .collect();
    let before = non_local_callers(old.authz.callers.iter(), &deleted);
    let after = non_local_callers(new.authz.callers.iter(), &BTreeSet::new());
    let mut identities = BTreeSet::new();
    for (rule, n) in &after {
        if before.get(rule).copied().unwrap_or(0) < *n {
            identities.insert(rule.0.clone()); // added (or changed into) a non-local rule
        }
    }
    for (rule, n) in &before {
        if after.get(rule).copied().unwrap_or(0) < *n {
            identities.insert(rule.0.clone()); // a non-local rule changed or removed
        }
    }
    for id in identities {
        admin.push(format!("authz.callers rule for {id} requires admin"));
    }

    // agents: created and deleted ones are editor; per agent, only `type`, `learning.mode: auto`
    // and new http tool origins need admin
    let old_origins = http_origins(&old.agents);
    for a in &new.agents {
        let prev = old.agent(&a.name);
        if let Some(p) = prev
            && p.agent_type != a.agent_type
        {
            admin.push(format!("agents.{}.type requires admin", a.name));
        }
        let was_auto = prev.is_some_and(|p| p.learning_or_default().mode == LearningMode::Auto);
        if a.learning_or_default().mode == LearningMode::Auto && !was_auto {
            admin.push(format!(
                "agents.{}.learning.mode: auto requires admin",
                a.name
            ));
        }
        for t in a.tools.iter().filter(|t| t.tool_type == ToolType::Http) {
            let origin = t.url.as_deref().and_then(http_origin);
            match origin {
                Some(o) if old_origins.contains(&o) => {}
                Some(o) => admin.push(format!(
                    "agents.{}.tools.{} (new http origin {o}) requires admin",
                    a.name, t.name
                )),
                None => admin.push(format!("agents.{}.tools.{} requires admin", a.name, t.name)),
            }
        }
    }

    let mut seen = BTreeSet::new();
    admin.retain(|r| seen.insert(r.clone()));
    if admin.is_empty() {
        (Role::Editor, admin)
    } else {
        (Role::Admin, admin)
    }
}

fn sorted(v: &[String]) -> Vec<&String> {
    let mut out: Vec<&String> = v.iter().collect();
    out.sort();
    out
}

fn rules(v: &[RegexRule]) -> Vec<(&str, &str)> {
    v.iter()
        .map(|r| (r.name.as_str(), r.regex.as_str()))
        .collect()
}

/// An `authz.callers` rule in a canonical form: (identity, sorted agents, sorted caller_agents).
type CanonicalRule = (String, Vec<String>, Vec<String>);

/// The non-local `authz.callers` rules, canonical, with how many times each occurs. The names in
/// `drop_agents` (agents being deleted) are removed from `agents` first, and a rule left with no
/// agents is dropped.
fn non_local_callers<'a>(
    rules: impl Iterator<Item = &'a CallerRule>,
    drop_agents: &BTreeSet<&str>,
) -> BTreeMap<CanonicalRule, usize> {
    let mut out = BTreeMap::new();
    for r in rules.filter(|r| r.identity != LOCAL_IDENTITY) {
        let mut agents: Vec<String> = r
            .agents
            .iter()
            .filter(|a| !drop_agents.contains(a.as_str()))
            .cloned()
            .collect();
        if agents.is_empty() {
            continue;
        }
        agents.sort();
        agents.dedup();
        let mut callers = r.caller_agents.clone();
        callers.sort();
        callers.dedup();
        *out.entry((r.identity.clone(), agents, callers))
            .or_insert(0) += 1;
    }
    out
}

/// Origins of every `http` tool of these agents.
fn http_origins(agents: &[AgentSpec]) -> BTreeSet<String> {
    agents
        .iter()
        .flat_map(|a| a.tools.iter())
        .filter(|t| t.tool_type == ToolType::Http)
        .filter_map(|t| t.url.as_deref().and_then(http_origin))
        .collect()
}
