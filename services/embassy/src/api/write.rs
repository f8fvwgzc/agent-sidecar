//! Every charter write (design §8.3, §8.4): charter validator → policy → role on the diff →
//! version-skew check → (restart-only fields while instances are connected) → store, and the
//! control-plane audit record of the attempt.
use agentsc_charter::Charter;
use agentsc_charter::diff::{self, FirstCharter};
use serde_json::Value;

use super::error::Fail;
use super::types::{CpAction, CpResult, ErrorCode};
use crate::config::{PolicyConfig, Role};
use crate::cp_audit::CpAudit;
use crate::hub::Hub;
use crate::registry::Registry;
use crate::store::file::{sha256_hex, yaml_to_json};
use crate::store::{Actor, ChangeSource, CharterWrite, Precondition, ServiceKey, StoredCharter};

/// How a write reaches the store; decides the role a first charter needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// `PUT .../charter`.
    Put,
    /// `POST .../adopt` (and `--auto-adopt`).
    Adopt,
    /// Agents, skills and links.
    Edit,
    /// `POST .../charter/rollback`.
    Rollback,
}

/// A validated candidate charter.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub yaml: String,
    pub charter: Charter,
    /// The YAML as JSON, as written.
    pub json: Value,
}

fn lines(e: agentsc_charter::CharterError) -> Vec<String> {
    match e {
        agentsc_charter::CharterError::Invalid(v) => v,
        other => vec![other.to_string()],
    }
}

/// The charter validator, plus: the charter names the service of the path.
pub fn candidate(key: &ServiceKey, yaml: String) -> Result<Candidate, Fail> {
    let charter = Charter::from_yaml(&yaml).map_err(|e| Fail::invalid(lines(e)))?;
    let mut errs = Vec::new();
    if charter.service.name != key.service {
        errs.push(format!(
            "service.name {:?} is not {:?} (the service of the path)",
            charter.service.name, key.service
        ));
    }
    if charter.service.namespace != key.namespace {
        errs.push(format!(
            "service.namespace {:?} is not {:?} (the namespace of the path)",
            charter.service.namespace, key.namespace
        ));
    }
    if !errs.is_empty() {
        return Err(Fail::invalid(errs));
    }
    let json = yaml_to_json(&yaml).map_err(|e| Fail::invalid([e]))?;
    Ok(Candidate {
        yaml,
        charter,
        json,
    })
}

/// The `policy` of the ControlPlaneConfig (design §8.2), each problem naming its rule.
pub fn policy_problems(policy: Option<&PolicyConfig>, c: &Charter) -> Vec<String> {
    let Some(p) = policy else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if p.require_authz_default_deny && c.authz.default != agentsc_charter::Decision::Deny {
        out.push("policy.require_authz_default_deny: authz.default must be deny".to_string());
    }
    if let Some(allow) = &p.http_origin_allowlist {
        for a in &c.agents {
            for t in a
                .tools
                .iter()
                .filter(|t| t.tool_type == agentsc_charter::ToolType::Http)
            {
                let origin = t.url.as_deref().and_then(agentsc_charter::http_origin);
                match origin {
                    Some(o) if allow.contains(&o) => {}
                    Some(o) => out.push(format!(
                        "policy.http_origin_allowlist: agents.{}.tools.{} uses the origin {o}, which is not allowed",
                        a.name, t.name
                    )),
                    None => out.push(format!(
                        "policy.http_origin_allowlist: agents.{}.tools.{} has no http(s) origin",
                        a.name, t.name
                    )),
                }
            }
        }
    }
    if p.forbid_learning_auto {
        for a in &c.agents {
            if a.learning_or_default().mode == agentsc_charter::LearningMode::Auto {
                out.push(format!(
                    "policy.forbid_learning_auto: agents.{}.learning.mode is auto",
                    a.name
                ));
            }
        }
    }
    out
}

fn role_of(r: diff::Role) -> Role {
    match r {
        diff::Role::Viewer => Role::Viewer,
        diff::Role::Editor => Role::Editor,
        diff::Role::Admin => Role::Admin,
    }
}

/// The role a write needs (design §8.3) and why: on the diff against the stored charter, or for
/// a service's first charter by the way it comes (editor to adopt, admin to `PUT`). A stored
/// charter that no longer parses can only be replaced by an admin.
pub fn needed_role(stored: Option<&StoredCharter>, new: &Charter, via: Via) -> (Role, Vec<String>) {
    let (role, reasons) = match stored {
        None => diff::first_charter_role(match via {
            Via::Adopt => FirstCharter::Adopt,
            _ => FirstCharter::Put,
        }),
        Some(s) => match Charter::from_yaml(&s.yaml) {
            Ok(old) => diff::required_role(&old, new),
            Err(_) => (
                diff::Role::Admin,
                vec!["replacing a stored charter that no longer validates requires admin".into()],
            ),
        },
    };
    let mut role = role_of(role);
    let mut reasons = reasons;
    if via == Via::Rollback && role < Role::Admin {
        role = Role::Admin;
        reasons.push("rollback requires admin".into());
    }
    (role, reasons)
}

/// The fields of a v0.2 charter (`charter_schema_level` 2), as paths.
pub fn level2_fields(c: &Charter) -> Vec<String> {
    let mut out = Vec::new();
    if !c.skills.is_empty() {
        out.push("skills".to_string());
    }
    if c.telemetry.is_some() {
        out.push("telemetry".into());
    }
    if !c.service.service_accounts.is_empty() {
        out.push("service.service_accounts".into());
    }
    for a in &c.agents {
        if !a.skills.is_empty() {
            out.push(format!("agents.{}.skills", a.name));
        }
        if a.harness.is_some() {
            out.push(format!("agents.{}.harness", a.name));
        }
        if a.learning.is_some() {
            out.push(format!("agents.{}.learning", a.name));
        }
    }
    out
}

/// Design §7 version skew: the charter must load on the lowest `charter_schema_level` of the
/// service's connected instances. One detail per field, naming the instances.
pub fn skew_problems(registry: &Registry, key: &ServiceKey, c: &Charter) -> Vec<String> {
    skew_against(
        registry
            .instances(key)
            .into_iter()
            .map(|i| (i.info.pod, i.schema_level))
            .collect(),
        c,
    )
}

/// [`skew_problems`] for explicit `(pod, level)` pairs.
pub fn skew_against(instances: Vec<(String, u32)>, c: &Charter) -> Vec<String> {
    let Some(lowest) = instances.iter().map(|(_, l)| (*l).max(1)).min() else {
        return Vec::new();
    };
    let level = c.schema_level();
    if level <= lowest {
        return Vec::new();
    }
    let pods: Vec<String> = instances
        .iter()
        .filter(|(_, l)| (*l).max(1) < level)
        .map(|(p, l)| format!("{p} (level {})", (*l).max(1)))
        .collect();
    level2_fields(c)
        .into_iter()
        .map(|f| {
            format!(
                "{f} needs charter_schema_level {level}; connected instances that cannot load it: {}",
                pods.join(", ")
            )
        })
        .collect()
}

/// Design §4: restart-only fields may not change while instances are connected.
pub fn restart_problems(
    registry: &Registry,
    key: &ServiceKey,
    stored: Option<&StoredCharter>,
    new: &Charter,
) -> Vec<String> {
    restart_problems_yaml(registry, key, stored.map(|s| s.yaml.as_str()), new)
}

/// [`restart_problems`] against the text of the charter being replaced.
pub fn restart_problems_yaml(
    registry: &Registry,
    key: &ServiceKey,
    old_yaml: Option<&str>,
    new: &Charter,
) -> Vec<String> {
    let Some(old) = old_yaml.and_then(|y| Charter::from_yaml(y).ok()) else {
        return Vec::new();
    };
    let instances = registry.instances(key);
    if instances.is_empty() {
        return Vec::new();
    }
    let pods: Vec<String> = instances.into_iter().map(|i| i.info.pod).collect();
    diff::restart_required(&old, new)
        .into_iter()
        .map(|f| {
            format!(
                "{f} can only change with a restart; connected instances: {}",
                pods.join(", ")
            )
        })
        .collect()
}

/// Who writes: the actor, and the role to check on the diff (`None`: a sidecar adopting by
/// `--auto-adopt`, which has no role and is admitted by the flag).
#[derive(Debug, Clone)]
pub struct Writer {
    pub actor: Actor,
    pub role: Option<Role>,
}

#[allow(clippy::too_many_arguments)]
/// The checks of every write, then the store. `stored` is what the caller read; `precondition`
/// makes sure it is still current when the store writes.
pub async fn write(
    hub: &Hub,
    writer: &Writer,
    key: &ServiceKey,
    precondition: Precondition,
    stored: Option<&StoredCharter>,
    cand: Candidate,
    via: Via,
    source: ChangeSource,
) -> Result<StoredCharter, Fail> {
    let config = hub.config.load();
    let policy = policy_problems(config.policy.as_ref(), &cand.charter);
    if !policy.is_empty() {
        return Err(Fail::invalid(policy));
    }
    if let Some(role) = writer.role {
        let (need, reasons) = needed_role(stored, &cand.charter, via);
        if role < need {
            return Err(Fail::forbidden(if reasons.is_empty() {
                vec![format!("this write requires {need}")]
            } else {
                reasons
            }));
        }
    }
    let skew = skew_problems(&hub.registry, key, &cand.charter);
    if !skew.is_empty() {
        return Err(Fail::new(ErrorCode::VersionSkew, skew));
    }
    let restart = restart_problems(&hub.registry, key, stored, &cand.charter);
    if !restart.is_empty() {
        return Err(Fail::new(ErrorCode::RestartRequired, restart));
    }
    hub.store
        .put_charter(
            key,
            &precondition,
            CharterWrite {
                yaml: cand.yaml,
                charter_json: cand.json,
                actor: writer.actor.clone(),
                source,
            },
        )
        .await
        .map_err(|e| Fail::store(e, &format!("no charter for {key}")))
}

/// The audit result of a failed request.
pub fn result_of(f: &Fail) -> CpResult {
    match f.code() {
        ErrorCode::Forbidden | ErrorCode::Unauthenticated => CpResult::Denied,
        ErrorCode::Invalid | ErrorCode::RestartRequired | ErrorCode::VersionSkew => {
            CpResult::Invalid
        }
        _ => CpResult::Error,
    }
}

/// Write the control-plane audit record of a charter write attempt.
pub async fn audit_write(
    hub: &Hub,
    action: CpAction,
    actor: &Actor,
    key: &ServiceKey,
    agent: Option<&str>,
    before: Option<&StoredCharter>,
    result: &Result<StoredCharter, Fail>,
) {
    let mut rec = CpAudit::entry(
        action,
        actor,
        match result {
            Ok(_) => CpResult::Ok,
            Err(f) => result_of(f),
        },
    );
    rec.namespace = Some(key.namespace.clone());
    rec.service = Some(key.service.clone());
    rec.agent = agent.map(str::to_string);
    rec.from_version = before.map(|s| s.version.clone());
    rec.sha256_before = before.map(|s| sha256_hex(&s.yaml));
    match result {
        Ok(s) => {
            rec.to_version = Some(s.version.clone());
            rec.sha256_after = Some(sha256_hex(&s.yaml));
        }
        Err(f) => rec.reason = Some(f.reason()),
    }
    hub.cp_audit.record(rec).await;
}

/// Validate `yaml` and write it, audited as `action`.
#[allow(clippy::too_many_arguments)]
pub async fn audited_write(
    hub: &Hub,
    writer: &Writer,
    action: CpAction,
    agent: Option<&str>,
    key: &ServiceKey,
    precondition: Precondition,
    stored: Option<&StoredCharter>,
    yaml: String,
    via: Via,
    source: ChangeSource,
) -> Result<StoredCharter, Fail> {
    let result = match candidate(key, yaml) {
        Ok(cand) => write(hub, writer, key, precondition, stored, cand, via, source).await,
        Err(f) => Err(f),
    };
    audit_write(hub, action, &writer.actor, key, agent, stored, &result).await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn charter(extra: &str) -> Charter {
        Charter::from_yaml(&format!(
            "apiVersion: agentsc.io/v1alpha1\nkind: Charter\nservice: {{name: orders, namespace: shop, app_port: 8080}}\n{extra}"
        ))
        .unwrap()
    }

    #[test]
    fn candidates_name_the_service_of_the_path() {
        let yaml = charter("").to_yaml().unwrap();
        assert!(candidate(&ServiceKey::new("shop", "orders"), yaml.clone()).is_ok());
        let e = candidate(&ServiceKey::new("shop", "billing"), yaml.clone()).unwrap_err();
        assert!(e.reason().contains("service.name"), "{}", e.reason());
        let e = candidate(&ServiceKey::new("shop", "orders"), "service: [".into()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::Invalid);
    }

    #[test]
    fn policy() {
        let c = charter(
            "authz: {default: allow}\nagents:\n  - name: a\n    model: mock\n    learning: {enabled: true, mode: auto}\n    tools:\n      - {name: t, description: d, type: http, method: GET, url: 'https://x.example/p'}\n",
        );
        assert!(policy_problems(None, &c).is_empty());
        let p = PolicyConfig {
            require_authz_default_deny: true,
            http_origin_allowlist: Some(vec!["https://y.example".into()]),
            forbid_learning_auto: true,
        };
        let got = policy_problems(Some(&p), &c).join("\n");
        assert!(got.contains("require_authz_default_deny"), "{got}");
        assert!(got.contains("https://x.example"), "{got}");
        assert!(got.contains("forbid_learning_auto: agents.a"), "{got}");
        let ok = PolicyConfig {
            http_origin_allowlist: Some(vec!["https://x.example".into()]),
            ..Default::default()
        };
        assert!(policy_problems(Some(&ok), &c).is_empty());
    }

    #[test]
    fn skew_names_fields_and_pods() {
        let v1 = charter("agents:\n  - {name: a, model: mock}\n");
        let v2 = charter("agents:\n  - name: a\n    model: mock\n    harness: {max_retries: 1}\n");
        assert!(skew_against(vec![], &v2).is_empty());
        assert!(skew_against(vec![("p".into(), 2)], &v2).is_empty());
        assert!(skew_against(vec![("p".into(), 1)], &v1).is_empty());
        let got = skew_against(vec![("p1".into(), 2), ("p0".into(), 0)], &v2);
        assert_eq!(got.len(), 1);
        assert!(
            got[0].starts_with("agents.a.harness needs charter_schema_level 2"),
            "{got:?}"
        );
        assert!(
            got[0].contains("p0 (level 1)") && !got[0].contains("p1"),
            "{got:?}"
        );
    }

    #[test]
    fn first_charters_and_rollbacks() {
        let c = charter("");
        assert_eq!(needed_role(None, &c, Via::Adopt).0, Role::Editor);
        assert_eq!(needed_role(None, &c, Via::Put).0, Role::Admin);
        let stored = StoredCharter {
            epoch: "e".into(),
            version: "1".into(),
            yaml: c.to_yaml().unwrap(),
            charter_json: serde_json::Value::Null,
        };
        assert_eq!(needed_role(Some(&stored), &c, Via::Edit).0, Role::Editor);
        assert_eq!(needed_role(Some(&stored), &c, Via::Rollback).0, Role::Admin);
        let broken = StoredCharter {
            yaml: "nope".into(),
            ..stored
        };
        assert_eq!(needed_role(Some(&broken), &c, Via::Edit).0, Role::Admin);
    }
}
