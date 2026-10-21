//! Edits of a stored charter document for the agent, skill and link endpoints (design §10,
//! AgentView). They work on the charter as JSON, as written (the `spec` of the custom-resource
//! form), so the rest of the document stays as it was; the result goes through the same checks
//! as any write ([`super::write`]).
use serde_json::{Map, Value, json};

use super::error::Fail;
use super::types::{AgentView, CallerRef, LinkTool, Skill};
use crate::store::charter_doc;

/// The plain charter object inside a stored document, for editing.
pub fn doc_mut(json: &mut Value) -> Result<&mut Map<String, Value>, Fail> {
    let is_cr = json.get("metadata").is_some() && json.get("spec").is_some();
    let doc = if is_cr {
        json.get_mut("spec")
    } else {
        Some(json)
    };
    doc.and_then(Value::as_object_mut)
        .ok_or_else(|| Fail::invalid(["the stored charter is not a YAML mapping"]))
}

fn list_mut<'a>(map: &'a mut Map<String, Value>, key: &str) -> Result<&'a mut Vec<Value>, Fail> {
    let v = map.entry(key).or_insert_with(|| Value::Array(Vec::new()));
    v.as_array_mut()
        .ok_or_else(|| Fail::invalid([format!("{key} is not a list")]))
}

fn object_mut<'a>(
    map: &'a mut Map<String, Value>,
    key: &str,
) -> Result<&'a mut Map<String, Value>, Fail> {
    let v = map.entry(key).or_insert_with(|| Value::Object(Map::new()));
    v.as_object_mut()
        .ok_or_else(|| Fail::invalid([format!("{key} is not a mapping")]))
}

fn name_of(v: &Value) -> Option<&str> {
    v.get("name").and_then(Value::as_str)
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The agent with the policy around it (`GET .../agents/{agent}`).
pub fn agent_view(json: &Value, agent: &str) -> Option<AgentView> {
    let doc = charter_doc(json);
    let entry = doc
        .get("agents")?
        .as_array()?
        .iter()
        .find(|a| name_of(a) == Some(agent))?
        .clone();
    let guard = doc.get("guardrails");
    let entry_of = |key: &str| {
        guard
            .and_then(|g| g.get(key))
            .and_then(|m| m.get(agent))
            .map(|v| strings(Some(v)))
    };
    let callers = doc
        .get("authz")
        .and_then(|a| a.get("callers"))
        .and_then(Value::as_array)
        .map(|rules| {
            rules
                .iter()
                .filter(|r| {
                    strings(r.get("agents"))
                        .iter()
                        .any(|a| a == "*" || a == agent)
                })
                .map(|r| CallerRef {
                    identity: r
                        .get("identity")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    caller_agents: r.get("caller_agents").map(|c| strings(Some(c))),
                })
                .collect()
        })
        .unwrap_or_default();
    Some(AgentView {
        agent: entry,
        allowed_tools: entry_of("allowed_tools"),
        allowed_services: entry_of("allowed_services"),
        callers: Some(callers),
    })
}

fn view_name(view: &AgentView) -> Result<String, Fail> {
    name_of(&view.agent)
        .map(str::to_string)
        .ok_or_else(|| Fail::invalid(["agent.name is required"]))
}

fn tool_names(agent: &Value) -> Vec<String> {
    agent
        .get("tools")
        .and_then(Value::as_array)
        .map(|t| {
            t.iter()
                .filter_map(|x| name_of(x).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn set_entry(
    doc: &mut Map<String, Value>,
    key: &str,
    agent: &str,
    list: Option<&Vec<String>>,
) -> Result<(), Fail> {
    match list {
        Some(l) => {
            let g = object_mut(doc, "guardrails")?;
            object_mut(g, key)?.insert(agent.to_string(), json!(l));
        }
        None => {
            if let Some(m) = doc
                .get_mut("guardrails")
                .and_then(Value::as_object_mut)
                .and_then(|g| g.get_mut(key))
                .and_then(Value::as_object_mut)
            {
                m.remove(agent);
            }
        }
    }
    Ok(())
}

fn same_callers(rule: &Value, wanted: &Option<Vec<String>>) -> bool {
    let mut have = strings(rule.get("caller_agents"));
    let mut want = wanted.clone().unwrap_or_default();
    have.sort();
    want.sort();
    have == want
}

fn rule_admits(rule: &Value, agent: &str) -> bool {
    strings(rule.get("agents"))
        .iter()
        .any(|a| a == "*" || a == agent)
}

/// Add `agent` to a rule of `identity` with these `caller_agents`, creating one when none.
fn admit(
    callers: &mut Vec<Value>,
    identity: &str,
    caller_agents: &Option<Vec<String>>,
    agent: &str,
) {
    if let Some(rule) = callers.iter_mut().find(|r| {
        r.get("identity").and_then(Value::as_str) == Some(identity)
            && same_callers(r, caller_agents)
    }) {
        if !rule_admits(rule, agent)
            && let Some(list) = rule.get_mut("agents").and_then(Value::as_array_mut)
        {
            list.push(json!(agent));
        }
        return;
    }
    let mut rule = Map::new();
    rule.insert("identity".into(), json!(identity));
    rule.insert("agents".into(), json!([agent]));
    if let Some(c) = caller_agents.as_ref().filter(|c| !c.is_empty()) {
        rule.insert("caller_agents".into(), json!(c));
    }
    callers.push(Value::Object(rule));
}

/// Remove `agent` from every rule that names it, dropping rules left with no agents.
fn unadmit(callers: &mut Vec<Value>, agent: &str, keep: impl Fn(&Value) -> bool) {
    callers.retain_mut(|r| {
        if keep(r) {
            return true;
        }
        let Some(list) = r.get_mut("agents").and_then(Value::as_array_mut) else {
            return true;
        };
        let before = list.len();
        list.retain(|a| a.as_str() != Some(agent));
        !(list.is_empty() && before > 0)
    });
}

fn callers_mut(doc: &mut Map<String, Value>) -> Result<&mut Vec<Value>, Fail> {
    list_mut(object_mut(doc, "authz")?, "callers")
}

/// `POST .../agents`: add the agent; without `callers` it joins the `identity: local` rule
/// (created as `{identity: local, agents: [name]}` when there is none).
pub fn add_agent(json: &mut Value, view: &AgentView) -> Result<String, Fail> {
    let name = view_name(view)?;
    let doc = doc_mut(json)?;
    let agents = list_mut(doc, "agents")?;
    if agents.iter().any(|a| name_of(a) == Some(name.as_str())) {
        return Err(Fail::invalid([format!(
            "agent {name} already exists (PUT .../agents/{name} changes it)"
        )]));
    }
    agents.push(view.agent.clone());
    set_entry(doc, "allowed_tools", &name, view.allowed_tools.as_ref())?;
    set_entry(
        doc,
        "allowed_services",
        &name,
        view.allowed_services.as_ref(),
    )?;
    let callers = callers_mut(doc)?;
    match &view.callers {
        None => {
            match callers
                .iter_mut()
                .find(|r| r.get("identity").and_then(Value::as_str) == Some("local"))
            {
                Some(rule) => {
                    if !rule_admits(rule, &name)
                        && let Some(list) = rule.get_mut("agents").and_then(Value::as_array_mut)
                    {
                        list.push(json!(name));
                    }
                }
                None => callers.push(json!({"identity": "local", "agents": [name]})),
            }
        }
        Some(refs) => {
            for r in refs {
                admit(callers, &r.identity, &r.caller_agents, &name);
            }
        }
    }
    Ok(name)
}

/// `PUT .../agents/{agent}`: replace the agent; `allowed_tools` entries naming tools it no
/// longer declares are pruned; with `callers`, the rules that name the agent become exactly
/// those (rules admitting `"*"` stay).
pub fn replace_agent(json: &mut Value, name: &str, view: &AgentView) -> Result<(), Fail> {
    let given = view_name(view)?;
    if given != name {
        return Err(Fail::invalid([format!(
            "agent.name {given:?} is not {name:?} (the agent of the path)"
        )]));
    }
    let doc = doc_mut(json)?;
    let agents = list_mut(doc, "agents")?;
    let slot = agents
        .iter_mut()
        .find(|a| name_of(a) == Some(name))
        .ok_or_else(|| Fail::not_found(format!("no agent {name}")))?;
    let old_tools = tool_names(slot);
    let new_tools = tool_names(&view.agent);
    *slot = view.agent.clone();
    let removed: Vec<&String> = old_tools
        .iter()
        .filter(|t| !new_tools.contains(t))
        .collect();
    let allowed = view.allowed_tools.as_ref().map(|l| {
        l.iter()
            .filter(|t| !removed.contains(t))
            .cloned()
            .collect::<Vec<_>>()
    });
    set_entry(doc, "allowed_tools", name, allowed.as_ref())?;
    set_entry(
        doc,
        "allowed_services",
        name,
        view.allowed_services.as_ref(),
    )?;
    if let Some(refs) = &view.callers {
        let callers = callers_mut(doc)?;
        let listed = |r: &Value| {
            refs.iter().any(|c| {
                r.get("identity").and_then(Value::as_str) == Some(c.identity.as_str())
                    && same_callers(r, &c.caller_agents)
            })
        };
        // keep the rules that are listed, and the ones that admit everyone
        unadmit(callers, name, |r| {
            listed(r) || strings(r.get("agents")).iter().any(|a| a == "*")
        });
        for c in refs {
            let admitted = callers.iter().any(|r| {
                r.get("identity").and_then(Value::as_str) == Some(c.identity.as_str())
                    && same_callers(r, &c.caller_agents)
                    && rule_admits(r, name)
            });
            if !admitted {
                admit(callers, &c.identity, &c.caller_agents, name);
            }
        }
    }
    Ok(())
}

/// `DELETE .../agents/{agent}`: 409 `in_use` while a local orchestrator's agent tool targets it;
/// else remove the agent, its `guardrails.allowed_*` keys and its name from every
/// `authz.callers[].agents` (dropping rules left empty).
pub fn delete_agent(json: &mut Value, own_service: &str, name: &str) -> Result<(), Fail> {
    let doc = doc_mut(json)?;
    let agents = list_mut(doc, "agents")?;
    if !agents.iter().any(|a| name_of(a) == Some(name)) {
        return Err(Fail::not_found(format!("no agent {name}")));
    }
    let mut users = Vec::new();
    for a in agents.iter().filter(|a| name_of(a) != Some(name)) {
        for t in a
            .get("tools")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let local = t
                .get("service")
                .and_then(Value::as_str)
                .is_none_or(|s| s == own_service);
            if t.get("type").and_then(Value::as_str) == Some("agent")
                && local
                && t.get("agent").and_then(Value::as_str) == Some(name)
            {
                users.push(format!(
                    "agents.{}.tools.{} targets {name}",
                    name_of(a).unwrap_or(""),
                    name_of(t).unwrap_or("")
                ));
            }
        }
    }
    if !users.is_empty() {
        return Err(Fail::in_use(users));
    }
    agents.retain(|a| name_of(a) != Some(name));
    set_entry(doc, "allowed_tools", name, None)?;
    set_entry(doc, "allowed_services", name, None)?;
    if doc.get("authz").is_some() {
        let callers = callers_mut(doc)?;
        unadmit(callers, name, |_| false);
    }
    Ok(())
}

/// `PUT .../skills/{skill}`: create or replace.
pub fn put_skill(json: &mut Value, name: &str, skill: &Skill) -> Result<(), Fail> {
    if skill.name != name {
        return Err(Fail::invalid([format!(
            "name {:?} is not {name:?} (the skill of the path)",
            skill.name
        )]));
    }
    let value = serde_json::to_value(skill).map_err(Fail::internal)?;
    let doc = doc_mut(json)?;
    let skills = list_mut(doc, "skills")?;
    match skills.iter_mut().find(|s| name_of(s) == Some(name)) {
        Some(slot) => *slot = value,
        None => skills.push(value),
    }
    Ok(())
}

/// `DELETE .../skills/{skill}`: 409 `in_use` while an agent lists it.
pub fn delete_skill(json: &mut Value, name: &str) -> Result<(), Fail> {
    let doc = doc_mut(json)?;
    let users: Vec<String> = doc
        .get("agents")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|a| strings(a.get("skills")).iter().any(|s| s == name))
        .map(|a| format!("agents.{} uses the skill {name}", name_of(a).unwrap_or("")))
        .collect();
    if !users.is_empty() {
        return Err(Fail::in_use(users));
    }
    let skills = list_mut(doc, "skills")?;
    let before = skills.len();
    skills.retain(|s| name_of(s) != Some(name));
    if skills.len() == before {
        return Err(Fail::not_found(format!("no skill {name}")));
    }
    if skills.is_empty() {
        doc.remove("skills");
    }
    Ok(())
}

/// The caller side of a link: the orchestrator `from` gets an `agent` tool to `to_agent` (in
/// `to_service` when that is another service), and the `guardrails.allowed_*` entries it has
/// are extended. Same service: a local caller rule must admit the target too.
pub fn link_source(
    json: &mut Value,
    from: &str,
    tool: &LinkTool,
    to_service: Option<&str>,
    to_agent: &str,
) -> Result<(), Fail> {
    let doc = doc_mut(json)?;
    let agents = list_mut(doc, "agents")?;
    let agent = agents
        .iter_mut()
        .find(|a| name_of(a) == Some(from))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| Fail::not_found(format!("no agent {from}")))?;
    let tools = list_mut(agent, "tools")?;
    if tools.iter().any(|t| name_of(t) == Some(tool.name.as_str())) {
        return Err(Fail::invalid([format!(
            "agents.{from} already has a tool {}",
            tool.name
        )]));
    }
    let mut t = Map::new();
    t.insert("name".into(), json!(tool.name));
    t.insert("description".into(), json!(tool.description));
    t.insert("type".into(), json!("agent"));
    if let Some(s) = to_service {
        t.insert("service".into(), json!(s));
    }
    t.insert("agent".into(), json!(to_agent));
    tools.push(Value::Object(t));
    if let Some(list) = doc
        .get_mut("guardrails")
        .and_then(|g| g.get_mut("allowed_tools"))
        .and_then(|m| m.get_mut(from))
        .and_then(Value::as_array_mut)
    {
        list.push(json!(tool.name));
    }
    if let Some(s) = to_service
        && let Some(list) = doc
            .get_mut("guardrails")
            .and_then(|g| g.get_mut("allowed_services"))
            .and_then(|m| m.get_mut(from))
            .and_then(Value::as_array_mut)
        && !list.iter().any(|x| x.as_str() == Some(s))
    {
        list.push(json!(s));
    }
    if to_service.is_none() {
        let callers = callers_mut(doc)?;
        let admitted = callers.iter().any(|r| {
            r.get("identity").and_then(Value::as_str) == Some("local")
                && rule_admits(r, to_agent)
                && {
                    let c = strings(r.get("caller_agents"));
                    c.is_empty() || c.iter().any(|x| x == from)
                }
        });
        if !admitted {
            admit(callers, "local", &None, to_agent);
        }
    }
    Ok(())
}

/// The callee side of a cross-service link: `authz.callers` admits `identity` (the caller's
/// service) calling `to_agent` from `from_agent`. `false` when a rule admits that already.
pub fn link_target(
    json: &mut Value,
    identity: &str,
    from_agent: &str,
    to_agent: &str,
) -> Result<bool, Fail> {
    let doc = doc_mut(json)?;
    if !doc
        .get("agents")
        .and_then(Value::as_array)
        .is_some_and(|a| a.iter().any(|x| name_of(x) == Some(to_agent)))
    {
        return Err(Fail::not_found(format!("no agent {to_agent}")));
    }
    let callers = callers_mut(doc)?;
    let admitted = callers.iter().any(|r| {
        r.get("identity").and_then(Value::as_str) == Some(identity) && rule_admits(r, to_agent) && {
            let c = strings(r.get("caller_agents"));
            c.is_empty() || c.iter().any(|x| x == from_agent)
        }
    });
    if admitted {
        return Ok(false);
    }
    admit(
        callers,
        identity,
        &Some(vec![from_agent.to_string()]),
        to_agent,
    );
    Ok(true)
}

/// The charter as YAML text.
pub fn to_yaml(json: &Value) -> Result<String, Fail> {
    serde_yaml_ng::to_string(json).map_err(Fail::internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc() -> Value {
        json!({
            "apiVersion": "attache.io/v1alpha1", "kind": "Charter",
            "service": {"name": "orders", "namespace": "shop", "app_port": 8080},
            "agents": [
                {"name": "boss", "type": "orchestrator", "model": "mock",
                 "tools": [{"name": "ask_helper", "description": "d", "type": "agent", "agent": "helper"}]},
                {"name": "helper", "model": "mock",
                 "tools": [{"name": "lookup", "description": "d", "type": "service", "service": "orders", "method": "GET", "path": "/x"}]}
            ],
            "guardrails": {"allowed_tools": {"helper": ["lookup"]}},
            "authz": {"default": "deny", "callers": [
                {"identity": "local", "agents": ["boss", "helper"]},
                {"identity": "spiffe://attache/ns/shop/svc/billing", "agents": ["helper"], "caller_agents": ["payer"]}
            ]}
        })
    }

    #[test]
    fn views() {
        let v = agent_view(&doc(), "helper").unwrap();
        assert_eq!(v.allowed_tools, Some(vec!["lookup".to_string()]));
        assert_eq!(v.allowed_services, None);
        let callers = v.callers.unwrap();
        assert_eq!(callers.len(), 2);
        assert_eq!(callers[0].caller_agents, None);
        assert_eq!(callers[1].caller_agents, Some(vec!["payer".to_string()]));
        assert!(agent_view(&doc(), "ghost").is_none());
        // the custom-resource form
        let cr = json!({"apiVersion": "attache.io/v1alpha1", "kind": "Charter",
            "metadata": {"name": "orders", "namespace": "shop"}, "spec": doc()});
        assert!(agent_view(&cr, "boss").is_some());
    }

    #[test]
    fn add_joins_the_local_rule_or_creates_it() {
        let mut d = doc();
        let view = AgentView {
            agent: json!({"name": "new", "model": "mock"}),
            allowed_tools: Some(vec![]),
            allowed_services: None,
            callers: None,
        };
        add_agent(&mut d, &view).unwrap();
        assert_eq!(
            d["authz"]["callers"][0]["agents"],
            json!(["boss", "helper", "new"])
        );
        assert_eq!(d["guardrails"]["allowed_tools"]["new"], json!([]));
        assert!(add_agent(&mut d, &view).is_err(), "twice");
        // no local rule: one is created
        let mut d = json!({"service": {}, "agents": []});
        add_agent(&mut d, &view).unwrap();
        assert_eq!(
            d["authz"]["callers"],
            json!([{"identity": "local", "agents": ["new"]}])
        );
        // explicit callers
        let mut d = doc();
        let view = AgentView {
            callers: Some(vec![CallerRef {
                identity: "spiffe://attache/ns/shop/svc/billing".into(),
                caller_agents: Some(vec!["payer".into()]),
            }]),
            ..view
        };
        add_agent(&mut d, &view).unwrap();
        assert_eq!(d["authz"]["callers"][1]["agents"], json!(["helper", "new"]));
        assert_eq!(
            d["authz"]["callers"][0]["agents"],
            json!(["boss", "helper"])
        );
    }

    #[test]
    fn put_prunes_removed_tools_and_syncs_callers() {
        let mut d = doc();
        let view = AgentView {
            agent: json!({"name": "helper", "model": "claude-opus-5-5", "tools": []}),
            allowed_tools: Some(vec!["lookup".into()]),
            allowed_services: None,
            callers: Some(vec![CallerRef {
                identity: "local".into(),
                caller_agents: None,
            }]),
        };
        replace_agent(&mut d, "helper", &view).unwrap();
        assert_eq!(d["agents"][1]["model"], "claude-opus-5-5");
        assert_eq!(d["guardrails"]["allowed_tools"]["helper"], json!([]));
        // the billing rule named only helper: dropped
        assert_eq!(d["authz"]["callers"].as_array().unwrap().len(), 1);
        assert!(
            replace_agent(&mut d, "boss", &view).is_err(),
            "name differs from the path"
        );
        let ghost = AgentView {
            agent: json!({"name": "ghost", "model": "mock"}),
            ..view
        };
        assert_eq!(
            replace_agent(&mut d, "ghost", &ghost).unwrap_err().status(),
            axum::http::StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn delete_cascades_and_refuses_targets_of_local_orchestrators() {
        let mut d = doc();
        let e = delete_agent(&mut d, "orders", "helper").unwrap_err();
        assert_eq!(e.code(), super::super::types::ErrorCode::InUse);
        assert!(
            e.reason().contains("agents.boss.tools.ask_helper"),
            "{}",
            e.reason()
        );
        // remove the tool first, then delete
        d["agents"][0]["tools"] = json!([]);
        delete_agent(&mut d, "orders", "helper").unwrap();
        assert_eq!(d["agents"].as_array().unwrap().len(), 1);
        assert!(d["guardrails"]["allowed_tools"].get("helper").is_none());
        assert_eq!(
            d["authz"]["callers"],
            json!([{"identity": "local", "agents": ["boss"]}]),
            "the billing rule left empty is dropped"
        );
        assert!(delete_agent(&mut d, "orders", "helper").is_err());
    }

    #[test]
    fn skills() {
        let mut d = doc();
        let s = Skill {
            name: "tone".into(),
            description: "d".into(),
            instructions: "i".into(),
            tools: None,
        };
        put_skill(&mut d, "tone", &s).unwrap();
        put_skill(&mut d, "tone", &s).unwrap();
        assert_eq!(d["skills"].as_array().unwrap().len(), 1);
        assert!(put_skill(&mut d, "other", &s).is_err());
        d["agents"][0]["skills"] = json!(["tone"]);
        assert_eq!(
            delete_skill(&mut d, "tone").unwrap_err().code(),
            super::super::types::ErrorCode::InUse
        );
        d["agents"][0]["skills"] = json!([]);
        delete_skill(&mut d, "tone").unwrap();
        assert!(d.get("skills").is_none());
        assert!(delete_skill(&mut d, "tone").is_err());
    }

    #[test]
    fn links() {
        let tool = LinkTool {
            name: "ask_new".into(),
            description: "d".into(),
        };
        // same service: a tool and a local rule
        let mut d = doc();
        d["agents"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name": "solo", "model": "mock"}));
        link_source(&mut d, "boss", &tool, None, "solo").unwrap();
        assert_eq!(
            d["agents"][0]["tools"][1],
            json!({"name": "ask_new", "description": "d", "type": "agent", "agent": "solo"})
        );
        assert_eq!(
            d["authz"]["callers"][0]["agents"],
            json!(["boss", "helper", "solo"])
        );
        assert!(
            link_source(&mut d, "boss", &tool, None, "solo").is_err(),
            "the tool exists"
        );
        // cross service: the source gets service and allowed entries
        let mut d = doc();
        d["guardrails"]["allowed_tools"]["boss"] = json!(["ask_helper"]);
        d["guardrails"]["allowed_services"] = json!({"boss": ["orders"]});
        link_source(&mut d, "boss", &tool, Some("inventory"), "stock-analyst").unwrap();
        assert_eq!(d["agents"][0]["tools"][1]["service"], "inventory");
        assert_eq!(
            d["guardrails"]["allowed_tools"]["boss"],
            json!(["ask_helper", "ask_new"])
        );
        assert_eq!(
            d["guardrails"]["allowed_services"]["boss"],
            json!(["orders", "inventory"])
        );
        // the target admits the caller's service and agent once
        let mut t = doc();
        let id = "spiffe://attache/ns/shop/svc/support";
        assert!(link_target(&mut t, id, "support-agent", "helper").unwrap());
        assert!(!link_target(&mut t, id, "support-agent", "helper").unwrap());
        assert_eq!(
            t["authz"]["callers"][2],
            json!({"identity": id, "agents": ["helper"], "caller_agents": ["support-agent"]})
        );
        assert!(link_target(&mut t, id, "x", "ghost").is_err());
    }
}
