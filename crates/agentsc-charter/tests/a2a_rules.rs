//! A2A (charter schema level 10, docs/design/a2a.md): `agents[].a2a`, `a2a:<name>` callers and
//! `type: a2a` tools: what the validator accepts, the defaults, what the runtime gets, and the role
//! a change needs.
mod common;

use agentsc_charter::diff::{Role, required_role};
use agentsc_charter::*;
use common::*;
use serde_json::json;

fn quotes() -> ToolSpec {
    serde_json::from_value(json!({
        "name": "partner_quotes",
        "type": "a2a",
        "description": "Quotes from the partner's agent.",
        "url": "https://agents.partner.example/a2a/quotes",
        "credential": {"secret": "partner"}
    }))
    .unwrap()
}

/// The v0.2 charter with its first agent served over A2A to `a2a:partner`.
fn served() -> Charter {
    let mut c = v02();
    let a = &mut c.agents[0];
    a.a2a = Some(A2aSpec {
        description: "Answers support questions.".into(),
        skills: vec![A2aSkillSpec {
            id: "refunds".into(),
            name: "Refunds".into(),
            description: "Refund decisions for orders.".into(),
            tags: vec!["orders".into()],
            examples: vec!["Refund order 7".into()],
        }],
    });
    a.taint = Some(TaintSpec {
        mode: TaintMode::Enforce,
        input: TaintLabel::Trusted,
    });
    let agent = a.name.clone();
    c.authz.callers.push(CallerRule {
        identity: "a2a:partner".into(),
        agents: vec![agent],
        caller_agents: Vec::new(),
    });
    c.validate().expect("valid with an a2a agent");
    c
}

fn error_of(c: &Charter) -> String {
    c.validate().unwrap_err().to_string()
}

#[test]
fn a2a_agents_callers_and_tools_are_level_10() {
    let c = served();
    let levels = c.level_fields();
    assert!(
        levels
            .iter()
            .any(|(f, l)| f == "agents.support.a2a" && *l == 10),
        "{levels:?}"
    );
    assert!(
        levels
            .iter()
            .any(|(f, l)| f.starts_with("authz.callers[") && *l == 10),
        "{levels:?}"
    );
    let mut c = v02();
    c.agents[0].tools.push(quotes());
    c.guardrails.allowed_tools.clear();
    c.validate().expect("valid with an a2a tool");
    assert!(
        c.level_fields()
            .iter()
            .any(|(f, l)| f == "agents.support.tools.partner_quotes" && *l == 10)
    );
    let t = c.agents[0].tools.last().unwrap();
    assert_eq!(t.effective_label(), TaintLabel::Untrusted);
    assert_eq!(t.effective_effect(), ToolEffect::Write);
    assert!(ToolType::A2a.is_egress());
    assert!(
        is_a2a_identity("a2a:partner")
            && !is_a2a_identity("a2a:Partner")
            && !is_a2a_identity("a2a:")
    );
    // YAML round trip
    let back = Charter::from_yaml(&c.to_yaml().unwrap()).unwrap();
    assert_eq!(back, c);
}

#[test]
fn the_runtime_gets_neither_the_card_nor_the_credential_and_a2a_tools_get_fixed_parameters() {
    let mut c = served();
    c.agents[0].tools.push(quotes());
    c.guardrails.allowed_tools.clear();
    c.validate().unwrap();
    let spec = c.runtime_spec("support", &[]);
    assert!(spec.get("a2a").is_none(), "{spec}");
    let t = spec["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "partner_quotes")
        .unwrap();
    assert!(t.get("credential").is_none(), "{t}");
    assert_eq!(t["parameters"], a2a_tool_parameters());
}

#[test]
fn the_validator_refuses_what_the_sidecar_could_not_enforce() {
    // an A2A caller runs untrusted: the agent needs a taint block
    let mut c = served();
    c.agents[0].taint = None;
    assert!(
        error_of(&c).contains("needs a taint block"),
        "{}",
        error_of(&c)
    );
    // an a2a: caller of an agent without an a2a block
    let mut c = served();
    let other = c.agents[1].name.clone();
    c.authz.callers.last_mut().unwrap().agents.push(other);
    assert!(
        error_of(&c).contains("has no a2a block"),
        "{}",
        error_of(&c)
    );
    // a2a:<DNS label>, and no caller_agents
    let mut c = served();
    c.authz.callers.last_mut().unwrap().identity = "a2a:Bad_Name".into();
    assert!(
        error_of(&c).contains("a DNS-1123 label"),
        "{}",
        error_of(&c)
    );
    let mut c = served();
    c.authz.callers.last_mut().unwrap().caller_agents = vec!["x".into()];
    assert!(
        error_of(&c).contains("no caller_agents"),
        "{}",
        error_of(&c)
    );
    // the card's text
    let mut c = served();
    let a2a = c.agents[0].a2a.as_mut().unwrap();
    a2a.skills.push(a2a.skills[0].clone());
    assert!(
        error_of(&c).contains("unique DNS-1123 label"),
        "{}",
        error_of(&c)
    );
    let mut c = served();
    c.agents[0].a2a.as_mut().unwrap().description = String::new();
    assert!(error_of(&c).contains("a2a.description"), "{}", error_of(&c));

    // a2a tools: a url, no parameters, no service fields, a file name for the credential
    for (edit, want) in [
        (
            (|t: &mut ToolSpec| t.url = None) as fn(&mut ToolSpec),
            "a2a tools need url",
        ),
        (
            |t| t.url = Some("https://a.example/{x}".into()),
            "no {param} or fragment",
        ),
        (
            |t| t.parameters = Some(json!({"type": "object"})),
            "may not set parameters",
        ),
        (
            |t| t.method = Some("POST".into()),
            "may not set service, agent, path or method",
        ),
        (
            |t| t.pin = Some(format!("sha256:{}", "0".repeat(64))),
            "mcp_tool and pin are for mcp tools only",
        ),
        (
            |t| {
                t.credential = Some(CredentialSpec {
                    secret: "../tls.key".into(),
                })
            },
            "not a DNS-1123 label",
        ),
    ] {
        let mut c = v02();
        let mut t = quotes();
        edit(&mut t);
        c.agents[0].tools.push(t);
        c.guardrails.allowed_tools.clear();
        assert!(error_of(&c).contains(want), "{want}: {}", error_of(&c));
    }
    // a credential is for mcp and a2a tools only
    let mut c = v02();
    c.agents[0].tools[0].credential = Some(CredentialSpec { secret: "x".into() });
    assert!(
        error_of(&c).contains("credential is for mcp and a2a tools only"),
        "{}",
        error_of(&c)
    );
}

fn role(old: &Charter, edit: impl FnOnce(&mut Charter)) -> (Role, Vec<String>) {
    let mut new = old.clone();
    edit(&mut new);
    new.validate().expect("the edited charter is valid");
    required_role(old, &new)
}

#[test]
fn publishing_an_agent_and_new_a2a_origins_need_admin_and_card_text_does_not() {
    let (r, why) = role(&served(), |c| {
        c.agents[0].a2a.as_mut().unwrap().description = "Answers support questions, faster.".into();
    });
    assert_eq!((r, why), (Role::Editor, vec![]));
    let (r, why) = role(&served(), |c| {
        c.agents[0].a2a = None;
        c.authz.callers.pop();
    });
    assert_eq!(r, Role::Admin);
    assert!(
        why.iter()
            .any(|w| w.contains("agents.support.a2a added or removed")),
        "{why:?}"
    );
    let (r, why) = role(&v02(), |c| {
        c.agents[0].tools.push(quotes());
        c.guardrails.allowed_tools.clear();
    });
    assert_eq!(r, Role::Admin);
    assert!(
        why.iter()
            .any(|w| w.contains("new a2a origin https://agents.partner.example")),
        "{why:?}"
    );
}
