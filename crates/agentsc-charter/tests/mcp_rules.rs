//! `type: mcp` tools (charter schema level 9, docs/design/mcp-tools.md): what the validator
//! accepts, the defaults, what the runtime gets, and the role a change needs.
mod common;

use agentsc_charter::diff::{Role, required_role};
use agentsc_charter::*;
use common::*;
use serde_json::json;

const PIN: &str = "sha256:3b0c5e1a9f7d2c4b6a8e0f1d3c5b7a9e2f4d6c8b0a1e3f5d7c9b2a4e6f8d0c1b";

fn search() -> ToolSpec {
    serde_json::from_value(json!({
        "name": "search_issues",
        "type": "mcp",
        "description": "Search issues in acme/app.",
        "url": "https://mcp.example.com/mcp",
        "pin": PIN,
        "parameters": {"type": "object", "properties": {
            "repo": {"type": "string", "enum": ["acme/app"]}, "query": {"type": "string"}},
            "required": ["repo", "query"], "additionalProperties": false},
        "effect": "read"
    }))
    .unwrap()
}

/// The v0.2 charter with `search` added to its first agent.
fn with_search() -> Charter {
    let mut c = v02();
    c.agents[0].tools.push(search());
    c.guardrails.allowed_tools.clear();
    c.validate().expect("valid with an mcp tool");
    c
}

fn invalid(edit: impl FnOnce(&mut ToolSpec), want: &str) {
    let mut c = with_search();
    let t = c.agents[0].tools.last_mut().unwrap();
    edit(t);
    let e = c.validate().unwrap_err().to_string();
    assert!(e.contains(want), "expected {want:?} in {e}");
}

#[test]
fn an_mcp_tool_is_level_9_and_valid_with_url_pin_and_parameters() {
    let c = with_search();
    assert_eq!(c.schema_level(), 9);
    assert!(
        c.level_fields()
            .contains(&("agents.support.tools.search_issues".to_string(), 9))
    );
    let t = c.agents[0].tools.last().unwrap();
    assert_eq!(t.mcp_tool_name(), "search_issues");
    assert!(t.tool_type.is_egress());
    // defaults: what an MCP server returns is untrusted, and its tools write unless marked
    let mut bare = search();
    bare.effect = None;
    assert_eq!(bare.effective_label(), TaintLabel::Untrusted);
    assert_eq!(bare.effective_effect(), ToolEffect::Write);
    assert_eq!(t.effective_effect(), ToolEffect::Read);
    // a YAML round trip keeps it
    let back = Charter::from_yaml(&c.to_yaml().unwrap()).unwrap();
    assert_eq!(back.agents[0].tools.last(), Some(t));
}

#[test]
fn the_runtime_gets_the_tool_without_its_server_name_pin_or_credential() {
    let mut c = with_search();
    let t = c.agents[0].tools.last_mut().unwrap();
    t.mcp_tool = Some("issues.search".into());
    t.credential = Some(CredentialSpec {
        secret: "github-pat".into(),
    });
    c.validate().unwrap();
    let spec = c.runtime_spec("support", &[]);
    let tool = spec["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "search_issues")
        .unwrap();
    assert_eq!(tool["type"], "mcp");
    assert!(tool["parameters"].is_object());
    for field in ["mcp_tool", "pin", "credential", "effect"] {
        assert!(
            tool.get(field).is_none(),
            "{field} reached the runtime: {tool}"
        );
    }
}

#[test]
fn the_validator_refuses_what_the_sidecar_could_not_enforce() {
    invalid(|t| t.pin = None, "mcp tools need pin");
    invalid(|t| t.pin = Some("sha256:ABC".into()), "is not sha256:");
    invalid(|t| t.url = None, "mcp tools need url");
    invalid(
        |t| t.url = Some("https://{host}/mcp".into()),
        "url must be http(s)://host[:port]/path",
    );
    invalid(
        |t| t.url = Some("https://mcp.example.com/{tenant}/mcp".into()),
        "with no {param}",
    );
    invalid(
        |t| t.url = Some("ftp://mcp.example.com/mcp".into()),
        "url must be",
    );
    invalid(|t| t.parameters = None, "mcp tools need parameters");
    invalid(
        |t| t.parameters = Some(json!({"$ref": "https://evil.example/schema.json"})),
        "not a usable JSON Schema",
    );
    invalid(|t| t.mcp_tool = Some("has space".into()), "mcp_tool");
    invalid(|t| t.mcp_tool = Some("x".repeat(129)), "mcp_tool");
    invalid(
        |t| {
            t.credential = Some(CredentialSpec {
                secret: "../tls/tls.key".into(),
            })
        },
        "never a path",
    );
    invalid(
        |t| {
            t.credential = Some(CredentialSpec {
                secret: "github-pat".into(),
            });
            t.delegation = Some(DelegationSpec {
                audience: "github-mcp".into(),
            });
        },
        "mutually exclusive",
    );
    invalid(
        |t| t.method = Some("POST".into()),
        "may not set service, agent, path or method",
    );
    // and the mcp fields belong to mcp tools only
    let mut c = v02();
    c.agents[0].tools[3].pin = Some(PIN.into());
    let e = c.validate().unwrap_err().to_string();
    assert!(e.contains("for mcp tools only"), "{e}");
    // an unknown field fails to parse (an older sidecar's view of a level-9 charter is the same)
    let yaml = with_search()
        .to_yaml()
        .unwrap()
        .replace("pin: ", "pinned: ");
    assert!(Charter::from_yaml(&yaml).is_err());
}

#[test]
fn delegation_works_for_mcp_tools() {
    let mut c = with_search();
    c.agents[0].tools.last_mut().unwrap().delegation = Some(DelegationSpec {
        audience: "github-mcp".into(),
    });
    c.validate().expect("delegation on an mcp tool");
}

fn role(old: &Charter, edit: impl FnOnce(&mut Charter)) -> (Role, Vec<String>) {
    let mut new = old.clone();
    edit(&mut new);
    new.validate().expect("the edited charter is valid");
    required_role(old, &new)
}

fn last(c: &mut Charter) -> &mut ToolSpec {
    c.agents[0].tools.last_mut().unwrap()
}

#[test]
fn the_security_fields_of_mcp_tools_need_admin() {
    // a new MCP origin, like a new http origin
    let (r, why) = role(&v02(), |c| c.agents[0].tools.push(search()));
    assert_eq!(r, Role::Admin);
    assert!(
        why.iter()
            .any(|w| w.contains("new mcp origin https://mcp.example.com")),
        "{why:?}"
    );

    let old = with_search();
    // a description, another tool on a known origin: editor
    let (r, why) = role(&old, |c| {
        last(c).description = "Search the issue tracker.".into();
        let mut other = search();
        other.name = "search_prs".into();
        other.effect = None; // setting effect or label on a new tool needs admin
        c.agents[0].tools.push(other);
    });
    assert_eq!((r, why), (Role::Editor, vec![]));

    let pin_reason =
        "agents.support.tools.search_issues pin, mcp_tool or parameters requires admin";
    for (what, edit) in [
        (
            "pin",
            (|t: &mut ToolSpec| t.pin = Some(format!("sha256:{}", "1".repeat(64))))
                as fn(&mut ToolSpec),
        ),
        ("mcp_tool", |t| t.mcp_tool = Some("search".into())),
        ("parameters", |t| {
            t.parameters = Some(json!({"type": "object"}))
        }),
    ] {
        let (r, why) = role(&old, |c| edit(last(c)));
        assert_eq!(r, Role::Admin, "{what}");
        assert!(why.iter().any(|w| w == pin_reason), "{what}: {why:?}");
    }

    let (r, why) = role(&old, |c| {
        last(c).credential = Some(CredentialSpec {
            secret: "github-pat".into(),
        })
    });
    assert_eq!(r, Role::Admin);
    assert!(
        why.iter()
            .any(|w| w == "agents.support.tools.search_issues credential requires admin"),
        "{why:?}"
    );
    // and lowering effect or label is a taint change, as for every tool
    let (r, _) = role(&old, |c| last(c).label = Some(TaintLabel::Trusted));
    assert_eq!(r, Role::Admin);
}
