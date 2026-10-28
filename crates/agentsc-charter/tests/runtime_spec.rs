//! `Charter::runtime_spec`: what the runtime receives in `ExecuteRequest.agent_spec_json`
//! (design §4 "What the runtime receives").
mod common;

use agentsc_charter::*;
use common::*;
use serde_json::{Value, json};

const NEW_KEYS: [&str; 5] = ["skills", "harness", "learning", "practices", "memory"];

fn without_new_keys(mut v: Value) -> Value {
    if let Value::Object(m) = &mut v {
        for k in NEW_KEYS {
            m.remove(k);
        }
    }
    v
}

#[test]
fn it_is_a_superset_of_what_the_sidecar_sends_today() {
    // services/agentscd sends serde_json::to_string(&charter.agent_for_runtime(agent)), with the
    // default parameters filled for agent tools
    for c in [orders(), Charter::from_yaml(INVENTORY).unwrap()] {
        for a in &c.agents {
            let mut today = serde_json::to_value(c.agent_for_runtime(a)).unwrap();
            for t in today["tools"].as_array_mut().unwrap() {
                if t["type"] == "agent" {
                    t["parameters"] = agent_tool_parameters();
                }
            }
            let spec = c.runtime_spec(&a.name, &[]);
            assert_eq!(without_new_keys(spec.clone()), today, "{}", a.name);
            assert_eq!(spec["skills"], json!([]));
            assert_eq!(spec["memory"], json!([]));
            assert_eq!(
                spec["harness"],
                json!({"max_retries": 2, "request_timeout_seconds": 120, "tool_result_max_chars": 20000})
            );
            assert_eq!(
                spec["learning"],
                json!({"enabled": false, "mode": "review", "max_notes": 20, "max_note_chars": 500,
                       "note_ttl_days": 7, "from_peers": false, "max_proposals_per_hour": 10,
                       "require_evidence": true, "contrast_runs": 5, "scopes": ["invariant", "domain"]})
            );
            assert_eq!(
                spec["practices"],
                json!({"plan": true, "clarify": "blocking", "max_questions": 5,
                       "brevity": "lite", "agent_brevity": "full", "auto_clarity": true})
            );
        }
    }
}

#[test]
fn tools_stay_filtered_by_allowed_tools() {
    let mut c = v02();
    c.guardrails
        .allowed_tools
        .insert("support".into(), vec!["get_order".into(), "triage".into()]);
    let spec = c.runtime_spec("support", &[]);
    let names: Vec<&str> = spec["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["get_order", "triage"]);
}

#[test]
fn agent_tools_get_input_and_an_optional_context() {
    // CONTRACT.md §3.1: an agent tool without parameters takes `input` and, optionally, a
    // `context` object the callee gets as its context
    let mut c = v02();
    let spec = c.runtime_spec("support", &[]);
    let tool = |spec: &Value, name: &str| {
        spec["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == name)
            .unwrap()
            .clone()
    };
    let params = tool(&spec, "triage")["parameters"].clone();
    assert_eq!(params, agent_tool_parameters());
    assert_eq!(params["required"], json!(["input"]));
    assert_eq!(params["properties"]["input"]["type"], "string");
    assert_eq!(params["properties"]["context"]["type"], "object");
    // service and http tools keep what they declare
    assert!(tool(&spec, "refund").get("parameters").is_none());
    assert!(tool(&spec, "partner").get("parameters").is_none());
    // an agent tool's own parameters are kept as they are
    let own = json!({"type": "object", "properties": {"order": {"type": "string"}}});
    c.agents[0]
        .tools
        .iter_mut()
        .find(|t| t.name == "triage")
        .unwrap()
        .parameters = Some(own.clone());
    assert_eq!(
        tool(&c.runtime_spec("support", &[]), "triage")["parameters"],
        own
    );
}

#[test]
fn skills_are_resolved_with_inline_by_size() {
    let mut c = v02();
    c.skills[1].instructions = "x".repeat(INLINE_SKILL_MAX_BYTES - 1);
    let spec = c.runtime_spec("support", &[]);
    assert_eq!(
        spec["skills"][0],
        json!({
            "name": "refund-policy",
            "description": "How to decide whether a refund is allowed.",
            "instructions": c.skills[0].instructions,
            "inline": true,
        }),
        "the skill's own tools are not passed on"
    );
    assert_eq!(spec["skills"][1]["name"], "escalation");
    assert_eq!(spec["skills"][1]["inline"], true, "2047 bytes is inline");
    c.skills[1].instructions.push('x');
    assert_eq!(
        c.runtime_spec("support", &[])["skills"][1]["inline"],
        false,
        "2048 bytes is loaded with load_skill"
    );
    // the agent's order, only the skills it uses
    c.agents[0].skills = vec!["escalation".into()];
    let spec = c.runtime_spec("support", &[]);
    assert_eq!(spec["skills"].as_array().unwrap().len(), 1);
    assert_eq!(spec["skills"][0]["name"], "escalation");
    assert_eq!(c.runtime_spec("triage", &[])["skills"], json!([]));
}

#[test]
fn harness_learning_and_memory() {
    let c = v02();
    let notes = vec![
        RuntimeNote {
            id: "n1".into(),
            text: "Orders older than 30 days are not refunded.".into(),
        },
        RuntimeNote {
            id: "n2".into(),
            text: "Ask for the order id first.".into(),
        },
    ];
    let spec = c.runtime_spec("support", &notes);
    assert_eq!(
        spec["harness"],
        json!({"max_retries": 2, "request_timeout_seconds": 120,
               "fallback_model": "claude-haiku-5-5", "tool_result_max_chars": 20000})
    );
    assert_eq!(spec["learning"]["enabled"], true);
    assert_eq!(spec["learning"]["require_evidence"], true);
    assert_eq!(spec["learning"]["contrast_runs"], 5);
    assert_eq!(spec["learning"]["scopes"], json!(["invariant", "domain"]));
    assert_eq!(
        spec["practices"],
        serde_json::to_value(PracticesSpec::default()).unwrap()
    );
    assert_eq!(
        spec["memory"],
        json!([
            {"id": "n1", "text": "Orders older than 30 days are not refunded."},
            {"id": "n2", "text": "Ask for the order id first."},
        ]),
        "oldest first, as given"
    );
    // partially given blocks get the rest of the defaults
    let mut c = v02();
    c.agents[0].harness = Some(HarnessSpec {
        max_retries: 5,
        ..HarnessSpec::default()
    });
    let spec = c.runtime_spec("support", &[]);
    assert_eq!(spec["harness"]["max_retries"], 5);
    assert_eq!(spec["harness"]["request_timeout_seconds"], 120);
    // the other fields are the agent's own
    assert_eq!(spec["name"], "support");
    assert_eq!(spec["type"], "orchestrator");
    assert_eq!(spec["model"], "claude-opus-5-5");
    assert_eq!(spec["budgets"]["max_steps"], 8);
}

#[test]
fn memory_is_passed_only_to_agents_with_learning_enabled() {
    // design §3: memory exists only for agents with learning enabled
    let notes = [RuntimeNote {
        id: "n1".into(),
        text: "Ask for the order id first.".into(),
    }];
    let c = v02();
    assert_eq!(
        c.runtime_spec("support", &notes)["memory"],
        json!([{"id": "n1", "text": "Ask for the order id first."}])
    );
    // triage has no learning block at all
    assert!(c.agent("triage").unwrap().learning.is_none());
    assert_eq!(c.runtime_spec("triage", &notes)["memory"], json!([]));
    // learning present but switched off
    let mut c = v02();
    c.agents[0].learning.as_mut().unwrap().enabled = false;
    let spec = c.runtime_spec("support", &notes);
    assert_eq!(spec["memory"], json!([]));
    assert_eq!(spec["learning"]["enabled"], false);
    // a v0.1 charter: no learning, so no memory either
    let o = orders();
    for a in &o.agents {
        assert_eq!(o.runtime_spec(&a.name, &notes)["memory"], json!([]));
    }
}

#[test]
fn practices_and_the_new_learning_fields_are_always_filled() {
    // agent-practices design: `practices` is always sent with every field, and `learning` gets
    // the three level-6 fields filled
    let mut c = v02();
    c.agents[0].practices = Some(PracticesSpec {
        clarify: Clarify::Never,
        brevity: Brevity::Ultra,
        ..PracticesSpec::default()
    });
    let l = c.agents[0].learning.as_mut().unwrap();
    l.contrast_runs = Some(0);
    l.scopes = Some(vec![LessonScope::Domain]);
    let spec = c.runtime_spec("support", &[]);
    assert_eq!(
        spec["practices"],
        json!({"plan": true, "clarify": "never", "max_questions": 5,
               "brevity": "ultra", "agent_brevity": "full", "auto_clarity": true})
    );
    assert_eq!(spec["learning"]["require_evidence"], true);
    assert_eq!(spec["learning"]["contrast_runs"], 0);
    assert_eq!(spec["learning"]["scopes"], json!(["domain"]));
    // an agent with neither block gets every default
    let spec = c.runtime_spec("triage", &[]);
    assert_eq!(
        spec["practices"],
        json!({"plan": true, "clarify": "blocking", "max_questions": 5,
               "brevity": "lite", "agent_brevity": "full", "auto_clarity": true})
    );
    assert_eq!(spec["learning"]["require_evidence"], true);
    assert_eq!(spec["learning"]["contrast_runs"], 5);
    assert_eq!(spec["learning"]["scopes"], json!(["invariant", "domain"]));
    // the keys come in the same order whichever blocks the charter spells out
    let keys = |v: &Value| v.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
    assert_eq!(
        keys(&c.runtime_spec("support", &[])),
        keys(&c.runtime_spec("triage", &[]))
    );
}

#[test]
fn an_unknown_agent_has_no_spec() {
    assert_eq!(v02().runtime_spec("ghost", &[]), Value::Null);
}

/// `schemas/runtime-agent-spec.example.json` is what the sidecar sends for the v0.2 fixture; the
/// runtime's tests (`runtime/tests/test_spec_v02.py`) parse the same file, which keeps the Rust
/// and Python sides in lockstep. `AGENTSC_UPDATE_GOLDEN=1 cargo test -p agentsc-charter` rewrites it.
#[test]
fn the_runtime_spec_example_is_in_sync() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../schemas/runtime-agent-spec.example.json"
    );
    let mut c = v02();
    // one inline skill and one the runtime loads with load_skill
    c.skills[1].instructions = format!(
        "Escalate when the customer asks for a manager.\n{}",
        "Collect the order id, the issue and what was tried. ".repeat(40)
    );
    let notes = [
        RuntimeNote {
            id: "6f1d2c3a-0000-4000-8000-000000000001".into(),
            text: "Orders older than 30 days are never refunded.".into(),
        },
        RuntimeNote {
            id: "6f1d2c3a-0000-4000-8000-000000000002".into(),
            text: "Ask for the order id before looking anything up.".into(),
        },
    ];
    let spec = c.runtime_spec("support", &notes);
    assert_eq!(spec["skills"][0]["inline"], true);
    assert_eq!(spec["skills"][1]["inline"], false);
    let text = format!("{}\n", serde_json::to_string_pretty(&spec).unwrap());
    if std::env::var_os("AGENTSC_UPDATE_GOLDEN").is_some() {
        std::fs::write(path, &text).unwrap();
    }
    let on_disk = std::fs::read_to_string(path).unwrap_or_default();
    assert_eq!(
        on_disk, text,
        "run `AGENTSC_UPDATE_GOLDEN=1 cargo test -p agentsc-charter --test runtime_spec`"
    );
}
