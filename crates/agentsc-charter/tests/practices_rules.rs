//! Agent practices and the level-6 learning fields (agent-practices design, CONTRACT.md §3.2,
//! §3.5): defaults, one passing and one failing case per rule, the schema, the level, and what
//! the runtime receives.
mod common;

use agentsc_charter::*;
use common::*;
use serde_json::json;

/// V02 with `extra` (YAML, indented for the `support` agent) after its learning block.
fn v02_with(extra: &str) -> String {
    let anchor = "      max_proposals_per_hour: 10\n";
    assert!(V02.contains(anchor));
    V02.replacen(anchor, &format!("{anchor}{extra}"), 1)
}

fn practices(edit: impl FnOnce(&mut PracticesSpec)) -> Charter {
    let mut c = v02();
    let mut p = PracticesSpec::default();
    edit(&mut p);
    c.agents[0].practices = Some(p);
    c
}

fn learning(edit: impl FnOnce(&mut LearningSpec)) -> Charter {
    let mut c = v02();
    edit(c.agents[0].learning.as_mut().unwrap());
    c
}

// --- defaults ---------------------------------------------------------------------------------

#[test]
fn an_absent_practices_block_is_every_practice_on() {
    let c = v02();
    let a = c.agent("support").unwrap();
    assert!(a.practices.is_none());
    let p = a.practices_or_default();
    assert_eq!(p, PracticesSpec::default());
    assert_eq!(
        (
            p.plan,
            p.clarify,
            p.max_questions,
            p.brevity,
            p.agent_brevity,
            p.auto_clarity
        ),
        (
            true,
            Clarify::Blocking,
            5,
            Brevity::Lite,
            Brevity::Full,
            true
        )
    );
    assert_eq!(Brevity::default(), Brevity::Lite);
    assert_eq!(Clarify::default(), Clarify::Blocking);
}

#[test]
fn a_partial_practices_block_fills_the_rest_with_defaults() {
    let c = Charter::from_yaml(&v02_with("    practices: {brevity: normal}\n")).unwrap();
    let p = c.agent("support").unwrap().practices.clone().unwrap();
    assert_eq!(
        p,
        PracticesSpec {
            brevity: Brevity::Normal,
            ..PracticesSpec::default()
        }
    );
    assert!(p.plan && p.auto_clarity && p.clarify == Clarify::Blocking);
    let c = Charter::from_yaml(&v02_with("    practices: {}\n")).unwrap();
    assert_eq!(
        c.agent("support").unwrap().practices,
        Some(PracticesSpec::default())
    );
    // every field spelled out
    let c = Charter::from_yaml(&v02_with(
        "    practices:\n      plan: false\n      clarify: always\n      max_questions: 3\n      brevity: ultra\n      agent_brevity: lite\n      auto_clarity: false\n",
    ))
    .unwrap();
    assert_eq!(
        c.agent("support").unwrap().practices,
        Some(PracticesSpec {
            plan: false,
            clarify: Clarify::Always,
            max_questions: 3,
            brevity: Brevity::Ultra,
            agent_brevity: Brevity::Lite,
            auto_clarity: false,
        })
    );
}

#[test]
fn the_new_learning_fields_default_when_absent() {
    let l = v02().agents[0].learning.clone().unwrap();
    assert_eq!(
        (l.require_evidence, l.contrast_runs, l.scopes.clone()),
        (None, None, None)
    );
    assert!(l.require_evidence_or_default());
    assert_eq!(l.contrast_runs_or_default(), 5);
    assert_eq!(
        l.scopes_or_default(),
        [LessonScope::Invariant, LessonScope::Domain]
    );
    assert_eq!(
        LearningSpec {
            enabled: true,
            ..LearningSpec::default()
        },
        l
    );
    // given, they are the charter's own
    let c = Charter::from_yaml(&V02.replacen(
        "      max_proposals_per_hour: 10\n",
        "      max_proposals_per_hour: 10\n      require_evidence: false\n      contrast_runs: 0\n      scopes: [domain]\n",
        1,
    ))
    .unwrap();
    let l = c.agents[0].learning.clone().unwrap();
    assert!(!l.require_evidence_or_default());
    assert_eq!(l.contrast_runs_or_default(), 0);
    assert_eq!(l.scopes_or_default(), [LessonScope::Domain]);
}

// --- rule: practices.max_questions is 1..=10 ----------------------------------------------------

#[test]
fn max_questions_is_1_to_10() {
    for ok in [1, 5, 10] {
        accepts(&practices(|p| p.max_questions = ok));
    }
    for bad in [0, 11, u32::MAX] {
        rejects(
            &practices(|p| p.max_questions = bad),
            "agents[0] (support): practices.max_questions must be 1..=10",
        );
    }
}

// --- rule: learning.contrast_runs is 0..=20 -----------------------------------------------------

#[test]
fn contrast_runs_is_0_to_20() {
    for ok in [0, 5, 20] {
        accepts(&learning(|l| l.contrast_runs = Some(ok)));
    }
    for bad in [21, u32::MAX] {
        rejects(
            &learning(|l| l.contrast_runs = Some(bad)),
            "agents[0] (support): learning.contrast_runs must be 0..=20",
        );
    }
}

// --- rule: learning.scopes is non-empty and lists each value once -------------------------------

#[test]
fn scopes_are_non_empty_and_unique() {
    use LessonScope::{Domain, Invariant};
    for ok in [
        vec![Invariant],
        vec![Domain],
        vec![Invariant, Domain],
        vec![Domain, Invariant],
    ] {
        accepts(&learning(|l| l.scopes = Some(ok)));
    }
    for bad in [
        vec![],
        vec![Domain, Domain],
        vec![Invariant, Domain, Invariant],
    ] {
        rejects(
            &learning(|l| l.scopes = Some(bad)),
            "agents[0] (support): learning.scopes must list invariant, domain or both, each once",
        );
    }
    // the same rules from YAML
    let with = |scopes: &str| {
        V02.replacen(
            "      max_proposals_per_hour: 10\n",
            &format!("      max_proposals_per_hour: 10\n      scopes: {scopes}\n"),
            1,
        )
    };
    Charter::from_yaml(&with("[invariant]")).unwrap();
    for bad in ["[]", "[domain, domain]"] {
        let err = Charter::from_yaml(&with(bad)).unwrap_err().to_string();
        assert!(err.contains("learning.scopes must list"), "{bad}: {err}");
    }
}

#[test]
fn the_learning_rules_hold_with_learning_off_too() {
    let mut c = learning(|l| l.contrast_runs = Some(21));
    c.agents[0].learning.as_mut().unwrap().enabled = false;
    rejects(&c, "learning.contrast_runs must be 0..=20");
    let mut c = learning(|l| l.scopes = Some(vec![]));
    c.agents[0].learning.as_mut().unwrap().enabled = false;
    rejects(&c, "learning.scopes must list");
}

// --- rule 12: no tool may be named ask_caller ---------------------------------------------------

#[test]
fn ask_caller_is_a_reserved_tool_name() {
    let mut c = v02();
    c.agents[0].tools[3].name = ASK_CALLER_TOOL.into();
    c.guardrails.allowed_tools.clear();
    rejects(
        &c,
        "agents[0] (support).tools[3] (ask_caller): the tool name ask_caller is reserved",
    );
    let mut c = v02();
    c.agents[0].tools[3].name = "ask_the_caller".into();
    c.guardrails.allowed_tools.clear();
    accepts(&c);
    assert_eq!(ASK_CALLER_TOOL, "ask_caller");
}

// --- unknown fields and bad values ----------------------------------------------------------------

#[test]
fn unknown_fields_inside_practices_are_rejected() {
    for (block, field) in [
        ("    practices: {plans: true}\n", "plans"),
        ("    practices: {brevity: lite, text: be brief}\n", "text"),
        (
            "    practices:\n      clarify: never\n      ask: always\n",
            "ask",
        ),
    ] {
        let err = Charter::from_yaml(&v02_with(block))
            .unwrap_err()
            .to_string();
        assert!(err.contains(&format!("unknown field `{field}`")), "{err}");
    }
    let err = Charter::from_yaml(&V02.replacen(
        "      max_proposals_per_hour: 10\n",
        "      max_proposals_per_hour: 10\n      evidence: true\n",
        1,
    ))
    .unwrap_err()
    .to_string();
    assert!(err.contains("unknown field `evidence`"), "{err}");
}

#[test]
fn bad_enum_values_are_rejected() {
    for block in [
        "    practices: {clarify: sometimes}\n",
        "    practices: {clarify: Blocking}\n",
        "    practices: {brevity: caveman}\n",
        "    practices: {agent_brevity: none}\n",
        // `off` is gone: YAML 1.1 readers (kubectl, Helm, PyYAML) read it as false
        "    practices: {clarify: off}\n",
        "    practices: {brevity: off}\n",
        "    practices: {brevity: false}\n",
        "    practices: {plan: maybe}\n",
        "    practices: {max_questions: -1}\n",
        "    practices: {max_questions: five}\n",
        "    practices: []\n",
    ] {
        assert!(Charter::from_yaml(&v02_with(block)).is_err(), "{block}");
    }
    for scopes in ["[subject]", "[Invariant]", "invariant", "[[domain]]"] {
        let text = V02.replacen(
            "      max_proposals_per_hour: 10\n",
            &format!("      max_proposals_per_hour: 10\n      scopes: {scopes}\n"),
            1,
        );
        assert!(Charter::from_yaml(&text).is_err(), "{scopes}");
    }
    for value in ["-1", "many", "true"] {
        let text = V02.replacen(
            "      max_proposals_per_hour: 10\n",
            &format!("      max_proposals_per_hour: 10\n      contrast_runs: {value}\n"),
            1,
        );
        assert!(Charter::from_yaml(&text).is_err(), "contrast_runs {value}");
    }
}

#[test]
fn every_enum_value_is_accepted() {
    for (value, want) in [
        ("normal", Brevity::Normal),
        ("lite", Brevity::Lite),
        ("full", Brevity::Full),
        ("ultra", Brevity::Ultra),
    ] {
        let c = Charter::from_yaml(&v02_with(&format!(
            "    practices: {{brevity: {value}, agent_brevity: {value}}}\n"
        )))
        .unwrap();
        let p = c.agents[0].practices.clone().unwrap();
        assert_eq!((p.brevity, p.agent_brevity), (want, want));
        assert_eq!(want.as_str(), value);
    }
    for (value, want) in [
        ("never", Clarify::Never),
        ("blocking", Clarify::Blocking),
        ("always", Clarify::Always),
    ] {
        let c = Charter::from_yaml(&v02_with(&format!("    practices: {{clarify: {value}}}\n")))
            .unwrap();
        assert_eq!(c.agents[0].practices.clone().unwrap().clarify, want);
        assert_eq!(want.as_str(), value);
    }
    assert_eq!(LessonScope::Invariant.as_str(), "invariant");
    assert_eq!(LessonScope::Domain.as_str(), "domain");
}

// --- the JSON Schema and the CRD mirror the validator ---------------------------------------------

#[test]
fn the_schema_mirrors_the_practice_rules() {
    let schema = json_schema();
    let defs = &schema["$defs"];
    let p = &defs["PracticesSpec"];
    assert_eq!(p["additionalProperties"], false);
    let props = &p["properties"];
    assert_eq!(props["max_questions"]["minimum"], 1);
    assert_eq!(props["max_questions"]["maximum"], 10);
    for (field, default) in [
        ("plan", json!(true)),
        ("clarify", json!("blocking")),
        ("max_questions", json!(5)),
        ("brevity", json!("lite")),
        ("agent_brevity", json!("full")),
        ("auto_clarity", json!(true)),
    ] {
        assert_eq!(props[field]["default"], default, "{field}");
    }
    let consts = |name: &str| -> Vec<String> {
        defs[name]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["const"].as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(consts("Brevity"), ["normal", "lite", "full", "ultra"]);
    assert_eq!(consts("Clarify"), ["never", "blocking", "always"]);
    assert_eq!(consts("LessonScope"), ["invariant", "domain"]);
    let l = &defs["LearningSpec"]["properties"];
    assert_eq!(l["contrast_runs"]["minimum"], 0);
    assert_eq!(l["contrast_runs"]["maximum"], 20);
    assert_eq!(l["scopes"]["minItems"], 1);
    assert_eq!(l["scopes"]["uniqueItems"], true);
    assert_eq!(l["require_evidence"]["type"], json!(["boolean", "null"]));
    assert_eq!(
        defs["ToolSpec"]["properties"]["name"]["not"],
        json!({"enum": ["load_skill", "ask_caller"]})
    );
    // and the CRD carries them (minus uniqueItems and not, which the webhook checks)
    let crd = crd::custom_resource_definition();
    let agent = &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"]
        ["agents"]["items"]["properties"];
    let p = &agent["practices"]["properties"];
    assert_eq!(p["max_questions"]["minimum"], 1);
    assert_eq!(p["max_questions"]["maximum"], 10);
    assert_eq!(p["clarify"]["enum"], json!(["never", "blocking", "always"]));
    for field in ["brevity", "agent_brevity"] {
        assert_eq!(
            p[field]["enum"],
            json!(["normal", "lite", "full", "ultra"]),
            "{field}"
        );
    }
    let l = &agent["learning"]["properties"];
    assert_eq!(l["contrast_runs"]["maximum"], 20);
    assert_eq!(l["scopes"]["minItems"], 1);
    assert_eq!(l["scopes"]["items"]["enum"], json!(["invariant", "domain"]));
}

#[test]
fn no_enum_value_is_a_yaml_1_1_boolean() {
    // kubectl, Helm and PyYAML read YAML 1.1, where a plain off, on, yes, no, y or n is a boolean
    fn strings(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, v) in m {
                    match (k.as_str(), v) {
                        ("const", serde_json::Value::String(s)) => out.push(s.clone()),
                        ("enum", serde_json::Value::Array(a)) => {
                            out.extend(a.iter().filter_map(|s| s.as_str()).map(str::to_string))
                        }
                        _ => strings(v, out),
                    }
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|v| strings(v, out)),
            _ => {}
        }
    }
    let mut values = Vec::new();
    strings(&json_schema(), &mut values);
    assert!(values.iter().any(|v| v == "never") && values.iter().any(|v| v == "normal"));
    for v in &values {
        let word = v.to_lowercase();
        assert!(
            !["y", "yes", "n", "no", "on", "off"].contains(&word.as_str()),
            "{v}"
        );
    }
}

// --- schema level 6 ------------------------------------------------------------------------------

#[test]
fn each_new_field_is_level_6() {
    type Edit = fn(&mut Charter);
    let edits: [(&str, Edit); 4] = [
        ("agents.support.practices", |c| {
            c.agents[0].practices = Some(PracticesSpec::default())
        }),
        ("agents.support.learning.require_evidence", |c| {
            c.agents[0].learning.as_mut().unwrap().require_evidence = Some(true)
        }),
        ("agents.support.learning.contrast_runs", |c| {
            c.agents[0].learning.as_mut().unwrap().contrast_runs = Some(5)
        }),
        ("agents.support.learning.scopes", |c| {
            c.agents[0].learning.as_mut().unwrap().scopes = Some(vec![LessonScope::Domain])
        }),
    ];
    assert_eq!(CHARTER_SCHEMA_LEVEL, 6);
    for (field, edit) in edits {
        let mut c = v02();
        edit(&mut c);
        accepts(&c);
        assert_eq!(c.schema_level(), 6, "{field}");
        let level6: Vec<_> = c
            .level_fields()
            .into_iter()
            .filter(|(_, l)| *l == 6)
            .collect();
        assert_eq!(level6, [(field.to_string(), 6)]);
    }
    // a v0.1 charter with only a practices block is level 6 too
    let mut c = orders();
    c.agents[0].practices = Some(PracticesSpec::default());
    assert_eq!(c.schema_level(), 6);
    assert_eq!(
        c.level_fields(),
        [(format!("agents.{}.practices", c.agents[0].name), 6)]
    );
}

#[test]
fn without_the_new_fields_the_level_is_unchanged() {
    assert_eq!(orders().schema_level(), 1);
    assert_eq!(Charter::from_yaml(INVENTORY).unwrap().schema_level(), 1);
    assert_eq!(v02().schema_level(), 2);
    assert!(v02().level_fields().iter().all(|(_, l)| *l <= 2));
    // a learning block without the new fields stays level 2
    let mut c = orders();
    c.agents[0].learning = Some(LearningSpec {
        enabled: true,
        ..LearningSpec::default()
    });
    assert_eq!(c.schema_level(), 2);
}

// --- serialization ------------------------------------------------------------------------------

#[test]
fn the_shared_fixtures_serialize_without_the_new_keys() {
    for c in [orders(), Charter::from_yaml(INVENTORY).unwrap(), v02()] {
        let json = serde_json::to_value(&c).unwrap();
        for a in json["agents"].as_array().unwrap() {
            assert!(a.get("practices").is_none(), "{}", a["name"]);
            if let Some(l) = a.get("learning") {
                for key in ["require_evidence", "contrast_runs", "scopes"] {
                    assert!(l.get(key).is_none(), "{key}");
                }
            }
        }
        let yaml = c.to_yaml().unwrap();
        for key in ["practices", "require_evidence", "contrast_runs", "scopes"] {
            assert!(!yaml.contains(key), "{key}");
        }
        assert_eq!(Charter::from_yaml(&yaml).unwrap(), c);
    }
    // a level-2 learning block serializes exactly as before
    assert_eq!(
        serde_json::to_value(LearningSpec::default()).unwrap(),
        json!({"enabled": false, "mode": "review", "max_notes": 20, "max_note_chars": 500,
               "note_ttl_days": 7, "from_peers": false, "max_proposals_per_hour": 10})
    );
}

#[test]
fn the_new_fields_round_trip() {
    let mut c = practices(|p| {
        p.clarify = Clarify::Always;
        p.agent_brevity = Brevity::Ultra;
    });
    let l = c.agents[0].learning.as_mut().unwrap();
    l.require_evidence = Some(false);
    l.contrast_runs = Some(0);
    l.scopes = Some(vec![LessonScope::Invariant]);
    accepts(&c);
    assert_eq!(Charter::from_yaml(&c.to_yaml().unwrap()).unwrap(), c);
    let json = serde_json::to_value(&c).unwrap();
    assert_eq!(Charter::from_value(&json).unwrap(), c);
    assert_eq!(
        json["agents"][0]["learning"]["scopes"],
        json!(["invariant"])
    );
    assert_eq!(json["agents"][0]["practices"]["clarify"], "always");
}

// --- what the runtime receives ------------------------------------------------------------------

#[test]
fn runtime_spec_fills_practices_for_an_agent_without_the_block() {
    let o = orders();
    for a in &o.agents {
        assert!(a.practices.is_none());
        let spec = o.runtime_spec(&a.name, &[]);
        assert_eq!(
            spec["practices"],
            json!({"plan": true, "clarify": "blocking", "max_questions": 5,
                   "brevity": "lite", "agent_brevity": "full", "auto_clarity": true}),
            "{}",
            a.name
        );
        assert_eq!(spec["learning"]["require_evidence"], true);
        assert_eq!(spec["learning"]["contrast_runs"], 5);
        assert_eq!(spec["learning"]["scopes"], json!(["invariant", "domain"]));
    }
    // a partial block arrives filled
    let c = Charter::from_yaml(&v02_with(
        "    practices: {clarify: never, max_questions: 2}\n",
    ))
    .unwrap();
    assert_eq!(
        c.runtime_spec("support", &[])["practices"],
        json!({"plan": true, "clarify": "never", "max_questions": 2,
               "brevity": "lite", "agent_brevity": "full", "auto_clarity": true})
    );
}

// --- the example ----------------------------------------------------------------------------------

#[test]
fn the_support_example_is_a_valid_level_6_charter() {
    let c = Charter::from_yaml(include_str!(
        "../../../examples/charters/support.charter.yaml"
    ))
    .expect("support charter valid");
    assert_eq!(c.schema_level(), 6);
    let a = c.agent("helpdesk").unwrap();
    let p = a.practices.clone().unwrap();
    assert_ne!(p, PracticesSpec::default(), "it shows non-default choices");
    assert_eq!(p.clarify, Clarify::Always);
    let l = a.learning.clone().unwrap();
    assert!(l.enabled && l.mode == LearningMode::Review);
    assert_eq!(l.scopes, Some(vec![LessonScope::Domain]));
    assert_eq!(l.contrast_runs, Some(10));
    assert_eq!(l.require_evidence, Some(true));
    // the custom resource form reads back the same
    let cr = c.to_resource().to_yaml().unwrap();
    assert_eq!(Charter::from_yaml(&cr).unwrap(), c);
}
