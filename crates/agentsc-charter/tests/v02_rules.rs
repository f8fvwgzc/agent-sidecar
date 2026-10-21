//! The v0.2 charter fields and their validation rules (design §3 size limits, §4 rules 1–8):
//! one passing and one failing case each.
mod common;

use agentsc_charter::*;
use common::*;

#[test]
fn the_v02_fixture_and_the_v01_examples_are_valid() {
    let c = v02();
    assert_eq!(c.skills.len(), 2);
    assert_eq!(
        c.service.service_accounts,
        ["support", "support-canary"].map(String::from)
    );
    let t = c.telemetry.as_ref().unwrap();
    assert_eq!(
        t.otlp_endpoint.as_deref(),
        Some("http://otel-collector:4318")
    );
    let a = c.agent("support").unwrap();
    assert_eq!(a.skills, ["refund-policy", "escalation"].map(String::from));
    assert_eq!(
        a.harness.as_ref().unwrap().fallback_model.as_deref(),
        Some("claude-haiku-5-5")
    );
    assert!(a.learning_enabled());
    orders();
    Charter::from_yaml(INVENTORY).unwrap();
}

#[test]
fn new_blocks_take_their_defaults() {
    let text = V02
        .replace(
            "    harness:\n      max_retries: 2\n      request_timeout_seconds: 120\n      fallback_model: claude-haiku-5-5\n      tool_result_max_chars: 20000\n",
            "    harness: {}\n",
        )
        .replace(
            "    learning:\n      enabled: true\n      mode: review\n      max_notes: 20\n      max_note_chars: 500\n      note_ttl_days: 7\n      from_peers: false\n      max_proposals_per_hour: 10\n",
            "    learning: {}\n",
        )
        .replace(
            "telemetry:\n  otlp_endpoint: http://otel-collector:4318\n  traces: true\n  metrics: true\n  export_payloads: false\n  control_plane_payloads: true\n",
            "telemetry: {}\n",
        );
    let c = Charter::from_yaml(&text).unwrap();
    let a = c.agent("support").unwrap();
    assert_eq!(a.harness, Some(HarnessSpec::default()));
    let h = HarnessSpec::default();
    assert_eq!(
        (
            h.max_retries,
            h.request_timeout_seconds,
            h.fallback_model,
            h.tool_result_max_chars
        ),
        (2, 120, None, 20_000)
    );
    let l = a.learning.clone().unwrap();
    assert_eq!(l, LearningSpec::default());
    assert_eq!(
        (
            l.enabled,
            l.mode,
            l.max_notes,
            l.max_note_chars,
            l.note_ttl_days,
            l.from_peers,
            l.max_proposals_per_hour
        ),
        (false, LearningMode::Review, 20, 500, 7, false, 10)
    );
    let t = c.telemetry.clone().unwrap();
    assert_eq!(t, TelemetrySpec::default());
    assert_eq!(
        (
            t.otlp_endpoint,
            t.traces,
            t.metrics,
            t.export_payloads,
            t.control_plane_payloads
        ),
        (None, true, true, false, true)
    );
    // absent blocks: the same defaults through the accessors
    let o = orders();
    assert_eq!(o.telemetry_or_default(), TelemetrySpec::default());
    assert_eq!(o.agents[0].harness_or_default(), HarnessSpec::default());
    assert_eq!(o.agents[0].learning_or_default(), LearningSpec::default());
    assert!(!o.agents[0].learning_enabled());
    assert_eq!(
        o.service.allowed_service_accounts(),
        vec![o.service.name.clone()]
    );
    assert_eq!(
        v02().service.allowed_service_accounts(),
        ["support", "support-canary"].map(String::from)
    );
}

#[test]
fn unknown_fields_in_new_blocks_are_rejected() {
    for (from, to, field) in [
        ("max_retries: 2", "max_retry: 2", "max_retry"),
        ("from_peers: false", "from_peer: false", "from_peer"),
        ("traces: true", "trace: true", "trace"),
        (
            "    tools: [get_order]\n",
            "    tools: [get_order]\n    tool: x\n",
            "tool",
        ),
    ] {
        let err = Charter::from_yaml(&V02.replacen(from, to, 1))
            .unwrap_err()
            .to_string();
        assert!(err.contains(&format!("unknown field `{field}`")), "{err}");
    }
}

// --- rule 1: skill names unique; agents[].skills exist and are not repeated ----------------

#[test]
fn rule1_skill_names_are_unique_dns_labels() {
    accepts(&v02());
    let mut c = v02();
    c.skills[1].name = "refund-policy".into();
    c.agents[0].skills = vec!["refund-policy".into()];
    rejects(&c, "skills[1] (refund-policy): duplicate skill name");
    let mut c = v02();
    c.skills[1].name = "Escalation_2".into();
    c.agents[0].skills = vec!["refund-policy".into()];
    rejects(&c, "skills[1] (Escalation_2): name is not a DNS-1123 label");
}

#[test]
fn rule1_agent_skills_exist_and_are_not_repeated() {
    let mut c = v02();
    c.agents[0].skills.push("ghost".into());
    rejects(&c, "agents[0] (support): unknown skill \"ghost\"");
    let mut c = v02();
    c.agents[0].skills.push("escalation".into());
    rejects(&c, "skill \"escalation\" is listed twice");
    // a skill no agent uses is fine
    let mut c = v02();
    c.agents[0].skills.clear();
    accepts(&c);
}

// --- rule 2: a skill's tools are allowed for every agent that uses it -------------------------

#[test]
fn rule2_skill_tools_must_be_allowed_for_each_agent_using_it() {
    accepts(&v02());
    // allowed_tools narrows the agent: get_order is declared but not allowed
    let mut c = v02();
    c.guardrails
        .allowed_tools
        .insert("support".into(), vec!["refund".into()]);
    rejects(&c, "skill \"refund-policy\" uses tool \"get_order\"");
    // the second agent uses it but does not declare get_order at all
    let mut c = v02();
    c.agents[1].skills = vec!["refund-policy".into()];
    rejects(
        &c,
        "agents[1] (triage): skill \"refund-policy\" uses tool \"get_order\"",
    );
    // without allowed_tools every declared tool is allowed
    let mut c = v02();
    c.guardrails.allowed_tools.clear();
    accepts(&c);
}

// --- rule 3: no tool may be named load_skill ---------------------------------------------------

#[test]
fn rule3_load_skill_is_a_reserved_tool_name() {
    let mut c = v02();
    c.agents[0].tools[3].name = "load_skill".into();
    c.guardrails.allowed_tools.clear();
    rejects(&c, "the tool name load_skill is reserved");
    let mut c = v02();
    c.agents[0].tools[3].name = "load_skills".into();
    c.guardrails.allowed_tools.clear();
    accepts(&c);
}

// --- rule 4: fallback_model follows the model rules and differs from model ---------------------

#[test]
fn rule4_fallback_model() {
    let set = |m: &str| {
        let mut c = v02();
        c.agents[0].harness.as_mut().unwrap().fallback_model = Some(m.into());
        c
    };
    accepts(&set("claude-haiku-5-5"));
    accepts(&set("mock"));
    rejects(
        &set("claude-opus-5-5"),
        "harness.fallback_model must differ from model",
    );
    rejects(&set(" "), "harness.fallback_model is required");
    rejects(
        &set("claude haiku"),
        "harness.fallback_model is not a model id",
    );
    // the same rules hold for model
    let mut c = v02();
    c.agents[0].model = "claude opus".into();
    rejects(&c, "agents[0] (support): model is not a model id");
    for bad in [
        "claude-opus-5-5\t",
        "claude\u{1}opus",
        "claude-opus\u{85}",
        "claude\u{feff}",
    ] {
        rejects(&set(bad), "harness.fallback_model is not a model id");
    }
    accepts(&set(&"m".repeat(MAX_MODEL_BYTES)));
    rejects(
        &set(&"m".repeat(MAX_MODEL_BYTES + 1)),
        "harness.fallback_model is not a model id",
    );
    let mut c = v02();
    c.agents[0].model = "é".repeat(65); // 65 characters, 130 bytes
    rejects(&c, "agents[0] (support): model is not a model id");
}

// --- the JSON Schema mirrors rules 3 and 4 --------------------------------------------------------

#[test]
fn the_schema_mirrors_the_tool_name_and_model_rules() {
    let schema = json_schema();
    let defs = &schema["$defs"];
    let name = &defs["ToolSpec"]["properties"]["name"];
    assert_eq!(name["pattern"], TOOL_NAME_PATTERN);
    assert_eq!(name["not"], serde_json::json!({"const": LOAD_SKILL_TOOL}));
    for node in [
        &defs["AgentSpec"]["properties"]["model"],
        &defs["HarnessSpec"]["properties"]["fallback_model"],
    ] {
        assert_eq!(node["pattern"], MODEL_PATTERN, "{node}");
        assert_eq!(node["maxLength"], 128, "{node}");
    }
    // the patterns say what the validator says
    let tool = regex::Regex::new(TOOL_NAME_PATTERN).unwrap();
    for (t, ok) in [
        ("lookup_parcel", true),
        ("get-parcel-2", true),
        ("x", true),
        ("", false),
        ("get order", false),
        ("get.order", false),
        ("é", false),
    ] {
        assert_eq!(tool.is_match(t), ok, "{t:?}");
        let mut c = v02();
        c.guardrails.allowed_tools.clear();
        c.agents[0].tools[3].name = t.into();
        assert_eq!(c.validate().is_ok(), ok, "{t:?}");
    }
    assert!(tool.is_match(&"a".repeat(64)) && !tool.is_match(&"a".repeat(65)));
    let model = regex::Regex::new(MODEL_PATTERN).unwrap();
    for (m, ok) in [
        ("claude-opus-5-5", true),
        ("mock", true),
        ("us.anthropic.claude-opus-5-5-v1:0", true),
        ("", false),
        ("claude opus", false),
        ("claude-opus\t", false),
        (" claude", false),
        ("claude\u{1}", false),
        ("claude\u{85}", false),
        ("claude\u{3000}", false),
    ] {
        assert_eq!(model.is_match(m), ok, "{m:?}");
        let mut c = v02();
        c.agents[0].model = m.into();
        assert_eq!(c.validate().is_ok(), ok, "{m:?}");
    }
    // and the CRD carries them (minus `not`, which a structural schema leaves to the webhook)
    let crd = crd::custom_resource_definition();
    let agent = &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"]
        ["agents"]["items"]["properties"];
    assert_eq!(agent["model"]["pattern"], MODEL_PATTERN);
    assert_eq!(agent["model"]["maxLength"], 128);
    assert_eq!(
        agent["harness"]["properties"]["fallback_model"]["pattern"],
        MODEL_PATTERN
    );
    assert_eq!(
        agent["tools"]["items"]["properties"]["name"]["pattern"],
        TOOL_NAME_PATTERN
    );
}

// --- rule 5: telemetry.otlp_endpoint ----------------------------------------------------------

#[test]
fn rule5_otlp_endpoint_is_an_origin() {
    let set = |e: &str| {
        let mut c = v02();
        c.telemetry.as_mut().unwrap().otlp_endpoint = Some(e.into());
        c
    };
    for good in [
        "http://otel-collector:4318",
        "https://otel.example.com/",
        "http://[::1]:4318",
        "http://10.0.0.7:4318",
    ] {
        accepts(&set(good));
        assert!(check_otlp_endpoint(good).is_ok(), "{good}");
    }
    for (bad, why) in [
        ("otel-collector:4318", "http:// or https://"),
        ("ftp://otel:21", "http:// or https://"),
        ("HTTP://otel:4318", "http:// or https://"),
        ("http://otel:4318/v1/traces", "path"),
        ("http://otel:4318//", "path"),
        ("http://otel:4318?x=1", "query"),
        ("http://otel:4318/?x=1", "query"),
        ("http://otel:4318#f", "fragment"),
        ("http://user:pw@otel:4318", "credentials"),
        ("http://", "URL"),
    ] {
        rejects(&set(bad), "telemetry.otlp_endpoint");
        let err = check_otlp_endpoint(bad).unwrap_err();
        assert!(err.contains(why), "{bad}: {err}");
    }
}

#[test]
fn rule5_otlp_endpoint_has_no_whitespace_or_control_characters() {
    // the URL parser would drop these quietly (trim the ends, delete tabs and newlines inside),
    // so they are refused before parsing
    for bad in [
        "http://otel-collector:4318 ",
        "http://otel-collector:4318\t",
        " http://otel-collector:4318",
        "http://otel-\tcollector:4318",
        "http://otel-collector:4318/\n",
        "http://otel-collector\r:4318",
        "http://otel collector:4318",
        "http://otel-collector:4318\u{0}",
        "http://otel-collector:4318\u{7f}",
        "http://otel-collector:4318\u{85}",
        "http://otel-collector\u{a0}:4318",
        "http://otel-collector\u{3000}:4318",
        "http://otel-\u{feff}collector:4318",
    ] {
        let err = check_otlp_endpoint(bad).unwrap_err();
        assert_eq!(
            err, "may not contain whitespace or control characters",
            "{bad:?}"
        );
        let mut c = v02();
        c.telemetry.as_mut().unwrap().otlp_endpoint = Some(bad.into());
        rejects(&c, "may not contain whitespace or control characters");
    }
    // the YAML way in: a quoted trailing space or tab
    for quoted in [
        "\"http://otel-collector:4318 \"",
        "\"http://otel-collector:4318\\t\"",
    ] {
        let text = V02.replace(
            "otlp_endpoint: http://otel-collector:4318",
            &format!("otlp_endpoint: {quoted}"),
        );
        let err = Charter::from_yaml(&text).unwrap_err().to_string();
        assert!(err.contains("whitespace or control characters"), "{err}");
    }
}

#[test]
fn rule5_the_schema_pattern_agrees_with_the_validator() {
    let schema = json_schema();
    let pattern = schema["$defs"]["TelemetrySpec"]["properties"]["otlp_endpoint"]["pattern"]
        .as_str()
        .unwrap();
    assert_eq!(pattern, OTLP_ENDPOINT_PATTERN);
    let re = regex::Regex::new(pattern).unwrap();
    for e in [
        "http://otel-collector:4318",
        "https://otel.example.com/",
        "http://10.0.0.7:4318",
        "http://otel-collector:4318 ",
        "http://otel-collector:4318\t",
        " http://otel-collector:4318",
        "http://otel-\tcollector:4318",
        "http://otel-collector:4318\n",
        "http://otel-collector:4318\u{1}",
        "http://otel-collector:4318\u{7f}",
        "http://otel-collector:4318\u{85}",
        "http://otel-collector\u{a0}:4318",
        "http://otel-collector\u{3000}:4318",
        "http://otel:4318/v1/traces",
        "http://otel:4318?x=1",
        "http://otel:4318#f",
        "http://user@otel:4318",
        "ftp://otel:21",
    ] {
        assert_eq!(
            re.is_match(e),
            check_otlp_endpoint(e).is_ok(),
            "schema and validator disagree on {e:?}"
        );
    }
}

// --- rule 6: learning.mode auto requires enabled ----------------------------------------------

#[test]
fn rule6_auto_learning_must_be_enabled() {
    let mut c = v02();
    let l = c.agents[0].learning.as_mut().unwrap();
    l.mode = LearningMode::Auto;
    accepts(&c);
    c.agents[0].learning.as_mut().unwrap().enabled = false;
    rejects(&c, "learning.mode: auto requires learning.enabled: true");
    // review mode may be off
    let mut c = v02();
    c.agents[0].learning.as_mut().unwrap().enabled = false;
    accepts(&c);
}

// --- rule 7: size limits (design §3) ----------------------------------------------------------

#[test]
fn rule7_at_most_64_skills() {
    let mut c = v02();
    while c.skills.len() < MAX_SKILLS {
        let n = c.skills.len();
        c.skills.push(SkillSpec {
            name: format!("skill-{n}"),
            description: "d".into(),
            instructions: "i".into(),
            tools: vec![],
        });
    }
    accepts(&c);
    c.skills.push(SkillSpec {
        name: "one-too-many".into(),
        description: "d".into(),
        instructions: "i".into(),
        tools: vec![],
    });
    rejects(&c, "skills: at most 64 skills, got 65");
}

#[test]
fn rule7_system_prompt_at_most_32_kib() {
    let mut c = v02();
    c.agents[0].system = "x".repeat(MAX_SYSTEM_BYTES);
    accepts(&c);
    c.agents[0].system.push('x');
    rejects(&c, "system is 32769 bytes, more than 32768");
}

#[test]
fn rule7_skill_instructions_and_description_sizes() {
    let mut c = v02();
    c.skills[0].instructions = "x".repeat(MAX_SKILL_INSTRUCTIONS_BYTES);
    accepts(&c);
    c.skills[0].instructions.push('x');
    rejects(&c, "instructions must be 1 to 32768 bytes, got 32769");
    let mut c = v02();
    c.skills[0].instructions = "  ".into();
    rejects(&c, "instructions must be 1 to 32768 bytes");
    // description: characters, not bytes
    let mut c = v02();
    c.skills[0].description = "é".repeat(MAX_SKILL_DESCRIPTION_CHARS);
    accepts(&c);
    c.skills[0].description.push('é');
    rejects(&c, "description must be 1 to 1024 characters, got 1025");
    let mut c = v02();
    c.skills[0].description = String::new();
    rejects(&c, "description must be 1 to 1024 characters, got 0");
}

#[test]
fn rule7_memory_limit_counts_learning_agents() {
    // 2 × 200 × 500 = 200000 ≤ 262144
    let mut c = v02();
    c.agents[1].learning = Some(LearningSpec {
        enabled: true,
        max_notes: 200,
        ..LearningSpec::default()
    });
    c.agents[0].learning.as_mut().unwrap().max_notes = 200;
    accepts(&c);
    // 200 × 4000 alone is 800000
    c.agents[1].learning.as_mut().unwrap().max_note_chars = 4000;
    rejects(
        &c,
        "may keep 900000 characters of notes (max_notes × max_note_chars), more than the 262144",
    );
    // an agent with learning off holds no notes
    c.agents[1].learning.as_mut().unwrap().enabled = false;
    accepts(&c);
}

#[test]
fn rule7_memory_limit_is_in_characters_at_the_boundary() {
    assert_eq!(MAX_MEMORY_CHARS, 262_144);
    assert_eq!(
        MAX_MEMORY_BYTES, MAX_MEMORY_CHARS,
        "the old name, same limit"
    );
    let set = |notes: u32, chars: u32| {
        let mut c = v02();
        let l = c.agents[0].learning.as_mut().unwrap();
        (l.max_notes, l.max_note_chars) = (notes, chars);
        c
    };
    accepts(&set(128, 2048)); // exactly 262144 characters
    rejects(
        &set(129, 2048),
        "may keep 264192 characters of notes (max_notes × max_note_chars), more than the 262144 characters",
    );
    // agents without a learning block, or with learning off, add nothing
    let mut c = set(128, 2048);
    c.agents[1].learning = None;
    accepts(&c);
    c.agents[1].learning = Some(LearningSpec {
        enabled: false,
        max_notes: 200,
        max_note_chars: 4000,
        ..LearningSpec::default()
    });
    accepts(&c);
}

#[test]
fn rule7_serialized_charter_at_most_256_kib() {
    // nine agents with a 31 KiB system prompt each: every agent is fine, the charter is not
    let mut c = v02();
    for i in 0..9 {
        let mut a = c.agents[1].clone();
        a.name = format!("bulk-{i}");
        a.system = "s".repeat(31 * 1024);
        c.agents.push(a);
    }
    rejects(&c, "bytes serialized, more than the 262144 allowed");
    c.agents.truncate(2 + 7);
    accepts(&c);
    // the YAML text is limited before it is parsed
    let big = format!("{V02}\n# {}\n", "x".repeat(MAX_CHARTER_BYTES));
    let err = Charter::from_yaml(&big).unwrap_err().to_string();
    assert!(err.contains("more than the 262144 allowed"), "{err}");
}

#[test]
fn rule7_harness_and_learning_ranges() {
    let h = |f: &dyn Fn(&mut HarnessSpec)| {
        let mut c = v02();
        f(c.agents[0].harness.as_mut().unwrap());
        c
    };
    accepts(&h(&|h| h.max_retries = 0));
    accepts(&h(&|h| h.max_retries = 10));
    rejects(
        &h(&|h| h.max_retries = 11),
        "harness.max_retries must be 0..=10",
    );
    accepts(&h(&|h| h.request_timeout_seconds = 600));
    rejects(
        &h(&|h| h.request_timeout_seconds = 0),
        "harness.request_timeout_seconds must be 1..=600",
    );
    rejects(
        &h(&|h| h.request_timeout_seconds = 601),
        "harness.request_timeout_seconds must be 1..=600",
    );
    accepts(&h(&|h| h.tool_result_max_chars = 100));
    accepts(&h(&|h| h.tool_result_max_chars = 200_000));
    rejects(
        &h(&|h| h.tool_result_max_chars = 99),
        "harness.tool_result_max_chars must be 100..=200000",
    );
    rejects(
        &h(&|h| h.tool_result_max_chars = 200_001),
        "harness.tool_result_max_chars must be 100..=200000",
    );

    let l = |f: &dyn Fn(&mut LearningSpec)| {
        let mut c = v02();
        f(c.agents[0].learning.as_mut().unwrap());
        c
    };
    for (field, low, high, set) in [
        (
            "max_notes",
            1,
            200,
            (&|l: &mut LearningSpec, v| l.max_notes = v) as &dyn Fn(&mut LearningSpec, u32),
        ),
        ("max_note_chars", 50, 4000, &|l, v| l.max_note_chars = v),
        ("note_ttl_days", 1, 365, &|l, v| l.note_ttl_days = v),
        ("max_proposals_per_hour", 1, 100, &|l, v| {
            l.max_proposals_per_hour = v
        }),
    ] {
        accepts(&l(&|x| set(x, low)));
        accepts(&l(&|x| set(x, high)));
        let msg = format!("learning.{field} must be {low}..={high}");
        rejects(&l(&|x| set(x, low - 1)), &msg);
        rejects(&l(&|x| set(x, high + 1)), &msg);
    }
}

// --- rule 8: service.service_accounts are DNS labels -----------------------------------------

#[test]
fn rule8_service_accounts_are_dns_labels() {
    accepts(&v02());
    let mut c = v02();
    c.service.service_accounts.push("Default_SA".into());
    rejects(
        &c,
        "service.service_accounts[2] \"Default_SA\" is not a DNS-1123 label",
    );
}

// --- schema level -----------------------------------------------------------------------------

#[test]
fn schema_level_is_1_without_v02_fields_and_2_with_any() {
    assert_eq!(CHARTER_SCHEMA_LEVEL, 2);
    assert_eq!(orders().schema_level(), 1);
    assert_eq!(Charter::from_yaml(INVENTORY).unwrap().schema_level(), 1);
    assert_eq!(v02().schema_level(), 2);
    type Edit = fn(&mut Charter);
    let edits: [(&str, Edit); 6] = [
        ("skills", |c| {
            c.skills.push(SkillSpec {
                name: "s".into(),
                description: "d".into(),
                instructions: "i".into(),
                tools: vec![],
            })
        }),
        ("telemetry", |c| {
            c.telemetry = Some(TelemetrySpec::default())
        }),
        ("service_accounts", |c| {
            c.service.service_accounts = vec!["orders".into()]
        }),
        ("agents[].skills", |c| {
            c.skills.push(SkillSpec {
                name: "s".into(),
                description: "d".into(),
                instructions: "i".into(),
                tools: vec![],
            });
            c.agents[0].skills = vec!["s".into()];
        }),
        ("harness", |c| {
            c.agents[0].harness = Some(HarnessSpec::default())
        }),
        ("learning", |c| {
            c.agents[0].learning = Some(LearningSpec::default())
        }),
    ];
    for (what, edit) in edits {
        let mut c = orders();
        edit(&mut c);
        accepts(&c);
        assert_eq!(c.schema_level(), 2, "{what}");
    }
    // empty v0.2 lists are not "used": they are not even serialized
    let c = Charter::from_yaml(&format!("{ORDERS}\nskills: []\n")).unwrap();
    assert_eq!(c.schema_level(), 1);
    assert!(!c.to_yaml().unwrap().contains("skills"));
}

#[test]
fn v01_charters_serialize_without_v02_keys() {
    let c = orders();
    let json = serde_json::to_value(&c).unwrap();
    for key in ["skills", "telemetry"] {
        assert!(json.get(key).is_none(), "{key}");
    }
    assert!(json["service"].get("service_accounts").is_none());
    for a in json["agents"].as_array().unwrap() {
        for key in ["skills", "harness", "learning"] {
            assert!(a.get(key).is_none(), "{key}");
        }
    }
    // and parse back to the same charter
    assert_eq!(Charter::from_yaml(&c.to_yaml().unwrap()).unwrap(), c);
    let v = v02();
    assert_eq!(Charter::from_yaml(&v.to_yaml().unwrap()).unwrap(), v);
}
