//! `agentsc_charter::diff`: restart-only fields (design §4), weakened protection (§5) and the
//! role a change needs (§8.3).
mod common;

use agentsc_charter::diff::{Role, required_role, restart_required, weakened};
use agentsc_charter::*;
use common::*;

fn changed(edit: impl FnOnce(&mut Charter)) -> (Charter, Charter) {
    let old = v02();
    let mut new = old.clone();
    edit(&mut new);
    new.validate().expect("the edited charter is valid");
    (old, new)
}

fn role(edit: impl FnOnce(&mut Charter)) -> (Role, Vec<String>) {
    let (old, new) = changed(edit);
    required_role(&old, &new)
}

fn editor(what: &str, edit: impl FnOnce(&mut Charter)) {
    let (r, reasons) = role(edit);
    assert_eq!((r, reasons), (Role::Editor, vec![]), "{what}");
}

fn admin(edit: impl FnOnce(&mut Charter), reason: &str) {
    let (r, reasons) = role(edit);
    assert_eq!(r, Role::Admin, "{reason}");
    assert!(
        reasons.iter().any(|x| x == reason),
        "expected {reason:?} in {reasons:?}"
    );
}

// --- restart_required ---------------------------------------------------------------------------

#[test]
fn restart_only_fields_are_named() {
    let c = v02();
    assert!(restart_required(&c, &c).is_empty());
    type Edit = fn(&mut Charter);
    let cases: [(&str, Edit); 7] = [
        ("service.name", |c| {
            c.service.name = "help".into();
        }),
        ("service.namespace", |c| {
            c.service.namespace = "store".into()
        }),
        ("service.app_port", |c| c.service.app_port = 9000),
        ("mesh.port", |c| c.mesh.port = 50003),
        ("audit.sink", |c| {
            c.audit.sink = AuditSink::File;
            c.audit.file = Some("/var/log/agentsc/audit.jsonl".into());
        }),
        ("audit.file", |c| c.audit.file = Some("/tmp/a.jsonl".into())),
        ("telemetry.otlp_endpoint", |c| {
            c.telemetry.as_mut().unwrap().otlp_endpoint = Some("http://other:4318".into())
        }),
    ];
    for (field, edit) in cases {
        let mut new = c.clone();
        edit(&mut new);
        let got = restart_required(&c, &new);
        assert!(got.contains(&field.to_string()), "{field}: {got:?}");
        if field != "audit.sink" {
            assert_eq!(got, vec![field.to_string()]);
        }
    }
    // everything else applies live
    let mut new = c.clone();
    new.agents[0].system = "Be brief.".into();
    new.mesh
        .peers
        .insert("orders".into(), "orders:50002".into());
    new.telemetry.as_mut().unwrap().traces = false;
    new.audit.redact.clear();
    assert!(restart_required(&c, &new).is_empty());
    // an absent telemetry block is the default one
    let o = orders();
    let mut with = o.clone();
    with.telemetry = Some(TelemetrySpec::default());
    assert!(restart_required(&o, &with).is_empty());
    with.telemetry.as_mut().unwrap().otlp_endpoint = Some("http://otel:4318".into());
    assert_eq!(restart_required(&o, &with), ["telemetry.otlp_endpoint"]);
}

// --- weakened ------------------------------------------------------------------------------------

#[test]
fn weakening_changes_are_listed() {
    let c = v02();
    assert!(weakened(&c, &c).is_empty());
    let (old, new) = changed(|c| c.audit.redact.clear());
    assert_eq!(weakened(&old, &new), ["audit.redact[input.context.card]"]);
    let (old, new) = changed(|c| c.guardrails.pii_redact = false);
    assert_eq!(weakened(&old, &new), ["guardrails.pii_redact"]);
    let (old, new) = changed(|c| c.telemetry.as_mut().unwrap().export_payloads = true);
    assert_eq!(weakened(&old, &new), ["telemetry.export_payloads"]);
    let (old, new) = changed(|c| c.authz.default = Decision::Allow);
    assert_eq!(weakened(&old, &new), ["authz.default"]);
    let (old, new) = changed(|c| c.guardrails.input_deny.clear());
    assert_eq!(weakened(&old, &new), ["guardrails.input_deny[no-secrets]"]);
    let (old, new) = changed(|c| c.guardrails.input_deny[0].regex = "never-matches-x".into());
    assert_eq!(
        weakened(&old, &new),
        ["guardrails.input_deny[no-secrets]"],
        "a changed regex counts as removed"
    );
    // output_deny: start from a charter that has one
    let mut old = v02();
    old.guardrails.output_deny.push(RegexRule {
        name: "no-cards".into(),
        regex: r"\d{16}".into(),
    });
    let new = v02();
    assert_eq!(weakened(&old, &new), ["guardrails.output_deny[no-cards]"]);
    // several at once, in a fixed order
    let (old, new) = changed(|c| {
        c.authz.default = Decision::Allow;
        c.audit.redact.clear();
        c.guardrails.pii_redact = false;
    });
    assert_eq!(
        weakened(&old, &new),
        [
            "audit.redact[input.context.card]",
            "guardrails.pii_redact",
            "authz.default"
        ]
    );
}

#[test]
fn strengthening_changes_are_not_weakening() {
    let (old, new) = changed(|c| {
        c.audit.redact.push("output.body.card".into());
        c.guardrails.input_deny.push(RegexRule {
            name: "no-keys".into(),
            regex: "(?i)api[_-]?key".into(),
        });
        c.telemetry.as_mut().unwrap().control_plane_payloads = false;
    });
    assert!(weakened(&old, &new).is_empty());
    // the reverse of a weakening is not one
    let mut open = v02();
    open.authz.default = Decision::Allow;
    open.guardrails.pii_redact = false;
    open.telemetry.as_mut().unwrap().export_payloads = true;
    assert!(weakened(&open, &v02()).is_empty());
    // absent telemetry is export_payloads: false
    let o = orders();
    let mut exporting = o.clone();
    exporting.telemetry = Some(TelemetrySpec {
        export_payloads: true,
        ..TelemetrySpec::default()
    });
    assert_eq!(weakened(&o, &exporting), ["telemetry.export_payloads"]);
}

// --- required_role: what an editor may do ----------------------------------------------------------

#[test]
fn editors_may_change_agents_skills_and_local_callers() {
    editor("no change", |_| {});
    editor("system", |c| c.agents[0].system = "Be brief.".into());
    editor("model", |c| c.agents[1].model = "claude-haiku-5-5".into());
    editor("budgets", |c| c.agents[0].budgets.max_steps = 3);
    editor("agent skills", |c| {
        c.agents[0].skills.pop().map(drop).unwrap_or(())
    });
    editor("harness", |c| {
        c.agents[0].harness.as_mut().unwrap().max_retries = 5;
        c.agents[1].harness = Some(HarnessSpec::default());
    });
    editor("learning, review mode", |c| {
        let l = c.agents[0].learning.as_mut().unwrap();
        l.max_notes = 50;
        l.from_peers = true;
        c.agents[1].learning = Some(LearningSpec {
            enabled: true,
            ..LearningSpec::default()
        });
    });
    editor("learning off, from auto", |c| {
        c.agents[0].learning.as_mut().unwrap().enabled = false;
    });
    editor("service and agent tools", |c| {
        c.agents[0].tools.push(ToolSpec {
            name: "cancel".into(),
            description: "Cancel an order.".into(),
            tool_type: ToolType::Service,
            parameters: None,
            service: Some("orders".into()),
            method: Some("POST".into()),
            path: Some("/orders/{id}/cancel".into()),
            agent: None,
            url: None,
        });
        c.agents[0].tools.push(ToolSpec {
            name: "stock".into(),
            description: "Ask the stock analyst.".into(),
            tool_type: ToolType::Agent,
            parameters: None,
            service: Some("inventory".into()),
            method: None,
            path: None,
            agent: Some("stock-analyst".into()),
            url: None,
        });
        c.guardrails.allowed_tools.remove("support");
    });
    editor("an http tool to a known origin", |c| {
        let mut t = c.agents[0].tools[3].clone();
        t.name = "partner_status".into();
        t.url = Some("https://api.partner.example/v1/status".into());
        c.agents[0].tools.push(t);
        c.guardrails.allowed_tools.remove("support");
    });
    editor("top-level skills", |c| {
        c.skills[1].instructions = "Escalate after two failed answers.".into();
        c.skills.push(SkillSpec {
            name: "tone".into(),
            description: "House style.".into(),
            instructions: "Be kind.".into(),
            tools: vec![],
        });
    });
    editor("allowed_tools and allowed_services", |c| {
        c.guardrails.allowed_tools.insert("triage".into(), vec![]);
        c.guardrails
            .allowed_services
            .insert("support".into(), vec!["orders".into()]);
    });
    editor("agent names in local caller rules", |c| {
        c.authz.callers[0].agents = vec!["support".into()];
        c.authz.callers.push(CallerRule {
            identity: LOCAL_IDENTITY.into(),
            agents: vec!["triage".into()],
            caller_agents: vec!["support".into()],
        });
    });
    editor("create an agent", |c| {
        let mut a = c.agents[1].clone();
        a.name = "billing".into();
        c.agents.push(a);
    });
}

#[test]
fn deleting_an_agent_cascades_through_caller_rules_as_editor() {
    // support is named in a peer's caller rule: deleting it drops that rule (left empty)
    editor("delete support", |c| {
        c.agents.retain(|a| a.name != "support");
        c.guardrails.allowed_tools.remove("support");
        c.authz.callers.retain(|r| r.identity == LOCAL_IDENTITY);
    });
    // a rule that names other agents too keeps them
    let mut old = v02();
    old.authz.callers[1].agents = vec!["support".into(), "triage".into()];
    let mut new = old.clone();
    new.agents.retain(|a| a.name != "support");
    new.guardrails.allowed_tools.remove("support");
    new.authz.callers[1].agents = vec!["triage".into()];
    new.validate().unwrap();
    assert_eq!(required_role(&old, &new), (Role::Editor, vec![]));
    // but removing a still-existing agent from a peer rule is an authz change
    let mut narrowed = old.clone();
    narrowed.authz.callers[1].agents = vec!["triage".into()];
    let (r, reasons) = required_role(&old, &narrowed);
    assert_eq!(r, Role::Admin);
    assert_eq!(
        reasons,
        ["authz.callers rule for spiffe://agentsc/ns/shop/svc/web requires admin"]
    );
}

// --- required_role: what needs an admin ----------------------------------------------------------

#[test]
fn authz_needs_admin_except_local_agent_names() {
    admin(
        |c| c.authz.default = Decision::Allow,
        "authz.default requires admin",
    );
    admin(
        |c| c.authz.services[0].allow.push("DELETE /orders/*".into()),
        "authz.services requires admin",
    );
    admin(
        |c| c.authz.services.clear(),
        "authz.services requires admin",
    );
    // a new caller rule for a non-local identity
    admin(
        |c| {
            c.authz.callers.push(CallerRule {
                identity: "spiffe://agentsc/ns/shop/svc/mobile".into(),
                agents: vec!["support".into()],
                caller_agents: vec![],
            })
        },
        "authz.callers rule for spiffe://agentsc/ns/shop/svc/mobile requires admin",
    );
    // widening an existing non-local rule, or narrowing its caller agents
    admin(
        |c| c.authz.callers[1].agents.push("triage".into()),
        "authz.callers rule for spiffe://agentsc/ns/shop/svc/web requires admin",
    );
    admin(
        |c| c.authz.callers[1].caller_agents = vec!["frontend".into()],
        "authz.callers rule for spiffe://agentsc/ns/shop/svc/web requires admin",
    );
    // removing one
    admin(
        |c| c.authz.callers.truncate(1),
        "authz.callers rule for spiffe://agentsc/ns/shop/svc/web requires admin",
    );
    // turning a local rule into a peer rule
    admin(
        |c| c.authz.callers[0].identity = "spiffe://agentsc/ns/shop/svc/x".into(),
        "authz.callers rule for spiffe://agentsc/ns/shop/svc/x requires admin",
    );
    // reordering rules is no change
    editor("reorder callers", |c| c.authz.callers.reverse());
}

#[test]
fn guardrail_rules_audit_telemetry_mesh_and_service_need_admin() {
    admin(
        |c| c.guardrails.max_input_bytes = 1024,
        "guardrails.max_input_bytes requires admin",
    );
    admin(
        |c| c.guardrails.pii_redact = false,
        "guardrails.pii_redact requires admin",
    );
    admin(
        |c| {
            c.guardrails.input_deny.push(RegexRule {
                name: "x".into(),
                regex: "x".into(),
            })
        },
        "guardrails.input_deny requires admin",
    );
    admin(
        |c| {
            c.guardrails.output_deny.push(RegexRule {
                name: "x".into(),
                regex: "x".into(),
            })
        },
        "guardrails.output_deny requires admin",
    );
    admin(|c| c.audit.redact.clear(), "audit.redact requires admin");
    admin(
        |c| {
            c.audit.sink = AuditSink::File;
            c.audit.file = Some("/var/log/agentsc/audit.jsonl".into());
        },
        "audit.sink requires admin",
    );
    admin(
        |c| c.audit.file = Some("/tmp/x".into()),
        "audit.file requires admin",
    );
    for (field, edit) in [
        (
            "telemetry.otlp_endpoint",
            (|t: &mut TelemetrySpec| t.otlp_endpoint = None) as fn(&mut TelemetrySpec),
        ),
        ("telemetry.traces", |t| t.traces = false),
        ("telemetry.metrics", |t| t.metrics = false),
        ("telemetry.export_payloads", |t| t.export_payloads = true),
        ("telemetry.control_plane_payloads", |t| {
            t.control_plane_payloads = false
        }),
    ] {
        admin(
            |c| edit(c.telemetry.as_mut().unwrap()),
            &format!("{field} requires admin"),
        );
    }
    admin(|c| c.mesh.port = 50003, "mesh.port requires admin");
    admin(
        |c| {
            c.mesh
                .peers
                .insert("orders".into(), "orders.other:50002".into());
        },
        "mesh.peers requires admin",
    );
    admin(
        |c| c.service.app_port = 9000,
        "service.app_port requires admin",
    );
    admin(
        |c| c.service.service_accounts.push("ops".into()),
        "service.service_accounts requires admin",
    );
    admin(
        |c| c.service.namespace = "store".into(),
        "service.namespace requires admin",
    );
    admin(
        |c| {
            c.service.name = "help".into();
            c.agents[0].tools[0].service = Some("orders".into());
        },
        "service.name requires admin",
    );
}

#[test]
fn auto_learning_agent_type_and_new_http_origins_need_admin() {
    admin(
        |c| c.agents[0].learning.as_mut().unwrap().mode = LearningMode::Auto,
        "agents.support.learning.mode: auto requires admin",
    );
    admin(
        |c| {
            let mut a = c.agents[1].clone();
            a.name = "learner".into();
            a.learning = Some(LearningSpec {
                enabled: true,
                mode: LearningMode::Auto,
                ..LearningSpec::default()
            });
            c.agents.push(a);
        },
        "agents.learner.learning.mode: auto requires admin",
    );
    // an agent already in auto mode may be tuned by an editor
    let mut old = v02();
    old.agents[0].learning.as_mut().unwrap().mode = LearningMode::Auto;
    let mut new = old.clone();
    new.agents[0].learning.as_mut().unwrap().note_ttl_days = 3;
    assert_eq!(required_role(&old, &new), (Role::Editor, vec![]));
    admin(
        |c| c.agents[1].agent_type = AgentType::Orchestrator,
        "agents.triage.type requires admin",
    );
    admin(
        |c| {
            c.agents[0].tools[3].url = Some("https://evil.example/v1/parcels/{id}".into());
        },
        "agents.support.tools.partner (new http origin https://evil.example) requires admin",
    );
    admin(
        |c| {
            let mut t = c.agents[0].tools[3].clone();
            t.name = "partner2".into();
            t.url = Some("https://api.partner.example:8443/v1/x".into());
            c.agents[1].agent_type = AgentType::Agent;
            c.agents[1].tools.push(t);
        },
        "agents.triage.tools.partner2 (new http origin https://api.partner.example:8443) requires admin",
    );
}

#[test]
fn every_admin_field_is_named_once() {
    let (old, new) = changed(|c| {
        c.authz.default = Decision::Allow;
        c.guardrails.pii_redact = false;
        c.mesh.port = 50003;
        c.agents[0].learning.as_mut().unwrap().mode = LearningMode::Auto;
    });
    let (r, reasons) = required_role(&old, &new);
    assert_eq!(r, Role::Admin);
    assert_eq!(
        reasons,
        [
            "mesh.port requires admin",
            "guardrails.pii_redact requires admin",
            "authz.default requires admin",
            "agents.support.learning.mode: auto requires admin",
        ]
    );
    assert!(Role::Viewer < Role::Editor && Role::Editor < Role::Admin);
    assert_eq!(serde_json::to_value(Role::Admin).unwrap(), "admin");
    assert_eq!(Role::Editor.to_string(), "editor");
}

#[test]
fn a_first_charter_needs_editor_to_adopt_and_admin_to_put() {
    use agentsc_charter::diff::{FirstCharter, first_charter_role};
    // design §8.3: adoption of a pending charter is an editor action; a first PUT is admin
    assert_eq!(
        first_charter_role(FirstCharter::Adopt),
        (Role::Editor, vec![])
    );
    let (r, reasons) = first_charter_role(FirstCharter::Put);
    assert_eq!(r, Role::Admin);
    assert_eq!(reasons, ["a first charter written with PUT requires admin"]);
    assert!(reasons.iter().all(|r| r.ends_with("requires admin")));
}
