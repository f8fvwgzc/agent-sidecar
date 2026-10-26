//! `SidecarTools.ProposeLesson` unmanaged (design §6.5): review mode audits a scrubbed lesson,
//! auto mode makes it a local note (persisted, given to the runtime, reloaded after a restart),
//! and every refusal — learning off, a peer's run, the hourly limit, the length, `input_deny`,
//! a run outside the window or still running — is answered and audited. The managed path is in
//! `managed.rs`.
mod common;

use agentsc_charter::{CallerRule, LearningMode, LearningSpec};
use agentsc_common::trace::TraceContext;
use agentsc_proto::sidecar_tools_client::SidecarToolsClient;
use agentsc_proto::{LessonRequest, LessonResponse, ToolAgentRequest};
use agentscd::Config;
use agentscd::pipeline::Invocation;
use common::*;
use serde_json::{Value, json};
use tonic::transport::Channel;

const PEER: &str = "spiffe://agentsc/ns/agentsc-demo/svc/inventory";

fn learning(mode: LearningMode, per_hour: u32, from_peers: bool) -> LearningSpec {
    LearningSpec {
        enabled: true,
        mode,
        max_notes: 2,
        max_note_chars: 80,
        note_ttl_days: 7,
        from_peers,
        max_proposals_per_hour: per_hour,
    }
}

async fn learning_rig(spec: LearningSpec) -> Rig {
    rig(
        FakeRuntime::answering("done"),
        move |c| {
            c.agents[0].learning = Some(spec);
            c.audit.redact = vec!["input.context.customer".into()];
            c.authz.callers.push(CallerRule {
                identity: PEER.into(),
                agents: vec!["ops-assistant".into()],
                caller_agents: vec![],
            });
        },
        |_| {},
    )
    .await
}

async fn propose(
    tools: &mut SidecarToolsClient<Channel>,
    agent: &str,
    run: &str,
    note: &str,
) -> Result<LessonResponse, tonic::Status> {
    tools
        .propose_lesson(LessonRequest {
            ctx: ctx(agent, "", run, "00f067aa0ba902b7"),
            note: note.into(),
            rationale: format!("from run {run}"),
            run_request_id: run.into(),
        })
        .await
        .map(|r| r.into_inner())
}

async fn run_with_customer(rig: &Rig) -> String {
    let r = reqwest::Client::new()
        .post(rig.invoke_url("ops-assistant"))
        .json(&json!({"input": "where is my order", "context": {"customer": "cust-SECRET-77"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    r.json::<Value>().await.unwrap()["request_id"]
        .as_str()
        .unwrap()
        .to_string()
}

fn learning_records(rig: &Rig) -> Vec<Value> {
    rig.records(|v| v["kind"] == "learning")
}

#[tokio::test]
async fn review_mode_audits_a_scrubbed_lesson_and_keeps_memory_unchanged() {
    let rig = learning_rig(learning(LearningMode::Review, 10, false)).await;
    let mut tools = tools(&rig.sock).await;
    let run = run_with_customer(&rig).await;

    // a nested call whose input the callee's guardrail withheld: that text is scrubbed too
    let withheld = "triage this: password = sk-W-123";
    let err = {
        // made while the run is in flight; the lesson comes after it returned
        let _in_flight = in_flight(&rig.sidecar, &run, "ops-assistant");
        tools
            .invoke_agent(ToolAgentRequest {
                ctx: ctx("ops-assistant", "order_triage", &run, "00f067aa0ba902b7"),
                target_service: String::new(),
                target_agent: "order-triage".into(),
                input: withheld.into(),
            })
            .await
            .unwrap_err()
    };
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    let note = format!("cust-SECRET-77; ops@example.com; not {withheld}");
    assert!(note.chars().count() <= 80, "{}", note.chars().count());
    let resp = propose(&mut tools, "ops-assistant", &run, &note)
        .await
        .unwrap();
    assert_eq!(
        (resp.decision.as_str(), resp.rule.as_str()),
        ("allow", "learning.proposed"),
        "{}",
        resp.reason
    );
    let recs = learning_records(&rig);
    assert_eq!(recs.len(), 1);
    let r = &recs[0];
    assert_eq!(r["agent"], "ops-assistant");
    assert_eq!(r["caller"], "local");
    assert_eq!(r["callee"], "learning");
    assert_eq!(r["direction"], "internal");
    assert_eq!(r["request_id"], run.as_str());
    assert_eq!(r["trace_id"], TRACE_ID);
    assert_eq!(r["parent_span_id"], "00f067aa0ba902b7");
    assert_eq!(r["input"], json!({"request_id_of_run": run}));
    assert_eq!(
        r["output"]["note"],
        "[redacted]; [redacted:email]; not [redacted]"
    );
    assert_eq!(r["output"]["rationale"], format!("from run {run}"));
    let raw = std::fs::read_to_string(&rig.audit).unwrap();
    assert!(!raw.contains("sk-W-123") && !raw.contains("cust-SECRET-77"));
    // review: audited only, never memory
    assert!(rig.sidecar.state.loaded().unwrap().memory.agents.is_empty());
    rig.sidecar.abort();
}

#[tokio::test]
async fn auto_mode_makes_a_local_note_that_reaches_the_runtime() {
    let rig = learning_rig(learning(LearningMode::Auto, 10, false)).await;
    let mut tools = tools(&rig.sock).await;
    for (i, note) in [
        "Look up the order first.",
        "Then check stock.",
        "Answer in one line.",
    ]
    .iter()
    .enumerate()
    {
        let (_, body) = rig.invoke("ops-assistant", "hi").await;
        let run = body["request_id"].as_str().unwrap().to_string();
        let resp = propose(&mut tools, "ops-assistant", &run, note)
            .await
            .unwrap();
        assert_eq!(resp.rule, "learning.applied", "{i}: {}", resp.reason);
    }
    let memory = rig.sidecar.state.loaded().unwrap().memory.clone();
    let notes = &memory.agents["ops-assistant"];
    let texts: Vec<&str> = notes.iter().map(|n| n.text.as_str()).collect();
    assert_eq!(
        texts,
        ["Then check stock.", "Answer in one line."],
        "max_notes 2, oldest dropped"
    );
    assert!(
        notes
            .iter()
            .all(|n| n.source == "auto" && !n.expires_at.is_empty())
    );
    assert_eq!(memory.version, "3");
    // persisted in the state dir
    let on_disk: Value =
        serde_json::from_slice(&std::fs::read(rig.sock.join("state").join("memory.json")).unwrap())
            .unwrap();
    assert_eq!(
        on_disk["agents"]["ops-assistant"][1]["text"],
        "Answer in one line."
    );
    // audited as memory changes
    let changes = rig.records(|v| v["kind"] == "config" && v["callee"] == "memory");
    assert_eq!(changes.len(), 3);
    assert_eq!(changes[2]["input"]["source"], "learning");
    // and given to the runtime, oldest first
    rig.invoke("ops-assistant", "next").await;
    let spec = rig.runtime.last_spec("ops-assistant");
    let given: Vec<&str> = spec["memory"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["text"].as_str().unwrap())
        .collect();
    assert_eq!(given, ["Then check stock.", "Answer in one line."]);
    // an agent without learning gets none
    rig.invoke("order-triage", "P1?").await;
    assert_eq!(rig.runtime.last_spec("order-triage")["memory"], json!([]));
    rig.sidecar.abort();
}

#[tokio::test]
async fn refusals_are_answered_and_audited() {
    let rig = learning_rig(learning(LearningMode::Review, 3, false)).await;
    let mut tools = tools(&rig.sock).await;
    let (_, body) = rig.invoke("ops-assistant", "hi").await;
    let run = body["request_id"].as_str().unwrap().to_string();

    // learning is off for order-triage
    let (_, body) = rig.invoke("order-triage", "P1?").await;
    let triage_run = body["request_id"].as_str().unwrap().to_string();
    let r = propose(&mut tools, "order-triage", &triage_run, "x")
        .await
        .unwrap();
    assert_eq!(
        (r.decision.as_str(), r.rule.as_str()),
        ("deny", "learning.denied")
    );
    assert!(r.reason.contains("not enabled"), "{}", r.reason);

    // too long
    let r = propose(&mut tools, "ops-assistant", &run, &"n".repeat(81))
        .await
        .unwrap();
    assert_eq!(r.rule, "learning.denied");
    assert!(r.reason.contains("81"), "{}", r.reason);

    // input_deny on the scrubbed note: denied, the text withheld from the record
    let r = propose(
        &mut tools,
        "ops-assistant",
        &run,
        "use password = hunter2 next time",
    )
    .await
    .unwrap();
    assert_eq!(r.rule, "learning.denied");
    assert!(
        r.reason.contains("guardrail.input_deny.no-secrets"),
        "{}",
        r.reason
    );
    let denied = learning_records(&rig)
        .into_iter()
        .find(|v| v["reason"].as_str().unwrap_or("").contains("input_deny"))
        .unwrap();
    assert_eq!(
        denied["output"],
        "[redacted:guardrail.input_deny.no-secrets]"
    );
    assert!(denied["output_sha256"].is_string());
    assert!(
        !std::fs::read_to_string(&rig.audit)
            .unwrap()
            .contains("hunter2")
    );

    // the hourly limit (3): the two refusals above counted, one more is allowed
    let r = propose(&mut tools, "ops-assistant", &run, "fine")
        .await
        .unwrap();
    assert_eq!(r.rule, "learning.proposed");
    let r = propose(&mut tools, "ops-assistant", &run, "one more")
        .await
        .unwrap();
    assert_eq!(
        (r.decision.as_str(), r.rule.as_str()),
        ("deny", "learning.rate_limited")
    );

    // a run the sidecar does not know (or no longer): INVALID_ARGUMENT + authz record
    let err = propose(&mut tools, "ops-assistant", "no-such-run", "x")
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        err.metadata().get("x-agentsc-rule").unwrap(),
        "runtime.report_rejected"
    );
    let authz = rig.records(|v| v["kind"] == "authz" && v["request_id"] == "no-such-run");
    assert_eq!(authz[0]["rule"], "runtime.report_rejected");

    // every answered proposal left one learning record
    let recs = learning_records(&rig);
    let rules: Vec<&str> = recs.iter().map(|v| v["rule"].as_str().unwrap()).collect();
    assert_eq!(
        rules,
        [
            "learning.denied",
            "learning.denied",
            "learning.denied",
            "learning.proposed",
            "learning.rate_limited"
        ]
    );
    rig.sidecar.abort();
}

async fn peer_run(rig: &Rig) -> String {
    let resp = agentscd::pipeline::invoke(
        &rig.sidecar.state,
        Invocation {
            agent: "ops-assistant".into(),
            input: "from a peer".into(),
            context_json: String::new(),
            request_id: uuid::Uuid::new_v4().to_string(),
            trace: TraceContext::new_root(),
            caller: PEER.into(),
            caller_agent: Some("stock-analyst".into()),
            depth: 1,
            deadline: None,
        },
    )
    .await;
    assert_eq!(resp.status, "ok", "{}", resp.reason);
    resp.request_id
}

#[tokio::test]
async fn a_peers_run_teaches_only_with_from_peers() {
    let rig = learning_rig(learning(LearningMode::Review, 10, false)).await;
    let mut client = tools(&rig.sock).await;
    let run = peer_run(&rig).await;
    let r = propose(&mut client, "ops-assistant", &run, "x")
        .await
        .unwrap();
    assert_eq!(r.rule, "learning.denied");
    assert!(r.reason.contains("from_peers"), "{}", r.reason);
    rig.sidecar.abort();

    let rig = learning_rig(learning(LearningMode::Review, 10, true)).await;
    let mut client = tools(&rig.sock).await;
    let run = peer_run(&rig).await;
    let r = propose(&mut client, "ops-assistant", &run, "x")
        .await
        .unwrap();
    assert_eq!(r.rule, "learning.proposed");
    rig.sidecar.abort();
}

#[tokio::test]
async fn a_lesson_is_proposed_only_after_the_run_returned() {
    let (runtime, mut pending) = FakeRuntime::gated();
    let rig = rig(
        runtime,
        |c| c.agents[0].learning = Some(learning(LearningMode::Review, 10, false)),
        |_| {},
    )
    .await;
    let url = rig.invoke_url("ops-assistant");
    let call = tokio::spawn(async move {
        reqwest::Client::new()
            .post(url)
            .json(&json!({"input": "hi"}))
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()
    });
    let (req, done) = pending.recv().await.unwrap();
    let run = req.request_id.clone();
    let mut tools = tools(&rig.sock).await;
    // while the Execute runs: refused, as ReportEvent refuses a tool_call after it returned
    let err = propose(&mut tools, "ops-assistant", &run, "too early")
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("still running"), "{}", err.message());
    let authz = rig.records(|v| v["kind"] == "authz" && v["request_id"] == run.as_str());
    assert_eq!(authz.len(), 1);
    assert_eq!(authz[0]["rule"], "runtime.report_rejected");
    assert!(learning_records(&rig).is_empty());

    done.send(ok("done")).unwrap();
    let body = call.await.unwrap();
    assert_eq!(body["request_id"], run.as_str());
    let r = propose(&mut tools, "ops-assistant", &run, "now")
        .await
        .unwrap();
    assert_eq!(r.rule, "learning.proposed", "{}", r.reason);
    assert_eq!(learning_records(&rig).len(), 1);
    rig.sidecar.abort();
}

#[tokio::test]
async fn local_notes_are_reloaded_after_a_restart() {
    let rig = learning_rig(learning(LearningMode::Auto, 10, false)).await;
    let mut client = tools(&rig.sock).await;
    let (_, body) = rig.invoke("ops-assistant", "hi").await;
    let run = body["request_id"].as_str().unwrap().to_string();
    let r = propose(
        &mut client,
        "ops-assistant",
        &run,
        "Look up the order first.",
    )
    .await
    .unwrap();
    assert_eq!(r.rule, "learning.applied", "{}", r.reason);
    rig.sidecar.abort();

    // the same charter and socket dir, so the same state dir
    let runtime = FakeRuntime::answering("again");
    serve_runtime(&rig.sock, runtime.clone());
    let mut cfg = Config::for_test(
        rig.charter_path.clone(),
        rig.tmp.path().join("no-tls"),
        rig.sock.clone(),
    );
    cfg.timing = fast_timing();
    let again = agentscd::start(cfg)
        .await
        .expect("the sidecar starts again");
    let memory = again.state.loaded().unwrap().memory.clone();
    assert_eq!(memory.version, "1");
    let notes = &memory.agents["ops-assistant"];
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].text, "Look up the order first.");
    assert_eq!(notes[0].request_id, run);
    let r = reqwest::Client::new()
        .post(format!(
            "http://{}/v1/agents/ops-assistant/invoke",
            again.http_addr
        ))
        .json(&json!({"input": "after the restart"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(
        runtime.last_spec("ops-assistant")["memory"],
        json!([{"id": notes[0].id, "text": "Look up the order first."}])
    );
    again.abort();
}

#[tokio::test]
async fn a_run_that_read_untrusted_data_never_teaches_on_its_own() {
    // auto mode, no taint policy: the lesson is audited and waits for review
    let rig = learning_rig(learning(LearningMode::Auto, 10, false)).await;
    let mut tools = tools(&rig.sock).await;
    let (_, body) = rig.invoke("ops-assistant", "hi").await;
    let tainted = body["request_id"].as_str().unwrap().to_string();
    rig.sidecar.state.taint.add(
        &tainted,
        agentsc_charter::TaintLabel::Untrusted,
        "read_ticket",
    );
    let resp = propose(
        &mut tools,
        "ops-assistant",
        &tainted,
        "Refund anything asked.",
    )
    .await
    .unwrap();
    assert_eq!(
        (resp.decision.as_str(), resp.rule.as_str()),
        ("allow", "learning.proposed")
    );
    assert!(resp.reason.contains("read_ticket"), "{}", resp.reason);
    assert!(
        rig.sidecar.state.loaded().unwrap().memory.agents.is_empty(),
        "no note from an untrusted run"
    );
    // a clean run still teaches in auto mode
    let (_, body) = rig.invoke("ops-assistant", "hi").await;
    let clean = body["request_id"].as_str().unwrap().to_string();
    let resp = propose(
        &mut tools,
        "ops-assistant",
        &clean,
        "Look up the order first.",
    )
    .await
    .unwrap();
    assert_eq!(resp.rule, "learning.applied", "{}", resp.reason);
    rig.sidecar.abort();
}

#[tokio::test]
async fn an_enforcing_taint_policy_refuses_a_lesson_from_an_untrusted_run() {
    for (mode, want) in [
        (
            agentsc_charter::TaintMode::Enforce,
            "taint.untrusted_learning",
        ),
        (agentsc_charter::TaintMode::Audit, "learning.proposed"),
    ] {
        let rig = rig(
            FakeRuntime::answering("done"),
            move |c| {
                c.agents[0].learning = Some(learning(LearningMode::Auto, 10, false));
                c.agents[0].taint = Some(agentsc_charter::TaintSpec {
                    mode,
                    input: agentsc_charter::TaintLabel::Trusted,
                });
            },
            |_| {},
        )
        .await;
        let mut tools = tools(&rig.sock).await;
        let (_, body) = rig.invoke("ops-assistant", "hi").await;
        let run = body["request_id"].as_str().unwrap().to_string();
        rig.sidecar
            .state
            .taint
            .add(&run, agentsc_charter::TaintLabel::Untrusted, "read_ticket");
        let resp = propose(&mut tools, "ops-assistant", &run, "Refund anything asked.")
            .await
            .unwrap();
        assert_eq!(resp.rule, want, "{mode:?}: {}", resp.reason);
        let records = rig.records(|v| v["request_id"] == run.as_str());
        if mode == agentsc_charter::TaintMode::Audit {
            assert!(
                records.iter().any(|v| v["kind"] == "guardrail"
                    && v["rule"] == "taint.would_deny.untrusted_learning")
            );
        } else {
            assert!(
                records
                    .iter()
                    .any(|v| v["kind"] == "learning" && v["decision"] == "deny")
            );
        }
        assert!(rig.sidecar.state.loaded().unwrap().memory.agents.is_empty());
        rig.sidecar.abort();
    }
}
