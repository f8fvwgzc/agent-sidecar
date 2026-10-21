//! `SidecarTools.ReportEvent` tightened (design §6.5): only `model_call` records, and `tool_call`
//! records for `load_skill:<skill>` of the agent's skills while its Execute runs, for an
//! (agent, request id) whose Execute is in flight or returned less than the run window ago;
//! anything else is `INVALID_ARGUMENT` plus an `authz` record `runtime.report_rejected`. Once the
//! agent's daily cost budget is spent, every answer carries `x-agentsc-rule`.
mod common;

use std::time::Duration;

use agentsc_charter::SkillSpec;
use agentsc_common::audit::{AuditRecord, Direction, Kind};
use agentsc_common::trace::TraceContext;
use agentsc_proto::AuditEvent;
use agentsc_proto::sidecar_tools_client::SidecarToolsClient;
use common::*;
use serde_json::{Value, json};
use tonic::Code;
use tonic::transport::Channel;

fn record(kind: Kind, request_id: &str, agent: Option<&str>, callee: &str, cost: f64) -> String {
    let mut r = AuditRecord::new(
        kind,
        if kind == Kind::ModelCall {
            Direction::Outbound
        } else {
            Direction::Internal
        },
        request_id,
        &TraceContext::from_traceparent(&format!("00-{TRACE_ID}-00f067aa0ba902b7-01")),
        agent,
        "local",
        None,
        callee,
        json!({"messages": []}),
        Value::Null,
    );
    if kind == Kind::ModelCall {
        r.cost_usd = Some(cost);
    }
    r.to_json_line()
}

/// `Ok(rule header)` or `Err((code, rule))`.
async fn report(
    tools: &mut SidecarToolsClient<Channel>,
    json: String,
) -> Result<Option<String>, (Code, String)> {
    match tools.report_event(AuditEvent { json }).await {
        Ok(r) => Ok(r
            .metadata()
            .get("x-agentsc-rule")
            .map(|v| v.to_str().unwrap().to_string())),
        Err(st) => Err((
            st.code(),
            st.metadata()
                .get("x-agentsc-rule")
                .map(|v| v.to_str().unwrap().to_string())
                .unwrap_or_default(),
        )),
    }
}

fn rejected() -> Result<Option<String>, (Code, String)> {
    Err((Code::InvalidArgument, "runtime.report_rejected".into()))
}

#[tokio::test]
async fn report_event_takes_only_what_the_run_may_report() {
    let (runtime, mut gate) = FakeRuntime::gated();
    let rig = rig(
        runtime,
        |c| {
            c.skills.push(SkillSpec {
                name: "refund-policy".into(),
                description: "How to decide refunds.".into(),
                instructions: "Look up the order first.".into(),
                tools: vec![],
            });
            c.agents[0].skills = vec!["refund-policy".into()];
        },
        |_| {},
    )
    .await;
    let mut tools = tools(&rig.sock).await;

    // no such run
    assert_eq!(
        report(
            &mut tools,
            record(Kind::ModelCall, "nope", Some("ops-assistant"), "mock", 0.0)
        )
        .await,
        rejected()
    );

    // a run in flight
    let url = rig.invoke_url("ops-assistant");
    let call = tokio::spawn(async move {
        reqwest::Client::new()
            .post(url)
            .json(&json!({"input": "refund order 1001?"}))
            .send()
            .await
            .unwrap()
            .status()
    });
    let (req, done) = gate.recv().await.unwrap();
    let id = req.request_id.clone();
    let ok_ = |r: Result<Option<String>, (Code, String)>| assert_eq!(r, Ok(None));
    ok_(report(
        &mut tools,
        record(Kind::ModelCall, &id, Some("ops-assistant"), "mock", 0.001),
    )
    .await);
    ok_(report(
        &mut tools,
        record(
            Kind::ToolCall,
            &id,
            Some("ops-assistant"),
            "load_skill:refund-policy",
            0.0,
        ),
    )
    .await);
    for (kind, agent, callee) in [
        (
            Kind::ToolCall,
            Some("ops-assistant"),
            "load_skill:other-skill",
        ),
        (Kind::ToolCall, Some("ops-assistant"), "load_skill"),
        (Kind::ToolCall, Some("ops-assistant"), "lookup_order"),
        (
            Kind::AgentInvocation,
            Some("ops-assistant"),
            "ops-assistant",
        ),
        (
            Kind::ServiceCall,
            Some("ops-assistant"),
            "orders GET /orders/1",
        ),
        (Kind::Learning, Some("ops-assistant"), "learning"),
        (Kind::ModelCall, Some("order-triage"), "mock"),
        (Kind::ModelCall, None, "mock"),
    ] {
        assert_eq!(
            report(&mut tools, record(kind, &id, agent, callee, 0.0)).await,
            rejected(),
            "{kind} {agent:?} {callee}"
        );
    }
    assert_eq!(
        report(&mut tools, "{\"not\": \"a record\"}".into()).await,
        rejected()
    );
    done.send(ok("refund allowed")).unwrap();
    assert_eq!(call.await.unwrap(), 200);

    // after the Execute returned: model calls only (a late-cancelled call, the reflection)
    ok_(report(
        &mut tools,
        record(Kind::ModelCall, &id, Some("ops-assistant"), "mock", 0.002),
    )
    .await);
    assert_eq!(
        report(
            &mut tools,
            record(
                Kind::ToolCall,
                &id,
                Some("ops-assistant"),
                "load_skill:refund-policy",
                0.0
            )
        )
        .await,
        rejected()
    );

    let accepted = rig.records(|v| {
        v["request_id"] == id.as_str() && (v["kind"] == "model_call" || v["kind"] == "tool_call")
    });
    assert_eq!(accepted.len(), 3);
    assert!(
        accepted
            .iter()
            .all(|v| v["service"] == "orders" && v["namespace"] == "agentsc-demo")
    );
    let refusals = rig.records(|v| v["rule"] == "runtime.report_rejected");
    assert_eq!(refusals.len(), 11, "one authz record per refusal");
    assert!(
        refusals
            .iter()
            .all(|v| v["kind"] == "authz" && v["decision"] == "deny")
    );
    let skill = refusals
        .iter()
        .find(|v| v["input"]["callee"] == "load_skill:other-skill")
        .unwrap();
    assert_eq!(skill["request_id"], id.as_str());
    assert_eq!(skill["agent"], "ops-assistant");
    rig.sidecar.abort();
}

#[tokio::test]
async fn reports_close_when_the_run_window_has_passed() {
    let rig = rig(
        FakeRuntime::answering("done"),
        |_| {},
        |cfg| cfg.timing.run_window = Duration::from_millis(400),
    )
    .await;
    let mut tools = tools(&rig.sock).await;
    let (status, body) = rig.invoke("ops-assistant", "hello").await;
    assert_eq!(status, 200);
    let id = body["request_id"].as_str().unwrap().to_string();
    assert_eq!(
        report(
            &mut tools,
            record(Kind::ModelCall, &id, Some("ops-assistant"), "mock", 0.0)
        )
        .await,
        Ok(None)
    );
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        report(
            &mut tools,
            record(Kind::ModelCall, &id, Some("ops-assistant"), "mock", 0.0)
        )
        .await,
        rejected()
    );
    rig.sidecar.abort();
}

#[tokio::test]
async fn every_report_carries_the_budget_rule_once_the_daily_cost_is_spent() {
    let rig = rig(
        FakeRuntime::answering("done"),
        |c| c.agents[0].budgets.max_cost_usd_per_day = 0.05,
        |_| {},
    )
    .await;
    let mut tools = tools(&rig.sock).await;
    let (_, body) = rig.invoke("ops-assistant", "hello").await;
    let id = body["request_id"].as_str().unwrap().to_string();
    let budget = Ok(Some("budget.max_cost_usd_per_day".to_string()));
    assert_eq!(
        report(
            &mut tools,
            record(Kind::ModelCall, &id, Some("ops-assistant"), "mock", 0.02)
        )
        .await,
        Ok(None)
    );
    assert_eq!(
        report(
            &mut tools,
            record(Kind::ModelCall, &id, Some("ops-assistant"), "mock", 0.04)
        )
        .await,
        budget,
        "the cost of this record is counted before answering"
    );
    assert_eq!(
        report(
            &mut tools,
            record(Kind::ModelCall, &id, Some("ops-assistant"), "mock", 0.0)
        )
        .await,
        budget,
        "and every later answer for the agent says so"
    );
    let (status, body) = rig.invoke("ops-assistant", "again").await;
    assert_eq!(status, 429);
    assert_eq!(body["rule"], "budget.max_cost_usd_per_day");
    rig.sidecar.abort();
}
