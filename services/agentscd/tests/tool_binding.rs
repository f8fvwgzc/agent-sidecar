//! Tool calls belong to runs (tools.rs, runs.rs): a runtime cannot make up a request id, act for
//! another agent, keep calling after its run returned, or reset the agent-call depth.
mod common;

use agentsc_proto::{ToolAgentRequest, ToolHttpRequest, ToolServiceRequest};
use agentscd::runs::RunInfo;
use common::*;
use serde_json::Value;
use tonic::Code;

fn lookup(request_id: &str, agent: &str) -> ToolServiceRequest {
    ToolServiceRequest {
        ctx: ctx(agent, "lookup_order", request_id, "00f067aa0ba902b7"),
        service: "orders".into(),
        method: "GET".into(),
        path: "/orders/1001".into(),
        headers: Default::default(),
        body: vec![],
    }
}

fn rule(st: &tonic::Status) -> String {
    st.metadata()
        .get("x-agentsc-rule")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default()
}

#[tokio::test]
async fn tool_calls_of_no_run_in_flight_are_refused() {
    let rig = rig(FakeRuntime::answering("done"), |_| {}, |_| {}).await;
    let mut tools = tools(&rig.sock).await;

    // 1. a request id the sidecar never started, on all three tool RPCs
    let unbound = |st: tonic::Status| {
        assert_eq!(st.code(), Code::PermissionDenied, "{st:?}");
        assert_eq!(rule(&st), "tool.unbound");
    };
    unbound(
        tools
            .invoke_service(lookup("made-up", "ops-assistant"))
            .await
            .unwrap_err(),
    );
    unbound(
        tools
            .invoke_agent(ToolAgentRequest {
                ctx: ctx(
                    "ops-assistant",
                    "order_triage",
                    "made-up",
                    "00f067aa0ba902b7",
                ),
                target_service: String::new(),
                target_agent: "order-triage".into(),
                input: "triage".into(),
                context_json: String::new(),
            })
            .await
            .unwrap_err(),
    );
    unbound(
        tools
            .invoke_http(ToolHttpRequest {
                ctx: ctx("ops-assistant", "fetch", "made-up", "00f067aa0ba902b7"),
                method: "GET".into(),
                url: "https://example.com/".into(),
                headers: Default::default(),
                body: vec![],
            })
            .await
            .unwrap_err(),
    );

    // 2. a run that returned, and another agent's run
    let (status, body) = rig.invoke("ops-assistant", "hello").await;
    assert_eq!(status, 200);
    let returned = body["request_id"].as_str().unwrap().to_string();
    unbound(
        tools
            .invoke_service(lookup(&returned, "ops-assistant"))
            .await
            .unwrap_err(),
    );
    let _other = in_flight(&rig.sidecar, "triage-run", "order-triage");
    unbound(
        tools
            .invoke_service(lookup("triage-run", "ops-assistant"))
            .await
            .unwrap_err(),
    );

    let refused: Vec<Value> = rig.records(|v| v["rule"] == "tool.unbound");
    assert_eq!(refused.len(), 5);
    assert!(
        refused
            .iter()
            .all(|v| v["kind"] == "tool_call" && v["decision"] == "deny")
    );
    rig.sidecar.abort();
}

#[tokio::test]
async fn the_runs_depth_wins_over_the_runtimes() {
    let rig = rig(FakeRuntime::answering("done"), |_| {}, |_| {}).await;
    let mut tools = tools(&rig.sock).await;
    // an Execute already four agent calls deep
    let _run = rig.sidecar.state.runs.start_run(
        "deep",
        "ops-assistant",
        RunInfo {
            caller: "local".into(),
            trace_id: TRACE_ID.into(),
            depth: agentscd::state::MAX_DEPTH,
            ..RunInfo::default()
        },
    );
    // its runtime claims depth 0 for the next agent call
    let err = tools
        .invoke_agent(ToolAgentRequest {
            ctx: ctx("ops-assistant", "order_triage", "deep", "00f067aa0ba902b7"),
            target_service: String::new(),
            target_agent: "order-triage".into(),
            input: "triage".into(),
            context_json: String::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(rule(&err), "budget.max_depth", "{err:?}");
    assert!(
        rig.runtime.seen().is_empty(),
        "the nested agent never ran: {:?}",
        rig.runtime.seen()
    );
    rig.sidecar.abort();
}
