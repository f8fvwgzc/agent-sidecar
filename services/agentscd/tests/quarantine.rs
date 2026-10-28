//! A quarantined agent (control.rs `apply_quarantine`, CONTRACT.md §5.3): its invocations are
//! refused, the tool calls of its runs in flight are refused, other agents go on, and a release
//! lifts it. Each refusal leaves its record.
mod common;

use agentsc_proto::{Quarantine, ToolServiceRequest};
use agentscd::state::RULE_QUARANTINE;
use common::*;

fn lookup(request_id: &str) -> ToolServiceRequest {
    ToolServiceRequest {
        ctx: ctx(
            "ops-assistant",
            "lookup_order",
            request_id,
            "00f067aa0ba902b7",
        ),
        service: "orders".into(),
        method: "GET".into(),
        path: "/orders/1001".into(),
        headers: Default::default(),
        body: vec![],
    }
}

fn quarantine(agents: &[(&str, &str)]) -> Quarantine {
    Quarantine {
        agents: agents
            .iter()
            .map(|(a, why)| (a.to_string(), why.to_string()))
            .collect(),
    }
}

#[tokio::test]
async fn a_quarantined_agent_is_refused_until_it_is_released() {
    let rig = rig(FakeRuntime::answering("done"), |_| {}, |_| {}).await;
    let state = rig.sidecar.state.clone();
    let (status, _) = rig.invoke("ops-assistant", "hi").await;
    assert_eq!(status, 200);

    // a run in flight when the quarantine arrives
    let _run = in_flight(&rig.sidecar, "in-flight", "ops-assistant");
    agentscd::control::apply_quarantine(
        &state,
        quarantine(&[("ops-assistant", "risk 7.5 over 6")]),
    );

    // a new invocation: 403, the rule and the reason
    let (status, v) = rig.invoke("ops-assistant", "hi").await;
    assert_eq!(status, 403, "{v}");
    assert_eq!(v["rule"], RULE_QUARANTINE);
    assert!(
        v["reason"].as_str().unwrap().contains("risk 7.5 over 6"),
        "{v}"
    );
    let denied = wait_audit(&rig.audit, 1, |r| {
        r["kind"] == "agent_invocation" && r["rule"] == RULE_QUARANTINE
    })
    .await;
    assert_eq!(denied[0]["decision"], "deny");

    // the run in flight: its next tool call is refused
    let mut tools = tools(&rig.sock).await;
    let err = tools.invoke_service(lookup("in-flight")).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err:?}");
    assert_eq!(
        err.metadata()
            .get("x-agentsc-rule")
            .unwrap()
            .to_str()
            .unwrap(),
        RULE_QUARANTINE
    );
    wait_audit(&rig.audit, 1, |r| {
        r["kind"] == "tool_call" && r["rule"] == RULE_QUARANTINE && r["request_id"] == "in-flight"
    })
    .await;

    // another agent of the service goes on
    let (status, v) = rig.invoke("order-triage", "hi").await;
    assert_ne!(v["rule"], RULE_QUARANTINE, "{status} {v}");

    // released (a full replacement without it)
    agentscd::control::apply_quarantine(&state, quarantine(&[]));
    assert!(state.quarantined().is_empty());
    let (status, v) = rig.invoke("ops-assistant", "hi").await;
    assert_eq!(status, 200, "{v}");
    rig.sidecar.abort();
}
