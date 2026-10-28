//! A tool with `approval` on a sidecar without a control plane (CONTRACT.md §5.4): there is no one
//! to ask, so every call of it is refused (`approval.unavailable`); other tools go on.
mod common;

use agentsc_proto::ToolServiceRequest;
use common::*;

#[tokio::test]
async fn without_a_control_plane_a_held_tool_is_refused() {
    let rig = rig(
        FakeRuntime::answering("done"),
        |c| {
            let t = c.agents[0]
                .tools
                .iter_mut()
                .find(|t| t.name == "lookup_order")
                .unwrap();
            t.approval = Some(agentsc_charter::ApprovalSpec { timeout_s: 600 });
        },
        |_| {},
    )
    .await;
    let _run = in_flight(&rig.sidecar, "r1", "ops-assistant");
    let mut tools = tools(&rig.sock).await;
    let err = tools
        .invoke_service(ToolServiceRequest {
            ctx: ctx("ops-assistant", "lookup_order", "r1", "00f067aa0ba902b7"),
            service: "orders".into(),
            method: "GET".into(),
            path: "/orders/1001".into(),
            headers: Default::default(),
            body: vec![],
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    assert_eq!(
        err.metadata()
            .get("x-agentsc-rule")
            .unwrap()
            .to_str()
            .unwrap(),
        "approval.unavailable"
    );
    wait_audit(&rig.audit, 1, |r| {
        r["kind"] == "tool_call" && r["rule"] == "approval.unavailable"
    })
    .await;
    rig.sidecar.abort();
}
