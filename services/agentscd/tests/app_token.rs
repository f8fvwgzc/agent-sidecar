//! The app API token (design §6.6): with a token configured, every app HTTP and gRPC request needs
//! `Authorization: Bearer <token>`; without it 401 / `UNAUTHENTICATED` and an `authz` record
//! `app.unauthenticated`. `/healthz` and `/readyz` stay open.
mod common;

use agentsc_proto::app_api_client::AppApiClient;
use agentsc_proto::{Empty, InvokeAgentRequest};
use common::*;
use serde_json::json;

const TOKEN: &str = "app-token-0123456789";

async fn token_rig(from_file: bool) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("token");
    std::fs::write(&file, format!("{TOKEN}\n")).unwrap();
    let rig = rig(
        FakeRuntime::answering("done"),
        |_| {},
        move |cfg| {
            if from_file {
                cfg.app_token_file = Some(file);
            } else {
                cfg.app_token = Some(TOKEN.into());
            }
        },
    )
    .await;
    drop(dir); // read at start-up
    rig
}

#[tokio::test]
async fn the_http_api_needs_the_token() {
    let rig = token_rig(true).await;
    let http = reqwest::Client::new();
    let base = format!("http://{}", rig.sidecar.http_addr);

    let r = http
        .post(rig.invoke_url("ops-assistant"))
        .json(&json!({"input": "hi"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(r.headers()["www-authenticate"], "Bearer");
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["rule"], "app.unauthenticated");

    for wrong in [
        "Bearer app-token-012345678",
        "Bearer app-token-01234567890",
        "Basic app-token-0123456789",
    ] {
        let r = http
            .get(format!("{base}/v1/agents"))
            .header("authorization", wrong)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401, "{wrong}");
    }
    let r = http.get(format!("{base}/v1/charter")).send().await.unwrap();
    assert_eq!(r.status(), 401);

    // with the token
    let r = http
        .post(rig.invoke_url("ops-assistant"))
        .bearer_auth(TOKEN)
        .json(&json!({"input": "hi"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let r = http
        .get(format!("{base}/v1/agents"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // the health endpoints stay open
    assert_eq!(
        http.get(format!("{base}/healthz"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let r = http.get(format!("{base}/readyz")).send().await.unwrap();
    assert_ne!(r.status(), 401);

    let denials = rig.records(|v| v["rule"] == "app.unauthenticated");
    assert_eq!(denials.len(), 5);
    let first = &denials[0];
    assert_eq!(first["kind"], "authz");
    assert_eq!(first["decision"], "deny");
    assert_eq!(first["caller"], "local");
    assert_eq!(first["direction"], "inbound");
    assert_eq!(first["callee"], "POST /v1/agents/ops-assistant/invoke");
    // the invocation itself never ran
    assert_eq!(rig.runtime.seen().len(), 1);
    rig.sidecar.abort();
}

#[tokio::test]
async fn the_grpc_api_needs_the_token() {
    let rig = token_rig(false).await;
    let mut app = AppApiClient::connect(format!("http://{}", rig.sidecar.grpc_addr))
        .await
        .unwrap();
    let invoke = || InvokeAgentRequest {
        agent: "ops-assistant".into(),
        input: "hi".into(),
        ..Default::default()
    };
    let err = app.invoke_agent(invoke()).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    assert_eq!(
        err.metadata().get("x-agentsc-rule").unwrap(),
        "app.unauthenticated"
    );
    let err = app.list_agents(Empty {}).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    let mut wrong = tonic::Request::new(invoke());
    wrong
        .metadata_mut()
        .insert("authorization", "Bearer nope".parse().unwrap());
    assert_eq!(
        app.invoke_agent(wrong).await.unwrap_err().code(),
        tonic::Code::Unauthenticated
    );

    let mut req = tonic::Request::new(invoke());
    req.metadata_mut()
        .insert("authorization", format!("Bearer {TOKEN}").parse().unwrap());
    let resp = app.invoke_agent(req).await.unwrap().into_inner();
    assert_eq!(resp.status, "ok");
    let mut req = tonic::Request::new(Empty {});
    req.metadata_mut()
        .insert("authorization", format!("Bearer {TOKEN}").parse().unwrap());
    assert_eq!(
        app.list_agents(req)
            .await
            .unwrap()
            .into_inner()
            .agents
            .len(),
        2
    );

    let denials = rig.records(|v| v["rule"] == "app.unauthenticated");
    let callees: Vec<&str> = denials
        .iter()
        .map(|v| v["callee"].as_str().unwrap())
        .collect();
    assert_eq!(
        callees,
        [
            "AppApi/InvokeAgent",
            "AppApi/ListAgents",
            "AppApi/InvokeAgent"
        ]
    );
    rig.sidecar.abort();
}

#[tokio::test]
async fn without_a_token_the_app_api_is_open() {
    let rig = rig(FakeRuntime::answering("done"), |_| {}, |_| {}).await;
    let (status, _) = rig.invoke("ops-assistant", "hi").await;
    assert_eq!(status, 200);
    assert!(
        rig.records(|v| v["rule"] == "app.unauthenticated")
            .is_empty()
    );
    rig.sidecar.abort();
}
