//! Hot reload of the `--charter` file (design §6.2): applied, refused (invalid, restart-only) and
//! weakened changes each leave a `config` record; budgets survive, removed agents are gone,
//! the audit writer's redaction follows the charter, peer channels are dropped when `mesh.peers`
//! changes, and the runtime gets `Charter::runtime_spec`.
mod common;

use agentsc_charter::{AgentSpec, AgentType, Charter, Decision, MeshSpec};
use agentsc_common::audit::sha256_hex;
use common::*;
use serde_json::json;

fn helper_agent() -> AgentSpec {
    let mut a = Charter::from_yaml(ORDERS).unwrap().agents[1].clone();
    a.name = "billing-helper".into();
    a.agent_type = AgentType::Agent;
    a.model = "mock".into();
    a
}

#[tokio::test]
async fn a_valid_change_applies_without_a_restart() {
    let rig = rig(FakeRuntime::answering("done"), |_| {}, |_| {}).await;
    let first = wait_audit(&rig.audit, 1, |v| v["kind"] == "config").await;
    assert_eq!(first[0]["rule"], "config.applied", "the start-up charter");
    assert_eq!(first[0]["caller"], "file");
    assert_eq!(first[0]["callee"], "charter");
    assert_eq!(first[0]["input"]["source"], "file");
    assert!(first[0]["agent"].is_null());
    assert_eq!(first[0]["direction"], "internal");

    let (status, _) = rig.invoke("billing-helper", "hi").await;
    assert_eq!(status, 404, "not declared yet");

    let mut c = orders(&rig.audit);
    c.agents.push(helper_agent());
    c.agents[0].system = "a new system prompt".into();
    let rec = rig.reload(&c, 2).await;
    assert_eq!(rec["rule"], "config.applied");
    assert_eq!(rec["decision"], "allow");
    let text = std::fs::read_to_string(&rig.charter_path).unwrap();
    assert_eq!(rec["input"]["sha256"], sha256_hex(text.as_bytes()));
    assert_eq!(rec["input"]["weakened"], json!([]));
    assert!(rec["input"]["epoch"].is_null() && rec["input"]["version"].is_null());

    let (status, body) = rig.invoke("billing-helper", "hi").await;
    assert_eq!(status, 200, "{body}");
    let agents: serde_json::Value =
        reqwest::get(format!("http://{}/v1/agents", rig.sidecar.http_addr))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_eq!(agents["agents"].as_array().unwrap().len(), 3);

    // the runtime receives Charter::runtime_spec: skills, harness, learning and memory filled
    let (status, _) = rig.invoke("ops-assistant", "hello").await;
    assert_eq!(status, 200);
    let spec = rig.runtime.last_spec("ops-assistant");
    assert_eq!(spec["system"], "a new system prompt");
    assert_eq!(spec["skills"], json!([]));
    assert_eq!(spec["memory"], json!([]));
    assert_eq!(spec["harness"]["max_retries"], 2);
    assert_eq!(spec["learning"]["enabled"], false);
    let tools: Vec<&str> = spec["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        tools,
        [
            "lookup_order",
            "stock_analyst",
            "order_triage",
            "inventory_admin_reset"
        ]
    );
    rig.sidecar.abort();
}

#[tokio::test]
async fn invalid_and_restart_only_changes_are_refused_and_audited() {
    let rig = rig(FakeRuntime::answering("done"), |_| {}, |_| {}).await;
    wait_audit(&rig.audit, 1, |v| v["kind"] == "config").await;

    // not a charter at all
    std::fs::write(
        &rig.charter_path,
        "apiVersion: agentsc.io/v1alpha1\nkind: Charter\nnope: 1\n",
    )
    .unwrap();
    let recs = wait_audit(&rig.audit, 2, |v| v["kind"] == "config").await;
    assert_eq!(recs[1]["rule"], "config.invalid");
    assert_eq!(recs[1]["decision"], "deny");
    assert!(
        recs[1]["reason"].as_str().unwrap().contains("nope"),
        "{}",
        recs[1]
    );

    // a valid charter that changes restart-only fields
    let mut c = orders(&rig.audit);
    c.service.app_port = 9999;
    c.mesh = MeshSpec {
        port: 50003,
        ..Default::default()
    };
    let rec = rig.reload(&c, 3).await;
    assert_eq!(rec["rule"], "config.invalid");
    let reason = rec["reason"].as_str().unwrap();
    assert!(
        reason.contains("service.app_port") && reason.contains("mesh.port"),
        "{reason}"
    );
    assert_eq!(
        rig.sidecar.state.loaded().unwrap().charter.service.app_port,
        8080
    );

    // a charter for another service
    let mut c = orders(&rig.audit);
    c.service.name = "billing".into();
    let rec = rig.reload(&c, 4).await;
    assert_eq!(rec["rule"], "config.invalid");

    // the old charter still serves
    let (status, _) = rig.invoke("ops-assistant", "still here").await;
    assert_eq!(status, 200);

    // and a valid change after that applies
    let mut c = orders(&rig.audit);
    c.agents[1].system = "triage, faster".into();
    let rec = rig.reload(&c, 5).await;
    assert_eq!(rec["rule"], "config.applied");
    rig.sidecar.abort();
}

#[tokio::test]
async fn weakened_changes_are_listed_and_the_audit_redaction_follows() {
    let rig = rig(
        FakeRuntime::answering("done"),
        |c| c.audit.redact = vec!["input.context.card".into()],
        |_| {},
    )
    .await;
    wait_audit(&rig.audit, 1, |v| v["kind"] == "config").await;
    assert_eq!(
        rig.sidecar.state.audit.redaction(),
        (vec!["input.context.card".to_string()], true)
    );

    let mut c = orders(&rig.audit);
    c.audit.redact = vec!["input.context.ssn".into()];
    c.guardrails.pii_redact = false;
    c.authz.default = Decision::Allow;
    c.guardrails.input_deny.clear();
    let rec = rig.reload(&c, 2).await;
    assert_eq!(rec["rule"], "config.applied");
    assert_eq!(
        rec["input"]["weakened"],
        json!([
            "audit.redact[input.context.card]",
            "guardrails.pii_redact",
            "authz.default",
            "guardrails.input_deny[no-secrets]"
        ])
    );
    // AuditWriter::set_redaction was applied
    assert_eq!(
        rig.sidecar.state.audit.redaction(),
        (vec!["input.context.ssn".to_string()], false)
    );
    let r = reqwest::Client::new()
        .post(rig.invoke_url("ops-assistant"))
        .json(&json!({"input": "mail a@example.com", "context": {"card": "4111-1111", "ssn": "123-45-6789"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let id = r.json::<serde_json::Value>().await.unwrap()["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    let inv = rig.records(|v| v["request_id"] == id.as_str() && v["kind"] == "agent_invocation");
    assert_eq!(inv[0]["input"]["context"]["ssn"], "[redacted]");
    assert_eq!(inv[0]["input"]["context"]["card"], "4111-1111");
    assert_eq!(
        inv[0]["input"]["input"], "mail a@example.com",
        "pii_redact is off now"
    );
    rig.sidecar.abort();
}

#[tokio::test]
async fn budgets_survive_a_reload_and_removed_agents_are_gone() {
    let rig = rig(
        FakeRuntime::answering("done"),
        |c| c.agents[1].budgets.max_calls_per_minute = 2,
        |_| {},
    )
    .await;
    for _ in 0..2 {
        let (status, _) = rig.invoke("order-triage", "P2?").await;
        assert_eq!(status, 200);
    }
    let mut c = orders(&rig.audit);
    c.agents[1].budgets.max_calls_per_minute = 2;
    c.agents[1].system = "reloaded".into();
    let rec = rig.reload(&c, 2).await;
    assert_eq!(rec["rule"], "config.applied");
    let (status, body) = rig.invoke("order-triage", "P2?").await;
    assert_eq!(status, 429, "{body}");
    assert_eq!(body["rule"], "budget.max_calls_per_minute");

    // remove order-triage (and the tool that called it)
    let mut c = orders(&rig.audit);
    c.agents.retain(|a| a.name != "order-triage");
    c.agents[0].tools.retain(|t| t.name != "order_triage");
    c.guardrails
        .allowed_tools
        .get_mut("ops-assistant")
        .unwrap()
        .retain(|t| t != "order_triage");
    let rec = rig.reload(&c, 3).await;
    assert_eq!(rec["rule"], "config.applied", "{rec}");
    let (status, body) = rig.invoke("order-triage", "P2?").await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["rule"], "agent.unknown");
    rig.sidecar.abort();
}

#[tokio::test]
async fn peer_channels_are_dropped_when_mesh_peers_change() {
    let pki = tempfile::tempdir().unwrap();
    let ca = agentsc_pki::ca_init().unwrap();
    let leaf = agentsc_pki::issue_leaf(&ca, "agentsc-demo", "orders", 1).unwrap();
    agentsc_pki::TlsMaterial::write(&leaf, &ca.cert_pem, pki.path()).unwrap();
    let tls_dir = pki.path().to_path_buf();
    let rig = rig(
        FakeRuntime::answering("done"),
        |_| {},
        |cfg| {
            cfg.tls_dir = tls_dir;
            cfg.peer_address_template = "{service}-sidecar.{namespace}:{port}".into();
        },
    )
    .await;
    let state = rig.sidecar.state.clone();
    let snap = state.loaded().unwrap();
    assert_eq!(
        state.peer_address(&snap.charter, "inventory"),
        "inventory-sidecar.agentsc-demo:50002",
        "--peer-address-template when mesh.peers has no entry"
    );
    state.mesh_client(&snap, "inventory").unwrap();
    assert_eq!(state.mesh_clients_cached(), 1);

    // a change that leaves mesh.peers alone keeps the channel
    let mut c = orders(&rig.audit);
    c.agents[1].system = "x".into();
    rig.reload(&c, 2).await;
    assert_eq!(state.mesh_clients_cached(), 1);

    c.mesh
        .peers
        .insert("inventory".into(), "127.0.0.1:1".into());
    let rec = rig.reload(&c, 3).await;
    assert_eq!(rec["rule"], "config.applied");
    assert_eq!(state.mesh_clients_cached(), 0, "cache cleared");
    let snap = state.loaded().unwrap();
    assert_eq!(
        state.peer_address(&snap.charter, "inventory"),
        "127.0.0.1:1"
    );
    rig.sidecar.abort();
}
