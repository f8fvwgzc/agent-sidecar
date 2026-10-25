//! Audit durability (CONTRACT.md §6, docs/operations.md "Audit sink failures"): with
//! `--audit-fail-closed`, a sidecar whose audit sink fails refuses new work with rule
//! `audit.unavailable` — the app's invocation 503, a peer's mesh call and the runtime's tool call
//! `UNAVAILABLE` — and is not ready, until the sink takes writes again. Nothing is lost: the
//! records of the work in flight and of every refusal are kept and written once it recovers.
mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agentsc_charter::{Charter, ToolSpec, ToolType};
use agentsc_proto::{ToolContext, ToolServiceRequest};
use agentscd::{Config, Sidecar};
use axum::routing::get;
use axum::{Json, Router};
use common::FakeRuntime;
use serde_json::{Value, json};

const INVENTORY: &str = include_str!("../../../examples/charters/inventory.charter.yaml");

/// A sink that fails while `failing` is set, like a full disk.
#[derive(Clone, Default)]
struct Disk {
    out: Arc<Mutex<Vec<u8>>>,
    failing: Arc<AtomicBool>,
}

impl std::io::Write for Disk {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if self.failing.load(Ordering::SeqCst) {
            return Err(std::io::Error::from_raw_os_error(28)); // ENOSPC
        }
        self.out.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Disk {
    fn records(&self) -> Vec<Value> {
        String::from_utf8(self.out.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}")))
            .collect()
    }
}

fn tls_dir(ca: &agentsc_pki::PemBundle, root: &Path, service: &str) -> PathBuf {
    let leaf = agentsc_pki::issue_leaf(ca, "agentsc-demo", service, 1).unwrap();
    let dir = root.join(format!("tls-{service}"));
    agentsc_pki::TlsMaterial::write(&leaf, &ca.cert_pem, &dir).unwrap();
    dir
}

async fn start(root: &Path, name: &str, c: &Charter, tls: PathBuf, fail_closed: bool) -> Sidecar {
    let charter = root.join(format!("{name}.charter.yaml"));
    std::fs::write(&charter, serde_yaml_ng::to_string(c).unwrap()).unwrap();
    let sock = root.join(format!("sock-{name}"));
    common::serve_runtime(&sock, FakeRuntime::answering("WIDGET-1: 42 on hand"));
    let mut cfg = Config::for_test(charter, tls, sock);
    cfg.audit_fail_closed = fail_closed;
    agentscd::start(cfg).await.expect("sidecar starts")
}

async fn readyz(s: &Sidecar) -> (u16, Value) {
    let r = reqwest::get(format!("http://{}/readyz", s.http_addr))
        .await
        .unwrap();
    (r.status().as_u16(), r.json().await.unwrap())
}

async fn wait_ready(s: &Sidecar, want: u16) -> Value {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        let (code, body) = readyz(s).await;
        if code == want {
            return body;
        }
        assert!(
            Instant::now() < until,
            "readyz never answered {want}: {body}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn invoke(s: &Sidecar, agent: &str) -> (u16, Value) {
    let r = reqwest::Client::new()
        .post(format!("http://{}/v1/agents/{agent}/invoke", s.http_addr))
        .json(&json!({ "input": "How many WIDGET-1?" }))
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.json().await.unwrap())
}

fn ctx(agent: &str, tool: &str, request_id: &str) -> Option<ToolContext> {
    Some(ToolContext {
        request_id: request_id.into(),
        trace_id: common::TRACE_ID.into(),
        span_id: "00f067aa0ba902b7".into(),
        agent: agent.into(),
        tool: tool.into(),
        depth: 0,
    })
}

#[tokio::test]
async fn fail_closed_refuses_new_work_while_the_audit_sink_fails_and_recovers() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let ca = agentsc_pki::ca_init().unwrap();
    let app = Router::new().route(
        "/stock/{sku}",
        get(|| async { Json(json!({"sku": "WIDGET-1", "on_hand": 42})) }),
    );
    let app_addr = common::serve_app(app).await;

    // inventory: fail-closed, its audit sink replaced by a disk that can fill up
    let mut inv = Charter::from_yaml(INVENTORY).unwrap();
    inv.service.app_port = app_addr.port();
    let inventory = start(
        root,
        "inventory",
        &inv,
        tls_dir(&ca, root, "inventory"),
        true,
    )
    .await;
    let disk = Disk::default();
    inventory.state.audit.replace_writer(Box::new(disk.clone()));
    let body = wait_ready(&inventory, 200).await;
    assert_eq!(body["audit"]["healthy"], true);
    assert_eq!(body["audit"]["fail_closed"], true);

    // orders: the default (fail-open), with a tool that reads inventory's stock over the mesh
    let mut ord = Charter::from_yaml(common::ORDERS).unwrap();
    ord.mesh
        .peers
        .insert("inventory".into(), inventory.mesh_addr.unwrap().to_string());
    let ops = ord
        .agents
        .iter_mut()
        .find(|a| a.name == "ops-assistant")
        .unwrap();
    ops.tools.push(ToolSpec {
        name: "check_stock".into(),
        description: "read stock".into(),
        tool_type: ToolType::Service,
        parameters: None,
        service: Some("inventory".into()),
        method: Some("GET".into()),
        path: Some("/stock/{sku}".into()),
        agent: None,
        url: None,
        label: None,
        effect: None,
    });
    ord.guardrails
        .allowed_tools
        .get_mut("ops-assistant")
        .unwrap()
        .push("check_stock".into());
    let orders_audit = root.join("orders-audit.jsonl");
    ord.audit.sink = agentsc_charter::AuditSink::File;
    ord.audit.file = Some(orders_audit.to_string_lossy().into_owned());
    let orders = start(root, "orders", &ord, tls_dir(&ca, root, "orders"), false).await;
    let mut orders_tools = common::tools(&root.join("sock-orders")).await;
    let stock = |request_id: &str| ToolServiceRequest {
        ctx: ctx("ops-assistant", "check_stock", request_id),
        service: "inventory".into(),
        method: "GET".into(),
        path: "/stock/WIDGET-1".into(),
        headers: Default::default(),
        body: vec![],
    };
    orders_tools
        .invoke_service(stock("req-before"))
        .await
        .expect("the mesh call works while inventory's sink does");

    // the disk fills up: the invocation in flight still runs (its records are kept)
    disk.failing.store(true, Ordering::SeqCst);
    let (code, _) = invoke(&inventory, "stock-analyst").await;
    assert_eq!(code, 200, "work that passed the gate finishes");

    // now nothing new starts: the app's invocation …
    let (code, body) = invoke(&inventory, "stock-analyst").await;
    assert_eq!(code, 503, "{body}");
    assert_eq!(body["status"], "denied");
    assert_eq!(body["rule"], "audit.unavailable");
    assert!(
        body["reason"]
            .as_str()
            .unwrap()
            .contains("No space left on device"),
        "{body}"
    );
    // … a peer's mesh call …
    let st = orders_tools
        .invoke_service(stock("req-refused"))
        .await
        .expect_err("refused by inventory");
    assert_eq!(st.code(), tonic::Code::Unavailable, "{st:?}");
    assert_eq!(
        st.metadata().get("x-agentsc-rule").unwrap(),
        "audit.unavailable"
    );
    // … and the runtime's own tool call
    let mut inv_tools = common::tools(&root.join("sock-inventory")).await;
    let st = inv_tools
        .invoke_service(ToolServiceRequest {
            ctx: ctx("stock-analyst", "get_stock", "req-tool"),
            service: "inventory".into(),
            method: "GET".into(),
            path: "/stock/WIDGET-1".into(),
            headers: Default::default(),
            body: vec![],
        })
        .await
        .expect_err("refused");
    assert_eq!(st.code(), tonic::Code::Unavailable);
    assert_eq!(
        st.metadata().get("x-agentsc-rule").unwrap(),
        "audit.unavailable"
    );
    // not ready, and /readyz says why
    let (code, body) = readyz(&inventory).await;
    assert_eq!(code, 503);
    let audit = &body["audit"];
    assert_eq!(audit["healthy"], false, "{body}");
    assert!(audit["write_errors"].as_u64().unwrap() >= 1, "{body}");
    assert!(audit["pending_bytes"].as_u64().unwrap() > 0, "{body}");
    assert!(
        audit["last_error"]
            .as_str()
            .unwrap()
            .contains("No space left"),
        "{body}"
    );
    // the fail-open orders sidecar was never refused anything: its caller side is recorded
    let orders_records = common::wait_audit(&orders_audit, 1, |r| {
        r["kind"] == "tool_call" && r["request_id"] == "req-refused"
    })
    .await;
    assert!(
        orders_records[0]["error"]
            .as_str()
            .unwrap()
            .contains("audit sink is failing"),
        "{}",
        orders_records[0]
    );
    assert_eq!(readyz(&orders).await.0, 200);

    // room on the disk again: the retry (timer or probe) writes the backlog and work resumes
    disk.failing.store(false, Ordering::SeqCst);
    let body = wait_ready(&inventory, 200).await;
    assert_eq!(body["audit"]["healthy"], true);
    assert_eq!(body["audit"]["pending_bytes"], 0);
    let (code, body) = invoke(&inventory, "stock-analyst").await;
    assert_eq!(code, 200, "{body}");

    // every record is there once, and the refusals name the rule
    let records = disk.records();
    let refused: Vec<(&str, &str)> = records
        .iter()
        .filter(|r| r["rule"] == "audit.unavailable")
        .map(|r| (r["kind"].as_str().unwrap(), r["decision"].as_str().unwrap()))
        .collect();
    assert_eq!(
        refused,
        [
            ("agent_invocation", "deny"),
            ("service_call", "deny"),
            ("tool_call", "deny")
        ],
        "{records:#?}"
    );
    let mesh = records
        .iter()
        .find(|r| r["kind"] == "service_call" && r["rule"] == "audit.unavailable")
        .unwrap();
    assert_eq!(mesh["direction"], "inbound");
    assert_eq!(mesh["request_id"], "req-refused");
    assert_eq!(
        mesh["caller"],
        "spiffe://agentsc/ns/agentsc-demo/svc/orders"
    );
    let invocations = records
        .iter()
        .filter(|r| r["kind"] == "agent_invocation" && r["decision"] == "allow")
        .count();
    assert_eq!(invocations, 2, "the one in flight and the one after");
    // whole lines only, none twice (records() already parsed every line)
    let text = String::from_utf8(disk.out.lock().unwrap().clone()).unwrap();
    let mut lines: Vec<&str> = text.lines().collect();
    let total = lines.len();
    lines.sort_unstable();
    lines.dedup();
    assert_eq!(lines.len(), total, "a record was written twice");
    assert!(records.iter().all(|r| r["service"] == "inventory"));

    orders.abort();
    inventory.abort();
}
