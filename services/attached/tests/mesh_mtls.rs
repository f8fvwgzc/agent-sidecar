//! Two sidecar cores on localhost with embassy-issued certificates (CONTRACT.md §10):
//! an allowed service call crosses the mesh, `/admin` is denied with the rule name,
//! an unknown identity is rejected, and the audit log carries request_id/trace_id.
use std::path::PathBuf;
use std::sync::Arc;

use attache_charter::{Charter, ToolSpec, ToolType};
use attache_proto::mesh_client::MeshClient;
use attache_proto::sidecar_tools_client::SidecarToolsClient;
use attache_proto::{InvokeAgentRequest, ToolContext, ToolServiceRequest};
use attached::{Config, Sidecar};
use axum::routing::{get, post};
use axum::{Json, Router};
use hyper_util::rt::TokioIo;
use serde_json::json;
use tokio::net::UnixStream;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

const ORDERS: &str = include_str!("../../../examples/charters/orders.charter.yaml");
const INVENTORY: &str = include_str!("../../../examples/charters/inventory.charter.yaml");

struct Pki {
    ca: attache_pki::PemBundle,
}

impl Pki {
    fn tls_dir(&self, root: &std::path::Path, service: &str) -> PathBuf {
        let leaf = attache_pki::issue_leaf(&self.ca, "attache-demo", service, 1).unwrap();
        let dir = root.join(format!("tls-{service}"));
        attache_pki::TlsMaterial::write(&leaf, &self.ca.cert_pem, &dir).unwrap();
        dir
    }
}

async fn fake_inventory_app() -> std::net::SocketAddr {
    let app = Router::new()
        .route("/stock/{sku}", get(|axum::extract::Path(sku): axum::extract::Path<String>| async move {
            Json(json!({"sku": sku, "on_hand": 42, "reorder_point": 50, "warehouse_contact": "ops-lead@example.com"}))
        }))
        .route("/admin/reset", post(|| async { Json(json!({"reset": true})) }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

fn write_charter(root: &std::path::Path, name: &str, c: &Charter) -> PathBuf {
    let p = root.join(format!("{name}.charter.yaml"));
    std::fs::write(&p, serde_yaml_ng::to_string(c).unwrap()).unwrap();
    p
}

async fn start(root: &std::path::Path, name: &str, charter: PathBuf, tls_dir: PathBuf) -> Sidecar {
    let sock = root.join(format!("sock-{name}"));
    let cfg = Config::for_test(charter, tls_dir, sock);
    attached::start(cfg).await.expect("sidecar starts")
}

async fn tools_client(
    socket_dir: &std::path::Path,
) -> SidecarToolsClient<tonic::transport::Channel> {
    let path = socket_dir.join("sidecar.sock");
    let channel = Endpoint::try_from("http://tools.attache.local")
        .unwrap()
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
        }))
        .await
        .unwrap();
    SidecarToolsClient::new(channel)
}

fn ctx(tool: &str, request_id: &str) -> Option<ToolContext> {
    Some(ToolContext {
        request_id: request_id.into(),
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".into(),
        span_id: "00f067aa0ba902b7".into(),
        agent: "ops-assistant".into(),
        tool: tool.into(),
        depth: 0,
    })
}

#[tokio::test]
async fn mesh_mtls_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let pki = Pki {
        ca: attache_pki::ca_init().unwrap(),
    };
    let app_addr = fake_inventory_app().await;

    // inventory: app port = fake app, audit to a file we can read back.
    let mut inv = Charter::from_yaml(INVENTORY).unwrap();
    inv.service.app_port = app_addr.port();
    inv.audit.sink = attache_charter::AuditSink::File;
    let inv_audit = root.join("inventory-audit.jsonl");
    inv.audit.file = Some(inv_audit.to_string_lossy().into_owned());
    let inventory = start(
        root,
        "inventory",
        write_charter(root, "inventory", &inv),
        pki.tls_dir(root, "inventory"),
    )
    .await;
    let inv_mesh = inventory.mesh_addr.expect("inventory mesh is up");

    // orders: peer override to the ephemeral inventory mesh port, plus a direct stock tool for the test.
    let mut ord = Charter::from_yaml(ORDERS).unwrap();
    ord.mesh
        .peers
        .insert("inventory".into(), inv_mesh.to_string());
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
    });
    ord.guardrails
        .allowed_tools
        .get_mut("ops-assistant")
        .unwrap()
        .push("check_stock".into());
    ord.audit.sink = attache_charter::AuditSink::File;
    let ord_audit = root.join("orders-audit.jsonl");
    ord.audit.file = Some(ord_audit.to_string_lossy().into_owned());
    let orders = start(
        root,
        "orders",
        write_charter(root, "orders", &ord),
        pki.tls_dir(root, "orders"),
    )
    .await;
    let mut tools = tools_client(&root.join("sock-orders")).await;

    // 1. allowed: orders/ops-assistant → mesh → inventory sidecar → fake app GET /stock/WIDGET-1
    let ok = tools
        .invoke_service(ToolServiceRequest {
            ctx: ctx("check_stock", "req-allowed"),
            service: "inventory".into(),
            method: "GET".into(),
            path: "/stock/WIDGET-1".into(),
            headers: Default::default(),
            body: vec![],
        })
        .await
        .expect("allowed call succeeds")
        .into_inner();
    assert_eq!(ok.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&ok.body).unwrap();
    assert_eq!(body["sku"], "WIDGET-1");

    // 2. denied by the callee's charter rule, surfaced with the rule name.
    let denied = tools
        .invoke_service(ToolServiceRequest {
            ctx: ctx("inventory_admin_reset", "req-denied"),
            service: "inventory".into(),
            method: "POST".into(),
            path: "/admin/reset".into(),
            headers: Default::default(),
            body: b"{}".to_vec(),
        })
        .await
        .expect_err("admin call is denied");
    assert_eq!(denied.code(), tonic::Code::PermissionDenied, "{denied:?}");
    assert_eq!(
        denied.metadata().get("x-attache-rule").unwrap(),
        "authz.services.deny-admin"
    );

    // 3. egress guardrail: a tool the agent is not allowed to use never leaves the pod.
    let not_allowed = tools
        .invoke_service(ToolServiceRequest {
            ctx: ctx("not_a_tool", "req-guardrail"),
            service: "inventory".into(),
            method: "GET".into(),
            path: "/stock".into(),
            headers: Default::default(),
            body: vec![],
        })
        .await
        .expect_err("unknown tool is denied");
    assert_eq!(
        not_allowed.metadata().get("x-attache-rule").unwrap(),
        "guardrail.allowed_tools"
    );

    // 4. a pod with a certificate for another service cannot invoke stock-analyst.
    let billing = attache_pki::TlsMaterial::load(pki.tls_dir(root, "billing")).unwrap();
    let channel = attached::tls::client_channel(
        &billing,
        &inv_mesh.to_string(),
        "inventory.attache-demo.svc.cluster.local",
    )
    .unwrap();
    let mut mesh = MeshClient::new(channel);
    let err = mesh
        .invoke_agent(InvokeAgentRequest {
            agent: "stock-analyst".into(),
            input: "hi".into(),
            ..Default::default()
        })
        .await
        .expect_err("billing is not an allowed caller");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    assert_eq!(
        err.metadata().get("x-attache-rule").unwrap(),
        "authz.callers.default"
    );

    // 5. the orders identity passes authz; without a runtime the call fails later, as UNAVAILABLE.
    let orders_tls = orders.state.tls.as_ref().unwrap();
    let channel = attached::tls::client_channel(
        orders_tls,
        &inv_mesh.to_string(),
        "inventory.attache-demo.svc.cluster.local",
    )
    .unwrap();
    let mut mesh = MeshClient::new(channel);
    let err = mesh
        .invoke_agent(InvokeAgentRequest {
            agent: "stock-analyst".into(),
            input: "hi".into(),
            ..Default::default()
        })
        .await
        .expect_err("no runtime in this test");
    assert_eq!(err.code(), tonic::Code::Unavailable, "{err:?}");
    assert_eq!(
        err.metadata().get("x-attache-rule").unwrap(),
        "runtime.unavailable"
    );

    // 6. a client without any certificate is refused at the TLS layer.
    let plain = Endpoint::from_shared(format!("http://{inv_mesh}"))
        .unwrap()
        .connect_lazy();
    let mut mesh = MeshClient::new(plain);
    assert!(
        mesh.invoke_agent(InvokeAgentRequest::default())
            .await
            .is_err()
    );

    // 7. the HTTP API: unknown agent → 404; secret in input → 403 with the guardrail rule.
    let http = reqwest::Client::new();
    let r = http
        .post(format!("http://{}/v1/agents/nope/invoke", orders.http_addr))
        .json(&json!({"input": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    let r = http
        .post(format!(
            "http://{}/v1/agents/ops-assistant/invoke",
            orders.http_addr
        ))
        .header(
            "traceparent",
            "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
        )
        .json(&json!({"input": "my password = hunter2"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    assert_eq!(
        r.headers().get("traceparent").unwrap().to_str().unwrap()[3..35],
        *"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    let v: serde_json::Value = r.json().await.unwrap();
    assert_eq!(v["status"], "denied");
    assert_eq!(v["rule"], "guardrail.input_deny.no-secrets");
    let r = http
        .get(format!("http://{}/readyz", orders.http_addr))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 503, "not ready without a runtime");

    // 8. audit: both pods logged the denied call with the same request_id and trace_id.
    let inv_log = std::fs::read_to_string(&inv_audit).unwrap();
    let ord_log = std::fs::read_to_string(&ord_audit).unwrap();
    let find = |log: &str, pred: &dyn Fn(&serde_json::Value) -> bool| -> Vec<serde_json::Value> {
        log.lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| pred(v))
            .collect()
    };
    let inv_denies = find(&inv_log, &|v| {
        v["request_id"] == "req-denied" && v["decision"] == "deny"
    });
    assert_eq!(inv_denies.len(), 1, "{inv_log}");
    assert_eq!(inv_denies[0]["kind"], "service_call");
    assert_eq!(inv_denies[0]["direction"], "inbound");
    assert_eq!(inv_denies[0]["rule"], "authz.services.deny-admin");
    assert_eq!(
        inv_denies[0]["caller"],
        "spiffe://attache/ns/attache-demo/svc/orders"
    );
    assert_eq!(inv_denies[0]["caller_agent"], "ops-assistant");
    assert_eq!(inv_denies[0]["service"], "inventory");
    assert_eq!(
        inv_denies[0]["trace_id"],
        "4bf92f3577b34da6a3ce929d0e0e4736"
    );
    let ord_denies = find(&ord_log, &|v| {
        v["request_id"] == "req-denied" && v["decision"] == "deny"
    });
    assert_eq!(
        ord_denies.len(),
        2,
        "tool_call + service_call on the caller side: {ord_log}"
    );
    assert!(
        ord_denies
            .iter()
            .all(|v| v["rule"] == "authz.services.deny-admin"
                && v["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736")
    );
    let inv_allowed = find(&inv_log, &|v| v["request_id"] == "req-allowed");
    assert_eq!(inv_allowed.len(), 1);
    assert_eq!(inv_allowed[0]["decision"], "allow");
    assert_eq!(inv_allowed[0]["rule"], "authz.services.orders-reads-stock");
    assert_eq!(inv_allowed[0]["output"]["body"]["sku"], "WIDGET-1");
    assert!(inv_allowed[0]["input_sha256"].is_string());
    let callers = find(&inv_log, &|v| v["rule"] == "authz.callers.default");
    assert_eq!(callers.len(), 1);
    assert_eq!(
        callers[0]["caller"],
        "spiffe://attache/ns/attache-demo/svc/billing"
    );

    let _ = Arc::new(());
    orders.abort();
    inventory.abort();
}
