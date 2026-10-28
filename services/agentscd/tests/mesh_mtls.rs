//! Two sidecar cores on localhost with embassy-issued certificates (CONTRACT.md §10):
//! an allowed service call crosses the mesh, `/admin` is denied with the rule name,
//! an unknown identity is rejected, and the audit log carries request_id/trace_id.
use std::path::PathBuf;
use std::sync::Arc;

use agentsc_charter::{Charter, ToolSpec, ToolType};
use agentsc_proto::mesh_client::MeshClient;
use agentsc_proto::sidecar_tools_client::SidecarToolsClient;
use agentsc_proto::{InvokeAgentRequest, ToolContext, ToolHttpRequest, ToolServiceRequest};
use agentscd::{Config, Sidecar};
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
    ca: agentsc_pki::PemBundle,
}

impl Pki {
    fn tls_dir(&self, root: &std::path::Path, service: &str) -> PathBuf {
        self.tls_dir_in(root, "agentsc", "agentsc-demo", service)
    }

    /// A certificate for `spiffe://<td>/ns/<ns>/svc/<service>` from the CA.
    fn tls_dir_in(&self, root: &std::path::Path, td: &str, ns: &str, service: &str) -> PathBuf {
        let leaf =
            agentsc_pki::issue_leaf_in(&self.ca, td, "cluster.local", ns, service, 1).unwrap();
        let dir = root.join(format!("tls-{td}-{ns}-{service}"));
        agentsc_pki::TlsMaterial::write(&leaf, &self.ca.cert_pem, &dir).unwrap();
        dir
    }
}

async fn fake_inventory_app() -> std::net::SocketAddr {
    // `seen_by_app` echoes the identity headers the app received, to prove the sidecar owns them.
    let app = Router::new()
        .route(
            "/stock/{sku}",
            get(|axum::extract::Path(sku): axum::extract::Path<String>, axum::extract::RawQuery(query): axum::extract::RawQuery, headers: axum::http::HeaderMap| async move {
                let all = |k: &str| headers.get_all(k).iter().map(|v| v.to_str().unwrap_or("").to_string()).collect::<Vec<_>>();
                Json(json!({
                    "sku": sku, "query": query, "on_hand": 42, "reorder_point": 50, "warehouse_contact": "ops-lead@example.com",
                    "seen_by_app": { "x-agentsc-caller": all("x-agentsc-caller"), "traceparent": all("traceparent") }
                }))
            }),
        )
        .route("/admin/reset", post(|| async { Json(json!({"reset": true})) }))
        .route("/restock", post(|| async { Json(json!({"restocked": true})) }));
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
    start_with(root, name, charter, tls_dir, |_| {}).await
}

async fn start_with(
    root: &std::path::Path,
    name: &str,
    charter: PathBuf,
    tls_dir: PathBuf,
    tweak: impl FnOnce(&mut Config),
) -> Sidecar {
    let sock = root.join(format!("sock-{name}"));
    let mut cfg = Config::for_test(charter, tls_dir, sock);
    tweak(&mut cfg);
    agentscd::start(cfg).await.expect("sidecar starts")
}

/// The orders charter with a `check_stock` service tool (GET /stock/{sku}) to `target`, and
/// `mesh.peers[target]` = `addr`; audit to `<root>/<name>-audit.jsonl`.
fn orders_calling(root: &std::path::Path, name: &str, target: &str, addr: &str) -> Charter {
    let mut ord = Charter::from_yaml(ORDERS).unwrap();
    ord.mesh.peers.insert(target.into(), addr.into());
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
        service: Some(target.into()),
        method: Some("GET".into()),
        path: Some("/stock/{sku}".into()),
        agent: None,
        url: None,
        label: None,
        effect: None,
        approval: None,
    });
    ord.guardrails
        .allowed_tools
        .get_mut("ops-assistant")
        .unwrap()
        .push("check_stock".into());
    ord.guardrails.allowed_services.remove("ops-assistant");
    ord.authz.services.push(agentsc_charter::ServiceRule {
        name: format!("check-stock-{}", target.replace('.', "-")),
        identity: None,
        agent: Some("ops-assistant".into()),
        service: target.into(),
        allow: vec!["GET /stock/*".into()],
        deny: vec![],
    });
    ord.audit.sink = agentsc_charter::AuditSink::File;
    ord.audit.file = Some(
        root.join(format!("{name}-audit.jsonl"))
            .to_string_lossy()
            .into_owned(),
    );
    ord
}

fn stock_request(service: &str, request_id: &str) -> ToolServiceRequest {
    ToolServiceRequest {
        ctx: ctx("check_stock", request_id),
        service: service.into(),
        method: "GET".into(),
        path: "/stock/WIDGET-1".into(),
        headers: Default::default(),
        body: vec![],
    }
}

async fn tools_client(
    socket_dir: &std::path::Path,
) -> SidecarToolsClient<tonic::transport::Channel> {
    let path = socket_dir.join("sidecar.sock");
    let channel = Endpoint::try_from("http://tools.agentsc.local")
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
        ca: agentsc_pki::ca_init().unwrap(),
    };
    let app_addr = fake_inventory_app().await;

    // inventory: app port = fake app, audit to a file we can read back.
    let mut inv = Charter::from_yaml(INVENTORY).unwrap();
    inv.service.app_port = app_addr.port();
    inv.audit.sink = agentsc_charter::AuditSink::File;
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
        label: None,
        effect: None,
        approval: None,
    });
    // and an http tool aimed at the same fake app, to check the URL template on InvokeHttp
    ops.tools.push(ToolSpec {
        name: "fetch_stock".into(),
        description: "read stock over plain http".into(),
        tool_type: ToolType::Http,
        parameters: None,
        service: None,
        method: Some("GET".into()),
        path: None,
        agent: None,
        url: Some(format!(
            "http://127.0.0.1:{}/stock/{{sku}}",
            app_addr.port()
        )),
        label: None,
        effect: None,
        approval: None,
    });
    let allowed = ord
        .guardrails
        .allowed_tools
        .get_mut("ops-assistant")
        .unwrap();
    allowed.push("check_stock".into());
    allowed.push("fetch_stock".into());
    ord.audit.sink = agentsc_charter::AuditSink::File;
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
    // The runs these tool calls belong to, in flight as while the runtime runs.
    let _runs: Vec<_> = [
        "req-allowed",
        "req-denied",
        "req-guardrail",
        "req-traversal",
        "req-http",
    ]
    .into_iter()
    .map(|id| {
        orders.state.runs.start(
            id,
            "ops-assistant",
            "local",
            "4bf92f3577b34da6a3ce929d0e0e4736",
        )
    })
    .collect();

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
        denied.metadata().get("x-agentsc-rule").unwrap(),
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
        not_allowed.metadata().get("x-agentsc-rule").unwrap(),
        "guardrail.allowed_tools"
    );

    // 4. a pod with a certificate for another service cannot invoke stock-analyst.
    let billing = agentsc_pki::TlsMaterial::load(pki.tls_dir(root, "billing")).unwrap();
    let channel = agentscd::tls::client_channel(
        &billing,
        &inv_mesh.to_string(),
        "spiffe://agentsc/ns/agentsc-demo/svc/inventory",
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
        err.metadata().get("x-agentsc-rule").unwrap(),
        "authz.callers.default"
    );

    // 5. the orders identity passes authz only for the calling agent its rule names (caller_agents);
    //    with ops-assistant it gets through, and without a runtime fails later, as UNAVAILABLE.
    let orders_tls = orders.state.tls().unwrap();
    let channel = agentscd::tls::client_channel(
        &orders_tls.material,
        &inv_mesh.to_string(),
        "spiffe://agentsc/ns/agentsc-demo/svc/inventory",
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
        .expect_err("no calling agent claimed");
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err:?}");
    assert_eq!(
        err.metadata().get("x-agentsc-rule").unwrap(),
        "authz.callers.orders"
    );
    let mut req = tonic::Request::new(InvokeAgentRequest {
        agent: "stock-analyst".into(),
        input: "hi".into(),
        ..Default::default()
    });
    req.metadata_mut()
        .insert("x-agentsc-agent", "ops-assistant".parse().unwrap());
    let err = mesh
        .invoke_agent(req)
        .await
        .expect_err("no runtime in this test");
    assert_eq!(err.code(), tonic::Code::Unavailable, "{err:?}");
    assert_eq!(
        err.metadata().get("x-agentsc-rule").unwrap(),
        "runtime.unavailable"
    );
    // an unknown agent: a peer allowed for nothing by that name gets the authz denial, not a 404 probe
    let mut req = tonic::Request::new(InvokeAgentRequest {
        agent: "secret-agent".into(),
        input: "hi".into(),
        ..Default::default()
    });
    req.metadata_mut()
        .insert("x-agentsc-agent", "ops-assistant".parse().unwrap());
    let err = mesh.invoke_agent(req).await.unwrap_err();
    assert_eq!(
        err.metadata().get("x-agentsc-rule").unwrap(),
        "authz.callers.orders"
    );

    // 5b. a peer cannot smuggle identity headers to the app: the sidecar's values replace them.
    let mut headers = std::collections::HashMap::new();
    headers.insert(
        "x-agentsc-caller".to_string(),
        "spiffe://agentsc/ns/agentsc-demo/svc/admin".to_string(),
    );
    headers.insert(
        "traceparent".to_string(),
        "00-11111111111111111111111111111111-2222222222222222-01".to_string(),
    );
    let mut req = tonic::Request::new(agentsc_proto::ServiceRequest {
        method: "GET".into(),
        path: "/stock/WIDGET-1".into(),
        headers,
        body: vec![],
        request_id: "req-spoof".into(),
        traceparent: String::new(),
        agent: String::new(),
    });
    req.metadata_mut()
        .insert("x-agentsc-agent", "ops-assistant".parse().unwrap());
    let resp = mesh
        .invoke_service(req)
        .await
        .expect("stock read is allowed")
        .into_inner();
    let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(
        body["seen_by_app"]["x-agentsc-caller"],
        json!(["spiffe://agentsc/ns/agentsc-demo/svc/orders"])
    );
    assert_eq!(
        body["seen_by_app"]["traceparent"].as_array().unwrap().len(),
        1
    );
    assert!(
        !body["seen_by_app"]["traceparent"][0]
            .as_str()
            .unwrap()
            .contains("1111111111")
    );

    // 5c. dot segments are resolved before anything is checked, so a traversal leaves the tool's
    //     template (`/stock/{sku}`), encoded slashes are refused outright, and so is a path that
    //     drops the param — on the caller's sidecar; the callee's check follows below.
    let traversal = |path: &str| ToolServiceRequest {
        ctx: ctx("check_stock", "req-traversal"),
        service: "inventory".into(),
        method: "GET".into(),
        path: path.into(),
        headers: Default::default(),
        body: vec![],
    };
    for (path, rule) in [
        ("/stock/../admin/reset", "guardrail.tool_spec"),
        ("/stock/%2e%2e/admin/reset", "guardrail.tool_spec"),
        ("/stock/..", "guardrail.tool_spec"),
        ("/stock", "guardrail.tool_spec"),
        ("/stock/", "guardrail.tool_spec"),
        ("/stock/W-1/x", "guardrail.tool_spec"),
        ("/stock/..%2Fadmin%2Freset", "guardrail.path"),
        ("/stock//W-1", "guardrail.path"),
        ("/stock/W-1;x", "guardrail.path"),
    ] {
        let err = tools.invoke_service(traversal(path)).await.expect_err(path);
        assert_eq!(err.code(), tonic::Code::PermissionDenied, "{path}: {err:?}");
        assert_eq!(
            err.metadata().get("x-agentsc-rule").unwrap(),
            rule,
            "{path}"
        );
    }
    let mut req = tonic::Request::new(agentsc_proto::ServiceRequest {
        method: "GET".into(),
        path: "/stock/../admin/reset".into(),
        headers: Default::default(),
        body: vec![],
        request_id: "req-traversal-inbound".into(),
        traceparent: String::new(),
        agent: String::new(),
    });
    req.metadata_mut()
        .insert("x-agentsc-agent", "ops-assistant".parse().unwrap());
    let err = mesh
        .invoke_service(req)
        .await
        .expect_err("callee resolves the traversal too");
    assert_eq!(
        err.metadata().get("x-agentsc-rule").unwrap(),
        "authz.services.deny-admin"
    );

    // 5d. other spellings of /admin from a peer meet the deny pattern too (a router would decode
    //     `%61`, ignore the trailing slash or the case); an empty segment is refused outright, and
    //     so is a `;` path parameter, which Tomcat, Spring and Jetty cut off before routing.
    let inbound = |method: &str, path: &str| {
        let mut req = tonic::Request::new(agentsc_proto::ServiceRequest {
            method: method.into(),
            path: path.into(),
            headers: Default::default(),
            body: vec![],
            request_id: "req-spelling-inbound".into(),
            traceparent: String::new(),
            agent: String::new(),
        });
        req.metadata_mut()
            .insert("x-agentsc-agent", "ops-assistant".parse().unwrap());
        req
    };
    for (method, path, rule) in [
        ("POST", "/%61dmin/reset", "authz.services.deny-admin"),
        ("POST", "/admin/", "authz.services.deny-admin"),
        ("POST", "/admin/reset/", "authz.services.deny-admin"),
        ("post", "/ADMIN/reset", "authz.services.deny-admin"),
        ("POST", "//admin/reset", "guardrail.path"),
        ("POST", "/admin%2Freset", "guardrail.path"),
        ("POST", "/admin;x", "guardrail.path"),
        ("POST", "/admin;x/reset", "guardrail.path"),
        ("POST", "/%61dmin;x/reset", "guardrail.path"),
        ("GET", "/stock/..;/admin/reset", "guardrail.path"),
        ("FETCH", "/stock/WIDGET-1", "guardrail.path"),
    ] {
        let err = mesh
            .invoke_service(inbound(method, path))
            .await
            .expect_err(path);
        assert_eq!(
            err.metadata().get("x-agentsc-rule").unwrap(),
            rule,
            "{method} {path}"
        );
    }
    // HEAD is held to the GET rules: `GET /stock/*` allows it, and the app's GET handler answers.
    let head = mesh
        .invoke_service(inbound("head", "/stock/WIDGET-1"))
        .await
        .expect("HEAD falls under GET /stock/*")
        .into_inner();
    assert_eq!(head.status, 200);
    // a `;` that is data comes escaped, as the runtime sends it, and reaches the app as part of the value
    let resp = mesh
        .invoke_service(inbound("GET", "/stock/WIDGET%3b1"))
        .await
        .expect("%3B is data")
        .into_inner();
    let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(body["sku"], "WIDGET;1");

    // 5e. an encoded slash in the query is data, not a path: a leftover argument such as a date
    //     reaches the app unchanged; a lowercase method is the declared GET.
    let mut dated = traversal("/stock/WIDGET-1?since=2026%2F10%2F21");
    dated.method = "get".into();
    let resp = tools
        .invoke_service(dated)
        .await
        .expect("a / in the query is fine")
        .into_inner();
    let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(body["query"], "since=2026%2F10%2F21");

    // 5f. an http tool's URL is held to its template the same way; the origin was already fixed.
    let fetch = |url: String| ToolHttpRequest {
        ctx: ctx("fetch_stock", "req-http"),
        method: "GET".into(),
        url,
        headers: Default::default(),
        body: vec![],
    };
    let base = format!("http://127.0.0.1:{}", app_addr.port());
    let resp = tools
        .invoke_http(fetch(format!(
            "{base}/stock/%57IDGET-1?since=2026%2F10%2F21"
        )))
        .await
        .expect("fits /stock/{sku}")
        .into_inner();
    let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(body["sku"], "WIDGET-1");
    assert_eq!(body["query"], "since=2026%2F10%2F21");
    for (path, rule) in [
        ("/stock/..", "guardrail.tool_spec"),
        ("/stock/%2e%2e/admin/reset", "guardrail.tool_spec"),
        ("/stock", "guardrail.tool_spec"),
        ("/admin/reset", "guardrail.tool_spec"),
        ("/stock/a%2Fb", "guardrail.path"),
        ("//stock/x", "guardrail.path"),
        ("/stock/..;/admin/reset", "guardrail.path"),
    ] {
        let err = tools
            .invoke_http(fetch(format!("{base}{path}")))
            .await
            .expect_err(path);
        assert_eq!(
            err.metadata().get("x-agentsc-rule").unwrap(),
            rule,
            "{path}"
        );
    }

    // 5g. the runtime cannot borrow a tool's name for a different request.
    let mut wrong = traversal("/stock/WIDGET-1");
    wrong.method = "DELETE".into();
    let err = tools
        .invoke_service(wrong)
        .await
        .expect_err("method differs from the declared tool");
    assert_eq!(
        err.metadata().get("x-agentsc-rule").unwrap(),
        "guardrail.tool_spec"
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
        "spiffe://agentsc/ns/agentsc-demo/svc/orders"
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
        "spiffe://agentsc/ns/agentsc-demo/svc/billing"
    );

    let _ = Arc::new(());
    orders.abort();
    inventory.abort();
}

#[tokio::test]
async fn a_peer_run_that_read_untrusted_data_cannot_write_with_authz_taint() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let pki = Pki {
        ca: agentsc_pki::ca_init().unwrap(),
    };
    let app_addr = fake_inventory_app().await;
    let mut inv = Charter::from_yaml(INVENTORY).unwrap();
    inv.service.app_port = app_addr.port();
    inv.audit.sink = agentsc_charter::AuditSink::File;
    let audit = root.join("inventory-audit.jsonl");
    inv.audit.file = Some(audit.to_string_lossy().into_owned());
    inv.authz.taint = Some(agentsc_charter::InboundTaintSpec {
        mode: agentsc_charter::TaintMode::Enforce,
    });
    inv.authz.services.push(
        serde_json::from_value(json!({
            "name": "orders-restocks", "identity": "spiffe://agentsc/ns/agentsc-demo/svc/orders",
            "service": "inventory", "allow": ["POST /restock"]
        }))
        .unwrap(),
    );
    let inventory = start(
        root,
        "inventory",
        write_charter(root, "inventory", &inv),
        pki.tls_dir(root, "inventory"),
    )
    .await;
    let orders = agentsc_pki::TlsMaterial::load(pki.tls_dir(root, "orders")).unwrap();
    let channel = agentscd::tls::client_channel(
        &orders,
        &inventory.mesh_addr.unwrap().to_string(),
        "spiffe://agentsc/ns/agentsc-demo/svc/inventory",
    )
    .unwrap();
    let mut mesh = MeshClient::new(channel);
    let call = |method: &str, path: &str, taint: Option<&str>| {
        let mut req = tonic::Request::new(agentsc_proto::ServiceRequest {
            method: method.into(),
            path: path.into(),
            headers: Default::default(),
            body: vec![],
            request_id: format!("req-{method}-{}", taint.unwrap_or("clean")),
            traceparent: String::new(),
            agent: String::new(),
        });
        req.metadata_mut()
            .insert("x-agentsc-agent", "ops-assistant".parse().unwrap());
        if let Some(t) = taint {
            req.metadata_mut()
                .insert("x-agentsc-taint", t.parse().unwrap());
        }
        req
    };

    // the caller's run read untrusted data: no write here
    let err = mesh
        .invoke_service(call("POST", "/restock", Some("untrusted")))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err:?}");
    assert_eq!(
        err.metadata().get("x-agentsc-rule").unwrap(),
        "taint.untrusted_write"
    );
    // a clean run writes, and a tainted one still reads
    let ok = mesh
        .invoke_service(call("POST", "/restock", None))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(ok.status, 200);
    let read = mesh
        .invoke_service(call("GET", "/stock/WIDGET-1", Some("untrusted")))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(read.status, 200);

    let recs: Vec<serde_json::Value> = std::fs::read_to_string(&audit)
        .unwrap()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .filter(|v: &serde_json::Value| v["rule"] == "taint.untrusted_write")
        .collect();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["kind"], "service_call");
    assert_eq!(recs[0]["decision"], "deny");
    assert_eq!(
        recs[0]["caller"],
        "spiffe://agentsc/ns/agentsc-demo/svc/orders"
    );
    inventory.abort();
}

/// The inventory charter for a fake app on `app`, its authz identities moved to trust domain
/// `td` and namespace `ns`; audit to `<root>/<name>-audit.jsonl`.
fn inventory_in(root: &std::path::Path, name: &str, td: &str, ns: &str, app: u16) -> Charter {
    let text = INVENTORY
        .replace("spiffe://agentsc/", &format!("spiffe://{td}/"))
        .replace("namespace: agentsc-demo", &format!("namespace: {ns}"));
    let mut inv = Charter::from_yaml(&text).unwrap();
    inv.service.app_port = app;
    inv.audit.sink = agentsc_charter::AuditSink::File;
    inv.audit.file = Some(
        root.join(format!("{name}-audit.jsonl"))
            .to_string_lossy()
            .into_owned(),
    );
    inv
}

fn audit_of(root: &std::path::Path, name: &str) -> Vec<serde_json::Value> {
    std::fs::read_to_string(root.join(format!("{name}-audit.jsonl")))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

#[tokio::test]
async fn a_configured_trust_domain_end_to_end() {
    const TD: &str = "prod.example";
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let pki = Pki {
        ca: agentsc_pki::ca_init().unwrap(),
    };
    let app = fake_inventory_app().await;
    let in_td = |cfg: &mut Config| cfg.trust_domain = TD.into();

    let inv = inventory_in(root, "inventory", TD, "agentsc-demo", app.port());
    let inventory = start_with(
        root,
        "inventory",
        write_charter(root, "inventory", &inv),
        pki.tls_dir_in(root, TD, "agentsc-demo", "inventory"),
        in_td,
    )
    .await;
    assert_eq!(
        inventory.state.self_identity,
        "spiffe://prod.example/ns/agentsc-demo/svc/inventory"
    );
    let inv_mesh = inventory.mesh_addr.unwrap().to_string();

    // 1. orders in prod.example reaches inventory in prod.example; the callee's rules name
    //    spiffe://prod.example/... and match
    let ord = orders_calling(root, "orders", "inventory", &inv_mesh);
    let orders = start_with(
        root,
        "orders",
        write_charter(root, "orders", &ord),
        pki.tls_dir_in(root, TD, "agentsc-demo", "orders"),
        in_td,
    )
    .await;
    let mut tools = tools_client(&root.join("sock-orders")).await;
    // the runs these tool calls belong to (tool calls of no run are refused)
    let _runs: Vec<_> = ["req-td"]
        .into_iter()
        .map(|id| {
            orders.state.runs.start(
                id,
                "ops-assistant",
                "local",
                "4bf92f3577b34da6a3ce929d0e0e4736",
            )
        })
        .collect();
    let ok = tools
        .invoke_service(stock_request("inventory", "req-td"))
        .await
        .expect("a call inside the trust domain")
        .into_inner();
    assert_eq!(ok.status, 200);
    let rec = audit_of(root, "inventory")
        .into_iter()
        .find(|v| v["request_id"] == "req-td")
        .unwrap();
    assert_eq!(
        rec["caller"],
        "spiffe://prod.example/ns/agentsc-demo/svc/orders"
    );
    assert_eq!(rec["rule"], "authz.services.orders-reads-stock");

    // 2. the same CA's certificate for orders in the default trust domain is no identity here:
    //    refused before any rule, with the trust domain in the message, and audited
    let foreign = agentsc_pki::TlsMaterial::load(pki.tls_dir(root, "orders")).unwrap();
    let channel = agentscd::tls::client_channel(
        &foreign,
        &inv_mesh,
        "spiffe://prod.example/ns/agentsc-demo/svc/inventory",
    )
    .unwrap();
    let mut req = tonic::Request::new(agentsc_proto::ServiceRequest {
        method: "GET".into(),
        path: "/stock/WIDGET-1".into(),
        request_id: "req-foreign-td".into(),
        ..Default::default()
    });
    req.metadata_mut()
        .insert("x-agentsc-agent", "ops-assistant".parse().unwrap());
    let err = MeshClient::new(channel)
        .invoke_service(req)
        .await
        .expect_err("another trust domain");
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err:?}");
    assert_eq!(
        err.metadata().get("x-agentsc-rule").unwrap(),
        "authz.identity.invalid"
    );
    assert!(err.message().contains("spiffe://prod.example/"), "{err:?}");
    let refused = audit_of(root, "inventory")
        .into_iter()
        .find(|v| v["request_id"] == "req-foreign-td")
        .expect("the refusal is audited");
    assert_eq!(refused["rule"], "authz.identity.invalid");

    // 2b. and the other way round: a server is held to the caller's trust domain too — the
    //     prod.example inventory is not spiffe://agentsc/ns/agentsc-demo/svc/inventory
    let ours =
        agentsc_pki::TlsMaterial::load(pki.tls_dir_in(root, TD, "agentsc-demo", "orders")).unwrap();
    let channel = agentscd::tls::client_channel(
        &ours,
        &inv_mesh,
        "spiffe://agentsc/ns/agentsc-demo/svc/inventory",
    )
    .unwrap();
    let err = MeshClient::new(channel)
        .invoke_service(agentsc_proto::ServiceRequest::default())
        .await
        .expect_err("refused in the handshake");
    assert_eq!(err.code(), tonic::Code::Unavailable, "{err:?}");

    // 3. a sidecar does not start with a --tls-dir certificate of another trust domain
    let sock = root.join("sock-mismatch");
    let mut cfg = Config::for_test(
        write_charter(root, "mismatch", &ord),
        pki.tls_dir(root, "orders"),
        sock,
    );
    in_td(&mut cfg);
    let err = agentscd::start(cfg).await.err().expect("refused");
    assert!(
        format!("{err:#}").contains("does not match charter identity spiffe://prod.example/"),
        "{err:#}"
    );

    orders.abort();
    inventory.abort();
}

#[tokio::test]
async fn a_peer_in_another_namespace_is_verified_by_its_spiffe_id() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let pki = Pki {
        ca: agentsc_pki::ca_init().unwrap(),
    };
    let app = fake_inventory_app().await;

    // inventory runs in namespace warehouse; its rules admit orders of agentsc-demo
    let inv = inventory_in(root, "warehouse", "agentsc", "warehouse", app.port());
    let inventory = start(
        root,
        "warehouse",
        write_charter(root, "warehouse", &inv),
        pki.tls_dir_in(root, "agentsc", "warehouse", "inventory"),
    )
    .await;
    let addr = inventory.mesh_addr.unwrap().to_string();

    // orders in agentsc-demo names it inventory.warehouse; a second tool names the same
    // address plain `inventory`, i.e. inventory of orders' own namespace
    let mut ord = orders_calling(root, "orders", "inventory.warehouse", &addr);
    ord.mesh.peers.insert("inventory".into(), addr.clone());
    let ops = ord
        .agents
        .iter_mut()
        .find(|a| a.name == "ops-assistant")
        .unwrap();
    let mut here = ops
        .tools
        .iter()
        .find(|t| t.name == "check_stock")
        .unwrap()
        .clone();
    here.name = "check_stock_here".into();
    here.service = Some("inventory".into());
    ops.tools.push(here);
    ord.guardrails
        .allowed_tools
        .get_mut("ops-assistant")
        .unwrap()
        .push("check_stock_here".into());
    assert_eq!(ord.schema_level(), 5);
    let orders = start(
        root,
        "orders",
        write_charter(root, "orders", &ord),
        pki.tls_dir(root, "orders"),
    )
    .await;
    let mut tools = tools_client(&root.join("sock-orders")).await;
    // the runs these tool calls belong to (tool calls of no run are refused)
    let _runs: Vec<_> = ["req-xns", "req-wrong-id"]
        .into_iter()
        .map(|id| {
            orders.state.runs.start(
                id,
                "ops-assistant",
                "local",
                "4bf92f3577b34da6a3ce929d0e0e4736",
            )
        })
        .collect();

    // 1. the cross-namespace call: the server is spiffe://agentsc/ns/warehouse/svc/inventory,
    //    as the charter names it, and the callee sees the caller's identity
    let ok = tools
        .invoke_service(stock_request("inventory.warehouse", "req-xns"))
        .await
        .expect("a call to another namespace")
        .into_inner();
    assert_eq!(ok.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&ok.body).unwrap();
    assert_eq!(body["sku"], "WIDGET-1");
    let rec = audit_of(root, "warehouse")
        .into_iter()
        .find(|v| v["request_id"] == "req-xns")
        .unwrap();
    assert_eq!(rec["caller"], "spiffe://agentsc/ns/agentsc-demo/svc/orders");
    assert_eq!(rec["decision"], "allow");
    let out = audit_of(root, "orders")
        .into_iter()
        .find(|v| v["request_id"] == "req-xns" && v["kind"] == "service_call")
        .unwrap();
    assert_eq!(out["callee"], "inventory.warehouse GET /stock/WIDGET-1");

    // 2. the same server under the name `inventory` is the wrong workload: the handshake fails
    //    on the SPIFFE ID (a DNS name check never decides), and the callee never sees the call
    let mut wrong = stock_request("inventory", "req-wrong-id");
    wrong.ctx = ctx("check_stock_here", "req-wrong-id");
    let err = tools
        .invoke_service(wrong)
        .await
        .expect_err("not spiffe://agentsc/ns/agentsc-demo/svc/inventory");
    assert_eq!(err.code(), tonic::Code::Unavailable, "{err:?}");
    assert_eq!(
        err.metadata().get("x-agentsc-rule").unwrap(),
        "mesh.unavailable"
    );
    assert!(
        err.message()
            .contains("spiffe://agentsc/ns/warehouse/svc/inventory"),
        "the error names what the peer presented: {err:?}"
    );
    assert!(
        !audit_of(root, "warehouse")
            .iter()
            .any(|v| v["request_id"] == "req-wrong-id"),
        "refused before any request"
    );

    // 3. with fixed material: the right SPIFFE ID passes, any other is refused
    let mine = orders.state.tls().unwrap();
    for (peer, ok) in [
        ("spiffe://agentsc/ns/warehouse/svc/inventory", true),
        ("spiffe://agentsc/ns/agentsc-demo/svc/inventory", false),
        ("spiffe://prod.example/ns/warehouse/svc/inventory", false),
    ] {
        let channel = agentscd::tls::client_channel(&mine.material, &addr, peer).unwrap();
        let mut req = tonic::Request::new(agentsc_proto::ServiceRequest {
            method: "GET".into(),
            path: "/stock/WIDGET-1".into(),
            ..Default::default()
        });
        req.metadata_mut()
            .insert("x-agentsc-agent", "ops-assistant".parse().unwrap());
        let r = MeshClient::new(channel).invoke_service(req).await;
        assert_eq!(r.is_ok(), ok, "{peer}: {r:?}");
    }

    // 4. default addresses use the peer's namespace and the cluster domain
    let snap = orders.state.loaded().unwrap();
    let mut no_peers = snap.charter.clone();
    no_peers.mesh.peers.clear();
    let p = orders.state.peer(&no_peers, "inventory.warehouse");
    assert_eq!(p.address, "inventory.warehouse.svc.cluster.local:50002");
    assert_eq!(p.identity, "spiffe://agentsc/ns/warehouse/svc/inventory");
    let p = orders.state.peer(&no_peers, "inventory");
    assert_eq!(p.address, "inventory.agentsc-demo.svc.cluster.local:50002");
    assert_eq!(p.identity, "spiffe://agentsc/ns/agentsc-demo/svc/inventory");

    orders.abort();
    inventory.abort();
}
