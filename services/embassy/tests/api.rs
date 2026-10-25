//! The REST API end to end (design §8, §10): auth, CSRF, Host, headers, roles on the diff,
//! namespace scope, payload hiding, versions, cascades, links, validate, history and rollback,
//! memory, proposals, recent events, the graph and the traces — against a running server with a
//! temporary file store.
mod common;

use std::collections::BTreeSet;

use common::{Env, NS, Opts, Resp, inventory_yaml, orders_yaml, rec, support_yaml};
use embassy::api::types::{
    AgentView, AuditRecord, CharterDoc, Graph, HistoryEntry, LinkResult, MemoryDoc, Node, Proposal,
    ProposalDecision, ServiceSummary, TraceDoc, TraceSummary, ValidateResult, WhoAmI,
};
use embassy::config::PolicyConfig;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

async fn put(env: &Env, who: &str, svc: &str, charter: &Value, v: &str) -> Resp {
    env.call(
        "PUT",
        &format!("/services/{NS}/{svc}/charter"),
        who,
        Some(json!({ "yaml": charter.to_string() })),
        Some(v),
    )
    .await
}

fn audit_lines(env: &Env) -> Vec<Value> {
    std::fs::read_to_string(env.store_dir.join(".audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn assert_secure(r: &Resp) {
    let h = &r.headers;
    assert_eq!(
        h["content-security-policy"],
        embassy::auth::http::CSP,
        "{}",
        r.text
    );
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["referrer-policy"], "no-referrer");
    assert_eq!(h["x-frame-options"], "DENY");
    assert!(
        !h.keys().any(|k| k.as_str().starts_with("access-control-")),
        "no CORS header: {h:?}"
    );
}

#[tokio::test]
async fn bearer_tokens_sessions_and_the_login_rate_limit() {
    let env = Env::start().await;
    let r = Env::send(env.req("GET", "/api/v1/whoami", None)).await;
    assert_eq!((r.status, r.error()), (401, "unauthenticated"));
    assert_secure(&r);
    let r = env.get("/whoami", "alice").await;
    assert_eq!(r.status, 200);
    let me: WhoAmI = serde_json::from_value(r.body).unwrap();
    assert_eq!((me.name.as_str(), me.payloads), ("alice", true));
    let r = Env::send(
        env.req("GET", "/api/v1/whoami", None)
            .bearer_auth(embassy::token::generate().unwrap()),
    )
    .await;
    assert_eq!(r.status, 401);

    // login → cookie
    let r = Env::send(
        env.req("POST", "/api/v1/login", None)
            .body(json!({"token": env.token("carol")}).to_string()),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["name"], "carol");
    let cookie = r.headers["set-cookie"].to_str().unwrap().to_string();
    assert!(cookie.starts_with("agentsc_session="), "{cookie}");
    assert!(
        cookie.contains("; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200"),
        "{cookie}"
    );
    assert!(!cookie.contains("Secure"), "plain HTTP: {cookie}");
    let session = cookie.split(';').next().unwrap().to_string();
    let r = Env::send(
        env.req("GET", "/api/v1/whoami", None)
            .header("Cookie", &session),
    )
    .await;
    assert_eq!((r.status, r.body["name"].as_str()), (200, Some("carol")));
    // a bad bearer token is never replaced by the cookie
    let r = Env::send(
        env.req("GET", "/api/v1/whoami", None)
            .header("Cookie", &session)
            .header("Authorization", "Bearer att_nope"),
    )
    .await;
    assert_eq!(r.status, 401);
    // logout clears the cookie
    let r = Env::send(
        env.req("POST", "/api/v1/logout", None)
            .header("Cookie", &session),
    )
    .await;
    assert_eq!(r.status, 204);
    assert!(
        r.headers["set-cookie"]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    let r = Env::send(env.req("POST", "/api/v1/logout", None)).await;
    assert_eq!(r.status, 401);

    // five failures per minute per client IP, then 429 even for a good token
    for _ in 0..5 {
        let r = Env::send(
            env.req("POST", "/api/v1/login", None)
                .body(json!({"token": embassy::token::generate().unwrap()}).to_string()),
        )
        .await;
        assert_eq!(r.status, 401);
    }
    let r = Env::send(
        env.req("POST", "/api/v1/login", None)
            .body(json!({"token": env.token("alice")}).to_string()),
    )
    .await;
    assert_eq!((r.status, r.error()), (429, "rate_limited"));
    let wait: u64 = r.headers["retry-after"].to_str().unwrap().parse().unwrap();
    assert!((1..=60).contains(&wait));
    assert_secure(&r);
    // bearer tokens are not rate limited
    assert_eq!(env.get("/whoami", "alice").await.status, 200);

    let actions: Vec<String> = audit_lines(&env)
        .iter()
        .map(|l| l["action"].as_str().unwrap().to_string())
        .collect();
    for want in ["login", "logout", "login_failed"] {
        assert!(actions.iter().any(|a| a == want), "{want} in {actions:?}");
    }
    env.stop().await;
}

#[tokio::test]
async fn sessions_end_when_the_token_leaves_the_config() {
    let env = Env::start().await;
    let r = Env::send(
        env.req("POST", "/api/v1/login", None)
            .body(json!({"token": env.token("bob")}).to_string()),
    )
    .await;
    let session = r.headers["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let mut cfg = embassy::config::ControlPlaneConfig::clone(&env.hub.config.load());
    cfg.auth.tokens.retain(|t| t.name != "bob");
    env.hub.config.store(std::sync::Arc::new(cfg));
    let r = Env::send(
        env.req("GET", "/api/v1/whoami", None)
            .header("Cookie", &session),
    )
    .await;
    assert_eq!(r.status, 401);
    env.stop().await;
}

#[tokio::test]
async fn csrf_and_content_type_on_every_mutation() {
    let env = Env::start().await;
    let login = |csrf: bool, ct: &str| {
        let mut b = env
            .http
            .post(format!("{}/api/v1/login", env.base))
            .header("Content-Type", ct.to_string())
            .body(json!({"token": env.token("alice")}).to_string());
        if csrf {
            b = b.header("X-Agentsc-CSRF", "1");
        }
        b
    };
    let r = Env::send(login(false, "application/json")).await;
    assert_eq!((r.status, r.error()), (403, "forbidden"));
    let r = Env::send(login(true, "text/plain")).await;
    assert_eq!((r.status, r.error()), (400, "invalid"));
    let r = Env::send(login(true, "application/json; charset=utf-8")).await;
    assert_eq!(r.status, 200);
    let r = Env::send(login(false, "application/json").header("X-Agentsc-CSRF", "yes")).await;
    assert_eq!(r.status, 403, "only the value 1");
    // PUT and DELETE with a valid token but no CSRF header
    for (m, path) in [
        ("PUT", format!("/api/v1/services/{NS}/orders/charter")),
        ("DELETE", format!("/api/v1/services/{NS}/orders")),
        ("POST", "/api/v1/links".to_string()),
    ] {
        let r = Env::send(
            env.http
                .request(m.parse().unwrap(), format!("{}{path}", env.base))
                .bearer_auth(env.token("alice"))
                .header("Content-Type", "application/json")
                .body("{}"),
        )
        .await;
        assert_eq!((r.status, r.error()), (403, "forbidden"), "{m} {path}");
        assert_secure(&r);
    }
    env.stop().await;
}

#[tokio::test]
async fn the_host_header_is_checked_on_every_path() {
    let env = Env::start().await;
    for path in ["/api/v1/whoami", "/healthz", "/", "/api/v1/healthz"] {
        let r = Env::send(
            env.req("GET", path, Some("alice"))
                .header("Host", "evil.example"),
        )
        .await;
        assert_eq!(
            (r.status, r.error()),
            (421, "misdirected_request"),
            "{path}"
        );
        assert_secure(&r);
    }
    for host in ["embassy.test:8080", "localhost", "127.0.0.1:1", "[::1]:9"] {
        let r = Env::send(env.req("GET", "/healthz", None).header("Host", host)).await;
        assert_eq!((r.status, r.text.as_str()), (200, "ok"), "{host}");
    }
    // security headers everywhere; a CORS preflight gets none
    for path in ["/", "/js/main.js", "/api/v1/nope", "/healthz", "/readyz"] {
        let r = Env::send(env.req("GET", path, Some("alice"))).await;
        assert_secure(&r);
    }
    let r = Env::send(
        env.http
            .request(
                reqwest::Method::OPTIONS,
                format!("{}/api/v1/whoami", env.base),
            )
            .header("Origin", "https://evil.example")
            .header("Access-Control-Request-Method", "PUT"),
    )
    .await;
    assert_secure(&r);
    env.stop().await;
}

#[tokio::test]
async fn health_and_readiness() {
    let env = Env::start().await;
    let r = Env::send(env.req("GET", "/readyz", None)).await;
    assert_eq!(r.status, 200, "{}", r.text);
    for c in ["api", "ui", "controlplane", "store"] {
        assert_eq!(r.body["components"][c], true, "{c}: {}", r.text);
    }
    let r = Env::send(env.req("GET", "/api/v1/readyz", None)).await;
    assert_eq!(r.body["ready"], true);
    // control-plane audit persistence is reported, without changing readiness
    assert_eq!(
        r.body["cp_audit"],
        json!({"persisted": true, "append_failures": 0, "last_error": null}),
        "{}",
        r.text
    );
    env.stop().await;
}

#[tokio::test]
async fn roles_are_enforced_on_the_charter_diff() {
    let env = Env::start().await;
    // creating the first charter with PUT needs admin
    let r = Env::send(
        env.req(
            "PUT",
            &format!("/api/v1/services/{NS}/orders/charter"),
            Some("bob"),
        )
        .header("If-None-Match", "*")
        .body(json!({"yaml": orders_yaml()}).to_string()),
    )
    .await;
    assert_eq!(r.status, 403, "{}", r.text);
    assert!(
        r.details()
            .contains("a first charter written with PUT requires admin")
    );
    let v1 = env.create("orders", &orders_yaml()).await;
    let (_, base) = env.charter("orders").await;

    // the editor allowances: system, model, budgets, harness, learning (review), agents,
    // service/agent tools, allowed_* entries, agent names in local caller rules
    let mut c = base.clone();
    c["agents"][1]["system"] = json!("Classify by urgency.");
    c["agents"][1]["model"] = json!("claude-haiku-5-5");
    c["agents"][1]["budgets"] = json!({"max_steps": 3});
    c["agents"][1]["harness"] = json!({"max_retries": 1});
    c["agents"][1]["learning"] = json!({"enabled": true});
    c["agents"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name": "extra", "model": "mock"}));
    c["guardrails"]["allowed_tools"]["triage"] = json!([]);
    c["guardrails"]["allowed_services"] = json!({"ops": ["orders", "inventory"]});
    c["authz"]["callers"]
        .as_array_mut()
        .unwrap()
        .push(json!({"identity": "local", "agents": ["extra"]}));
    c["agents"][0]["tools"].as_array_mut().unwrap().push(json!({
        "name": "lookup_more", "description": "d", "type": "service", "service": "orders",
        "method": "GET", "path": "/more"
    }));
    let r = put(&env, "bob", "orders", &c, &v1).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let v2 = r.version();
    assert_eq!(r.etag().as_deref(), Some(v2.as_str()));
    let (_, base) = env.charter("orders").await;

    // each admin category, refused for the editor with the reason, accepted for an admin
    type Change = Box<dyn Fn(&mut Value)>;
    let cases: Vec<(&str, Change, &str)> = vec![
        (
            "authz.default",
            Box::new(|c| c["authz"]["default"] = json!("allow")),
            "authz.default requires admin",
        ),
        (
            "guardrails rules",
            Box::new(|c| c["guardrails"]["input_deny"] = json!([])),
            "guardrails.input_deny requires admin",
        ),
        (
            "pii",
            Box::new(|c| c["guardrails"]["pii_redact"] = json!(false)),
            "guardrails.pii_redact requires admin",
        ),
        (
            "audit",
            Box::new(|c| c["audit"] = json!({"redact": ["input.card"]})),
            "audit.redact requires admin",
        ),
        (
            "telemetry",
            Box::new(|c| c["telemetry"] = json!({"traces": false})),
            "telemetry.traces requires admin",
        ),
        (
            "mesh",
            Box::new(|c| c["mesh"] = json!({"peers": {"inventory": "inv:50002"}})),
            "mesh.peers requires admin",
        ),
        (
            "non-local caller",
            Box::new(|c| {
                c["authz"]["callers"].as_array_mut().unwrap().push(json!({"identity": "spiffe://agentsc/ns/shop/svc/billing", "agents": ["triage"]}))
            }),
            "authz.callers rule for spiffe://agentsc/ns/shop/svc/billing requires admin",
        ),
        (
            "learning auto",
            Box::new(|c| c["agents"][1]["learning"] = json!({"enabled": true, "mode": "auto"})),
            "agents.triage.learning.mode: auto requires admin",
        ),
        (
            "http origin",
            Box::new(|c| {
                c["agents"][0]["tools"].as_array_mut().unwrap().push(json!({"name": "eta", "description": "d", "type": "http", "method": "GET", "url": "https://api.partner.example/eta"}))
            }),
            "(new http origin https://api.partner.example) requires admin",
        ),
        (
            "agent type",
            Box::new(|c| c["agents"][1]["type"] = json!("orchestrator")),
            "agents.triage.type requires admin",
        ),
    ];
    let mut v = v2.clone();
    for (what, change, reason) in &cases {
        let mut c = base.clone();
        change(&mut c);
        let r = put(&env, "bob", "orders", &c, &v).await;
        assert_eq!(
            (r.status, r.error()),
            (403, "forbidden"),
            "{what}: {}",
            r.text
        );
        assert!(r.details().contains(reason), "{what}: {}", r.details());
        // validate reports the same need
        let r = env
            .call(
                "POST",
                &format!("/services/{NS}/orders/charter/validate"),
                "bob",
                Some(json!({"yaml": c.to_string()})),
                None,
            )
            .await;
        assert_eq!(
            (r.status, r.body["needs_role"].as_str()),
            (200, Some("admin")),
            "{what}: {}",
            r.text
        );
        // an admin may (one at a time, back to the base each time)
        let r = put(&env, "alice", "orders", &c, &v).await;
        assert_eq!(r.status, 200, "{what}: {}", r.text);
        let r = put(&env, "alice", "orders", &base, &r.version()).await;
        assert_eq!(r.status, 200, "{what} back: {}", r.text);
        v = r.version();
    }
    // a viewer may not write at all
    let r = put(&env, "carol", "orders", &base, &v).await;
    assert_eq!(r.status, 403);
    assert!(r.details().contains("requires editor"), "{}", r.details());
    // rollback and service deletion are admin
    let r = env
        .call(
            "POST",
            &format!("/services/{NS}/orders/charter/rollback"),
            "bob",
            Some(json!({"version": v1})),
            Some(&v),
        )
        .await;
    assert_eq!(r.status, 403);
    let r = env
        .call(
            "DELETE",
            &format!("/services/{NS}/orders"),
            "bob",
            None,
            Some(&v),
        )
        .await;
    assert_eq!(r.status, 403);
    // denied writes are audited
    assert!(
        audit_lines(&env)
            .iter()
            .any(|l| l["action"] == "charter_put"
                && l["result"] == "denied"
                && l["actor"] == "bob")
    );
    env.stop().await;
}

#[tokio::test]
async fn policy_runs_on_every_write() {
    let env = Env::start_with(Opts {
        policy: Some(PolicyConfig {
            require_authz_default_deny: true,
            http_origin_allowlist: Some(vec!["https://ok.example".into()]),
            forbid_learning_auto: true,
        }),
        ..Default::default()
    })
    .await;
    let v = env.create("orders", &orders_yaml()).await;
    let (_, base) = env.charter("orders").await;
    for (change, want) in [(
        json!({"authz": {"default": "allow", "callers": base["authz"]["callers"]}}),
        "policy.require_authz_default_deny",
    )] {
        let mut c = base.clone();
        c["authz"] = change["authz"].clone();
        let r = put(&env, "alice", "orders", &c, &v).await;
        assert_eq!((r.status, r.error()), (400, "invalid"), "{}", r.text);
        assert!(r.details().contains(want), "{}", r.details());
    }
    let mut c = base.clone();
    c["agents"][1]["learning"] = json!({"enabled": true, "mode": "auto"});
    let r = put(&env, "alice", "orders", &c, &v).await;
    assert!(
        r.details().contains("policy.forbid_learning_auto"),
        "{}",
        r.text
    );
    let mut c = base.clone();
    c["agents"][0]["tools"].as_array_mut().unwrap().push(json!({"name": "eta", "description": "d", "type": "http", "method": "GET", "url": "https://other.example/eta"}));
    let r = put(&env, "alice", "orders", &c, &v).await;
    assert!(
        r.details().contains("policy.http_origin_allowlist"),
        "{}",
        r.text
    );
    // validate runs the policy too
    let r = env
        .call(
            "POST",
            &format!("/services/{NS}/orders/charter/validate"),
            "alice",
            Some(json!({"yaml": c.to_string()})),
            None,
        )
        .await;
    assert_eq!(r.status, 400);
    env.stop().await;
}

#[tokio::test]
async fn versions_and_if_match() {
    let env = Env::start().await;
    let v1 = env.create("orders", &orders_yaml()).await;
    assert_eq!(v1, "1");
    let r = env
        .get(&format!("/services/{NS}/orders/charter"), "carol")
        .await;
    assert_eq!(r.etag().as_deref(), Some("1"));
    let doc: CharterDoc = serde_json::from_value(r.body.clone()).unwrap();
    assert_eq!(doc.yaml, orders_yaml(), "stored as written");
    let (_, c) = env.charter("orders").await;
    // missing precondition
    let r = env
        .call(
            "PUT",
            &format!("/services/{NS}/orders/charter"),
            "alice",
            Some(json!({"yaml": c.to_string()})),
            None,
        )
        .await;
    assert_eq!((r.status, r.error()), (400, "invalid"));
    // a second first charter
    let r = Env::send(
        env.req(
            "PUT",
            &format!("/api/v1/services/{NS}/orders/charter"),
            Some("alice"),
        )
        .header("If-None-Match", "*")
        .body(json!({"yaml": orders_yaml()}).to_string()),
    )
    .await;
    assert_eq!(
        (r.status, r.body["current_version"].as_str()),
        (409, Some("1"))
    );
    let r = put(&env, "alice", "orders", &c, "1").await;
    assert_eq!(r.version(), "2");
    // stale
    let r = put(&env, "alice", "orders", &c, "1").await;
    assert_eq!((r.status, r.error()), (409, "version_conflict"));
    assert_eq!(r.body["current_version"], "2");
    // ahead of the stored version: refused before any role-on-diff is computed, so a version
    // guessed one ahead can never be checked against an older charter than the one it replaces
    let r = put(&env, "alice", "orders", &c, "3").await;
    assert_eq!((r.status, r.error()), (409, "version_conflict"));
    assert_eq!(r.body["current_version"], "2");
    // If-Match on a service without a charter
    let r = put(&env, "alice", "nothing", &c, "1").await;
    assert_eq!(r.status, 404);
    // a charter for another service than the path
    let r = put(&env, "alice", "inventory", &c, "1").await;
    assert_eq!(r.status, 404);
    let r = Env::send(
        env.req(
            "PUT",
            &format!("/api/v1/services/{NS}/inventory/charter"),
            Some("alice"),
        )
        .header("If-None-Match", "*")
        .body(json!({"yaml": orders_yaml()}).to_string()),
    )
    .await;
    assert_eq!(r.status, 400);
    assert!(r.details().contains("service.name"), "{}", r.details());
    // invalid charters say why
    let r = put(
        &env,
        "alice",
        "orders",
        &json!({"apiVersion": "agentsc.io/v1alpha1"}),
        "2",
    )
    .await;
    assert_eq!((r.status, r.error()), (400, "invalid"));
    let r = env
        .call(
            "GET",
            &format!("/services/{NS}/Bad/charter"),
            "alice",
            None,
            None,
        )
        .await;
    assert_eq!(r.status, 400);
    env.stop().await;
}

#[tokio::test]
async fn namespace_scope_applies_to_every_endpoint() {
    let env = Env::start().await;
    env.create("orders", &orders_yaml()).await;
    env.ingest(rec("agent_invocation", json!({})));
    // dave sees namespace "other" only
    let r = env.get("/services", "dave").await;
    assert_eq!(r.body, json!([]));
    for path in [
        format!("/services/{NS}/orders/charter"),
        format!("/services/{NS}/orders/charter/history"),
        format!("/services/{NS}/orders/agents/ops"),
        format!("/services/{NS}/orders/memory"),
    ] {
        let r = env.get(&path, "dave").await;
        assert_eq!((r.status, r.error()), (404, "not_found"), "{path}");
    }
    let g: Graph = serde_json::from_value(env.get("/graph", "dave").await.body).unwrap();
    assert!(
        g.nodes.iter().all(|n| !n.id().contains(NS)),
        "{:?}",
        g.nodes.iter().map(Node::id).collect::<Vec<_>>()
    );
    assert_eq!(env.get("/events/recent", "dave").await.body, json!([]));
    assert_eq!(env.get("/traces", "dave").await.body, json!([]));
    assert_eq!(
        env.get(&format!("/traces?namespace={NS}"), "dave")
            .await
            .body,
        json!([])
    );
    let r = env
        .call(
            "POST",
            "/links",
            "dave",
            Some(json!({
                "from": format!("agent:{NS}/orders/ops"), "to": format!("agent:{NS}/orders/triage"),
                "tool": {"name": "x", "description": "d"}, "if_match": {}
            })),
            None,
        )
        .await;
    assert_eq!(r.status, 404);
    // carol (viewer of shop) sees it
    let r = env.get("/services", "carol").await;
    assert_eq!(r.body.as_array().unwrap().len(), 1);
    assert_eq!(
        env.get("/events/recent", "carol")
            .await
            .body
            .as_array()
            .unwrap()
            .len(),
        1
    );
    env.stop().await;
}

#[tokio::test]
async fn payloads_are_hidden_from_tokens_without_them() {
    let env = Env::start().await;
    env.create("orders", &orders_yaml()).await;
    env.ingest(rec(
        "agent_invocation",
        json!({"input_sha256": "a".repeat(64), "added_later": {"secret": "s"}, "tokens": {"input": 3, "output": 1, "cache_read": 9}}),
    ));
    let alice = env.get("/events/recent", "alice").await.body;
    assert_eq!(
        alice[0]["input"]["input"],
        "How many WIDGET-1 are in stock?"
    );
    assert_eq!(
        alice[0]["added_later"]["secret"], "s",
        "unknown fields served again"
    );
    for who in ["carol", "erin"] {
        let r = env.get("/events/recent", who).await.body;
        assert!(
            r[0]["input"].is_null() && r[0]["output"].is_null(),
            "{who}: {r}"
        );
        assert_eq!(r[0]["input_sha256"], "a".repeat(64), "hashes stay");
        assert!(r[0].get("added_later").is_none(), "unknown fields go: {r}");
        assert_eq!(r[0]["tokens"]["cache_read"], 9, "usage stays");
    }
    // traces: the title is the input only with payloads
    let t: Vec<TraceSummary> =
        serde_json::from_value(env.get("/traces", "alice").await.body).unwrap();
    assert_eq!(t[0].title, "How many WIDGET-1 are in stock?");
    let t: Vec<TraceSummary> =
        serde_json::from_value(env.get("/traces", "carol").await.body).unwrap();
    assert_eq!(t[0].title, "ops · 6e2d9ff9");
    env.stop().await;
}

#[tokio::test]
async fn agent_views_and_their_cascades() {
    let env = Env::start().await;
    let v = env.create("orders", &orders_yaml()).await;
    let iv = env.create("inventory", &inventory_yaml()).await;
    let r = env
        .get(&format!("/services/{NS}/orders/agents/ops"), "carol")
        .await;
    assert_eq!((r.status, r.etag().as_deref()), (200, Some(v.as_str())));
    let view: AgentView = serde_json::from_value(r.body).unwrap();
    assert_eq!(view.agent["name"], "ops");
    assert_eq!(view.allowed_tools.as_deref().map(<[String]>::len), Some(3));
    assert_eq!(view.callers.as_ref().unwrap()[0].identity, "local");
    assert_eq!(
        env.get(&format!("/services/{NS}/orders/agents/ghost"), "carol")
            .await
            .status,
        404
    );

    // POST without callers joins the local rule (inventory's names agents)
    let r = env
        .call(
            "POST",
            &format!("/services/{NS}/inventory/agents"),
            "bob",
            Some(json!({"agent": {"name": "counter", "model": "mock"}})),
            Some(&iv),
        )
        .await;
    assert_eq!(r.status, 201, "{}", r.text);
    let (_, inv) = env.charter("inventory").await;
    assert_eq!(
        inv["authz"]["callers"][0]["agents"],
        json!(["stock", "counter"])
    );
    // POST of an existing agent, a missing If-Match, a viewer
    let r = env
        .call(
            "POST",
            &format!("/services/{NS}/inventory/agents"),
            "bob",
            Some(json!({"agent": {"name": "counter", "model": "mock"}})),
            Some(&r.version()),
        )
        .await;
    assert_eq!(r.status, 400);
    let r = env
        .call(
            "POST",
            &format!("/services/{NS}/inventory/agents"),
            "bob",
            Some(json!({"agent": {"name": "x2", "model": "mock"}})),
            None,
        )
        .await;
    assert_eq!(r.status, 400);
    let r = env
        .call(
            "POST",
            &format!("/services/{NS}/inventory/agents"),
            "carol",
            Some(json!({"agent": {"name": "x3", "model": "mock"}})),
            Some("2"),
        )
        .await;
    assert_eq!(r.status, 403);

    // DELETE of an agent a local orchestrator calls: in use
    let r = env
        .call(
            "DELETE",
            &format!("/services/{NS}/orders/agents/triage"),
            "bob",
            None,
            Some(&v),
        )
        .await;
    assert_eq!((r.status, r.error()), (409, "in_use"), "{}", r.text);
    assert!(r.details().contains("agents.ops.tools.ask_triage"));
    // PUT ops without that tool: its allowed_tools entry is pruned
    let mut ops = view.clone();
    let tools: Vec<Value> = ops.agent["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| t["name"] != "ask_triage")
        .cloned()
        .collect();
    ops.agent["tools"] = json!(tools);
    let r = env
        .call(
            "PUT",
            &format!("/services/{NS}/orders/agents/ops"),
            "bob",
            Some(serde_json::to_value(&ops).unwrap()),
            Some(&v),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let v = r.version();
    let after: AgentView = serde_json::from_value(
        env.get(&format!("/services/{NS}/orders/agents/ops"), "bob")
            .await
            .body,
    )
    .unwrap();
    assert_eq!(
        after.allowed_tools,
        Some(vec!["lookup_order".to_string(), "ask_stock".to_string()])
    );
    // PUT with another name than the path
    let r = env
        .call(
            "PUT",
            &format!("/services/{NS}/orders/agents/triage"),
            "bob",
            Some(serde_json::to_value(&ops).unwrap()),
            Some(&v),
        )
        .await;
    assert_eq!(r.status, 400);
    // now triage can go; its allowed_* keys and caller entries go with it
    let r = env
        .call(
            "DELETE",
            &format!("/services/{NS}/orders/agents/triage"),
            "bob",
            None,
            Some(&v),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let (_, c) = env.charter("orders").await;
    assert!(
        c["agents"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["name"] != "triage")
    );
    let r = env
        .call(
            "DELETE",
            &format!("/services/{NS}/inventory/agents/counter"),
            "bob",
            None,
            Some("2"),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let (_, inv) = env.charter("inventory").await;
    assert_eq!(inv["authz"]["callers"][0]["agents"], json!(["stock"]));
    // audited per action
    let actions: BTreeSet<String> = audit_lines(&env)
        .iter()
        .map(|l| l["action"].as_str().unwrap().to_string())
        .collect();
    for a in ["agent_post", "agent_put", "agent_delete"] {
        assert!(actions.contains(a), "{a}");
    }
    env.stop().await;
}

#[tokio::test]
async fn skills_are_created_replaced_and_deleted() {
    let env = Env::start().await;
    let v = env.create("orders", &orders_yaml()).await;
    let skill = json!({"name": "tone", "description": "House style.", "instructions": "Be brief."});
    let r = env
        .call(
            "PUT",
            &format!("/services/{NS}/orders/skills/tone"),
            "bob",
            Some(skill.clone()),
            Some(&v),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let v = r.version();
    let r = env
        .call(
            "PUT",
            &format!("/services/{NS}/orders/skills/other"),
            "bob",
            Some(skill.clone()),
            Some(&v),
        )
        .await;
    assert_eq!(r.status, 400, "name differs from the path");
    // an agent uses it: in use
    let mut triage: AgentView = serde_json::from_value(
        env.get(&format!("/services/{NS}/orders/agents/triage"), "bob")
            .await
            .body,
    )
    .unwrap();
    triage.agent["skills"] = json!(["tone"]);
    let r = env
        .call(
            "PUT",
            &format!("/services/{NS}/orders/agents/triage"),
            "bob",
            Some(serde_json::to_value(&triage).unwrap()),
            Some(&v),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let v = r.version();
    let r = env
        .call(
            "DELETE",
            &format!("/services/{NS}/orders/skills/tone"),
            "bob",
            None,
            Some(&v),
        )
        .await;
    assert_eq!((r.status, r.error()), (409, "in_use"));
    triage.agent["skills"] = json!([]);
    let r = env
        .call(
            "PUT",
            &format!("/services/{NS}/orders/agents/triage"),
            "bob",
            Some(serde_json::to_value(&triage).unwrap()),
            Some(&v),
        )
        .await;
    let v = r.version();
    let r = env
        .call(
            "DELETE",
            &format!("/services/{NS}/orders/skills/tone"),
            "bob",
            None,
            Some(&v),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = env
        .call(
            "DELETE",
            &format!("/services/{NS}/orders/skills/tone"),
            "bob",
            None,
            Some(&r.version()),
        )
        .await;
    assert_eq!(r.status, 404);
    env.stop().await;
}

#[tokio::test]
async fn links_within_and_across_services() {
    let env = Env::start().await;
    let ov = env.create("orders", &orders_yaml()).await;
    let iv = env.create("inventory", &inventory_yaml()).await;
    let sv = env.create("support", &support_yaml(false)).await;
    let link = |from: &str, to: &str, tool: &str, if_match: Value| {
        json!({
            "from": format!("agent:{NS}/{from}"), "to": format!("agent:{NS}/{to}"),
            "tool": {"name": tool, "description": "Ask it."}, "if_match": if_match
        })
    };
    // same service: an editor may
    let r = env
        .call(
            "POST",
            "/links",
            "bob",
            Some(link(
                "orders/ops",
                "orders/triage",
                "ask_triage_2",
                json!({format!("{NS}/orders"): ov}),
            )),
            None,
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let res: LinkResult = serde_json::from_value(r.body).unwrap();
    assert_eq!(res.applied.len(), 1);
    assert!(res.failed.is_empty());
    // cross service: the target's authz needs admin
    let req = link(
        "support/helper",
        "inventory/stock",
        "ask_stock",
        json!({format!("{NS}/support"): sv, format!("{NS}/inventory"): iv}),
    );
    let r = env
        .call("POST", "/links", "bob", Some(req.clone()), None)
        .await;
    let res: LinkResult = serde_json::from_value(r.body).unwrap();
    assert!(res.applied.is_empty());
    assert_eq!(
        res.failed[&format!("{NS}/inventory")].error,
        embassy::api::types::ErrorCode::Forbidden
    );
    // an admin, with a stale version for the source: the target applies, the source fails
    let stale = link(
        "support/helper",
        "inventory/stock",
        "ask_stock",
        json!({format!("{NS}/support"): "99", format!("{NS}/inventory"): iv}),
    );
    let r = env.call("POST", "/links", "alice", Some(stale), None).await;
    let res: LinkResult = serde_json::from_value(r.body).unwrap();
    assert_eq!(res.applied[0].service, format!("{NS}/inventory"));
    let fail = &res.failed[&format!("{NS}/support")];
    assert_eq!(
        (fail.error, fail.current_version.as_deref()),
        (
            embassy::api::types::ErrorCode::VersionConflict,
            Some(sv.as_str())
        ),
        "{fail:?}"
    );
    let (iv2, inv) = env.charter("inventory").await;
    assert_eq!(
        inv["authz"]["callers"][2],
        json!({"identity": format!("spiffe://agentsc/ns/{NS}/svc/support"), "agents": ["stock"], "caller_agents": ["helper"]})
    );
    // again with the right versions: the target already admits it, only the source changes
    let ok = link(
        "support/helper",
        "inventory/stock",
        "ask_stock",
        json!({format!("{NS}/support"): sv, format!("{NS}/inventory"): iv2}),
    );
    let r = env.call("POST", "/links", "alice", Some(ok), None).await;
    let res: LinkResult = serde_json::from_value(r.body).unwrap();
    assert_eq!(res.applied.len(), 1, "{res:?}");
    assert_eq!(res.applied[0].service, format!("{NS}/support"));
    let (_, sup) = env.charter("support").await;
    assert_eq!(
        sup["agents"][0]["tools"][0],
        json!({"name": "ask_stock", "description": "Ask it.", "type": "agent", "service": "inventory", "agent": "stock"})
    );
    // only orchestrators call other agents: refused before anything is written
    let r = env
        .call(
            "POST",
            "/links",
            "alice",
            Some(link("orders/triage", "inventory/stock", "x", json!({}))),
            None,
        )
        .await;
    assert_eq!(r.status, 400);
    assert!(r.details().contains("not an orchestrator"), "{}", r.text);
    // cross-namespace and malformed ids are refused
    let r = env
        .call(
            "POST",
            "/links",
            "alice",
            Some(json!({
                "from": format!("agent:{NS}/orders/ops"), "to": "agent:other/x/y",
                "tool": {"name": "t", "description": "d"}, "if_match": {}
            })),
            None,
        )
        .await;
    assert_eq!(r.status, 400);
    assert!(r.details().contains("cross-namespace"));
    let r = env
        .call(
            "POST",
            "/links",
            "alice",
            Some(json!({
                "from": "svc:shop/orders", "to": format!("agent:{NS}/orders/triage"),
                "tool": {"name": "t", "description": "d"}, "if_match": {}
            })),
            None,
        )
        .await;
    assert_eq!(r.status, 400);
    env.stop().await;
}

#[tokio::test]
async fn validate_reports_the_role_and_what_weakens_protection() {
    let env = Env::start().await;
    env.create("orders", &orders_yaml()).await;
    let (_, mut c) = env.charter("orders").await;
    c["guardrails"]["input_deny"] = json!([]);
    c["guardrails"]["pii_redact"] = json!(false);
    let r = env
        .call(
            "POST",
            &format!("/services/{NS}/orders/charter/validate"),
            "bob",
            Some(json!({"yaml": c.to_string()})),
            None,
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let v: ValidateResult = serde_json::from_value(r.body).unwrap();
    assert_eq!(v.needs_role, embassy::config::Role::Admin);
    assert_eq!(
        v.weakened,
        ["guardrails.pii_redact", "guardrails.input_deny[no-secrets]"]
    );
    assert_eq!(v.charter, c);
    // a valid edit an editor may make
    let (_, mut c) = env.charter("orders").await;
    c["agents"][1]["system"] = json!("x");
    let r = env
        .call(
            "POST",
            &format!("/services/{NS}/orders/charter/validate"),
            "bob",
            Some(json!({"yaml": c.to_string()})),
            None,
        )
        .await;
    assert_eq!(r.body["needs_role"], "editor");
    assert_eq!(r.body["weakened"], json!([]));
    // a first charter needs admin; invalid charters are 400; viewers may not validate
    let r = env
        .call(
            "POST",
            &format!("/services/{NS}/inventory/charter/validate"),
            "bob",
            Some(json!({"yaml": inventory_yaml()})),
            None,
        )
        .await;
    assert_eq!(r.body["needs_role"], "admin");
    let r = env
        .call(
            "POST",
            &format!("/services/{NS}/orders/charter/validate"),
            "bob",
            Some(json!({"yaml": "agents: nope"})),
            None,
        )
        .await;
    assert_eq!((r.status, r.error()), (400, "invalid"));
    let r = env
        .call(
            "POST",
            &format!("/services/{NS}/orders/charter/validate"),
            "carol",
            Some(json!({"yaml": inventory_yaml()})),
            None,
        )
        .await;
    assert_eq!(r.status, 403);
    env.stop().await;
}

#[tokio::test]
async fn history_and_rollback() {
    let env = Env::start().await;
    let v1 = env.create("orders", &orders_yaml()).await;
    let (_, mut c) = env.charter("orders").await;
    c["agents"][1]["system"] = json!("second");
    let v2 = put(&env, "bob", "orders", &c, &v1).await.version();
    let r = env
        .get(&format!("/services/{NS}/orders/charter/history"), "carol")
        .await;
    let h: Vec<HistoryEntry> = serde_json::from_value(r.body).unwrap();
    assert_eq!(
        h.iter().map(|e| e.version.as_str()).collect::<Vec<_>>(),
        [v2.as_str(), v1.as_str()]
    );
    assert_eq!((h[0].actor.as_str(), h[1].actor.as_str()), ("bob", "alice"));
    assert_eq!(
        h[1].sha256,
        embassy::store::file::sha256_hex(&orders_yaml())
    );
    let r = env
        .get(
            &format!("/services/{NS}/orders/charter/history/{v1}"),
            "carol",
        )
        .await;
    assert_eq!(r.body["yaml"], orders_yaml());
    assert_eq!(
        env.get(
            &format!("/services/{NS}/orders/charter/history/77"),
            "carol"
        )
        .await
        .status,
        404
    );
    // rollback: a new version with the old text
    let r = env
        .call(
            "POST",
            &format!("/services/{NS}/orders/charter/rollback"),
            "alice",
            Some(json!({"version": v1})),
            Some(&v2),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.version(), "3");
    let doc: CharterDoc = serde_json::from_value(
        env.get(&format!("/services/{NS}/orders/charter"), "alice")
            .await
            .body,
    )
    .unwrap();
    assert_eq!(doc.yaml, orders_yaml());
    let r = env
        .call(
            "POST",
            &format!("/services/{NS}/orders/charter/rollback"),
            "alice",
            Some(json!({"version": "42"})),
            Some("3"),
        )
        .await;
    assert_eq!(r.status, 404);
    assert!(
        audit_lines(&env)
            .iter()
            .any(|l| l["action"] == "rollback" && l["to_version"] == "3")
    );
    // deleting the service; a new charter gets a new epoch and the next version
    let epoch = doc.epoch.clone();
    let r = env
        .call(
            "DELETE",
            &format!("/services/{NS}/orders"),
            "alice",
            None,
            Some("2"),
        )
        .await;
    assert_eq!(r.status, 409);
    let r = env
        .call(
            "DELETE",
            &format!("/services/{NS}/orders"),
            "alice",
            None,
            Some("3"),
        )
        .await;
    assert_eq!(r.status, 204);
    assert_eq!(
        env.get(&format!("/services/{NS}/orders/charter"), "alice")
            .await
            .status,
        404
    );
    assert_eq!(env.create("orders", &orders_yaml()).await, "4");
    let doc: CharterDoc = serde_json::from_value(
        env.get(&format!("/services/{NS}/orders/charter"), "alice")
            .await
            .body,
    )
    .unwrap();
    assert_ne!(doc.epoch, epoch);
    env.stop().await;
}

#[tokio::test]
async fn memory_exists_only_for_agents_that_learn() {
    let env = Env::start().await;
    let v = env.create("support", &support_yaml(true)).await;
    let path = format!("/services/{NS}/support/memory");
    let r = env.get(&path, "carol").await;
    assert_eq!((r.status, r.etag().as_deref()), (200, Some("0")));
    assert_eq!(r.body, json!({"version": "0", "agents": {}}));
    let put_mem = |body: Value, v: &str| {
        let v = v.to_string();
        let path = path.clone();
        let env = &env;
        async move { env.call("PUT", &path, "bob", Some(body), Some(&v)).await }
    };
    let r = put_mem(
        json!({"agents": {"helper": [{"text": "Check the order first."}]}}),
        "0",
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.version(), "1");
    let m: MemoryDoc = serde_json::from_value(env.get(&path, "bob").await.body).unwrap();
    let note = &m.agents["helper"][0];
    assert_eq!(
        (note.approved_by.as_deref(), note.request_id.as_deref()),
        (Some("bob"), None)
    );
    uuid::Uuid::parse_str(&note.id).unwrap();
    // refused: an agent without learning, an unknown agent, too long, too many, a stale version
    for (body, want) in [
        (
            json!({"agents": {"faq": [{"text": "x"}]}}),
            "learning is not enabled for faq",
        ),
        (
            json!({"agents": {"ghost": [{"text": "x"}]}}),
            "no agent ghost",
        ),
        (
            json!({"agents": {"helper": [{"text": "x".repeat(61)}]}}),
            "max_note_chars is 60",
        ),
        (
            json!({"agents": {"helper": [{"text": "a"}, {"text": "b"}, {"text": "c"}]}}),
            "max_notes is 2",
        ),
        (
            json!({"agents": {"helper": [{"id": "n", "text": "x", "source": "manual", "request_id": null, "trace_id": null, "approved_by": "mallory", "ts": "2026-10-21T10:00:00.000Z", "expires_at": null}]}}),
            "has no stored note",
        ),
    ] {
        let r = put_mem(body, "1").await;
        assert_eq!(
            (r.status, r.error()),
            (400, "invalid"),
            "{want}: {}",
            r.text
        );
        assert!(r.details().contains(want), "{want}: {}", r.details());
    }
    let r = put_mem(json!({"agents": {}}), "0").await;
    assert_eq!(
        (r.status, r.body["current_version"].as_str()),
        (409, Some("1"))
    );
    let r = env
        .call(
            "PUT",
            &path,
            "carol",
            Some(json!({"agents": {}})),
            Some("1"),
        )
        .await;
    assert_eq!(r.status, 403);
    // turning learning off drops the agent's notes in the same change
    let (_, mut c) = env.charter("support").await;
    c["agents"][0]["learning"]["enabled"] = json!(false);
    let r = put(&env, "bob", "support", &c, &v).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let m: MemoryDoc = serde_json::from_value(env.get(&path, "bob").await.body).unwrap();
    assert_eq!(m.version, "2");
    assert!(m.agents.is_empty());
    // no charter, no memory
    assert_eq!(
        env.get(&format!("/services/{NS}/nothing/memory"), "bob")
            .await
            .status,
        404
    );
    assert!(
        audit_lines(&env)
            .iter()
            .any(|l| l["action"] == "memory_put" && l["result"] == "ok")
    );
    env.stop().await;
}

async fn propose(env: &Env, note: &str, dedup: &str) {
    let actor = embassy::controlplane::sidecar_actor(
        &agentsc_common::identity::SpiffeId {
            namespace: NS.into(),
            service: "support".into(),
        },
        "support-0",
    );
    embassy::controlplane::ingest_proposal(
        &env.hub,
        &embassy::store::ServiceKey::new(NS, "support"),
        &actor,
        agentsc_proto::LearningProposal {
            dedup_key: dedup.into(),
            agent: "helper".into(),
            note: note.into(),
            rationale: "it helped".into(),
            request_id: "0c4a3f8e-1111-4222-8333-444455556666".into(),
            trace_id: "6e2d9ff960031afca28de8fa28704004".into(),
            auto: false,
        },
    )
    .await;
}

#[tokio::test]
async fn proposals_are_decided_once() {
    let env = Env::start().await;
    env.create("support", &support_yaml(true)).await;
    propose(&env, "Read the ticket first.", "k1").await;
    propose(&env, "Read the ticket first.", "k1").await; // deduplicated
    propose(&env, "Second lesson.", "k2").await;
    let r = env.get("/proposals?status=pending", "carol").await;
    let list: Vec<Proposal> = serde_json::from_value(r.body).unwrap();
    assert_eq!(list.len(), 2);
    assert!(list[0].ts >= list[1].ts, "newest first");
    assert_eq!(
        env.get("/proposals?status=bogus", "carol").await.status,
        400
    );
    assert_eq!(
        env.get(&format!("/proposals?namespace={NS}&service=other"), "carol")
            .await
            .body,
        json!([])
    );
    assert_eq!(env.get("/proposals", "dave").await.body, json!([]));
    let id = list
        .iter()
        .find(|p| p.note == "Read the ticket first.")
        .unwrap()
        .id
        .clone();
    // approve and reject race: exactly one wins, the other learns why
    let (pa, pb) = (
        format!("/proposals/{id}/approve"),
        format!("/proposals/{id}/reject"),
    );
    let a = env.call("POST", &pa, "bob", None, Some("0"));
    let b = env.call("POST", &pb, "bob", None, Some("0"));
    let (a, b) = tokio::join!(a, b);
    let statuses = [a.status, b.status];
    assert!(
        statuses.contains(&200) && statuses.contains(&409),
        "{statuses:?} {} {}",
        a.text,
        b.text
    );
    let lost = if a.status == 409 { &a } else { &b };
    assert_eq!(lost.error(), "not_pending", "{}", lost.text);
    let won = if a.status == 200 { &a } else { &b };
    let d: ProposalDecision = serde_json::from_value(won.body.clone()).unwrap();
    let m: MemoryDoc = serde_json::from_value(
        env.get(&format!("/services/{NS}/support/memory"), "bob")
            .await
            .body,
    )
    .unwrap();
    if a.status == 200 {
        assert_eq!(d.memory_version, "1");
        assert_eq!(m.agents["helper"][0].approved_by.as_deref(), Some("bob"));
    } else {
        assert_eq!(d.memory_version, "0");
        assert!(m.agents.is_empty());
    }
    // the other one: a stale memory version is a conflict, an unknown id 404, viewers 403
    let other = list.iter().find(|p| p.id != id).unwrap().id.clone();
    let r = env
        .call(
            "POST",
            &format!("/proposals/{other}/approve"),
            "bob",
            None,
            Some("77"),
        )
        .await;
    assert_eq!((r.status, r.error()), (409, "version_conflict"));
    assert_eq!(
        env.call("POST", "/proposals/nope/approve", "bob", None, Some("0"))
            .await
            .status,
        404
    );
    assert_eq!(
        env.call(
            "POST",
            &format!("/proposals/{other}/reject"),
            "carol",
            None,
            Some("0")
        )
        .await
        .status,
        403
    );
    assert_eq!(
        env.call(
            "POST",
            &format!("/proposals/{other}/reject"),
            "dave",
            None,
            Some("0")
        )
        .await
        .status,
        404
    );
    assert_eq!(
        env.call(
            "POST",
            &format!("/proposals/{other}/reject"),
            "bob",
            None,
            None
        )
        .await
        .status,
        400
    );
    env.stop().await;
}

#[tokio::test]
async fn recent_events_filter_and_order() {
    let env = Env::start().await;
    env.create("orders", &orders_yaml()).await;
    env.create("inventory", &inventory_yaml()).await;
    let ts = "2026-10-21T10:00:00.000Z";
    env.ingest(rec("tool_call", json!({"ts": ts, "span_id": "1111111111111111", "callee": "ask_stock", "direction": "internal"})));
    env.ingest(rec("agent_call", json!({"ts": ts, "span_id": "2222222222222222", "parent_span_id": "1111111111111111", "callee": "inventory/stock", "direction": "outbound"})));
    env.ingest(rec("agent_invocation", json!({"ts": "2026-10-21T10:00:01.000Z", "service": "inventory", "agent": "stock", "caller": "spiffe://agentsc/ns/shop/svc/orders", "caller_agent": "ops", "trace_id": "ffffffffffffffffffffffffffffffff", "request_id": "r2"})));
    let all = env.get("/events/recent", "alice").await.body;
    let kinds: Vec<&str> = all
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["kind"].as_str().unwrap())
        .collect();
    // newest first; equal timestamps in reverse arrival order
    assert_eq!(kinds, ["agent_invocation", "agent_call", "tool_call"]);
    let records: Vec<AuditRecord> = serde_json::from_value(all).unwrap();
    assert_eq!(records.len(), 3);
    for (q, n) in [
        ("limit=1", 1),
        ("service=inventory", 1),
        (&format!("namespace={NS}") as &str, 3),
        ("namespace=other", 0),
        ("agent=ops", 3), // agent or caller_agent
        ("agent=stock", 1),
        ("trace_id=ffffffffffffffffffffffffffffffff", 1),
        ("request_id=r2", 1),
        ("kind=tool_call", 1),
        ("kind=agent_call&service=orders", 1),
    ] {
        let r = env.get(&format!("/events/recent?{q}"), "alice").await;
        assert_eq!(r.body.as_array().map(Vec::len), Some(n), "{q}: {}", r.text);
    }
    for bad in ["limit=0", "limit=1001", "limit=x"] {
        assert_eq!(
            env.get(&format!("/events/recent?{bad}"), "alice")
                .await
                .status,
            400,
            "{bad}"
        );
    }
    env.stop().await;
}

fn node<'a>(g: &'a Graph, id: &str) -> &'a Node {
    g.nodes
        .iter()
        .find(|n| n.id() == id)
        .unwrap_or_else(|| panic!("no node {id}"))
}

#[tokio::test]
async fn the_graph_follows_the_charters_and_the_mapping_table() {
    let env = Env::start().await;
    env.create("orders", &orders_yaml()).await;
    let g0: Graph = serde_json::from_value(env.get("/graph", "alice").await.body).unwrap();
    // declared: invoke edges (local "*"), tool edges, model edges; placeholders for the
    // unknown inventory peer
    let ids: BTreeSet<&str> = g0.edges.iter().map(|e| e.id.as_str()).collect();
    for want in [
        "edge:invoke:app:shop/orders->agent:shop/orders/ops",
        "edge:invoke:app:shop/orders->agent:shop/orders/triage",
        "edge:tool:agent:shop/orders/ops->app:shop/orders#lookup_order",
        "edge:tool:agent:shop/orders/ops->agent:shop/inventory/stock#ask_stock",
        "edge:tool:agent:shop/orders/ops->agent:shop/orders/triage#ask_triage",
        "edge:model:agent:shop/orders/ops->model:mock",
        "edge:model:agent:shop/orders/triage->model:anthropic",
    ] {
        assert!(ids.contains(want), "missing {want} in {ids:?}");
    }
    assert!(g0.edges.iter().all(|e| e.declared));
    assert!(matches!(
        node(&g0, "agent:shop/inventory/stock"),
        Node::Placeholder(_)
    ));
    assert!(matches!(
        node(&g0, "svc:shop/inventory"),
        Node::Placeholder(_)
    ));
    let Node::App(app) = node(&g0, "app:shop/orders") else {
        panic!()
    };
    assert_eq!(
        (app.port, app.ports.inputs.as_slice()),
        (Some(8080), &["service".to_string()][..])
    );
    let Node::Service(s) = node(&g0, "svc:shop/orders") else {
        panic!()
    };
    assert_eq!(s.status, embassy::api::types::ServiceStatus::Disconnected);

    // records → stats
    env.ingest(rec("agent_invocation", json!({"latency_ms": 500})));
    env.ingest(rec("agent_invocation", json!({"caller_agent": "ops", "agent": "triage", "callee": "triage", "span_id": "3333333333333333", "latency_ms": 50, "error": "boom"})));
    env.ingest(rec(
        "tool_call",
        json!({"span_id": "1111111111111111", "callee": "lookup_order", "direction": "internal"}),
    ));
    env.ingest(rec("service_call", json!({"span_id": "2222222222222222", "parent_span_id": "1111111111111111", "callee": "orders GET /orders/1", "direction": "internal", "latency_ms": 30})));
    env.ingest(rec("model_call", json!({"span_id": "4444444444444444", "callee": "mock", "direction": "outbound", "tokens": {"input": 10, "output": 5}, "cost_usd": 0.25})));
    env.ingest(rec(
        "tool_call",
        json!({"span_id": "5555555555555555", "callee": "eta", "direction": "internal"}),
    ));
    env.ingest(rec("http_call", json!({"span_id": "6666666666666666", "parent_span_id": "5555555555555555", "callee": "GET https://api.partner.example/eta", "direction": "outbound", "decision": "deny"})));
    env.ingest(rec("service_call", json!({"agent": "boss", "caller": "spiffe://agentsc/ns/shop/svc/billing", "caller_agent": "boss", "callee": "orders POST /refund", "direction": "inbound", "latency_ms": 7})));
    let g: Graph = serde_json::from_value(env.get("/graph", "alice").await.body).unwrap();
    assert!(g.version.parse::<u64>().unwrap() > g0.version.parse::<u64>().unwrap());
    let Node::Agent(ops) = node(&g, "agent:shop/orders/ops") else {
        panic!()
    };
    assert_eq!((ops.stats.invocations, ops.stats.p50_ms), (1, 500));
    assert_eq!((ops.stats.tokens_in, ops.stats.tokens_out), (10, 5));
    assert_eq!(ops.status, embassy::api::types::AgentStatus::Ok);
    let Node::Agent(triage) = node(&g, "agent:shop/orders/triage") else {
        panic!()
    };
    assert_eq!((triage.stats.invocations, triage.stats.errors), (1, 1));
    assert_eq!(triage.status, embassy::api::types::AgentStatus::Errors);
    let edge = |id: &str| {
        g.edges
            .iter()
            .find(|e| e.id == id)
            .unwrap_or_else(|| panic!("no edge {id}"))
    };
    assert_eq!(
        edge("edge:invoke:app:shop/orders->agent:shop/orders/ops")
            .stats
            .calls,
        1
    );
    assert_eq!(
        edge("edge:invoke:app:shop/orders->agent:shop/orders/triage")
            .stats
            .calls,
        0,
        "a local orchestrator's call does not use the invoke edge"
    );
    let lookup = edge("edge:tool:agent:shop/orders/ops->app:shop/orders#lookup_order");
    assert_eq!((lookup.stats.calls, lookup.stats.avg_ms), (1, 30));
    assert_eq!(
        edge("edge:model:agent:shop/orders/ops->model:mock")
            .stats
            .calls,
        1
    );
    // the http call: an undeclared edge to a new external node
    let eta = edge("edge:tool:agent:shop/orders/ops->external:https://api.partner.example#eta");
    assert!(!eta.declared);
    assert_eq!((eta.stats.calls, eta.stats.denied), (1, 1));
    let Node::External(ext) = node(&g, "external:https://api.partner.example") else {
        panic!()
    };
    assert_eq!(ext.label, "api.partner.example");
    // inbound service call: the app's stats
    let Node::App(app) = node(&g, "app:shop/orders") else {
        panic!()
    };
    assert_eq!((app.stats.calls, app.stats.avg_ms), (1, 7));
    // every endpoint is a node
    let nodes: BTreeSet<&str> = g.nodes.iter().map(Node::id).collect();
    for e in &g.edges {
        assert!(
            nodes.contains(e.source.as_str()) && nodes.contains(e.target.as_str()),
            "{}",
            e.id
        );
    }
    env.stop().await;
}

#[tokio::test]
async fn traces_come_from_span_starts_and_audit_records() {
    let env = Env::start().await;
    env.create("orders", &orders_yaml()).await;
    let key = embassy::store::ServiceKey::new(NS, "orders");
    let start =
        |span: &str, kind: &str, ts: &str, callee: &str, parent: &str| agentsc_proto::SpanStart {
            request_id: "q".into(),
            trace_id: "6e2d9ff960031afca28de8fa28704004".into(),
            span_id: span.into(),
            parent_span_id: parent.into(),
            kind: kind.into(),
            agent: "ops".into(),
            caller: "local".into(),
            caller_agent: String::new(),
            callee: callee.into(),
            direction: "outbound".into(),
            ts: ts.into(),
        };
    let t0 = chrono::Utc::now() - chrono::Duration::seconds(30);
    let at = |s: i64| embassy::traces::fmt_ts(t0 + chrono::Duration::seconds(s));
    embassy::controlplane::ingest_span_start(
        &env.hub,
        &key,
        start("aaaaaaaaaaaaaaaa", "agent_invocation", &at(0), "ops", ""),
    );
    env.ingest(rec("model_call", json!({"ts": at(2), "latency_ms": 2000, "span_id": "bbbbbbbbbbbbbbbb", "parent_span_id": "aaaaaaaaaaaaaaaa", "callee": "mock", "direction": "outbound", "input": {"attempt": 1}, "error": "overloaded"})));
    env.ingest(rec("model_call", json!({"ts": at(4), "latency_ms": 1000, "span_id": "cccccccccccccccc", "parent_span_id": "aaaaaaaaaaaaaaaa", "callee": "mock", "direction": "outbound", "input": {"attempt": 2, "fallback": true}, "tokens": {"input": 7, "output": 3}})));
    env.ingest(rec("tool_call", json!({"ts": at(6), "latency_ms": 1500, "span_id": "dddddddddddddddd", "parent_span_id": "aaaaaaaaaaaaaaaa", "callee": "ask_triage", "direction": "internal"})));
    embassy::controlplane::ingest_span_start(
        &env.hub,
        &key,
        start(
            "eeeeeeeeeeeeeeee",
            "agent_call",
            &at(5),
            "triage",
            "dddddddddddddddd",
        ),
    );
    let list: Vec<TraceSummary> =
        serde_json::from_value(env.get("/traces", "alice").await.body).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].status, embassy::api::types::SpanStatus::Running);
    assert_eq!(list[0].root_agent, "agent:shop/orders/ops");
    assert_eq!(list[0].model_calls, 2);
    assert_eq!(
        env.get("/traces?status=running", "alice")
            .await
            .body
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(env.get("/traces?status=ok", "alice").await.body, json!([]));
    assert_eq!(env.get("/traces?status=bogus", "alice").await.status, 400);
    let r = env
        .get("/traces/6e2d9ff960031afca28de8fa28704004", "carol")
        .await;
    let doc: TraceDoc = serde_json::from_value(r.body).unwrap();
    let span = |id: &str| doc.spans.iter().find(|s| s.span_id == id).unwrap();
    use embassy::api::types::Segment;
    assert_eq!(
        (
            span("aaaaaaaaaaaaaaaa").segment,
            span("aaaaaaaaaaaaaaaa").end.as_deref()
        ),
        (Segment::Invocation, None)
    );
    assert_eq!(
        (
            span("bbbbbbbbbbbbbbbb").segment,
            span("bbbbbbbbbbbbbbbb").attempt,
            span("bbbbbbbbbbbbbbbb").call_index
        ),
        (Segment::Thinking, 1, 1)
    );
    let c = span("cccccccccccccccc");
    assert_eq!(
        (c.attempt, c.fallback, c.call_index, c.tokens_in),
        (2, true, 2, 7)
    );
    assert_eq!(span("bbbbbbbbbbbbbbbb").start, at(0));
    assert_eq!(span("dddddddddddddddd").segment, Segment::Tool);
    assert_eq!(span("eeeeeeeeeeeeeeee").segment, Segment::Waiting);
    assert_eq!(
        span("eeeeeeeeeeeeeeee").callee_node.as_deref(),
        Some("agent:shop/orders/triage")
    );
    // the invocation ends
    env.ingest(rec(
        "agent_invocation",
        json!({"ts": at(10), "latency_ms": 10_000, "span_id": "aaaaaaaaaaaaaaaa"}),
    ));
    let list: Vec<TraceSummary> =
        serde_json::from_value(env.get("/traces", "alice").await.body).unwrap();
    assert_eq!(
        (list[0].status, list[0].duration_ms),
        (embassy::api::types::SpanStatus::Ok, Some(10_000))
    );
    assert_eq!(env.get("/traces/0000", "alice").await.status, 404);
    assert_eq!(
        env.get("/traces/6e2d9ff960031afca28de8fa28704004", "dave")
            .await
            .status,
        404
    );
    env.stop().await;
}

#[tokio::test]
async fn services_list_charters_and_instances() {
    let env = Env::start().await;
    env.create("orders", &orders_yaml()).await;
    let list: Vec<ServiceSummary> =
        serde_json::from_value(env.get("/services", "carol").await.body).unwrap();
    assert_eq!(list.len(), 1);
    let s = &list[0];
    assert_eq!(
        (
            s.status,
            s.charter_version.as_deref(),
            s.memory_version.as_deref()
        ),
        (
            embassy::api::types::ServiceStatus::Disconnected,
            Some("1"),
            Some("0")
        )
    );
    uuid::Uuid::parse_str(s.epoch.as_deref().unwrap()).unwrap();
    assert!(s.pending_adoption.is_none() && s.instances.is_empty());
    env.stop().await;
}

#[tokio::test]
async fn the_dev_anonymous_viewer() {
    let env = Env::start_with(Opts {
        dev_anonymous: true,
        ..Default::default()
    })
    .await;
    let r = Env::send(env.req("GET", "/api/v1/whoami", None)).await;
    assert_eq!(r.status, 200);
    assert_eq!(
        r.body,
        json!({"name": "anonymous", "role": "viewer", "namespaces": ["*"], "payloads": false})
    );
    let r = Env::send(
        env.req(
            "PUT",
            &format!("/api/v1/services/{NS}/orders/charter"),
            None,
        )
        .header("If-None-Match", "*")
        .body(json!({"yaml": orders_yaml()}).to_string()),
    )
    .await;
    assert_eq!(r.status, 403);
    env.stop().await;
}

#[tokio::test]
async fn over_tls_the_session_cookie_is_secure() {
    let env = Env::start_with(Opts {
        http_tls: true,
        ..Default::default()
    })
    .await;
    let r = Env::send(
        env.req("POST", "/api/v1/login", None)
            .body(json!({"token": env.token("alice")}).to_string()),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert!(
        r.headers["set-cookie"]
            .to_str()
            .unwrap()
            .ends_with("; Secure")
    );
    assert_secure(&r);
    env.stop().await;
}

fn round_trip<T: DeserializeOwned + Serialize>(what: &str, v: Value) {
    let t: T = serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{what}: {e}\n{v}"));
    assert_eq!(
        serde_json::to_value(&t).unwrap(),
        v,
        "{what} changed in the round trip"
    );
}

/// Every response has the shape of `ui/fixtures` (the API types the fixtures round-trip
/// through), and round-trips through them unchanged.
#[tokio::test]
async fn responses_round_trip_through_the_api_types() {
    let env = Env::start().await;
    let ov = env.create("orders", &orders_yaml()).await;
    env.create("support", &support_yaml(true)).await;
    propose(&env, "A lesson.", "k").await;
    env.ingest(rec(
        "agent_invocation",
        json!({"tokens": {"input": 1, "output": 2}}),
    ));
    let get = |p: &str| {
        let p = p.to_string();
        let env = &env;
        async move { env.get(&p, "alice").await.body }
    };
    round_trip::<WhoAmI>("whoami", get("/whoami").await);
    round_trip::<Graph>("graph", get("/graph").await);
    round_trip::<Vec<ServiceSummary>>("services", get("/services").await);
    round_trip::<CharterDoc>(
        "charter",
        get(&format!("/services/{NS}/orders/charter")).await,
    );
    round_trip::<AgentView>(
        "agent",
        get(&format!("/services/{NS}/orders/agents/ops")).await,
    );
    round_trip::<MemoryDoc>(
        "memory",
        get(&format!("/services/{NS}/support/memory")).await,
    );
    round_trip::<Vec<Proposal>>("proposals", get("/proposals").await);
    round_trip::<Vec<AuditRecord>>("recent", get("/events/recent").await);
    round_trip::<Vec<HistoryEntry>>(
        "history",
        get(&format!("/services/{NS}/orders/charter/history")).await,
    );
    round_trip::<Vec<TraceSummary>>("traces", get("/traces").await);
    round_trip::<TraceDoc>(
        "trace",
        get("/traces/6e2d9ff960031afca28de8fa28704004").await,
    );
    let r = env
        .call(
            "POST",
            &format!("/services/{NS}/orders/charter/validate"),
            "alice",
            Some(json!({"yaml": orders_yaml()})),
            None,
        )
        .await;
    round_trip::<ValidateResult>("validate", r.body);
    let r = env.call("POST", "/links", "alice", Some(json!({
        "from": format!("agent:{NS}/orders/ops"), "to": format!("agent:{NS}/orders/triage"),
        "tool": {"name": "ask_again", "description": "d"}, "if_match": {format!("{NS}/orders"): ov}
    })), None).await;
    round_trip::<LinkResult>("links", r.body);
    let r = env
        .call(
            "PUT",
            &format!("/services/{NS}/support/memory"),
            "alice",
            Some(json!({"agents": {}})),
            Some("0"),
        )
        .await;
    round_trip::<embassy::api::types::VersionResult>("memory put", r.body);
    let r = env.get("/services/x/y/charter", "alice").await;
    round_trip::<embassy::api::types::ApiError>("error", r.body);
    env.stop().await;
}
