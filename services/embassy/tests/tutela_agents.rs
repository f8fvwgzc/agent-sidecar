//! Agents as principals of a real `tutelad` v0.2.0 on a real PostgreSQL (#24, crate::tutela,
//! docs/adr/0005-agents-in-tutelad.md): embassy registers the registry's agents through
//! `tutela.admin.v1` as its app (`client_credentials`, only `org:manage_agents`), disables them on
//! quarantine and retirement so their tokens stop, and enables them again on release. A wrong app
//! and another tenant are refused, and a `tutelad` that is down holds nothing up but the actions
//! that need it.
//!
//! Needs `ATTACHE_TUTELAD_BIN` and a PostgreSQL (tests/tutelad/mod.rs); without them each test
//! says so and passes, unless `ATTACHE_REQUIRE_TUTELAD=1`.
mod common;
mod tutelad;

use std::time::Duration;

use common::{Env, NS, Opts, orders_yaml};
use embassy::tutela::client::{Error, Exchange};
use serde_json::{Value, json};
use tutelad::Tutelad;

/// Start embassy on a port chosen first (the trust file names its agent-token issuer), as tenant
/// A's app `attache`, signing agent tokens.
async fn embassy(t: &Tutelad, port: u16) -> Env {
    let key = t.dir.path().join("agent-key.pem");
    if !key.exists() {
        std::fs::write(&key, embassy::tutela::agent_token::generate_pem().unwrap()).unwrap();
    }
    let mut cfg = t.config(&t.a.attache);
    cfg.agent_tokens = Some(embassy::config::AgentTokensConfig {
        issuer: t.embassy_iss.clone(),
        key_file: key,
    });
    Env::start_with(Opts {
        tutela: Some(cfg),
        http_addr: Some(format!("127.0.0.1:{port}")),
        ..Opts::default()
    })
    .await
}

/// The registry entry of agent `name` of `orders`.
async fn agent(env: &Env, name: &str) -> Value {
    let r = env
        .get(&format!("/agents?namespace={NS}&service=orders"), "alice")
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    r.body
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == name)
        .cloned()
        .unwrap_or_else(|| panic!("no agent {name}: {}", r.text))
}

/// Wait until `check` holds for agent `name`'s entry, at most 15 s.
async fn until(env: &Env, name: &str, what: &str, check: impl Fn(&Value) -> bool) -> Value {
    let start = std::time::Instant::now();
    loop {
        let a = agent(env, name).await;
        if check(&a) {
            return a;
        }
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "agent {name} never got {what}: {a}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn tutela_principal(a: &Value) -> String {
    a["tutela"]["principal"].as_str().unwrap().to_string()
}

/// The charter of `orders` with a third agent, `billing`.
fn with_billing() -> String {
    orders_yaml().replace(
        "guardrails:",
        "  - name: billing\n    model: mock\nguardrails:",
    )
}

/// A delegated token for `audience`: the person's `tutelad` token as the subject, `actor` as the
/// actor, asked by embassy's app.
async fn delegate(
    env: &Env,
    person: &str,
    actor: &str,
    audience: &str,
) -> Result<embassy::tutela::client::Issued, Error> {
    let conn = env.hub.tutela.connection().unwrap();
    conn.client
        .exchange(&Exchange {
            subject_token: person,
            audience,
            actor_token: Some(actor),
            cap: Some(r#"{"tools":["lookup_order"]}"#),
            run_id: Some("run-1"),
            node_id: None,
        })
        .await
}

fn invalid_grant(r: Result<embassy::tutela::client::Issued, Error>) {
    match r {
        Err(e) => assert_eq!(e.code(), Some("invalid_grant"), "{e}"),
        Ok(_) => panic!("a token was issued"),
    }
}

#[tokio::test]
async fn agents_are_registered_disabled_on_quarantine_and_enabled_on_release() {
    let port = tutelad::free_port();
    let Some(t) = Tutelad::start(port).await else {
        return;
    };
    let env = embassy(&t, port).await;
    env.create("orders", &with_billing()).await;

    // every agent of the service gets its own principal in tutelad, made by tutelad
    let ops = until(&env, "ops", "a tutela principal", |a| {
        a["tutela"].is_object()
    })
    .await;
    let triage = until(&env, "triage", "a tutela principal", |a| {
        a["tutela"].is_object()
    })
    .await;
    let (p_ops, p_triage) = (tutela_principal(&ops), tutela_principal(&triage));
    assert_ne!(
        p_ops, p_triage,
        "two agents of one workload are two principals"
    );
    assert_ne!(p_ops, ops["principal"].as_str().unwrap());
    assert!(p_ops.starts_with("agent:agt_"), "{p_ops}");
    assert_eq!(ops["tutela"]["disabled"], false);
    let conn = env.hub.tutela.connection().unwrap();
    let state = conn.client.principal_state(&p_ops).await.unwrap();
    assert!(!state.disabled);
    assert_eq!(state.epoch, 0);

    // embassy publishes the key of its agents' tokens, and tutelad takes one as the actor
    let r = env
        .http
        .get(format!("{}/.well-known/agent-jwks.json", env.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let person = t.person_token("carla").await;
    let ops_id = ops["id"].as_str().unwrap().to_string();
    let actor = embassy::tutela::agent_token(&env.hub, &ops_id)
        .await
        .unwrap();
    let issued = delegate(&env, &person, &actor, "tutela-authz")
        .await
        .unwrap();
    let c = tutelad::claims(&issued.access_token);
    assert_eq!(c["act"]["sub"], p_ops.as_str());
    assert_eq!(c["azp"], conn.client.credentials().client_id.as_str());
    t.until_whoami(&issued.access_token, 200).await;

    // quarantine: tutelad disables the agent, its delegated token stops, no token is signed or
    // exchanged for it any more
    let r = env
        .call(
            "POST",
            &format!("/agents/{ops_id}/quarantine"),
            "alice",
            Some(json!({"reason": "test"})),
            None,
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let ops = until(&env, "ops", "disabled in tutelad", |a| {
        a["tutela"]["disabled"] == true
    })
    .await;
    assert!(ops["tutela"]["epoch"].as_u64().unwrap() >= 1);
    assert!(conn.client.principal_state(&p_ops).await.unwrap().disabled);
    t.until_whoami(&issued.access_token, 401).await;
    assert!(matches!(
        embassy::tutela::agent_token(&env.hub, &ops_id).await,
        Err(embassy::tutela::TokenRefusal::Quarantined)
    ));
    invalid_grant(delegate(&env, &person, &actor, "tutela-authz").await);

    // release: enabled again with the raised epoch; the old agent token stays refused, a new one
    // (with the new epoch) works
    let r = env
        .call(
            "POST",
            &format!("/agents/{ops_id}/release"),
            "alice",
            None,
            None,
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let ops = until(&env, "ops", "enabled in tutelad", |a| {
        a["tutela"]["disabled"] == false
    })
    .await;
    let epoch = ops["tutela"]["epoch"].as_u64().unwrap();
    assert!(epoch >= 1);
    invalid_grant(delegate(&env, &person, &actor, "tutela-authz").await);
    let fresh = embassy::tutela::agent_token(&env.hub, &ops_id)
        .await
        .unwrap();
    assert_eq!(tutelad::claims(&fresh)["epoch"], epoch);
    let again = delegate(&env, &person, &fresh, "tutela-authz")
        .await
        .unwrap();
    t.until_whoami(&again.access_token, 200).await;

    // revoke the agent's tokens without a quarantine: the epoch goes up, it stays enabled
    let r = env
        .call(
            "POST",
            &format!("/agents/{ops_id}/revoke-tokens"),
            "alice",
            None,
            None,
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert!(r.body["tutela"]["epoch"].as_u64().unwrap() > epoch);
    assert_eq!(r.body["tutela"]["disabled"], false);
    invalid_grant(delegate(&env, &person, &fresh, "tutela-authz").await);
    let r = env
        .call(
            "POST",
            &format!("/agents/{ops_id}/revoke-tokens"),
            "bob",
            None,
            None,
        )
        .await;
    assert_eq!(r.status, 403, "an editor may not: {}", r.text);

    // retire: billing leaves the charter and is disabled in tutelad
    let billing = agent(&env, "billing").await;
    let (version, _) = env.charter("orders").await;
    let r = env
        .call(
            "PUT",
            &format!("/services/{NS}/orders/charter"),
            "alice",
            Some(json!({"yaml": orders_yaml()})),
            Some(&version),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    until(&env, "billing", "disabled in tutelad", |a| {
        a["status"] == "retired" && a["tutela"]["disabled"] == true
    })
    .await;
    assert!(
        conn.client
            .principal_state(&tutela_principal(&billing))
            .await
            .unwrap()
            .disabled
    );
    env.stop().await;
    t.finish().await;
}

#[tokio::test]
async fn a_wrong_app_and_another_tenants_agent_are_refused() {
    let port = tutelad::free_port();
    let Some(t) = Tutelad::start(port).await else {
        return;
    };
    let env = embassy(&t, port).await;
    env.create("orders", &orders_yaml()).await;
    let ops = until(&env, "ops", "a tutela principal", |a| {
        a["tutela"].is_object()
    })
    .await;
    let p_ops = tutela_principal(&ops);

    // an app without manage_agents may not register or disable agents
    let client = |creds: &std::path::Path| {
        let cfg = t.config(creds);
        embassy::tutela::client::Client::new(
            &cfg,
            embassy::tutela::Credentials::read(creds).unwrap(),
        )
        .unwrap()
    };
    let other = client(&t.a.other);
    let e = other.register_agent().await.unwrap_err();
    assert_eq!(
        (e.status(), e.code()),
        (Some(403), Some("forbidden")),
        "{e}"
    );
    let e = other.set_disabled(&p_ops, true).await.unwrap_err();
    assert_eq!(e.status(), Some(403), "{e}");

    // a wrong secret is not the app
    let bad = t.dir.path().join("bad-secret.json");
    let mut creds: Value =
        serde_json::from_str(&std::fs::read_to_string(&t.a.attache).unwrap()).unwrap();
    creds["client_secret"] = json!("tut_sk_not_the_secret");
    std::fs::write(&bad, creds.to_string()).unwrap();
    let e = client(&bad).service_token().await.unwrap_err();
    assert_eq!(
        (e.status(), e.code()),
        (Some(401), Some("invalid_client")),
        "{e}"
    );

    // tenant B's attache app finds no agent of tenant A
    let b = client(&t.b.attache);
    let e = b.principal_state(&p_ops).await.unwrap_err();
    assert_eq!(
        (e.status(), e.code()),
        (Some(404), Some("not_found")),
        "{e}"
    );
    let e = b.set_disabled(&p_ops, true).await.unwrap_err();
    assert_eq!(e.status(), Some(404), "{e}");
    let e = b.revoke_sessions(&p_ops).await.unwrap_err();
    assert_eq!(e.status(), Some(404), "{e}");
    let conn = env.hub.tutela.connection().unwrap();
    assert!(!conn.client.principal_state(&p_ops).await.unwrap().disabled);

    // an embassy that runs as the wrong app registers nothing, and says why in its log
    env.stop().await;
    let port2 = tutelad::free_port();
    let env2 = Env::start_with(Opts {
        tutela: Some(t.config(&t.a.other)),
        http_addr: Some(format!("127.0.0.1:{port2}")),
        ..Opts::default()
    })
    .await;
    env2.create("orders", &orders_yaml()).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(agent(&env2, "ops").await.get("tutela").is_none());
    env2.stop().await;
    t.finish().await;
}

#[tokio::test]
async fn a_tutelad_that_is_down_holds_up_only_what_needs_it() {
    let port = tutelad::free_port();
    let Some(mut t) = Tutelad::start(port).await else {
        return;
    };
    let env = embassy(&t, port).await;
    env.create("orders", &orders_yaml()).await;
    let ops = until(&env, "ops", "a tutela principal", |a| {
        a["tutela"].is_object()
    })
    .await;
    let ops_id = ops["id"].as_str().unwrap().to_string();
    t.stop().await;

    // a quarantine takes effect in attache at once; revoking tokens fails closed
    let r = env
        .call(
            "POST",
            &format!("/agents/{ops_id}/quarantine"),
            "alice",
            Some(json!({"reason": "while tutelad is down"})),
            None,
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(
        r.body["tutela"]["disabled"], false,
        "tutelad has not heard yet"
    );
    let r = env
        .call(
            "POST",
            &format!("/agents/{ops_id}/revoke-tokens"),
            "alice",
            None,
            None,
        )
        .await;
    assert_eq!(r.status, 503, "{}", r.text);
    assert_eq!(r.body["error"], "tutela_unavailable");
    // a new agent waits for tutelad
    let (version, _) = env.charter("orders").await;
    let r = env
        .call(
            "PUT",
            &format!("/services/{NS}/orders/charter"),
            "alice",
            Some(json!({"yaml": with_billing()})),
            Some(&version),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(agent(&env, "billing").await.get("tutela").is_none());

    // tutelad is back: the quarantine and the new agent reach it without anyone asking again
    t.serve().await;
    until(&env, "ops", "disabled in tutelad", |a| {
        a["tutela"]["disabled"] == true
    })
    .await;
    until(&env, "billing", "a tutela principal", |a| {
        a["tutela"].is_object()
    })
    .await;
    env.stop().await;
    t.finish().await;
}
