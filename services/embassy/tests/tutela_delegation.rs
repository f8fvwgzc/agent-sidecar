//! Delegated agent tokens against a real `tutelad` v0.2.0 on a real PostgreSQL (#25,
//! crate::tutela::delegation): a sidecar asks on its `Connect` stream, embassy checks the
//! person's token with `tutela-sdk` and exchanges it with its own agent token as the actor.
//! The chain of actors stops at 4, an expired or revoked person and a quarantined agent get
//! nothing, a token for an audience Tutela does not mark `delegation_aware` is never issued, and
//! attache refuses a delegated token when its own audience is not delegation-aware.
//!
//! Needs `ATTACHE_TUTELAD_BIN` and a PostgreSQL (tests/tutelad/mod.rs); without them each test
//! says so and passes, unless `ATTACHE_REQUIRE_TUTELAD=1`.
mod common;
mod tutelad;

use std::time::Duration;

use agentsc_proto::{DelegationRequest, control_message, sidecar_message};
use common::{Env, NS, Opts, hello, orders_yaml};
use embassy::config::{AgentTokensConfig, DelegationConfig};
use embassy::store::ServiceKey;
use embassy::tutela::delegation::{RULE_REFUSED, Refusal, delegate};
use serde_json::{Value, json};
use tutelad::{ATTACHE, DELEGATION_AWARE, NOT_DELEGATION_AWARE, Tutelad, claims};

/// embassy as tenant A's app, signing agent tokens, delegating for people's tokens addressed to
/// `attache` (`aware`: delegated tokens too).
async fn embassy(t: &Tutelad, port: u16, aware: bool) -> Env {
    let key = t.dir.path().join(format!("agent-key-{port}.pem"));
    std::fs::write(&key, embassy::tutela::agent_token::generate_pem().unwrap()).unwrap();
    let mut cfg = t.config(&t.a.attache);
    cfg.agent_tokens = Some(AgentTokensConfig {
        issuer: t.embassy_iss.clone(),
        key_file: key,
    });
    cfg.delegation = Some(DelegationConfig {
        audience: ATTACHE.into(),
        delegation_aware: aware,
        audiences: vec![
            DELEGATION_AWARE.into(),
            NOT_DELEGATION_AWARE.into(),
            "tutela-authz".into(),
            ATTACHE.into(),
        ],
    });
    Env::start_with(Opts {
        tutela: Some(cfg),
        http_addr: Some(format!("127.0.0.1:{port}")),
        ..Opts::default()
    })
    .await
}

/// The orders charter with two more agents, so a chain can hold four actors.
fn four_agents() -> String {
    orders_yaml().replace(
        "guardrails:",
        "  - name: billing\n    model: mock\n  - name: audit\n    model: mock\nguardrails:",
    )
}

/// Wait until every agent of `orders` is registered and enabled in tutelad; name → registry entry.
async fn registered(env: &Env, names: &[&str]) -> std::collections::HashMap<String, Value> {
    let start = std::time::Instant::now();
    loop {
        let r = env
            .get(&format!("/agents?namespace={NS}&service=orders"), "alice")
            .await;
        let all: Vec<Value> = r.body.as_array().cloned().unwrap_or_default();
        let ready: std::collections::HashMap<String, Value> = all
            .into_iter()
            .filter(|a| a["tutela"]["disabled"] == false)
            .map(|a| (a["name"].as_str().unwrap().to_string(), a))
            .collect();
        if names.iter().all(|n| ready.contains_key(*n)) {
            return ready;
        }
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "not registered: {}",
            r.text
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn request(agent: &str, audience: &str, subject: &str) -> DelegationRequest {
    DelegationRequest {
        id: uuid::Uuid::new_v4().to_string(),
        agent: agent.into(),
        audience: audience.into(),
        subject_token: subject.into(),
        run_id: "run-7".into(),
        node_id: format!("{agent}.ask_partner"),
    }
}

fn orders() -> ServiceKey {
    ServiceKey::new(NS, "orders")
}

/// `delegate` refused, with `rule` and a reason that contains `needle`.
fn refused(r: Result<embassy::tutela::client::Issued, Refusal>, rule: &str, needle: &str) {
    match r {
        Ok(_) => panic!("a token was issued; expected {rule} ({needle})"),
        Err(f) => {
            assert_eq!(f.rule, rule, "{f:?}");
            assert!(f.reason.contains(needle), "{needle:?} not in {f:?}");
        }
    }
}

#[tokio::test]
async fn a_sidecar_gets_a_delegated_token_for_the_person_and_nothing_else() {
    let port = tutelad::free_port();
    let Some(t) = Tutelad::start(port).await else {
        return;
    };
    let env = embassy(&t, port, false).await;
    env.create("orders", &orders_yaml()).await;
    let agents = registered(&env, &["ops", "triage"]).await;
    let person = t.person_token_for("carla", ATTACHE, 600).await;

    // over the Connect stream: the answer comes back to this sidecar only
    let mut h = hello(NS, "orders", "orders-0");
    h.charter_schema_level = agentsc_charter::CHARTER_SCHEMA_LEVEL;
    let mut sidecar = env.sidecar(NS, "orders", h).await.unwrap();
    let req = request("ops", DELEGATION_AWARE, &person);
    sidecar
        .send(sidecar_message::Msg::DelegationRequest(req.clone()))
        .await;
    let answer = loop {
        match tokio::time::timeout(Duration::from_secs(10), sidecar.rx.message())
            .await
            .expect("an answer")
            .unwrap()
            .unwrap()
            .msg
        {
            Some(control_message::Msg::DelegationResponse(r)) => break r,
            _ => continue,
        }
    };
    assert_eq!(answer.id, req.id);
    assert!(answer.error.is_empty(), "{}", answer.error);
    let token = answer.access_token;
    let header: Value = serde_json::from_slice(
        &base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            token.split('.').next().unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(header["typ"], "agent+jwt");
    let c = claims(&token);
    let p = claims(&person);
    assert_eq!(c["sub"], p["sub"], "the person");
    assert_eq!(c["act"]["sub"], agents["ops"]["tutela"]["principal"]);
    assert!(c["act"].get("act").is_none(), "one actor");
    assert_eq!(c["aud"], DELEGATION_AWARE);
    let conn = env.hub.tutela.connection().unwrap();
    assert_eq!(c["azp"], conn.client.credentials().client_id.as_str());
    assert_eq!(
        (c["run_id"].as_str(), c["node_id"].as_str()),
        (Some("run-7"), Some("ops.ask_partner"))
    );
    assert_eq!(c["cap"]["attache"]["agent"], "ops");
    assert_eq!(c["cap"]["attache"]["service"], format!("{NS}/orders"));
    assert!(
        c["cap"]["attache"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t == "lookup_order")
    );
    let (iat, exp) = (c["iat"].as_u64().unwrap(), c["exp"].as_u64().unwrap());
    assert!(
        exp - iat <= 120 && exp > iat,
        "a delegated token lives 60 to 120 s"
    );
    assert!(
        exp <= p["exp"].as_u64().unwrap(),
        "never past the person's token"
    );

    // an audience outside tutela.delegation.audiences, or one Tutela does not mark
    // delegation_aware, gets nothing
    refused(
        delegate(&env.hub, &orders(), &request("ops", "billing-api", &person)).await,
        RULE_REFUSED,
        "not in tutela.delegation.audiences",
    );
    refused(
        delegate(
            &env.hub,
            &orders(),
            &request("ops", NOT_DELEGATION_AWARE, &person),
        )
        .await,
        RULE_REFUSED,
        "invalid_target",
    );
    // another service's agent, an unknown agent, a token for another audience, no token
    refused(
        delegate(
            &env.hub,
            &ServiceKey::new(NS, "inventory"),
            &request("ops", DELEGATION_AWARE, &person),
        )
        .await,
        RULE_REFUSED,
        "is not an active agent",
    );
    let for_tutela = t.person_token("carla").await;
    refused(
        delegate(
            &env.hub,
            &orders(),
            &request("ops", DELEGATION_AWARE, &for_tutela),
        )
        .await,
        RULE_REFUSED,
        "not valid for audience attache",
    );
    refused(
        delegate(&env.hub, &orders(), &request("ops", DELEGATION_AWARE, "")).await,
        RULE_REFUSED,
        "missing",
    );
    // a person's token that another app exchanged names that app as azp: only it may exchange it
    let other = embassy::tutela::client::Client::new(
        &t.config(&t.a.other),
        embassy::tutela::Credentials::read(&t.a.other).unwrap(),
    )
    .unwrap();
    let theirs = other
        .exchange(&embassy::tutela::client::Exchange {
            subject_token: &t.person_token("dana").await,
            audience: ATTACHE,
            ..Default::default()
        })
        .await
        .unwrap()
        .access_token;
    refused(
        delegate(
            &env.hub,
            &orders(),
            &request("ops", DELEGATION_AWARE, &theirs),
        )
        .await,
        RULE_REFUSED,
        "invalid_grant",
    );

    // attache's audience is not delegation-aware here: a delegated token as the subject is refused
    // by attache itself, before tutelad is asked
    let delegated_to_attache = delegate(&env.hub, &orders(), &request("triage", ATTACHE, &person))
        .await
        .unwrap()
        .access_token;
    refused(
        delegate(
            &env.hub,
            &orders(),
            &request("ops", DELEGATION_AWARE, &delegated_to_attache),
        )
        .await,
        RULE_REFUSED,
        "not valid for audience attache",
    );
    env.stop().await;
    t.finish().await;
}

#[tokio::test]
async fn the_chain_stops_at_four_actors() {
    let port = tutelad::free_port();
    let Some(t) = Tutelad::start(port).await else {
        return;
    };
    let env = embassy(&t, port, true).await;
    env.create("orders", &four_agents()).await;
    registered(&env, &["ops", "triage", "billing", "audit"]).await;
    // each hop: the token addressed to attache is the subject, one more attache agent the actor
    let mut subject = t.person_token_for("carla", ATTACHE, 600).await;
    for (depth, agent) in ["ops", "triage", "billing", "audit"]
        .into_iter()
        .enumerate()
    {
        let issued = delegate(&env.hub, &orders(), &request(agent, ATTACHE, &subject))
            .await
            .unwrap_or_else(|f| panic!("actor {}: {f:?}", depth + 1));
        let c = claims(&issued.access_token);
        let mut chain = 0;
        let mut act = &c["act"];
        while act.is_object() {
            chain += 1;
            act = &act["act"];
        }
        assert_eq!(chain, depth + 1, "{c}");
        subject = issued.access_token;
    }
    // a fifth actor: tutelad refuses
    refused(
        delegate(&env.hub, &orders(), &request("ops", ATTACHE, &subject)).await,
        RULE_REFUSED,
        "invalid_grant",
    );
    // the four-actor token still goes to a downstream audience with one more exchange? no: that
    // would be a fifth actor too
    refused(
        delegate(
            &env.hub,
            &orders(),
            &request("triage", DELEGATION_AWARE, &subject),
        )
        .await,
        RULE_REFUSED,
        "invalid_grant",
    );
    env.stop().await;
    t.finish().await;
}

#[tokio::test]
async fn an_expired_or_revoked_person_and_a_quarantined_agent_get_nothing() {
    let port = tutelad::free_port();
    let Some(t) = Tutelad::start(port).await else {
        return;
    };
    let env = embassy(&t, port, false).await;
    env.create("orders", &orders_yaml()).await;
    let agents = registered(&env, &["ops", "triage"]).await;

    // expired: the person's token ends in 3 s; attache's check allows the clock skew, tutelad's
    // exchange does not
    let short = t.person_token_for("erin", ATTACHE, 3).await;
    assert!(claims(&short)["exp"].as_u64().unwrap() <= tutelad::now() + 3);
    tokio::time::sleep(Duration::from_secs(4)).await;
    refused(
        delegate(
            &env.hub,
            &orders(),
            &request("ops", DELEGATION_AWARE, &short),
        )
        .await,
        RULE_REFUSED,
        "invalid_grant",
    );

    // a revoked person: a delegated token issued before stops on tutelad's API, and the person's
    // token gives nothing more
    let person = t.person_token_for("carla", ATTACHE, 600).await;
    let before = delegate(
        &env.hub,
        &orders(),
        &request("ops", "tutela-authz", &person),
    )
    .await
    .unwrap()
    .access_token;
    t.until_whoami(&before, 200).await;
    let owner = embassy::tutela::client::Client::new(
        &t.config(&t.a.owner),
        embassy::tutela::Credentials::read(&t.a.owner).unwrap(),
    )
    .unwrap();
    let carla = claims(&person)["sub"].as_str().unwrap().to_string();
    owner.revoke_sessions(&carla).await.unwrap();
    t.until_whoami(&before, 401).await;
    refused(
        delegate(
            &env.hub,
            &orders(),
            &request("ops", DELEGATION_AWARE, &person),
        )
        .await,
        RULE_REFUSED,
        "invalid_grant",
    );

    // a quarantined agent: embassy signs no actor for it, so nothing is asked of tutelad; its
    // delegated token from before stops too
    let person = t.person_token_for("dana", ATTACHE, 600).await;
    let before = delegate(
        &env.hub,
        &orders(),
        &request("triage", "tutela-authz", &person),
    )
    .await
    .unwrap()
    .access_token;
    t.until_whoami(&before, 200).await;
    let triage_id = agents["triage"]["id"].as_str().unwrap();
    let r = env
        .call(
            "POST",
            &format!("/agents/{triage_id}/quarantine"),
            "alice",
            Some(json!({"reason": "test"})),
            None,
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    refused(
        delegate(
            &env.hub,
            &orders(),
            &request("triage", DELEGATION_AWARE, &person),
        )
        .await,
        RULE_REFUSED,
        "quarantined",
    );
    t.until_whoami(&before, 401).await;
    // another agent of the service still acts for the same person
    delegate(
        &env.hub,
        &orders(),
        &request("ops", DELEGATION_AWARE, &person),
    )
    .await
    .unwrap();
    env.stop().await;
    t.finish().await;
}
