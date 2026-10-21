//! `GET /events` (design §10.2): ids, `Last-Event-ID` replay, `reset`, `lagged`, filters and
//! payload hiding, the `graph` throttle and the keep-alive comment.
mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use common::{Env, NS, SseReader, orders_yaml, rec};
use embassy::api::types::{GraphEvent, SseEvent};
use embassy::config::{ControlPlaneConfig, Role, TokenEntry};
use embassy::events::Scope;
use embassy::hub::{Hub, HubOptions};
use serde_json::json;
use tokio_util::sync::CancellationToken;

async fn open(env: &Env, who: &str, query: &str, last: Option<&str>) -> SseReader {
    let mut b = env.req("GET", &format!("/api/v1/events{query}"), Some(who));
    if let Some(id) = last {
        b = b.header("Last-Event-ID", id);
    }
    let resp = b.send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], "text/event-stream");
    assert_eq!(resp.headers()["cache-control"], "no-store");
    assert_eq!(
        resp.headers()["content-security-policy"],
        embassy::auth::http::CSP
    );
    SseReader::new(resp)
}

fn marker(env: &Env, v: u64) {
    env.hub.publish(
        SseEvent::Graph(GraphEvent {
            version: format!("9000{v}"),
        }),
        Scope::All,
    );
}

/// Read until the marker graph event `9000<v>`; returns the audit request ids seen before it.
async fn audits_until_marker(r: &mut SseReader, v: u64) -> Vec<String> {
    let want = format!("9000{v}");
    let mut out = Vec::new();
    loop {
        let f = r.next_within(common::WAIT).await.expect("the marker");
        if f.event == "graph" && f.data["version"] == want {
            return out;
        }
        if f.event == "audit" {
            out.push(f.data["record"]["request_id"].as_str().unwrap().to_string());
        }
    }
}

#[tokio::test]
async fn ids_increase_and_reconnects_replay_or_reset() {
    let env = Env::start().await;
    let mut a = open(&env, "alice", "", None).await;
    for i in 0..3 {
        env.ingest(rec(
            "agent_invocation",
            json!({"request_id": format!("r{i}")}),
        ));
    }
    let mut ids = Vec::new();
    while ids.len() < 3 {
        let f = a.until("audit").await;
        ids.push((
            f.id.unwrap(),
            f.data["record"]["request_id"].as_str().unwrap().to_string(),
        ));
    }
    assert!(ids.windows(2).all(|w| w[0].0 < w[1].0), "{ids:?}");
    // a reconnect with the first id replays what came after it
    let mut b = open(&env, "alice", "", Some(&ids[0].0.to_string())).await;
    let f = b.until("audit").await;
    assert_eq!(
        (f.id, f.data["record"]["request_id"].as_str()),
        (Some(ids[1].0), Some("r1"))
    );
    let f = b.until("audit").await;
    assert_eq!(f.id, Some(ids[2].0));
    // an id from the future (a restarted server): reset with the current id
    let mut c = open(&env, "alice", "", Some("99999999")).await;
    let f = c.next_within(common::WAIT).await.unwrap();
    assert_eq!(f.event, "reset");
    assert_eq!(f.data, json!({}));
    let current = env.hub.events.current_seq();
    assert_eq!(f.id, Some(current));
    // an id older than the ring
    for v in 0..(embassy::events::REPLAY_EVENTS as u64 + 10) {
        env.hub.publish(
            SseEvent::Graph(GraphEvent {
                version: v.to_string(),
            }),
            Scope::All,
        );
    }
    let mut d = open(&env, "alice", "", Some("1")).await;
    assert_eq!(d.next_within(common::WAIT).await.unwrap().event, "reset");
    // garbage is a reset too
    let mut e = open(&env, "alice", "", Some("abc")).await;
    assert_eq!(e.next_within(common::WAIT).await.unwrap().event, "reset");
    env.stop().await;
}

#[tokio::test]
async fn a_full_queue_becomes_one_lagged_event() {
    let env = Env::start().await;
    let mut r = open(&env, "alice", "", None).await;
    marker(&env, 1);
    audits_until_marker(&mut r, 1).await;
    // nothing else runs while this loop publishes (a current-thread runtime): the client's
    // queue takes 1024 events, the 1025th overflows it, the rest are counted until it reads
    let n = 1100u64;
    for v in 0..n {
        env.hub.publish(
            SseEvent::Graph(GraphEvent {
                version: v.to_string(),
            }),
            Scope::All,
        );
    }
    let last = env.hub.events.current_seq();
    let f = r.next_within(common::WAIT).await.unwrap();
    assert_eq!(f.event, "lagged", "{f:?}");
    assert_eq!(f.data["dropped"], n);
    assert_eq!(f.id, Some(last));
    // after the lagged event, events flow again
    marker(&env, 2);
    let f = r.next_within(common::WAIT).await.unwrap();
    assert_eq!(f.data["version"], "90002");
    env.stop().await;
}

#[tokio::test]
async fn filters_scope_and_payloads() {
    let env = Env::start().await;
    let v = env.create("orders", &orders_yaml()).await;
    let mut carol = open(&env, "carol", "", None).await; // viewer of shop, no payloads
    let mut alice = open(&env, "alice", "?payloads=false", None).await;
    let mut bob = open(&env, "bob", "?service=inventory", None).await;
    let mut admin = open(&env, "alice", &format!("?namespace={NS}"), None).await;
    env.ingest(rec("agent_invocation", json!({"request_id": "in-shop"})));
    env.ingest(rec(
        "agent_invocation",
        json!({"request_id": "elsewhere", "namespace": "other"}),
    ));
    env.ingest(rec(
        "agent_invocation",
        json!({"request_id": "inventory", "service": "inventory", "agent": "stock"}),
    ));
    marker(&env, 1);
    let f = carol.until("audit").await;
    assert_eq!(f.data["record"]["request_id"], "in-shop");
    assert!(f.data["record"]["input"].is_null(), "no payloads for carol");
    assert_eq!(
        f.data["edge_id"],
        "edge:invoke:app:shop/orders->agent:shop/orders/ops"
    );
    assert_eq!(f.data["animate"], true);
    assert_eq!(
        audits_until_marker(&mut carol, 1).await,
        ["inventory"],
        "not the other namespace"
    );
    let f = alice.until("audit").await;
    assert!(f.data["record"]["input"].is_null(), "?payloads=false");
    assert_eq!(audits_until_marker(&mut bob, 1).await, ["inventory"]);
    let f = admin.until("audit").await;
    assert_eq!(
        f.data["record"]["input"]["input"],
        "How many WIDGET-1 are in stock?"
    );
    assert_eq!(audits_until_marker(&mut admin, 1).await, ["inventory"]);
    // cp_audit: admins only
    let (_, mut c) = env.charter("orders").await;
    c["agents"][1]["system"] = json!("x");
    let r = env
        .call(
            "PUT",
            &format!("/services/{NS}/orders/charter"),
            "alice",
            Some(json!({"yaml": c.to_string()})),
            Some(&v),
        )
        .await;
    assert_eq!(r.status, 200);
    // the config event (store) and the cp_audit record (API) come in either order
    let (mut cp, mut config) = (None, None);
    while cp.is_none() || config.is_none() {
        let f = admin
            .next_within(common::WAIT)
            .await
            .expect("cp_audit and config");
        match f.event.as_str() {
            "cp_audit" => cp = Some(f),
            "config" => config = Some(f),
            _ => {}
        }
    }
    let (cp, config) = (cp.unwrap(), config.unwrap());
    assert_eq!(
        (cp.data["action"].as_str(), cp.data["actor"].as_str()),
        (Some("charter_put"), Some("alice"))
    );
    assert_eq!(
        config.data,
        json!({"namespace": NS, "service": "orders", "version": "2", "actor": "alice", "source": "api"})
    );
    // carol gets the config event but never cp_audit
    let f = carol.until("config").await;
    assert_eq!(f.data["version"], "2");
    marker(&env, 2);
    loop {
        let f = carol.next_within(common::WAIT).await.unwrap();
        assert_ne!(f.event, "cp_audit");
        if f.event == "graph" && f.data["version"] == "90002" {
            break;
        }
    }
    env.stop().await;
}

#[tokio::test]
async fn graph_events_come_at_most_every_two_seconds() {
    let env = Env::start().await;
    let mut r = open(&env, "alice", "", None).await;
    env.ingest(rec("agent_invocation", json!({})));
    let first = r.until("graph").await;
    let t1 = Instant::now();
    env.ingest(rec("agent_invocation", json!({})));
    let second = r.until("graph").await;
    let gap = t1.elapsed();
    assert!(gap >= Duration::from_millis(1900), "{gap:?}");
    let (a, b): (u64, u64) = (
        first.data["version"].as_str().unwrap().parse().unwrap(),
        second.data["version"].as_str().unwrap().parse().unwrap(),
    );
    assert!(b > a);
    assert_eq!(b, env.hub.graph.version());
    env.stop().await;
}

/// A hub with a short keep-alive, served on its own.
#[tokio::test]
async fn keepalive_comments_and_revoked_tokens_end_the_stream() {
    let dir = tempfile::tempdir().unwrap();
    let store = embassy::store::file::FileStore::open_with_poll(dir.path(), None)
        .await
        .unwrap();
    let token = embassy::token::generate().unwrap();
    let mut cfg = ControlPlaneConfig::default();
    cfg.auth.tokens.push(TokenEntry {
        name: "alice".into(),
        role: Role::Admin,
        sha256: embassy::token::sha256_hex(&token),
        namespaces: vec!["*".into()],
        payloads: true,
    });
    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let audit = Arc::new(embassy::cp_audit::CpAudit::with_writer(
        None,
        Box::new(std::io::sink()),
    ));
    let auth = embassy::auth::Auth::new(config.clone(), false, false).unwrap();
    let stop = CancellationToken::new();
    let hub = Hub::new(
        store,
        config.clone(),
        audit,
        auth,
        HubOptions {
            keepalive: Duration::from_millis(100),
            ..Default::default()
        },
        stop.clone(),
    );
    let app = embassy::api::router(hub.clone(), true, None);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let s = stop.clone();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<embassy::api::ClientAddr>(),
        )
        .with_graceful_shutdown(s.cancelled_owned())
        .await
    });
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/events"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let mut r = SseReader::new(resp);
    let f = r.next_within(Duration::from_secs(2)).await.unwrap();
    assert!(f.comment && f.event == "keepalive", "{f:?}");
    // the token leaves the config: the next keep-alive tick ends the stream
    config.store(Arc::new(ControlPlaneConfig::default()));
    let mut ended = false;
    for _ in 0..20 {
        match r.next_within(Duration::from_millis(500)).await {
            Some(f) if f.comment => continue,
            Some(f) => panic!("{f:?}"),
            None => {
                ended = true;
                break;
            }
        }
    }
    assert!(ended, "the stream ended");
    stop.cancel();
}
