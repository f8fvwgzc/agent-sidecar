//! The agent registry (secops/, docs/design/agent-registry.md, CONTRACT.md §5.3): the stores
//! (SQLite always, PostgreSQL with `AGENTSC_TEST_POSTGRES_URL`), the API, and the ids a sidecar
//! gets over Connect.
mod common;

use std::collections::BTreeSet;
use std::sync::Arc;

use agentsc_common::principal::AgentId;
use agentsc_proto::{AuditBatch, sidecar_message};
use common::{Env, NS, hello, orders_yaml};
use embassy::api::types::CpAction;
use embassy::secops::{AgentFilter, AgentStatus, RegistryChange, SecOpsStore};
use embassy::store::postgres::{PgOptions, PgStore};
use embassy::store::sqlite::SqliteStore;
use embassy::store::{Actor, ActorKind, ServiceKey, StoreError};
use serde_json::{Value, json};

fn names(n: &[&str]) -> BTreeSet<String> {
    n.iter().map(|s| s.to_string()).collect()
}

fn admin() -> Actor {
    Actor {
        name: "alice".into(),
        kind: ActorKind::Token,
        role: None,
    }
}

/// What every SQL store must do (secops/mod.rs `SecOpsStore`).
async fn registry_rules(store: Arc<dyn SecOpsStore>) {
    let key = ServiceKey::new(NS, "orders");
    // a new agent gets a fresh id; nothing changes on a second sync
    let first = store
        .sync_agents(&key, &names(&["ops", "triage"]))
        .await
        .unwrap();
    assert_eq!(first.len(), 2);
    assert!(first.iter().all(|c| c.change == RegistryChange::Registered));
    let ops = first
        .iter()
        .find(|c| c.entry.name == "ops")
        .unwrap()
        .entry
        .clone();
    AgentId::parse(&ops.id).unwrap();
    assert_eq!(ops.principal, format!("agent:{}", ops.id));
    assert_eq!(ops.status, AgentStatus::Active);
    assert!(
        store
            .sync_agents(&key, &names(&["ops", "triage"]))
            .await
            .unwrap()
            .is_empty()
    );

    // gone from the charter: retired, never deleted; declared again: the same id
    let gone = store.sync_agents(&key, &names(&["triage"])).await.unwrap();
    assert_eq!(gone.len(), 1);
    assert_eq!(gone[0].change, RegistryChange::Retired);
    assert_eq!(gone[0].entry.id, ops.id);
    let retired = store.get_agent(&ops.id).await.unwrap();
    assert_eq!(retired.status, AgentStatus::Retired);
    let back = store
        .sync_agents(&key, &names(&["ops", "triage"]))
        .await
        .unwrap();
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].change, RegistryChange::Reactivated);
    assert_eq!(back[0].entry.id, ops.id, "an agent keeps its id");

    // another service's agent of the same name is another agent
    let other = store
        .sync_agents(&ServiceKey::new(NS, "inventory"), &names(&["ops"]))
        .await
        .unwrap();
    assert_ne!(other[0].entry.id, ops.id);

    // filters
    let active_orders = store
        .list_agents(&AgentFilter {
            namespace: Some(NS.into()),
            service: Some("orders".into()),
            status: Some(AgentStatus::Active),
        })
        .await
        .unwrap();
    assert_eq!(
        active_orders
            .iter()
            .map(|a| a.name.as_str())
            .collect::<Vec<_>>(),
        ["ops", "triage"]
    );
    assert_eq!(
        store
            .list_agents(&AgentFilter::default())
            .await
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        store
            .get_agent("agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102")
            .await,
        Err(StoreError::NotFound)
    );

    // aliases: one agent each, idempotent, removable
    let alias = "agent://acme/ops";
    let with = store.put_alias(&ops.id, alias, &admin()).await.unwrap();
    assert_eq!(with.aliases, [alias]);
    assert_eq!(
        store
            .put_alias(&ops.id, alias, &admin())
            .await
            .unwrap()
            .aliases,
        [alias]
    );
    assert_eq!(store.resolve_alias(alias).await.unwrap().id, ops.id);
    assert_eq!(
        store.put_alias(&other[0].entry.id, alias, &admin()).await,
        Err(StoreError::Conflict {
            current: ops.id.clone()
        })
    );
    assert!(matches!(
        store.put_alias(&ops.id, "not an alias", &admin()).await,
        Err(StoreError::Invalid(_))
    ));
    assert_eq!(store.get_agent(&ops.id).await.unwrap().aliases, [alias]);
    assert!(
        store
            .delete_alias(&ops.id, alias)
            .await
            .unwrap()
            .aliases
            .is_empty()
    );
    assert_eq!(
        store.delete_alias(&ops.id, alias).await,
        Err(StoreError::NotFound)
    );
    assert_eq!(store.resolve_alias(alias).await, Err(StoreError::NotFound));
    for i in 0..embassy::secops::MAX_ALIASES {
        store
            .put_alias(&ops.id, &format!("agent://acme/ops-{i}"), &admin())
            .await
            .unwrap();
    }
    assert!(matches!(
        store
            .put_alias(&ops.id, "agent://acme/one-too-many", &admin())
            .await,
        Err(StoreError::Invalid(_))
    ));

    // quarantine: once, with a reason; kept across syncs; released once
    let at = "2026-10-29T10:00:00.000Z";
    assert!(matches!(
        store.quarantine_agent(&ops.id, "  ", &admin(), at).await,
        Err(StoreError::Invalid(_))
    ));
    let q = store
        .quarantine_agent(&ops.id, "risky", &admin(), at)
        .await
        .unwrap();
    let state = q.quarantine.clone().unwrap();
    assert_eq!(
        (state.at.as_str(), state.reason.as_str(), state.by.as_str()),
        (at, "risky", "alice")
    );
    assert_eq!(
        store.quarantine_agent(&ops.id, "again", &admin(), at).await,
        Err(StoreError::Conflict { current: at.into() })
    );
    store
        .sync_agents(&key, &names(&["ops", "triage"]))
        .await
        .unwrap();
    assert!(store.get_agent(&ops.id).await.unwrap().quarantine.is_some());
    assert!(
        store
            .release_agent(&ops.id)
            .await
            .unwrap()
            .quarantine
            .is_none()
    );
    assert!(matches!(
        store.release_agent(&ops.id).await,
        Err(StoreError::Conflict { .. })
    ));
    assert_eq!(
        store
            .quarantine_agent(
                "agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102",
                "x",
                &admin(),
                at
            )
            .await,
        Err(StoreError::NotFound)
    );

    // a deleted service's agents retire
    let all_gone = store.sync_agents(&key, &BTreeSet::new()).await.unwrap();
    assert_eq!(all_gone.len(), 2);
    assert!(all_gone.iter().all(|c| c.change == RegistryChange::Retired));
}

#[tokio::test]
async fn the_sqlite_store_keeps_the_registry() {
    registry_rules(SqliteStore::open_in_memory().unwrap()).await;
}

#[tokio::test]
async fn a_version_1_sqlite_database_gets_the_registry_and_its_rules() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("embassy.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(embassy::store::sqlite::SCHEMA).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
    }
    let store = SqliteStore::open(&path).unwrap();
    let key = ServiceKey::new(NS, "orders");
    let made = store.sync_agents(&key, &names(&["ops"])).await.unwrap();
    let id = made[0].entry.id.clone();
    drop(store);
    let conn = rusqlite::Connection::open(&path).unwrap();
    let v: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, embassy::store::sqlite::SCHEMA_VERSION);
    let refused = |sql: &str| {
        conn.execute(sql, rusqlite::params![id])
            .unwrap_err()
            .to_string()
    };
    assert!(refused("DELETE FROM agents WHERE id = ?1").contains("never deleted"));
    assert!(refused("UPDATE agents SET name = 'x' WHERE id = ?1").contains("never change"));
    assert!(refused("UPDATE agents SET id = 'agt_x' WHERE id = ?1").contains("never change"));
}

async fn pg_store() -> Option<(Arc<PgStore>, Arc<PgStore>, tokio_postgres::Client)> {
    let Ok(base) = std::env::var("AGENTSC_TEST_POSTGRES_URL") else {
        eprintln!("AGENTSC_TEST_POSTGRES_URL is not set: the PostgreSQL registry test did not run");
        return None;
    };
    let schema = format!("t_{}", uuid::Uuid::new_v4().simple());
    let (admin, conn) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(conn);
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let sep = if base.contains('?') { '&' } else { '?' };
    let url = format!("{base}{sep}options=-c%20search_path%3D{schema}");
    let open = |name: &str| {
        PgStore::open(PgOptions {
            url: url.clone(),
            ca_file: None,
            pool_size: 4,
            application_name: format!("{schema}-{name}"),
            allow_plaintext: false,
        })
    };
    let a = open("a").await.unwrap();
    let b = open("b").await.unwrap();
    let (raw, conn) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(conn);
    Some((a, b, raw))
}

#[tokio::test]
async fn the_postgres_store_keeps_the_registry() {
    let Some((a, _, raw)) = pg_store().await else {
        return;
    };
    registry_rules(a.clone()).await;
    let id: String = raw
        .query_one("SELECT id FROM agents LIMIT 1", &[])
        .await
        .unwrap()
        .get(0);
    for sql in [
        "DELETE FROM agents WHERE id = $1",
        "UPDATE agents SET name = 'x' WHERE id = $1",
    ] {
        assert!(raw.execute(sql, &[&id]).await.is_err(), "{sql}");
    }
    assert!(raw.batch_execute("TRUNCATE agents CASCADE").await.is_err());
}

#[tokio::test]
async fn two_replicas_syncing_one_change_register_each_agent_once() {
    let Some((a, b, _)) = pg_store().await else {
        return;
    };
    let key = ServiceKey::new(NS, "orders");
    let declared = names(&["ops", "triage", "billing"]);
    let (ra, rb) = tokio::join!(
        a.sync_agents(&key, &declared),
        b.sync_agents(&key, &declared)
    );
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert_eq!(
        ra.len() + rb.len(),
        3,
        "each agent is registered by one replica"
    );
    let seen_a = a.list_agents(&AgentFilter::default()).await.unwrap();
    let seen_b = b.list_agents(&AgentFilter::default()).await.unwrap();
    assert_eq!(seen_a, seen_b);
    assert_eq!(seen_a.len(), 3);
}

// ---- through the API and Connect (file store: the registry is in <dir>/.secops.sqlite3) ----

/// The orders charter with a third agent, `billing`.
fn with_billing() -> String {
    orders_yaml().replace(
        "guardrails:",
        "  - name: billing\n    model: mock\nguardrails:",
    )
}

/// Store `yaml` as the orders charter (alice, the current version).
async fn put(env: &Env, yaml: &str) {
    let (version, _) = env.charter("orders").await;
    let r = env
        .call(
            "PUT",
            &format!("/services/{NS}/orders/charter"),
            "alice",
            Some(json!({ "yaml": yaml })),
            Some(&version),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
}

fn agents_of(body: &Value) -> Vec<(String, String, String)> {
    body.as_array()
        .unwrap()
        .iter()
        .map(|a| {
            (
                a["name"].as_str().unwrap().to_string(),
                a["status"].as_str().unwrap().to_string(),
                a["id"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[tokio::test]
async fn a_stored_charter_registers_its_agents_and_the_api_resolves_them() {
    let env = Env::start().await;
    env.create("orders", &orders_yaml()).await;
    common::eventually("the charter's agents registered", || async {
        agents_of(&env.get("/agents?service=orders", "alice").await.body).len() == 2
    })
    .await;
    let listed = agents_of(&env.get("/agents?service=orders", "alice").await.body);
    let ops_id = listed.iter().find(|a| a.0 == "ops").unwrap().2.clone();
    assert!(listed.iter().all(|a| a.1 == "active"));
    AgentId::parse(&ops_id).unwrap();
    assert!(env.hub.secops().is_some());

    // scope: carol sees the namespace, dave (another namespace) sees nothing
    assert_eq!(agents_of(&env.get("/agents", "carol").await.body).len(), 2);
    assert!(agents_of(&env.get("/agents", "dave").await.body).is_empty());
    assert_eq!(
        env.get(&format!("/agents/{ops_id}"), "dave").await.status,
        404
    );
    let one = env.get(&format!("/agents/{ops_id}"), "carol").await;
    assert_eq!(one.status, 200, "{}", one.text);
    assert_eq!(one.body["principal"], format!("agent:{ops_id}"));
    assert_eq!(one.body["service"], "orders");
    assert_eq!(env.get("/agents/not-an-id", "carol").await.status, 400);
    assert_eq!(env.get("/agents?status=gone", "carol").await.status, 400);

    // principals
    let r = env
        .get(&format!("/principals?principal=agent:{ops_id}"), "carol")
        .await;
    assert_eq!(r.body["kind"], "agent", "{}", r.text);
    assert_eq!(r.body["agent"]["id"], ops_id);
    let w = "workload:spiffe://agentsc/ns/shop/svc/orders";
    let r = env
        .get(&format!("/principals?principal={w}"), "carol")
        .await;
    assert_eq!(r.body["kind"], "workload", "{}", r.text);
    assert_eq!(r.body["agents"].as_array().unwrap().len(), 2);
    assert_eq!(
        env.get(&format!("/principals?principal={w}"), "dave")
            .await
            .status,
        404
    );
    assert_eq!(env.get("/principals", "carol").await.status, 400);

    // aliases: admin only, one agent each, audited
    let path = format!("/agents/{ops_id}/aliases");
    let body = json!({"alias": "agent://acme/ops"});
    assert_eq!(
        env.call("POST", &path, "bob", Some(body.clone()), None)
            .await
            .status,
        403
    );
    let r = env
        .call("POST", &path, "alice", Some(body.clone()), None)
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["aliases"], json!(["agent://acme/ops"]));
    let r = env
        .get("/principals?principal=agent://acme/ops", "carol")
        .await;
    assert_eq!(r.body["agent"]["id"], ops_id, "{}", r.text);
    let triage_id = listed.iter().find(|a| a.0 == "triage").unwrap().2.clone();
    let r = env
        .call(
            "POST",
            &format!("/agents/{triage_id}/aliases"),
            "alice",
            Some(body),
            None,
        )
        .await;
    assert_eq!((r.status, r.error()), (409, "in_use"), "{}", r.text);
    let r = env
        .call(
            "DELETE",
            &format!("{path}?alias=agent://acme/ops"),
            "alice",
            None,
            None,
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(
        env.get("/principals?principal=agent://acme/ops", "carol")
            .await
            .status,
        404
    );

    // a charter with `billing`: registered; without it: retired; with it again: the same id
    let billing_of = |body: &Value| {
        agents_of(body)
            .into_iter()
            .find(|a| a.0 == "billing")
            .map(|a| (a.1, a.2))
    };
    put(&env, &with_billing()).await;
    common::eventually("billing registered", || async {
        billing_of(&env.get("/agents?service=orders", "alice").await.body).is_some()
    })
    .await;
    let (_, billing_id) =
        billing_of(&env.get("/agents?service=orders", "alice").await.body).unwrap();
    put(&env, &orders_yaml()).await;
    common::eventually("billing retired", || async {
        billing_of(&env.get("/agents?service=orders", "alice").await.body)
            == Some(("retired".into(), billing_id.clone()))
    })
    .await;
    put(&env, &with_billing()).await;
    common::eventually("billing active again, same id", || async {
        billing_of(&env.get("/agents?service=orders", "alice").await.body)
            == Some(("active".into(), billing_id.clone()))
    })
    .await;

    // what the control-plane audit says
    let audit = env.hub.store.cp_audit(100).await.unwrap();
    let registered: Vec<_> = audit
        .iter()
        .filter(|r| r.action == CpAction::AgentRegistered)
        .collect();
    assert_eq!(registered.len(), 3, "ops, triage, billing");
    let ops_rec = registered
        .iter()
        .find(|r| r.agent.as_deref() == Some("ops"))
        .unwrap();
    assert_eq!(
        ops_rec.reason.as_deref(),
        Some(format!("agent:{ops_id}").as_str())
    );
    assert_eq!(ops_rec.actor, "alice", "the charter write's actor");
    assert!(
        audit
            .iter()
            .any(|r| r.action == CpAction::AgentRetired && r.agent.as_deref() == Some("billing"))
    );
    assert!(
        audit.iter().any(
            |r| r.action == CpAction::AgentReactivated && r.agent.as_deref() == Some("billing")
        )
    );
    assert!(audit.iter().any(|r| r.action == CpAction::AgentAliasPut));
    assert!(audit.iter().any(|r| r.action == CpAction::AgentAliasDelete));
    env.stop().await;
}

#[tokio::test]
async fn a_sidecar_gets_its_agents_ids_and_its_records_carry_them() {
    let env = Env::start().await;
    env.create("orders", &orders_yaml()).await;
    common::eventually("registered", || async {
        agents_of(&env.get("/agents?service=orders", "alice").await.body).len() == 2
    })
    .await;
    let mut sc = env
        .sidecar(NS, "orders", hello(NS, "orders", "orders-1"))
        .await
        .unwrap();
    let ids = sc.next_agent_ids().await;
    assert_eq!(
        ids.keys().cloned().collect::<BTreeSet<_>>(),
        names(&["ops", "triage"])
    );
    let ops_id = ids["ops"].clone();

    // a record without agent_id (an older sidecar) gets it on the way in
    sc.send(sidecar_message::Msg::Audit(AuditBatch {
        records_json: vec![
            common::rec(
                "agent_invocation",
                json!({"service": "orders", "agent": "ops"}),
            )
            .to_string(),
        ],
    }))
    .await;
    common::eventually("the record with its agent_id", || async {
        let r = env.get("/events/recent?limit=10", "alice").await;
        r.text.contains(&ops_id)
    })
    .await;

    // a new agent: the sidecar gets the ids again
    put(&env, &with_billing()).await;
    let again = sc.next_agent_ids().await;
    assert_eq!(
        again.keys().cloned().collect::<BTreeSet<_>>(),
        names(&["billing", "ops", "triage"])
    );
    assert_eq!(again["ops"], ops_id);
    env.stop().await;
}

#[tokio::test]
async fn a_quarantine_reaches_the_sidecars_and_a_release_lifts_it() {
    let env = Env::start().await;
    env.create("orders", &orders_yaml()).await;
    common::eventually("registered", || async {
        agents_of(&env.get("/agents?service=orders", "alice").await.body).len() == 2
    })
    .await;
    let mut sc = env
        .sidecar(NS, "orders", hello(NS, "orders", "orders-1"))
        .await
        .unwrap();
    // after hello: the ids, then the (empty) quarantine list
    let ids = sc.next_agent_ids().await;
    let ops = ids["ops"].clone();
    assert!(sc.next_quarantine().await.is_empty(), "none after hello");

    let path = format!("/agents/{ops}/quarantine");
    let body = json!({"reason": "risk 7.5 over 6"});
    assert_eq!(
        env.call("POST", &path, "bob", Some(body.clone()), None)
            .await
            .status,
        403
    );
    assert_eq!(
        env.call("POST", &path, "dave", Some(body.clone()), None)
            .await
            .status,
        403
    );
    let blank = env
        .call("POST", &path, "alice", Some(json!({"reason": " "})), None)
        .await;
    assert_eq!(blank.status, 400, "{}", blank.text);
    let r = env
        .call("POST", &path, "alice", Some(body.clone()), None)
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["quarantine"]["reason"], "risk 7.5 over 6");
    assert_eq!(r.body["quarantine"]["by"], "alice");
    // an earlier push (a registry sync) may come first: wait for the one that names ops
    let mut pushed = sc.next_quarantine().await;
    for _ in 0..10 {
        if pushed.contains_key("ops") {
            break;
        }
        pushed = sc.next_quarantine().await;
    }
    assert_eq!(
        pushed.get("ops").map(String::as_str),
        Some("risk 7.5 over 6")
    );
    assert_eq!(pushed.len(), 1);
    let again = env.call("POST", &path, "alice", Some(body), None).await;
    assert_eq!(again.status, 409, "{}", again.text);
    assert_eq!(
        env.get(&format!("/agents/{ops}"), "carol").await.body["quarantine"]["reason"],
        "risk 7.5 over 6"
    );

    // a sidecar that connects later gets it after hello
    let mut late = env
        .sidecar(NS, "orders", hello(NS, "orders", "orders-2"))
        .await
        .unwrap();
    assert_eq!(late.next_quarantine().await.len(), 1);

    let release = format!("/agents/{ops}/release");
    let r = env.call("POST", &release, "alice", None, None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert!(r.body["quarantine"].is_null());
    assert!(sc.next_quarantine().await.is_empty());
    assert_eq!(
        env.call("POST", &release, "alice", None, None).await.status,
        409
    );

    let audit = env.hub.store.cp_audit(100).await.unwrap();
    assert!(audit.iter().any(|r| {
        r.action == CpAction::AgentQuarantined
            && r.result == embassy::api::types::CpResult::Ok
            && r.reason
                .as_deref()
                .unwrap_or("")
                .contains("risk 7.5 over 6")
    }));
    assert!(audit.iter().any(|r| r.action == CpAction::AgentReleased));
    env.stop().await;
}
