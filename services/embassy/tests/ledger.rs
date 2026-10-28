//! The evidence ledger in embassy (secops/ledger.rs, CONTRACT.md §6.3): the stores (SQLite
//! always, PostgreSQL with `AGENTSC_TEST_POSTGRES_URL`), and records sent over Connect coming out
//! as bundles that `agentsc-ledger` verifies with the published keys alone.
mod common;

use std::sync::Arc;

use agentsc_ledger::{Bundle, Jwks, SigningKey, check_chain, verify_bundle};
use agentsc_proto::{AuditBatch, sidecar_message};
use common::{Env, NS, Opts, hello, orders_yaml};
use embassy::api::types::CpAction;
use embassy::secops::ledger::{LedgerKeys, seal_head};
use embassy::secops::{ChainFilter, LedgerRecord, SecOpsStore};
use embassy::store::postgres::{PgOptions, PgStore};
use embassy::store::sqlite::SqliteStore;
use serde_json::{Value, json};

fn lr(chain: &str, service: &str, i: usize) -> LedgerRecord {
    LedgerRecord {
        chain: chain.into(),
        namespace: NS.into(),
        service: service.into(),
        agent_id: None,
        kind: "tool_call".into(),
        record: json!({"kind": "tool_call", "request_id": chain, "i": i, "cost_usd": 0.0052}),
    }
}

/// What every SQL store must do with the ledger.
async fn ledger_rules(store: Arc<dyn SecOpsStore>) {
    // one batch, two chains, records of two services
    let batch = [
        lr("r1", "orders", 0),
        lr("r2", "orders", 0),
        lr("r1", "inventory", 1),
    ];
    assert_eq!(
        store
            .ledger_append("2026-10-29T10:00:00.000Z", &batch)
            .await
            .unwrap(),
        3
    );
    assert_eq!(
        store
            .ledger_append("2026-10-29T10:00:01.000Z", &[lr("r1", "orders", 2)])
            .await
            .unwrap(),
        1
    );
    let entries = store.ledger_entries("r1").await.unwrap();
    assert_eq!(entries.len(), 3);
    check_chain("r1", &entries).unwrap();
    assert_eq!(entries[1].record["i"], 1, "in the order taken in");
    let head = store.ledger_head("r1").await.unwrap();
    assert_eq!((head.entries, head.sealed), (3, 0));
    assert_eq!(head.head, entries[2].hash);
    assert_eq!(head.updated_at, "2026-10-29T10:00:01.000Z");
    assert_eq!(
        head.services
            .iter()
            .map(|s| s.service.as_str())
            .collect::<Vec<_>>(),
        ["inventory", "orders"]
    );
    assert_eq!(
        store.ledger_head("none").await.unwrap_err(),
        embassy::store::StoreError::NotFound
    );
    assert!(store.ledger_entries("none").await.unwrap().is_empty());

    // listing: newest first, by service
    let all = store
        .ledger_chains(&ChainFilter {
            limit: 10,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        all.iter().map(|h| h.chain.as_str()).collect::<Vec<_>>(),
        ["r1", "r2"]
    );
    let inv = store
        .ledger_chains(&ChainFilter {
            namespace: Some(NS.into()),
            service: Some("inventory".into()),
            limit: 10,
        })
        .await
        .unwrap();
    assert_eq!(
        inv.iter().map(|h| h.chain.as_str()).collect::<Vec<_>>(),
        ["r1"]
    );

    // sealing: quiet chains are listed, a seal of each length is kept once
    let unsealed = store
        .ledger_unsealed("2026-10-29T10:00:00.500Z", 10)
        .await
        .unwrap();
    assert_eq!(
        unsealed
            .iter()
            .map(|h| h.chain.as_str())
            .collect::<Vec<_>>(),
        ["r2"]
    );
    let keys = LedgerKeys::with_signer(SigningKey::from_seed(&[3; 32]));
    assert!(seal_head(store.as_ref(), &keys, &head).await.unwrap());
    assert!(
        !seal_head(store.as_ref(), &keys, &head).await.unwrap(),
        "sealed already"
    );
    let sealed = store.ledger_head("r1").await.unwrap();
    assert_eq!(sealed.sealed, 3);
    assert!(
        store
            .ledger_unsealed("2099-01-01T00:00:00.000Z", 10)
            .await
            .unwrap()
            .iter()
            .all(|h| h.chain != "r1")
    );
    let seals = store.ledger_seals("r1").await.unwrap();
    assert_eq!(seals.len(), 1);
    // a seal of more entries than the chain has is refused
    let too_long = agentsc_ledger::seal(keys.signer().unwrap(), "r1", 9, &head.head, "t");
    assert!(
        store
            .ledger_put_seal("r1", 9, "t", &too_long)
            .await
            .is_err()
    );

    // what a bundle of it holds verifies
    let bundle = Bundle {
        format: agentsc_ledger::BUNDLE_FORMAT.into(),
        exported_at: "t".into(),
        chain: "r1".into(),
        entries,
        seals,
    };
    let r = verify_bundle(&bundle, &keys.jwks());
    assert!(r.ok, "{}", r.text());
}

#[tokio::test]
async fn the_sqlite_store_keeps_the_ledger() {
    let store = SqliteStore::open_in_memory().unwrap();
    ledger_rules(store).await;
}

#[tokio::test]
async fn the_sqlite_ledger_is_append_only_and_a_version_2_file_gets_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("embassy.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(embassy::store::sqlite::SCHEMA).unwrap();
        conn.execute_batch(embassy::store::sqlite::MIGRATIONS[0].1)
            .unwrap();
        conn.pragma_update(None, "user_version", 2).unwrap();
    }
    let store = SqliteStore::open(&path).unwrap();
    store
        .ledger_append(
            "2026-10-29T10:00:00.000Z",
            &[lr("r1", "orders", 0), lr("r1", "orders", 1)],
        )
        .await
        .unwrap();
    drop(store);
    let conn = rusqlite::Connection::open(&path).unwrap();
    let refused = |sql: &str| conn.execute_batch(sql).unwrap_err().to_string();
    for sql in [
        "UPDATE ledger_entries SET record = '{}' WHERE seq = 0",
        "DELETE FROM ledger_entries WHERE seq = 1",
        "DELETE FROM ledger_heads",
    ] {
        assert!(refused(sql).contains("append-only"), "{sql}");
    }
    assert!(refused("UPDATE ledger_heads SET entries = 1").contains("never goes back"));
    // an entry that does not follow the head
    let gap = "INSERT INTO ledger_entries (chain, seq, ingested_at, record, prev_hash, hash, namespace, service, kind) \
               VALUES ('r1', 5, 't', '{}', '0000000000000000000000000000000000000000000000000000000000000000', \
               '1111111111111111111111111111111111111111111111111111111111111111', 'shop', 'orders', 'x')";
    assert!(refused(gap).contains("follow the head"));
}

async fn pg() -> Option<(Arc<PgStore>, Arc<PgStore>, tokio_postgres::Client)> {
    let Ok(base) = std::env::var("AGENTSC_TEST_POSTGRES_URL") else {
        eprintln!("AGENTSC_TEST_POSTGRES_URL is not set: the PostgreSQL ledger test did not run");
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
async fn the_postgres_store_keeps_the_ledger_append_only() {
    let Some((a, _, raw)) = pg().await else {
        return;
    };
    ledger_rules(a).await;
    for sql in [
        "UPDATE ledger_entries SET record = '{}' WHERE seq = 0",
        "DELETE FROM ledger_entries",
        "DELETE FROM ledger_seals",
        "UPDATE ledger_heads SET entries = 0",
    ] {
        assert!(raw.batch_execute(sql).await.is_err(), "{sql}");
    }
    assert!(
        raw.batch_execute("TRUNCATE ledger_entries CASCADE")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn two_replicas_appending_to_one_chain_keep_it_whole() {
    let Some((a, b, _)) = pg().await else {
        return;
    };
    let write = |s: Arc<PgStore>, who: usize| async move {
        for i in 0..20 {
            // two chains in each batch, in opposite orders on the two replicas
            let batch = if who == 0 {
                vec![lr("shared", "orders", i), lr("other", "orders", i)]
            } else {
                vec![lr("other", "inventory", i), lr("shared", "inventory", i)]
            };
            s.ledger_append(&common::now_ts(), &batch).await.unwrap();
        }
    };
    tokio::join!(write(a.clone(), 0), write(b.clone(), 1));
    for chain in ["shared", "other"] {
        let e = a.ledger_entries(chain).await.unwrap();
        assert_eq!(e.len(), 40, "{chain}");
        check_chain(chain, &e).unwrap();
    }
}

// ---- through Connect and the API --------------------------------------------------------------

const RUN: &str = "0c4a3f8e-aaaa-4bbb-8ccc-ddddeeeeffff";

fn quiet(kind: &str, over: Value) -> Value {
    let mut r = common::rec(
        kind,
        json!({"request_id": RUN, "input": null, "output": null}),
    );
    for (k, v) in over.as_object().unwrap() {
        r[k] = v.clone();
    }
    r
}

async fn ledger_env(with_key: bool) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("ledger.key");
    std::fs::write(
        &key,
        format!("{}\n", SigningKey::generate_seed_text().unwrap()),
    )
    .unwrap();
    let mut args = vec!["--ledger-seal-after".to_string(), "0".to_string()];
    if with_key {
        args.push("--ledger-key-file".into());
        args.push(key.display().to_string());
    }
    let env = Env::start_with(Opts {
        args,
        ..Default::default()
    })
    .await;
    std::mem::forget(dir);
    env
}

async fn send(env: &Env, records: Vec<Value>) -> common::Sidecar {
    let sc = env
        .sidecar(NS, "orders", hello(NS, "orders", "orders-1"))
        .await
        .unwrap();
    sc.send(sidecar_message::Msg::Audit(AuditBatch {
        records_json: records.iter().map(Value::to_string).collect(),
    }))
    .await;
    sc
}

async fn jwks(env: &Env) -> Jwks {
    let r = Env::send(env.req("GET", "/.well-known/jwks.json", None)).await;
    assert_eq!(r.status, 200, "{}", r.text);
    serde_json::from_value(r.body).unwrap()
}

#[tokio::test]
async fn a_run_sent_over_connect_comes_out_as_a_bundle_that_verifies_offline() {
    let env = ledger_env(true).await;
    env.create("orders", &orders_yaml()).await;
    let _sc = send(
        &env,
        vec![
            quiet("model_call", json!({"span_id": "00f067aa0ba902b1"})),
            quiet("tool_call", json!({"span_id": "00f067aa0ba902b2"})),
            quiet("agent_invocation", json!({})),
        ],
    )
    .await;
    common::eventually("the run in the ledger", || async {
        let r = env.get("/ledger/runs?service=orders", "carol").await;
        r.body
            .as_array()
            .is_some_and(|a| a.iter().any(|h| h["chain"] == RUN && h["entries"] == 3))
    })
    .await;
    // the sealer seals the quiet chain by itself
    common::eventually("sealed", || async {
        env.get(&format!("/ledger/runs/{RUN}"), "carol").await.body["sealed"] == 3
    })
    .await;

    let keys = jwks(&env).await;
    assert_eq!(keys.keys.len(), 1);
    let r = env
        .get(&format!("/ledger/runs/{RUN}/bundle"), "carol")
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert!(
        r.headers["content-disposition"]
            .to_str()
            .unwrap()
            .contains(".evidence.json")
    );
    let bundle: Bundle = serde_json::from_value(r.body.clone()).unwrap();
    let report = verify_bundle(&bundle, &keys);
    assert!(report.ok, "{}", report.text());
    assert_eq!(bundle.entries.len(), 3);
    // the records carry what embassy filled: the registry's agent_id
    assert!(
        bundle.entries[0].record["agent_id"]
            .as_str()
            .unwrap()
            .starts_with("agt_")
    );

    // tampered: the verifier says so
    let mut forged = bundle.clone();
    forged.entries[1].record["decision"] = json!("deny");
    assert!(!verify_bundle(&forged, &keys).ok);

    // scope: another namespace's caller sees nothing
    assert_eq!(
        env.get(&format!("/ledger/runs/{RUN}/bundle"), "dave")
            .await
            .status,
        404
    );
    assert!(
        env.get("/ledger/runs", "dave")
            .await
            .body
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(env.get("/ledger/runs?limit=0", "carol").await.status, 400);
    let keys_api = env.get("/ledger/keys", "carol").await;
    assert_eq!(serde_json::from_value::<Jwks>(keys_api.body).unwrap(), keys);

    // a run whose records carry payloads needs the payload permission
    let other = "0c4a3f8e-0000-4000-8000-000000000001";
    let _sc2 = send(
        &env,
        vec![common::rec(
            "agent_invocation",
            json!({"request_id": other}),
        )],
    )
    .await;
    common::eventually("the second run", || async {
        env.get(&format!("/ledger/runs/{other}"), "alice")
            .await
            .status
            == 200
    })
    .await;
    let r = env
        .get(&format!("/ledger/runs/{other}/bundle"), "carol")
        .await;
    assert_eq!(r.status, 403, "{}", r.text);
    let r = env
        .get(&format!("/ledger/runs/{other}/bundle"), "alice")
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let b: Bundle = serde_json::from_value(r.body).unwrap();
    assert!(verify_bundle(&b, &keys).ok, "an export seals first");

    let audit = env.hub.store.cp_audit(100).await.unwrap();
    let exports: Vec<_> = audit
        .iter()
        .filter(|r| r.action == CpAction::LedgerExport)
        .collect();
    assert_eq!(exports.len(), 3, "two exports and one refusal");
    assert!(
        exports
            .iter()
            .any(|r| r.actor == "carol" && r.reason.as_deref().unwrap_or("").contains("3 entries"))
    );
    env.stop().await;
}

#[tokio::test]
async fn without_a_key_chains_are_kept_and_nothing_is_sealed() {
    let env = ledger_env(false).await;
    env.create("orders", &orders_yaml()).await;
    let _sc = send(&env, vec![quiet("agent_invocation", json!({}))]).await;
    common::eventually("the run in the ledger", || async {
        env.get(&format!("/ledger/runs/{RUN}"), "alice")
            .await
            .status
            == 200
    })
    .await;
    assert!(jwks(&env).await.keys.is_empty());
    let r = env
        .get(&format!("/ledger/runs/{RUN}/bundle"), "alice")
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let b: Bundle = serde_json::from_value(r.body).unwrap();
    assert!(b.seals.is_empty());
    let report = verify_bundle(&b, &Jwks::default());
    let failed: Vec<_> = report
        .checks
        .iter()
        .filter(|c| !c.ok)
        .map(|c| c.name.as_str())
        .collect();
    assert_eq!(failed, ["seals"]);
    env.stop().await;
}

// ---- retention (#31) ------------------------------------------------------------------------------

/// Purging removes only whole chains a seal covers, leaves a purge record, and never touches a
/// bundle exported before: it still verifies with the keys alone.
async fn purge_rules(store: Arc<dyn SecOpsStore>) -> Bundle {
    let keys = LedgerKeys::with_signer(SigningKey::from_seed(&[5; 32]));
    let t0 = "2026-10-29T10:00:00.000Z";
    store
        .ledger_append(
            t0,
            &[
                lr("old", "orders", 0),
                lr("old", "orders", 1),
                lr("open", "orders", 0),
                lr("partly", "orders", 0),
            ],
        )
        .await
        .unwrap();
    for chain in ["old", "partly"] {
        let h = store.ledger_head(chain).await.unwrap();
        assert!(seal_head(store.as_ref(), &keys, &h).await.unwrap());
    }
    store
        .ledger_append(t0, &[lr("partly", "orders", 1)])
        .await
        .unwrap();
    let bundle = Bundle {
        format: agentsc_ledger::BUNDLE_FORMAT.into(),
        exported_at: t0.into(),
        chain: "old".into(),
        entries: store.ledger_entries("old").await.unwrap(),
        seals: store.ledger_seals("old").await.unwrap(),
    };
    assert!(verify_bundle(&bundle, &keys.jwks()).ok);

    // nothing is older than the cut-off yet
    assert!(
        store
            .ledger_purge(t0, 10, "embassy:retention", "t1")
            .await
            .unwrap()
            .is_empty()
    );
    let gone = store
        .ledger_purge("2099-01-01T00:00:00.000Z", 10, "embassy:retention", "t1")
        .await
        .unwrap();
    assert_eq!(
        gone.iter().map(|c| c.chain.as_str()).collect::<Vec<_>>(),
        ["old"],
        "only a whole sealed chain"
    );
    let p = store.ledger_purged("old").await.unwrap().unwrap();
    assert_eq!(
        (p.entries, p.head.as_str()),
        (2, bundle.entries[1].hash.as_str())
    );
    assert_eq!(
        p.seal,
        bundle.seals.last().unwrap().statement,
        "the covering seal is kept"
    );
    assert_eq!(
        store.ledger_head("old").await,
        Err(embassy::store::StoreError::NotFound)
    );
    assert!(store.ledger_entries("old").await.unwrap().is_empty());
    // the bundle exported before still verifies; what is left still holds
    assert!(
        verify_bundle(&bundle, &keys.jwks()).ok,
        "a purge never breaks an exported bundle"
    );
    for chain in ["open", "partly"] {
        check_chain(chain, &store.ledger_entries(chain).await.unwrap()).unwrap();
    }
    // a late record of the purged run is not kept; a second purge finds nothing
    store
        .ledger_append("t2", &[lr("old", "orders", 9)])
        .await
        .unwrap();
    assert!(store.ledger_entries("old").await.unwrap().is_empty());
    assert!(
        store
            .ledger_purge("2099-01-01T00:00:00.000Z", 10, "x", "t3")
            .await
            .unwrap()
            .is_empty()
    );
    bundle
}

#[tokio::test]
async fn the_sqlite_ledger_purges_whole_sealed_chains_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("embassy.db");
    let store = SqliteStore::open(&path).unwrap();
    purge_rules(store.clone()).await;
    drop(store);
    let conn = rusqlite::Connection::open(&path).unwrap();
    for sql in [
        "DELETE FROM ledger_entries WHERE chain = 'open'",
        "DELETE FROM ledger_heads WHERE chain = 'partly'",
        "DELETE FROM ledger_purges",
        "INSERT INTO ledger_purges VALUES ('partly', 2, '0000000000000000000000000000000000000000000000000000000000000000', 's', 't', 't', 'x')",
    ] {
        assert!(conn.execute_batch(sql).is_err(), "{sql}");
    }
}

#[tokio::test]
async fn the_postgres_ledger_purges_whole_sealed_chains_and_nothing_else() {
    let Some((a, _, raw)) = pg().await else {
        return;
    };
    purge_rules(a).await;
    for sql in [
        "DELETE FROM ledger_entries WHERE chain = 'open'",
        "DELETE FROM ledger_heads WHERE chain = 'partly'",
        "DELETE FROM ledger_purges",
        "TRUNCATE ledger_chain_services CASCADE",
    ] {
        assert!(raw.batch_execute(sql).await.is_err(), "{sql}");
    }
}

#[tokio::test]
async fn a_purged_run_is_gone_from_the_api_and_its_bundle_still_verifies() {
    let env = ledger_env(true).await;
    env.create("orders", &orders_yaml()).await;
    let _sc = send(&env, vec![quiet("agent_invocation", json!({}))]).await;
    common::eventually("sealed", || async {
        env.get(&format!("/ledger/runs/{RUN}"), "alice").await.body["sealed"] == 1
    })
    .await;
    let bundle: Bundle = serde_json::from_value(
        env.get(&format!("/ledger/runs/{RUN}/bundle"), "alice")
            .await
            .body,
    )
    .unwrap();
    let keys = jwks(&env).await;
    let n = embassy::secops::ledger::purge_before(&env.hub, "2099-01-01T00:00:00.000Z")
        .await
        .unwrap();
    assert_eq!(n, 1);
    let r = env.get(&format!("/ledger/runs/{RUN}"), "alice").await;
    assert_eq!(r.status, 404);
    assert!(r.details().contains("was purged at"), "{}", r.text);
    assert!(verify_bundle(&bundle, &keys).ok);
    let audit = env.hub.store.cp_audit(200).await.unwrap();
    let purge = audit
        .iter()
        .find(|r| r.action == CpAction::LedgerPurge)
        .unwrap();
    assert_eq!(purge.actor, "embassy:retention");
    assert!(
        purge
            .reason
            .as_deref()
            .unwrap()
            .starts_with("1 chain(s), 1 entries"),
        "{purge:?}"
    );
    // retention must be 1..=36500 days
    let mut cfg = embassy::config::ControlPlaneConfig::default();
    cfg.ledger.retention_days = Some(0);
    assert!(
        cfg.validate("agentsc-system")
            .unwrap_err()
            .iter()
            .any(|e| e.contains("retention_days"))
    );
    cfg.ledger.retention_days = Some(30);
    assert!(cfg.validate("agentsc-system").is_ok());
    env.stop().await;
}
