//! The `postgres` store (store/postgres.rs, docs/design/agentsecops-merge.md §7): what the SQLite
//! store does (tests/sqlite_store.rs), and what many replicas on one database need: migrations
//! applied once, writes that serialize, events that reach the other replicas, and a listen
//! connection that comes back and resyncs.
//!
//! Needs a PostgreSQL server: `AGENTSC_TEST_POSTGRES_URL=postgres://user@host:port/db` (CI runs
//! one). Without it every test passes without running, and says so on stderr. Each test gets a
//! schema of its own.
mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use common::{NS, orders_yaml, support_yaml};
use embassy::config::Role;
use embassy::store::file::yaml_to_json;
use embassy::store::postgres::{PgOptions, PgStore};
use embassy::store::{
    Actor, ActorKind, ChangeSource, CharterWrite, Note, NoteSource, PendingAdoption, Precondition,
    Proposal, ProposalFilter, ProposalPut, ProposalStatus, ServiceKey, Store, StoreError,
    StoreEvent,
};

fn alice() -> Actor {
    Actor {
        name: "alice".into(),
        kind: ActorKind::Token,
        role: Some(Role::Admin),
    }
}

fn write(yaml: &str) -> CharterWrite {
    CharterWrite {
        yaml: yaml.to_string(),
        charter_json: yaml_to_json(yaml).unwrap(),
        actor: alice(),
        source: ChangeSource::Api,
    }
}

fn proposal(id: &str, agent: &str, note: &str) -> Proposal {
    Proposal {
        id: id.into(),
        namespace: NS.into(),
        service: "support".into(),
        agent: agent.into(),
        note: note.into(),
        rationale: "r".into(),
        request_id: "q".into(),
        trace_id: String::new(),
        ts: common::now_ts(),
        status: ProposalStatus::Pending,
        auto: false,
    }
}

/// A database for one test: a new schema in `AGENTSC_TEST_POSTGRES_URL`'s database, and a raw
/// client on it. `None` (with a note) when the variable is not set.
struct Db {
    url: String,
    schema: String,
    raw: tokio_postgres::Client,
}

async fn db() -> Option<Db> {
    let Ok(base) = std::env::var("AGENTSC_TEST_POSTGRES_URL") else {
        eprintln!("AGENTSC_TEST_POSTGRES_URL is not set: the PostgreSQL store test did not run");
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
    let (raw, conn) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(conn);
    Some(Db { url, schema, raw })
}

async fn open_as(db: &Db, name: &str) -> Arc<PgStore> {
    PgStore::open(PgOptions {
        url: db.url.clone(),
        ca_file: None,
        pool_size: 4,
        application_name: format!("{}-{name}", db.schema),
    })
    .await
    .unwrap()
}

async fn open(db: &Db) -> Arc<PgStore> {
    open_as(db, "a").await
}

/// The next event, within 10 s.
async fn next(rx: &mut tokio::sync::broadcast::Receiver<StoreEvent>) -> StoreEvent {
    tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("an event within 10 s")
        .unwrap()
}

#[tokio::test]
async fn versions_epochs_history_and_revisions() {
    let Some(db) = db().await else { return };
    let store = open(&db).await;
    assert_eq!(store.schema(), db.schema);
    let key = ServiceKey::new(NS, "orders");
    assert_eq!(store.get_charter(&key).await, Err(StoreError::NotFound));
    assert!(store.list_services().await.unwrap().is_empty());
    assert_eq!(
        store
            .put_charter(
                &key,
                &Precondition::Version("0".into()),
                write(&orders_yaml())
            )
            .await,
        Err(StoreError::NotFound)
    );
    let v1 = store
        .put_charter(&key, &Precondition::NotExists, write(&orders_yaml()))
        .await
        .unwrap();
    assert_eq!(v1.version, "1");
    assert_eq!(
        store.list_services().await.unwrap(),
        std::slice::from_ref(&key)
    );
    assert_eq!(
        store.get_charter(&key).await.unwrap(),
        v1,
        "the JSON round-trips through jsonb"
    );

    let v2_yaml = orders_yaml().replace("app_port: 8080", "app_port: 8082");
    assert_eq!(
        store
            .put_charter(&key, &Precondition::NotExists, write(&v2_yaml))
            .await,
        Err(StoreError::Conflict {
            current: "1".into()
        })
    );
    assert_eq!(
        store
            .put_charter(&key, &Precondition::Version("7".into()), write(&v2_yaml))
            .await,
        Err(StoreError::Conflict {
            current: "1".into()
        })
    );
    let v2 = store
        .put_charter(&key, &Precondition::Version("1".into()), write(&v2_yaml))
        .await
        .unwrap();
    assert_eq!((v2.version.as_str(), &v2.epoch), ("2", &v1.epoch));
    let hist = store.history(&key).await.unwrap();
    assert_eq!(
        hist.iter().map(|h| h.version.as_str()).collect::<Vec<_>>(),
        ["2", "1"]
    );
    assert!(
        hist.iter()
            .all(|h| h.actor == "alice" && h.sha256.len() == 64)
    );
    assert_eq!(store.get_revision(&key, "1").await.unwrap(), orders_yaml());
    assert_eq!(
        store.get_revision(&key, "3").await,
        Err(StoreError::NotFound)
    );
    assert_eq!(
        store.get_revision(&key, "x").await,
        Err(StoreError::NotFound)
    );

    assert_eq!(
        store.delete_service(&key, "1", &alice()).await,
        Err(StoreError::Conflict {
            current: "2".into()
        })
    );
    store.delete_service(&key, "2", &alice()).await.unwrap();
    assert_eq!(store.get_charter(&key).await, Err(StoreError::NotFound));
    assert_eq!(store.history(&key).await, Err(StoreError::NotFound));
    let v3 = store
        .put_charter(&key, &Precondition::NotExists, write(&orders_yaml()))
        .await
        .unwrap();
    assert_eq!(v3.version, "3", "a recreated service continues the counter");
    assert_ne!(v3.epoch, v1.epoch);

    // another process on the same database sees it all
    drop(store);
    let again = open(&db).await;
    let got = again.get_charter(&key).await.unwrap();
    assert_eq!((got.version.as_str(), got.epoch), ("3", v3.epoch));
}

#[tokio::test]
async fn memory_is_versioned_and_pruned_by_charter_writes() {
    let Some(db) = db().await else { return };
    let store = open(&db).await;
    let key = ServiceKey::new(NS, "support");
    let m = store.get_memory(&key).await.unwrap();
    assert_eq!((m.version.as_str(), m.agents.len()), ("0", 0));
    store
        .put_charter(&key, &Precondition::NotExists, write(&support_yaml(true)))
        .await
        .unwrap();
    let note = |id: &str| Note {
        id: id.into(),
        text: format!("note {id}"),
        source: NoteSource::Manual,
        request_id: None,
        trace_id: Some("t".into()),
        approved_by: Some("alice".into()),
        ts: common::now_ts(),
        expires_at: None,
    };
    let mut agents = BTreeMap::new();
    agents.insert("helper".to_string(), vec![note("a"), note("b")]);
    agents.insert("faq".to_string(), vec![note("c")]);
    agents.insert("empty".to_string(), vec![]);
    assert_eq!(
        store.put_memory(&key, "3", agents.clone(), &alice()).await,
        Err(StoreError::Conflict {
            current: "0".into()
        })
    );
    let m1 = store.put_memory(&key, "0", agents, &alice()).await.unwrap();
    assert_eq!(m1.version, "1");
    assert_eq!(
        m1.agents.keys().cloned().collect::<Vec<_>>(),
        ["faq", "helper"]
    );
    assert_eq!(store.get_memory(&key).await.unwrap(), m1);
    store
        .put_charter(
            &key,
            &Precondition::Version("1".into()),
            write(&support_yaml(false)),
        )
        .await
        .unwrap();
    let m2 = store.get_memory(&key).await.unwrap();
    assert_eq!(m2.version, "2");
    assert!(m2.agents.is_empty(), "{m2:?}");
}

#[tokio::test]
async fn proposals_dedup_list_and_decide() {
    let Some(db) = db().await else { return };
    let store = open(&db).await;
    let key = ServiceKey::new(NS, "support");
    store
        .put_charter(&key, &Precondition::NotExists, write(&support_yaml(true)))
        .await
        .unwrap();
    let p1 = proposal("p1", "helper", "short note");
    assert_eq!(
        store.put_proposal(&p1, Some("d1")).await.unwrap(),
        ProposalPut::Stored
    );
    assert_eq!(
        store
            .put_proposal(&proposal("p9", "helper", "again"), Some("d1"))
            .await
            .unwrap(),
        ProposalPut::Duplicate {
            existing_id: "p1".into()
        }
    );
    let mut p2 = proposal("p2", "helper", "x".repeat(61).as_str());
    p2.ts = "2026-10-24T11:00:00.000Z".into();
    store.put_proposal(&p2, Some("d2")).await.unwrap();
    store
        .put_proposal(&proposal("p3", "faq", "faq learns nothing"), Some("d3"))
        .await
        .unwrap();
    let all = store
        .list_proposals(&ProposalFilter::default())
        .await
        .unwrap();
    assert_eq!(all.len(), 3);
    assert!(
        all.windows(2)
            .all(|w| (w[0].ts.as_str(), w[0].id.as_str()) >= (w[1].ts.as_str(), w[1].id.as_str()))
    );
    let filtered = store
        .list_proposals(&ProposalFilter {
            status: Some(ProposalStatus::Pending),
            namespace: Some(NS.into()),
            service: Some("support".into()),
        })
        .await
        .unwrap();
    assert_eq!(filtered.len(), 3);
    assert_eq!(store.get_proposal("nope").await, Err(StoreError::NotFound));

    assert_eq!(
        store.approve_proposal(&key, "p1", "4", &alice()).await,
        Err(StoreError::Conflict {
            current: "0".into()
        })
    );
    let (m, d) = store
        .approve_proposal(&key, "p1", "0", &alice())
        .await
        .unwrap();
    assert_eq!(
        (m.version.as_str(), d.status),
        ("1", ProposalStatus::Approved)
    );
    assert_eq!(m.agents["helper"][0].text, "short note");
    assert_eq!(
        store.reject_proposal(&key, "p1", "1", &alice()).await,
        Err(StoreError::NotPending {
            status: ProposalStatus::Approved
        })
    );
    assert!(matches!(
        store.approve_proposal(&key, "p2", "1", &alice()).await,
        Err(StoreError::Invalid(_))
    ));
    let (_, d) = store
        .reject_proposal(&key, "p3", "1", &alice())
        .await
        .unwrap();
    assert_eq!(d.status, ProposalStatus::Rejected);
    store.delete_service(&key, "1", &alice()).await.unwrap();
    assert!(
        store
            .list_proposals(&ProposalFilter::default())
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn pending_adoptions_are_shared_by_the_replicas() {
    let Some(db) = db().await else { return };
    let (a, b) = (open_as(&db, "a").await, open_as(&db, "b").await);
    let key = ServiceKey::new(NS, "orders");
    let adoption = PendingAdoption {
        key: key.clone(),
        sha256: "a".repeat(64),
        pod: "orders-0".into(),
        ts: common::now_ts(),
        yaml: orders_yaml(),
    };
    a.put_pending_adoption(adoption.clone()).await.unwrap();
    assert_eq!(
        b.list_pending_adoptions().await.unwrap(),
        std::slice::from_ref(&adoption)
    );
    assert_eq!(
        b.take_pending_adoption(&key, &"b".repeat(64)).await,
        Err(StoreError::NotFound)
    );
    assert_eq!(
        b.take_pending_adoption(&key, &adoption.sha256)
            .await
            .unwrap(),
        adoption
    );
    assert!(
        a.list_pending_adoptions().await.unwrap().is_empty(),
        "taken once, for all"
    );
    a.put_pending_adoption(adoption.clone()).await.unwrap();
    b.put_charter(&key, &Precondition::NotExists, write(&orders_yaml()))
        .await
        .unwrap();
    assert!(a.list_pending_adoptions().await.unwrap().is_empty());
    assert_eq!(
        a.put_pending_adoption(adoption).await,
        Err(StoreError::Conflict {
            current: "1".into()
        })
    );
}

#[tokio::test]
async fn the_audit_is_persisted_and_append_only() {
    let Some(db) = db().await else { return };
    let store = open(&db).await;
    let rec: embassy::cp_audit::CpAuditRecord = serde_json::from_value(serde_json::json!({
        "ts": "2026-10-24T10:00:00.000Z", "actor": "alice", "actor_kind": "token", "role": "admin",
        "action": "charter_put", "namespace": NS, "service": "orders", "agent": null,
        "from_version": "1", "to_version": "2", "sha256_before": "a".repeat(64),
        "sha256_after": "b".repeat(64), "result": "ok", "reason": null
    }))
    .unwrap();
    store.append_cp_audit(&rec).await.unwrap();
    let mut second = rec.clone();
    second.to_version = Some("3".into());
    store.append_cp_audit(&second).await.unwrap();
    assert_eq!(
        store.cp_audit(10).await.unwrap(),
        [rec.clone(), second.clone()]
    );
    assert_eq!(store.cp_audit(1).await.unwrap(), [second]);
    for sql in [
        "DELETE FROM cp_audit",
        "UPDATE cp_audit SET actor = 'mallory'",
        "TRUNCATE cp_audit",
    ] {
        let e = db.raw.batch_execute(sql).await.unwrap_err();
        assert!(format!("{e:?}").contains("append-only"), "{sql}: {e:?}");
    }
    // the schema's other floors hold for raw SQL too
    let id: i64 = db
        .raw
        .query_one(
            "INSERT INTO services (namespace, service) VALUES ('shop', 'raw') RETURNING id",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let e = db
        .raw
        .execute(
            "INSERT INTO charter_versions (service_id, version, epoch, yaml, json, sha256, ts, actor, actor_kind, source) \
             VALUES ($1, 2, 'e', 'a: 1', '{}', repeat('0', 64), 't', 'x', 'token', 'api')",
            &[&id],
        )
        .await
        .unwrap_err();
    assert!(format!("{e:?}").contains("next version"), "{e:?}");
}

#[tokio::test]
async fn replicas_starting_together_migrate_once_and_a_newer_schema_is_refused() {
    let Some(db) = db().await else { return };
    let opened = futures::future::join_all((0..4).map(|i| {
        let db = &db;
        async move { open_as(db, &format!("r{i}")).await }
    }))
    .await;
    assert_eq!(opened.len(), 4);
    let rows = db
        .raw
        .query("SELECT version FROM agentsc_schema_migrations", &[])
        .await
        .unwrap();
    assert_eq!(
        rows.iter().map(|r| r.get::<_, i64>(0)).collect::<Vec<_>>(),
        [1]
    );
    db.raw
        .execute(
            "INSERT INTO agentsc_schema_migrations (version) VALUES (99)",
            &[],
        )
        .await
        .unwrap();
    let e = PgStore::open(PgOptions {
        url: db.url.clone(),
        ca_file: None,
        pool_size: 1,
        application_name: "newer".into(),
    })
    .await
    .unwrap_err();
    assert!(e.to_string().contains("newer embassy"), "{e}");
}

#[tokio::test]
async fn writes_of_two_replicas_serialize_and_exactly_one_wins() {
    let Some(db) = db().await else { return };
    let (a, b) = (open_as(&db, "a").await, open_as(&db, "b").await);
    let key = ServiceKey::new(NS, "support");
    let (ra, rb) = tokio::join!(
        a.put_charter(&key, &Precondition::NotExists, write(&support_yaml(true))),
        b.put_charter(&key, &Precondition::NotExists, write(&support_yaml(true))),
    );
    let results = [ra, rb];
    assert_eq!(
        results.iter().filter(|r| r.is_ok()).count(),
        1,
        "{results:?}"
    );
    assert!(results.contains(&Err(StoreError::Conflict {
        current: "1".into()
    })));
    let v1 = Precondition::Version("1".into());
    let (ra, rb) = tokio::join!(
        a.put_charter(&key, &v1, write(&support_yaml(true))),
        b.put_charter(&key, &v1, write(&support_yaml(true))),
    );
    let results = [ra, rb];
    assert_eq!(
        results.iter().filter(|r| r.is_ok()).count(),
        1,
        "{results:?}"
    );
    assert!(results.contains(&Err(StoreError::Conflict {
        current: "2".into()
    })));
    // an approve and a reject of one proposal on two replicas: one decides it
    a.put_proposal(&proposal("p1", "helper", "a lesson"), Some("d1"))
        .await
        .unwrap();
    let who = alice();
    let (ra, rb) = tokio::join!(
        a.approve_proposal(&key, "p1", "0", &who),
        b.reject_proposal(&key, "p1", "0", &who),
    );
    assert_eq!(
        [ra.is_ok(), rb.is_ok()].iter().filter(|ok| **ok).count(),
        1,
        "{ra:?} {rb:?}"
    );
    assert!(matches!(
        ra.as_ref().err().or(rb.as_ref().err()),
        Some(StoreError::NotPending { .. }) | Some(StoreError::Conflict { .. })
    ));
}

#[tokio::test]
async fn a_change_on_one_replica_reaches_the_others_subscribers() {
    let Some(db) = db().await else { return };
    let (a, b) = (open_as(&db, "a").await, open_as(&db, "b").await);
    let mut on_a = a.subscribe();
    let mut on_b = b.subscribe();
    let key = ServiceKey::new(NS, "orders");
    let v1 = a
        .put_charter(&key, &Precondition::NotExists, write(&orders_yaml()))
        .await
        .unwrap();
    for rx in [&mut on_a, &mut on_b] {
        match next(rx).await {
            StoreEvent::CharterChanged {
                key: k,
                epoch,
                version,
                actor,
                source,
            } => {
                assert_eq!(
                    (k, epoch, version),
                    (key.clone(), v1.epoch.clone(), "1".to_string())
                );
                assert_eq!((actor, source), (alice(), ChangeSource::Api));
            }
            other => panic!("{other:?}"),
        }
    }
    b.delete_service(&key, "1", &alice()).await.unwrap();
    assert!(matches!(next(&mut on_a).await, StoreEvent::ServiceDeleted { key: k, .. } if k == key));
    assert!(matches!(
        next(&mut on_b).await,
        StoreEvent::ServiceDeleted { .. }
    ));
    assert!(
        on_b.try_recv().is_err(),
        "a replica's own event comes once, not again by NOTIFY"
    );
}

#[tokio::test]
async fn a_broken_listen_connection_comes_back_and_resyncs() {
    let Some(db) = db().await else { return };
    let a = open_as(&db, "a").await;
    let b = open_as(&db, "b").await;
    let mut on_b = b.subscribe();
    let key = ServiceKey::new(NS, "orders");
    // b's listen connection goes away (a failover, a restart of the server's process)
    let killed: bool = db
        .raw
        .query_one(
            "SELECT bool_or(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE application_name = $1",
            &[&format!("{}-b-listen", db.schema)],
        )
        .await
        .unwrap()
        .get(0);
    assert!(killed, "b's listen connection was found");
    // a writes while b may not be listening; b must still learn of it
    let v1 = a
        .put_charter(&key, &Precondition::NotExists, write(&orders_yaml()))
        .await
        .unwrap();
    let mut seen = None;
    for _ in 0..4 {
        if let StoreEvent::CharterChanged {
            key: k,
            version,
            epoch,
            ..
        } = next(&mut on_b).await
        {
            seen = Some((k, version, epoch));
            break;
        }
    }
    assert_eq!(seen, Some((key.clone(), "1".to_string(), v1.epoch)));
    // and it keeps listening afterwards
    let v2 = a
        .put_charter(
            &key,
            &Precondition::Version("1".into()),
            write(&orders_yaml()),
        )
        .await
        .unwrap();
    let mut latest = None;
    while let Ok(Ok(e)) = tokio::time::timeout(Duration::from_secs(5), on_b.recv()).await {
        if let StoreEvent::CharterChanged { version, .. } = e {
            latest = Some(version.clone());
            if version == v2.version {
                break;
            }
        }
    }
    assert_eq!(latest, Some("2".to_string()));
}

#[tokio::test]
async fn keys_sort_bytewise_and_bad_keys_are_not_found() {
    let Some(db) = db().await else { return };
    let store = open(&db).await;
    for svc in ["ab", "a-b", "a0", "b"] {
        store
            .put_charter(
                &ServiceKey::new(NS, svc),
                &Precondition::NotExists,
                write(&orders_yaml()),
            )
            .await
            .unwrap();
    }
    let got: Vec<String> = store
        .list_services()
        .await
        .unwrap()
        .into_iter()
        .map(|k| k.service)
        .collect();
    assert_eq!(got, ["a-b", "a0", "ab", "b"], "like SQLite's BINARY order");
    let bad = ServiceKey::new("Shop", "orders");
    assert_eq!(store.get_charter(&bad).await, Err(StoreError::NotFound));
    assert_eq!(
        store
            .put_charter(&bad, &Precondition::NotExists, write(&orders_yaml()))
            .await,
        Err(StoreError::NotFound)
    );
}
