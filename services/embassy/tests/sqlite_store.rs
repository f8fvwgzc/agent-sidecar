//! The `sqlite:<path>` store (docs/adr/0003-sqlite-store-schema.md): versions and epochs, the
//! history, memory pruning, proposals, reopening, and what the schema refuses.
mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use common::{NS, orders_yaml, support_yaml};
use embassy::config::Role;
use embassy::store::file::yaml_to_json;
use embassy::store::sqlite::SqliteStore;
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

async fn open(dir: &std::path::Path) -> Arc<SqliteStore> {
    SqliteStore::open(dir.join("embassy.db")).unwrap()
}

#[tokio::test]
async fn versions_epochs_history_and_revisions() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path()).await;
    let key = ServiceKey::new(NS, "orders");
    assert_eq!(store.get_charter(&key).await, Err(StoreError::NotFound));
    assert!(store.list_services().await.unwrap().is_empty());

    // the first charter needs If-None-Match: *
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
    assert!(!v1.epoch.is_empty());
    assert_eq!(
        store.list_services().await.unwrap(),
        std::slice::from_ref(&key)
    );
    let got = store.get_charter(&key).await.unwrap();
    assert_eq!(got, v1);

    // a stale precondition is a conflict naming the current version
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

    // history newest first, every revision readable
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
    assert_eq!(store.get_revision(&key, "2").await.unwrap(), v2_yaml);
    assert_eq!(
        store.get_revision(&key, "3").await,
        Err(StoreError::NotFound)
    );
    assert_eq!(
        store.get_revision(&key, "x").await,
        Err(StoreError::NotFound)
    );

    // delete: If-Match must be the current version; afterwards the service is gone, but a
    // recreated one continues the counter in a new epoch
    assert_eq!(
        store.delete_service(&key, "1", &alice()).await,
        Err(StoreError::Conflict {
            current: "2".into()
        })
    );
    store.delete_service(&key, "2", &alice()).await.unwrap();
    assert_eq!(store.get_charter(&key).await, Err(StoreError::NotFound));
    assert_eq!(store.history(&key).await, Err(StoreError::NotFound));
    assert!(store.list_services().await.unwrap().is_empty());
    let v3 = store
        .put_charter(&key, &Precondition::NotExists, write(&orders_yaml()))
        .await
        .unwrap();
    assert_eq!(v3.version, "3");
    assert_ne!(v3.epoch, v1.epoch);
    assert_eq!(
        store
            .history(&key)
            .await
            .unwrap()
            .iter()
            .map(|h| h.version.clone())
            .collect::<Vec<_>>(),
        ["3"]
    );

    // the same file, reopened: everything is still there
    drop(store);
    let again = open(dir.path()).await;
    let got = again.get_charter(&key).await.unwrap();
    assert_eq!((got.version.as_str(), got.epoch), ("3", v3.epoch));
    assert_eq!(again.get_revision(&key, "3").await.unwrap(), orders_yaml());
}

#[tokio::test]
async fn events_are_broadcast() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path()).await;
    let mut rx = store.subscribe();
    let key = ServiceKey::new(NS, "orders");
    let v1 = store
        .put_charter(&key, &Precondition::NotExists, write(&orders_yaml()))
        .await
        .unwrap();
    match rx.recv().await.unwrap() {
        StoreEvent::CharterChanged {
            key: k,
            epoch,
            version,
            actor,
            source,
        } => {
            assert_eq!(
                (k, epoch, version),
                (key.clone(), v1.epoch, "1".to_string())
            );
            assert_eq!((actor.name.as_str(), source), ("alice", ChangeSource::Api));
        }
        other => panic!("{other:?}"),
    }
    store.delete_service(&key, "1", &alice()).await.unwrap();
    assert!(matches!(
        rx.recv().await.unwrap(),
        StoreEvent::ServiceDeleted { key: k, .. } if k == key
    ));
}

#[tokio::test]
async fn memory_is_versioned_and_pruned_by_charter_writes() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path()).await;
    let key = ServiceKey::new(NS, "support");
    // memory before any charter: version 0, empty
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
        ["faq", "helper"],
        "an agent without notes is not kept"
    );
    assert_eq!(
        m1.agents["helper"]
            .iter()
            .map(|n| n.id.as_str())
            .collect::<Vec<_>>(),
        ["a", "b"],
        "notes keep their order"
    );
    assert_eq!(store.get_memory(&key).await.unwrap(), m1);

    // turning learning off drops helper's notes in the same change; faq never learned, so its
    // notes go too (memory exists only for agents with learning enabled)
    let mut rx = store.subscribe();
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
    let mut saw_memory = false;
    for _ in 0..2 {
        if let StoreEvent::MemoryChanged { version, .. } = rx.recv().await.unwrap() {
            assert_eq!(version, "2");
            saw_memory = true;
        }
    }
    assert!(saw_memory);
}

#[tokio::test]
async fn proposals_dedup_list_and_decide() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path()).await;
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
    let p3 = proposal("p3", "faq", "faq learns nothing");
    store.put_proposal(&p3, Some("d3")).await.unwrap();

    let all = store
        .list_proposals(&ProposalFilter::default())
        .await
        .unwrap();
    assert_eq!(all.len(), 3);
    assert!(
        all.windows(2)
            .all(|w| (w[0].ts.as_str(), w[0].id.as_str()) >= (w[1].ts.as_str(), w[1].id.as_str())),
        "newest first: {all:?}"
    );
    let pending_support = store
        .list_proposals(&ProposalFilter {
            status: Some(ProposalStatus::Pending),
            namespace: Some(NS.into()),
            service: Some("support".into()),
        })
        .await
        .unwrap();
    assert_eq!(pending_support.len(), 3);
    assert!(
        store
            .list_proposals(&ProposalFilter {
                service: Some("orders".into()),
                ..Default::default()
            })
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(store.get_proposal("p1").await.unwrap().note, "short note");
    assert_eq!(store.get_proposal("nope").await, Err(StoreError::NotFound));

    // approve: needs the memory version; stores the note; the proposal is decided for good
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
    assert_eq!(m.agents["helper"][0].source, NoteSource::Review);
    assert_eq!(m.agents["helper"][0].approved_by.as_deref(), Some("alice"));
    assert_eq!(
        store.reject_proposal(&key, "p1", "1", &alice()).await,
        Err(StoreError::NotPending {
            status: ProposalStatus::Approved
        })
    );
    assert_eq!(
        store.get_proposal("p1").await.unwrap().status,
        ProposalStatus::Approved
    );
    // too long for max_note_chars (60): refused, memory untouched
    let e = store
        .approve_proposal(&key, "p2", "1", &alice())
        .await
        .unwrap_err();
    assert!(matches!(e, StoreError::Invalid(_)), "{e:?}");
    assert_eq!(store.get_memory(&key).await.unwrap().version, "1");
    // faq does not learn: approving is refused, rejecting is fine
    let e = store
        .approve_proposal(&key, "p3", "1", &alice())
        .await
        .unwrap_err();
    assert!(matches!(e, StoreError::Invalid(_)), "{e:?}");
    let (m, d) = store
        .reject_proposal(&key, "p3", "1", &alice())
        .await
        .unwrap();
    assert_eq!(
        (m.version.as_str(), d.status),
        ("1", ProposalStatus::Rejected)
    );
    // a proposal of another service, or an unknown one
    assert_eq!(
        store
            .approve_proposal(&ServiceKey::new(NS, "orders"), "p2", "1", &alice())
            .await,
        Err(StoreError::NotFound)
    );
    assert_eq!(
        store.approve_proposal(&key, "p8", "1", &alice()).await,
        Err(StoreError::NotFound)
    );
    // deleting the service takes its proposals and notes with it
    store.delete_service(&key, "1", &alice()).await.unwrap();
    assert!(
        store
            .list_proposals(&ProposalFilter::default())
            .await
            .unwrap()
            .is_empty()
    );
    let m = store.get_memory(&key).await.unwrap();
    assert_eq!((m.version.as_str(), m.agents.len()), ("1", 0));
}

#[tokio::test]
async fn pending_adoptions_live_in_memory() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path()).await;
    let key = ServiceKey::new(NS, "orders");
    let adoption = PendingAdoption {
        key: key.clone(),
        sha256: "a".repeat(64),
        pod: "orders-0".into(),
        ts: common::now_ts(),
        yaml: orders_yaml(),
    };
    store.put_pending_adoption(adoption.clone()).await.unwrap();
    assert_eq!(
        store.list_pending_adoptions().await.unwrap(),
        std::slice::from_ref(&adoption)
    );
    assert_eq!(
        store.take_pending_adoption(&key, "b").await,
        Err(StoreError::NotFound)
    );
    assert_eq!(
        store
            .take_pending_adoption(&key, &adoption.sha256)
            .await
            .unwrap(),
        adoption
    );
    // storing the charter clears a pending adoption, and a stored charter refuses a new one
    store.put_pending_adoption(adoption.clone()).await.unwrap();
    store
        .put_charter(&key, &Precondition::NotExists, write(&orders_yaml()))
        .await
        .unwrap();
    assert!(store.list_pending_adoptions().await.unwrap().is_empty());
    assert_eq!(
        store.put_pending_adoption(adoption).await,
        Err(StoreError::Conflict {
            current: "1".into()
        })
    );
    // gone with the process: a reopened store has none
    drop(store);
    assert!(
        open(dir.path())
            .await
            .list_pending_adoptions()
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn the_audit_is_persisted_and_append_only() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path()).await;
    let rec: embassy::cp_audit::CpAuditRecord = serde_json::from_value(serde_json::json!({
        "ts": "2026-10-24T10:00:00.000Z", "actor": "alice", "actor_kind": "token", "role": "admin",
        "action": "charter_put", "namespace": NS, "service": "orders", "agent": null,
        "from_version": "1", "to_version": "2", "sha256_before": "a".repeat(64),
        "sha256_after": "b".repeat(64), "result": "ok", "reason": null
    }))
    .unwrap();
    store.append_cp_audit(&rec).await.unwrap();
    store.append_cp_audit(&rec).await.unwrap();

    let conn = rusqlite::Connection::open(store.path()).unwrap();
    let (n, action, record): (i64, String, String) = conn
        .query_row(
            "SELECT count(*), max(action), max(record) FROM cp_audit WHERE namespace = ?1 AND service = 'orders'",
            [NS],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!((n, action.as_str()), (2, "charter_put"));
    let back: embassy::cp_audit::CpAuditRecord = serde_json::from_str(&record).unwrap();
    assert_eq!(back, rec);
    assert!(conn.execute("DELETE FROM cp_audit", []).is_err());
    assert!(
        conn.execute("UPDATE cp_audit SET actor = 'mallory'", [])
            .is_err()
    );
}

#[tokio::test]
async fn bad_keys_are_not_found_and_the_file_is_created_in_a_new_directory() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteStore::open(dir.path().join("deep/er/embassy.db")).unwrap();
    assert!(dir.path().join("deep/er/embassy.db").is_file());
    let bad = ServiceKey::new("Shop", "orders");
    assert_eq!(store.get_charter(&bad).await, Err(StoreError::NotFound));
    assert_eq!(
        store
            .put_charter(&bad, &Precondition::NotExists, write(&orders_yaml()))
            .await,
        Err(StoreError::NotFound)
    );
    assert_eq!(store.get_memory(&bad).await, Err(StoreError::NotFound));
}
