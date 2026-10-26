//! The `file:<dir>` store (design §8.4): the layout, atomic writes, versions and epochs, memory
//! pruning, proposals, reopening, and external edits of the charter files.
mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use common::{NS, orders_yaml, support_yaml};
use embassy::config::Role;
use embassy::store::file::{FileStore, sha256_hex, yaml_to_json};
use embassy::store::{
    Actor, ActorKind, ChangeSource, CharterWrite, Note, NoteSource, PendingAdoption, Precondition,
    Proposal, ProposalFilter, ProposalPut, ProposalStatus, ServiceKey, Store, StoreError,
    StoreEvent,
};
use tokio::sync::broadcast;

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

fn files(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            if e.file_type().unwrap().is_dir() {
                walk(root, &e.path(), out);
            } else {
                out.push(e.path().strip_prefix(root).unwrap().display().to_string());
            }
        }
    }
    walk(dir, dir, &mut out);
    out.sort();
    out
}

async fn next(
    rx: &mut broadcast::Receiver<StoreEvent>,
    pred: impl Fn(&StoreEvent) -> bool,
) -> StoreEvent {
    let deadline = tokio::time::Instant::now() + common::WAIT;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let ev = tokio::time::timeout(left, rx.recv())
            .await
            .expect("an event")
            .unwrap();
        if pred(&ev) {
            return ev;
        }
    }
}

fn note(id: &str, text: &str) -> Note {
    Note {
        id: id.into(),
        text: text.into(),
        source: NoteSource::Manual,
        request_id: None,
        trace_id: None,
        approved_by: Some("alice".into()),
        ts: "2026-10-21T10:00:00.000Z".into(),
        expires_at: None,
    }
}

#[tokio::test]
async fn the_layout_versions_and_epochs() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::open_with_poll(dir.path(), None).await.unwrap();
    let key = ServiceKey::new(NS, "orders");
    let mut rx = store.subscribe();
    let s1 = store
        .put_charter(&key, &Precondition::NotExists, write(&orders_yaml()))
        .await
        .unwrap();
    assert_eq!(s1.version, "1");
    uuid::Uuid::parse_str(&s1.epoch).unwrap();
    assert!(
        matches!(rx.recv().await.unwrap(), StoreEvent::CharterChanged { version, source: ChangeSource::Api, .. } if version == "1")
    );
    let changed = orders_yaml().replace("model: claude-opus-5-5", "model: claude-haiku-5-5");
    let s2 = store
        .put_charter(&key, &Precondition::Version("1".into()), write(&changed))
        .await
        .unwrap();
    assert_eq!(
        (s2.version.as_str(), s2.epoch.as_str()),
        ("2", s1.epoch.as_str())
    );
    // preconditions
    assert_eq!(
        store
            .put_charter(&key, &Precondition::Version("1".into()), write(&changed))
            .await,
        Err(StoreError::Conflict {
            current: "2".into()
        })
    );
    assert_eq!(
        store
            .put_charter(&key, &Precondition::NotExists, write(&changed))
            .await,
        Err(StoreError::Conflict {
            current: "2".into()
        })
    );
    assert_eq!(
        store
            .put_charter(
                &ServiceKey::new(NS, "nothing"),
                &Precondition::Version("1".into()),
                write(&changed)
            )
            .await,
        Err(StoreError::NotFound)
    );
    let rec = embassy::cp_audit::CpAudit::entry(
        embassy::api::types::CpAction::CharterPut,
        &alice(),
        embassy::api::types::CpResult::Ok,
    );
    store.append_cp_audit(&rec).await.unwrap();
    // read back through the trait
    assert_eq!(store.cp_audit(10).await.unwrap(), [rec]);
    // the exact layout
    let f = files(dir.path());
    assert_eq!(
        f,
        [
            ".audit.jsonl",
            ".history/shop/orders/1.yaml",
            ".history/shop/orders/2.yaml",
            ".meta/shop/orders.json",
            "shop/orders.charter.yaml",
        ],
        "no temporary files are left"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("shop/orders.charter.yaml")).unwrap(),
        changed
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join(".history/shop/orders/1.yaml")).unwrap(),
        orders_yaml()
    );
    let meta: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join(".meta/shop/orders.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        (meta["epoch"].as_str(), meta["version"].as_str()),
        (Some(s1.epoch.as_str()), Some("2"))
    );
    let h = store.history(&key).await.unwrap();
    assert_eq!(
        h.iter().map(|e| e.version.as_str()).collect::<Vec<_>>(),
        ["2", "1"]
    );
    assert_eq!(h[0].sha256, sha256_hex(&changed));
    assert_eq!(store.get_revision(&key, "1").await.unwrap(), orders_yaml());
    assert_eq!(
        store.get_revision(&key, "9").await,
        Err(StoreError::NotFound)
    );
    // delete: the counter stays; a recreated service has a new epoch and the next version
    assert_eq!(
        store.delete_service(&key, "1", &alice()).await,
        Err(StoreError::Conflict {
            current: "2".into()
        })
    );
    store.delete_service(&key, "2", &alice()).await.unwrap();
    assert_eq!(store.get_charter(&key).await, Err(StoreError::NotFound));
    assert!(store.list_services().await.unwrap().is_empty());
    assert!(!dir.path().join("shop/orders.charter.yaml").exists());
    assert!(!dir.path().join(".history/shop/orders").exists());
    let s3 = store
        .put_charter(&key, &Precondition::NotExists, write(&orders_yaml()))
        .await
        .unwrap();
    assert_eq!(s3.version, "3");
    assert_ne!(s3.epoch, s1.epoch);
    // names that are not DNS labels never reach the disk
    assert_eq!(
        store.get_charter(&ServiceKey::new("..", "x")).await,
        Err(StoreError::NotFound)
    );
}

#[tokio::test]
async fn memory_proposals_and_reopening() {
    let dir = tempfile::tempdir().unwrap();
    let key = ServiceKey::new(NS, "support");
    {
        let store = FileStore::open_with_poll(dir.path(), None).await.unwrap();
        store
            .put_charter(&key, &Precondition::NotExists, write(&support_yaml(true)))
            .await
            .unwrap();
        assert_eq!(store.get_memory(&key).await.unwrap().version, "0");
        let m = store
            .put_memory(
                &key,
                "0",
                BTreeMap::from([("helper".to_string(), vec![note("n1", "one")])]),
                &alice(),
            )
            .await
            .unwrap();
        assert_eq!(m.version, "1");
        assert_eq!(
            store.put_memory(&key, "0", BTreeMap::new(), &alice()).await,
            Err(StoreError::Conflict {
                current: "1".into()
            })
        );
        let p = Proposal {
            id: "p1".into(),
            namespace: NS.into(),
            service: "support".into(),
            agent: "helper".into(),
            note: "two".into(),
            rationale: "r".into(),
            request_id: "q".into(),
            trace_id: "t".into(),
            ts: "2026-10-21T10:00:00.000Z".into(),
            status: ProposalStatus::Pending,
            auto: false,
        };
        assert_eq!(
            store.put_proposal(&p, Some("k")).await.unwrap(),
            ProposalPut::Stored
        );
        let mut dup = p.clone();
        dup.id = "p2".into();
        assert_eq!(
            store.put_proposal(&dup, Some("k")).await.unwrap(),
            ProposalPut::Duplicate {
                existing_id: "p1".into()
            }
        );
        assert!(dir.path().join(".memory/shop/support.json").exists());
        assert!(dir.path().join(".proposals/shop/support.json").exists());
    }
    // a new process sees the same
    let store = FileStore::open_with_poll(dir.path(), None).await.unwrap();
    assert_eq!(store.get_charter(&key).await.unwrap().version, "1");
    assert_eq!(
        store.get_memory(&key).await.unwrap().agents["helper"][0].text,
        "one"
    );
    assert_eq!(
        store
            .list_proposals(&ProposalFilter::default())
            .await
            .unwrap()
            .len(),
        1
    );
    // approve: atomic, the note joins the memory
    let (m, p) = store
        .approve_proposal(&key, "p1", "1", &alice())
        .await
        .unwrap();
    assert_eq!(
        (m.version.as_str(), p.status),
        ("2", ProposalStatus::Approved)
    );
    assert_eq!(m.agents["helper"].len(), 2);
    assert_eq!(
        store.reject_proposal(&key, "p1", "2", &alice()).await,
        Err(StoreError::NotPending {
            status: ProposalStatus::Approved
        })
    );
    // turning learning off drops the notes in the same change
    let mut rx = store.subscribe();
    store
        .put_charter(
            &key,
            &Precondition::Version("1".into()),
            write(&support_yaml(false)),
        )
        .await
        .unwrap();
    let ev = next(&mut rx, |e| matches!(e, StoreEvent::MemoryChanged { .. })).await;
    assert_eq!(
        ev,
        StoreEvent::MemoryChanged {
            key: key.clone(),
            version: "3".into()
        }
    );
    let m = store.get_memory(&key).await.unwrap();
    assert_eq!((m.version.as_str(), m.agents.len()), ("3", 0));
    // pending adoptions live in memory; none for a service with a charter
    let pending = PendingAdoption {
        key: ServiceKey::new(NS, "shipping"),
        sha256: "a".repeat(64),
        pod: "shipping-0".into(),
        ts: "2026-10-21T10:00:00.000Z".into(),
        yaml: "x".into(),
    };
    store.put_pending_adoption(pending.clone()).await.unwrap();
    assert_eq!(
        store.list_pending_adoptions().await.unwrap(),
        std::slice::from_ref(&pending)
    );
    assert_eq!(
        store.take_pending_adoption(&pending.key, "b").await,
        Err(StoreError::NotFound)
    );
    assert_eq!(
        store
            .take_pending_adoption(&pending.key, &pending.sha256)
            .await
            .unwrap(),
        pending
    );
    let mut on_support = pending.clone();
    on_support.key = key.clone();
    assert!(matches!(
        store.put_pending_adoption(on_support).await,
        Err(StoreError::Conflict { .. })
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn approve_and_reject_never_both_win() {
    let dir = tempfile::tempdir().unwrap();
    let store: Arc<FileStore> = FileStore::open_with_poll(dir.path(), None).await.unwrap();
    let key = ServiceKey::new(NS, "support");
    store
        .put_charter(&key, &Precondition::NotExists, write(&support_yaml(true)))
        .await
        .unwrap();
    for round in 0..20 {
        let id = format!("p{round}");
        let p = Proposal {
            id: id.clone(),
            namespace: NS.into(),
            service: "support".into(),
            agent: "helper".into(),
            note: "n".into(),
            rationale: "r".into(),
            request_id: "q".into(),
            trace_id: String::new(),
            ts: "2026-10-21T10:00:00.000Z".into(),
            status: ProposalStatus::Pending,
            auto: false,
        };
        store.put_proposal(&p, Some(&id)).await.unwrap();
        let v = store.get_memory(&key).await.unwrap().version;
        // keep room for the note
        store
            .put_memory(&key, &v, BTreeMap::new(), &alice())
            .await
            .unwrap();
        let v = store.get_memory(&key).await.unwrap().version;
        let (a, b) = (store.clone(), store.clone());
        let (k1, k2, i1, i2, v1, v2) = (
            key.clone(),
            key.clone(),
            id.clone(),
            id.clone(),
            v.clone(),
            v.clone(),
        );
        let approve =
            tokio::spawn(async move { a.approve_proposal(&k1, &i1, &v1, &alice()).await });
        let reject = tokio::spawn(async move { b.reject_proposal(&k2, &i2, &v2, &alice()).await });
        let (x, y) = (approve.await.unwrap(), reject.await.unwrap());
        assert!(x.is_ok() != y.is_ok(), "round {round}: {x:?} / {y:?}");
    }
}

/// Write a file the way editors do (a temporary file renamed), so the store's poll never
/// reads it half written.
fn put_file(path: impl AsRef<Path>, text: impl AsRef<[u8]>) -> std::io::Result<()> {
    let path = path.as_ref();
    let tmp = path.with_extension("swp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)
}

#[tokio::test]
async fn external_edits_are_validated_stored_and_audited() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::open_with_poll(dir.path(), Some(Duration::from_millis(30)))
        .await
        .unwrap();
    let key = ServiceKey::new(NS, "orders");
    store
        .put_charter(&key, &Precondition::NotExists, write(&orders_yaml()))
        .await
        .unwrap();
    let mut rx = store.subscribe();
    let file = dir.path().join("shop/orders.charter.yaml");
    // a valid edit becomes the next version, source file
    let edited = orders_yaml().replace("model: claude-opus-5-5", "model: claude-haiku-5-5");
    put_file(&file, &edited).unwrap();
    let ev = next(&mut rx, |e| matches!(e, StoreEvent::CharterChanged { .. })).await;
    let StoreEvent::CharterChanged {
        version,
        actor,
        source,
        ..
    } = ev
    else {
        unreachable!()
    };
    assert_eq!(
        (version.as_str(), actor.name.as_str(), source),
        ("2", "file", ChangeSource::File)
    );
    let ev = next(&mut rx, |e| matches!(e, StoreEvent::CpAudit(_))).await;
    let StoreEvent::CpAudit(rec) = ev else {
        unreachable!()
    };
    assert_eq!(
        (rec.action, rec.result),
        (
            embassy::api::types::CpAction::CrExternalEdit,
            embassy::api::types::CpResult::Ok
        )
    );
    assert_eq!(
        (rec.from_version.as_deref(), rec.to_version.as_deref()),
        (Some("1"), Some("2"))
    );
    assert_eq!(store.get_charter(&key).await.unwrap().yaml, edited);
    assert_eq!(store.history(&key).await.unwrap()[0].actor, "file");
    // an invalid edit is ignored, audited once
    put_file(
        &file,
        "apiVersion: agentsc.io/v1alpha1\nkind: Charter\nservice: {name: orders}\n",
    )
    .unwrap();
    let ev = next(&mut rx, |e| matches!(e, StoreEvent::CpAudit(_))).await;
    let StoreEvent::CpAudit(rec) = ev else {
        unreachable!()
    };
    assert_eq!(rec.result, embassy::api::types::CpResult::Invalid);
    assert!(
        rec.reason
            .as_deref()
            .unwrap()
            .contains("invalid and was ignored")
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(rx.try_recv().is_err(), "audited once");
    assert_eq!(store.get_charter(&key).await.unwrap().version, "2");
    // a charter for another service than its file name is invalid too
    put_file(
        &file,
        orders_yaml().replace("name: orders", "name: billing"),
    )
    .unwrap();
    let ev = next(&mut rx, |e| matches!(e, StoreEvent::CpAudit(_))).await;
    let StoreEvent::CpAudit(rec) = ev else {
        unreachable!()
    };
    assert!(
        rec.reason.as_deref().unwrap().contains("the file's name"),
        "{rec:?}"
    );
    // a new service dropped in
    std::fs::create_dir_all(dir.path().join("shop")).unwrap();
    put_file(
        dir.path().join("shop/support.charter.yaml"),
        support_yaml(true),
    )
    .unwrap();
    next(
        &mut rx,
        |e| matches!(e, StoreEvent::CharterChanged { key, .. } if key.service == "support"),
    )
    .await;
    assert_eq!(
        store
            .get_charter(&ServiceKey::new(NS, "support"))
            .await
            .unwrap()
            .version,
        "1"
    );
    // a removed file: audited, the stored charter stays
    std::fs::remove_file(dir.path().join("shop/support.charter.yaml")).unwrap();
    let ev = next(&mut rx, |e| {
        matches!(e, StoreEvent::CpAudit(r) if r.reason.as_deref().is_some_and(|r| r.contains("was removed")))
    })
    .await;
    let StoreEvent::CpAudit(rec) = ev else {
        unreachable!()
    };
    assert_eq!(rec.result, embassy::api::types::CpResult::Invalid);
    assert!(
        store
            .get_charter(&ServiceKey::new(NS, "support"))
            .await
            .is_ok()
    );
    // the audit file has them all
    let audit = std::fs::read_to_string(dir.path().join(".audit.jsonl")).unwrap();
    assert!(
        audit
            .lines()
            .filter(|l| l.contains("cr_external_edit"))
            .count()
            >= 5,
        "{audit}"
    );
}

#[tokio::test]
async fn charters_already_on_disk_are_taken_in_when_the_store_opens() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("shop")).unwrap();
    std::fs::write(dir.path().join("shop/orders.charter.yaml"), orders_yaml()).unwrap();
    std::fs::write(dir.path().join("shop/.orders.charter.yaml.tmp-x"), "junk").unwrap();
    std::fs::write(dir.path().join("shop/Bad.charter.yaml"), "junk").unwrap();
    let store = FileStore::open_with_poll(dir.path(), None).await.unwrap();
    assert_eq!(
        store.list_services().await.unwrap(),
        [ServiceKey::new(NS, "orders")]
    );
    assert_eq!(
        store
            .get_charter(&ServiceKey::new(NS, "orders"))
            .await
            .unwrap()
            .version,
        "1"
    );
}
