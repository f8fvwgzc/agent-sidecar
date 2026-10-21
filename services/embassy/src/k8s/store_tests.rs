//! Tests of [`super`] (the kubernetes store) against [`crate::k8s::fake::FakeCluster`].
use super::*;
use crate::config::Role;
use crate::k8s::fake::FakeCluster;

/// A shared buffer standing in for stdout.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Capture {
    fn records(&self) -> Vec<CpAuditRecord> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

struct Rig {
    cluster: Arc<FakeCluster>,
    store: KubeStore,
    events: broadcast::Receiver<StoreEvent>,
    out: Capture,
}

fn rig() -> Rig {
    let cluster = Arc::new(FakeCluster::new());
    let out = Capture::default();
    let store = KubeStore::with_writer(cluster.clone(), Box::new(out.clone()));
    let events = store.subscribe();
    Rig {
        cluster,
        store,
        events,
        out,
    }
}

fn key() -> ServiceKey {
    ServiceKey::new("shop", "support")
}

/// A valid charter for `shop/support`: one agent `support-agent` learning in review mode.
fn charter(model: &str, learning: bool) -> Value {
    json!({
        "apiVersion": "attache.io/v1alpha1",
        "kind": "Charter",
        "service": {"name": "support", "namespace": "shop", "app_port": 8080},
        "agents": [{
            "name": "support-agent",
            "model": model,
            "budgets": {"max_cost_usd_per_day": 10.0},
            "learning": {"enabled": learning, "mode": "review", "max_notes": 5, "max_note_chars": 400}
        }],
        "authz": {"default": "deny", "callers": [{"identity": "local", "agents": ["*"]}]}
    })
}

fn alice() -> Actor {
    Actor {
        name: "alice".into(),
        kind: ActorKind::Token,
        role: Some(Role::Admin),
    }
}

fn write(json: Value) -> CharterWrite {
    CharterWrite {
        yaml: format!(
            "# written by alice\n{}",
            serde_yaml_ng::to_string(&json).unwrap()
        ),
        charter_json: json,
        actor: alice(),
        source: ChangeSource::Api,
    }
}

async fn put(store: &KubeStore, pre: Precondition, model: &str) -> StoredCharter {
    store
        .put_charter(&key(), &pre, write(charter(model, true)))
        .await
        .unwrap()
}

fn drain(rx: &mut broadcast::Receiver<StoreEvent>) -> Vec<StoreEvent> {
    let mut out = Vec::new();
    while let Ok(e) = rx.try_recv() {
        out.push(e);
    }
    out
}

fn condition(obj: &Value, type_: &str) -> Condition {
    CharterStatus::of(obj)
        .unwrap()
        .conditions
        .into_iter()
        .find(|c| c.type_ == type_)
        .unwrap()
}

fn proposal(id: &str, ts: &str, status: ProposalStatus) -> Proposal {
    Proposal {
        id: id.into(),
        namespace: "shop".into(),
        service: "support".into(),
        agent: "support-agent".into(),
        note: format!("lesson {id}"),
        rationale: "r".into(),
        request_id: "req".into(),
        trace_id: "trace".into(),
        ts: ts.into(),
        status,
        auto: false,
    }
}

#[tokio::test]
async fn versions_live_in_the_annotation_and_the_epoch_is_the_uid() {
    let mut r = rig();
    let first = put(&r.store, Precondition::NotExists, "claude-opus-5-5").await;
    assert_eq!(first.version, "1");
    let obj = r.cluster.charter("shop", "support").unwrap();
    assert_eq!(first.epoch, obj["metadata"]["uid"].as_str().unwrap());
    assert_eq!(annotation(&obj, VERSION_ANNOTATION), Some("1"));
    assert_eq!(
        annotation(&obj, SPEC_SHA256_ANNOTATION),
        Some(spec_sha256(&obj["spec"]).as_str())
    );
    // the CR spec is the charter without apiVersion/kind
    assert!(obj["spec"].get("apiVersion").is_none());
    assert_eq!(obj["spec"]["agents"][0]["model"], "claude-opus-5-5");
    // status: observed, applied, valid
    assert_eq!(
        obj["status"]["observedGeneration"],
        obj["metadata"]["generation"]
    );
    assert_eq!(obj["status"]["appliedVersion"], "1");
    assert_eq!(condition(&obj, "Valid").status, "True");
    // spec first, then its revision, then the status that marks it observed
    let calls = r.cluster.calls();
    let kinds: Vec<&str> = calls
        .iter()
        .map(|c| c.rsplit_once(' ').unwrap().0)
        .collect();
    assert_eq!(
        kinds,
        ["create charter", "create revision", "replace status"]
    );

    let second = put(
        &r.store,
        Precondition::Version("1".into()),
        "claude-haiku-5-5",
    )
    .await;
    assert_eq!(
        (second.version.as_str(), second.epoch.as_str()),
        ("2", first.epoch.as_str())
    );
    let obj = r.cluster.charter("shop", "support").unwrap();
    assert_eq!(annotation(&obj, VERSION_ANNOTATION), Some("2"));
    assert!(!needs_processing(&obj));

    // reads: the YAML exactly as written, its JSON, the epoch
    let got = r.store.get_charter(&key()).await.unwrap();
    assert_eq!(got.version, "2");
    assert!(got.yaml.starts_with("# written by alice\n"));
    assert_eq!(got.charter_json, charter("claude-haiku-5-5", true));
    assert_eq!(r.store.list_services().await.unwrap(), [key()]);

    let changed = |version: &str| StoreEvent::CharterChanged {
        key: key(),
        epoch: first.epoch.clone(),
        version: version.into(),
        actor: alice(),
        source: ChangeSource::Api,
    };
    assert_eq!(drain(&mut r.events), [changed("1"), changed("2")]);
}

#[tokio::test]
async fn preconditions_are_409_semantics_and_api_conflicts_are_retried() {
    let r = rig();
    // If-Match on a service without a charter
    let e = r
        .store
        .put_charter(
            &key(),
            &Precondition::Version("1".into()),
            write(charter("m", true)),
        )
        .await
        .unwrap_err();
    assert_eq!(e, StoreError::NotFound);
    put(&r.store, Precondition::NotExists, "m1").await;
    // a second create, and a stale If-Match, name the current version
    for pre in [Precondition::NotExists, Precondition::Version("7".into())] {
        let e = r
            .store
            .put_charter(&key(), &pre, write(charter("m", true)))
            .await
            .unwrap_err();
        assert_eq!(
            e,
            StoreError::Conflict {
                current: "1".into()
            }
        );
    }
    // resourceVersion conflicts (someone else wrote the object) are read again and retried
    r.cluster.fail_replaces_with_conflict(2);
    r.cluster.fail_status_writes_with_conflict(2);
    assert_eq!(
        put(&r.store, Precondition::Version("1".into()), "m2")
            .await
            .version,
        "2"
    );
    // ...but not forever
    r.cluster.fail_replaces_with_conflict(MAX_ATTEMPTS + 1);
    let e = r
        .store
        .put_charter(
            &key(),
            &Precondition::Version("2".into()),
            write(charter("m3", true)),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(e, StoreError::Io(ref m) if m.contains("concurrent")),
        "{e:?}"
    );
    r.cluster.fail_replaces_with_conflict(0);
    // an admission webhook refusal is an invalid write
    r.cluster.refuse_next_replace(
        "admission webhook \"charter-validator.attache.io\" denied the request: policy",
    );
    let e = r
        .store
        .put_charter(
            &key(),
            &Precondition::Version("2".into()),
            write(charter("m3", true)),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(e, StoreError::Invalid(ref m) if m[0].contains("denied")),
        "{e:?}"
    );
    assert_eq!(r.store.get_charter(&key()).await.unwrap().version, "2");
    // a charter for another service is refused before anything is written
    let mut other = charter("m", true);
    other["service"]["name"] = json!("orders");
    let e = r
        .store
        .put_charter(&key(), &Precondition::Version("2".into()), write(other))
        .await
        .unwrap_err();
    assert!(matches!(e, StoreError::Invalid(_)), "{e:?}");
}

#[tokio::test]
async fn history_keeps_the_newest_20_revisions() {
    let r = rig();
    put(&r.store, Precondition::NotExists, "m-1").await;
    for v in 1..25u64 {
        put(
            &r.store,
            Precondition::Version(v.to_string()),
            &format!("m-{}", v + 1),
        )
        .await;
    }
    let history = r.store.history(&key()).await.unwrap();
    assert_eq!(history.len(), HISTORY_LIMIT);
    let versions: Vec<&str> = history.iter().map(|h| h.version.as_str()).collect();
    let want: Vec<String> = (6..=25).rev().map(|v| v.to_string()).collect();
    assert_eq!(versions, want);
    assert!(
        history
            .iter()
            .all(|h| h.actor == "alice" && h.sha256.len() == 64)
    );
    assert_eq!(r.cluster.revision_names("shop").len(), HISTORY_LIMIT);
    let yaml = r.store.get_revision(&key(), "6").await.unwrap();
    assert!(yaml.contains("m-6"), "{yaml}");
    assert_eq!(history.last().unwrap().sha256, sha256_hex(yaml.as_bytes()));
    assert_eq!(
        r.store.get_revision(&key(), "5").await,
        Err(StoreError::NotFound)
    );
    assert_eq!(
        r.store.get_revision(&key(), "../x").await,
        Err(StoreError::NotFound)
    );
    // revisions are owned by the Charter
    let obj = r.cluster.charter("shop", "support").unwrap();
    let uid = obj["metadata"]["uid"].as_str().unwrap();
    let rev = r
        .cluster
        .get_revision("shop", &revision_name("support", uid, 25))
        .await
        .unwrap()
        .unwrap();
    let owner = &rev.metadata.owner_references.as_ref().unwrap()[0];
    assert_eq!(
        (owner.kind.as_str(), owner.uid.as_str(), owner.controller),
        ("Charter", uid, Some(true))
    );
    assert_eq!(rev.revision, 25);
}

#[tokio::test]
async fn memory_and_proposals_live_in_the_status() {
    let mut r = rig();
    // no Charter yet: version 0, nothing
    assert_eq!(r.store.get_memory(&key()).await.unwrap().version, "0");
    put(&r.store, Precondition::NotExists, "m").await;
    drain(&mut r.events);

    let note = |id: &str| Note {
        id: id.into(),
        text: format!("note {id}"),
        source: crate::store::NoteSource::Manual,
        request_id: None,
        trace_id: None,
        approved_by: Some("alice".into()),
        ts: "2026-10-21T10:00:00.000Z".into(),
        expires_at: None,
    };
    let agents = BTreeMap::from([("support-agent".to_string(), vec![note("n1")])]);
    let m = r
        .store
        .put_memory(&key(), "0", agents.clone(), &alice())
        .await
        .unwrap();
    assert_eq!(m.version, "1");
    assert_eq!(
        r.store
            .put_memory(&key(), "0", agents.clone(), &alice())
            .await,
        Err(StoreError::Conflict {
            current: "1".into()
        })
    );
    let obj = r.cluster.charter("shop", "support").unwrap();
    assert_eq!(obj["status"]["memory"]["version"], "1");
    assert_eq!(
        obj["status"]["memory"]["agents"]["support-agent"][0]["id"],
        "n1"
    );
    assert_eq!(r.store.get_memory(&key()).await.unwrap(), m);

    let p1 = proposal("p1", "2026-10-21T10:00:01.000Z", ProposalStatus::Pending);
    let p2 = proposal("p2", "2026-10-21T10:00:02.000Z", ProposalStatus::Pending);
    assert_eq!(
        r.store.put_proposal(&p1, Some("dk1")).await.unwrap(),
        ProposalPut::Stored
    );
    assert_eq!(
        r.store
            .put_proposal(
                &proposal("p1-again", "x", ProposalStatus::Pending),
                Some("dk1")
            )
            .await
            .unwrap(),
        ProposalPut::Duplicate {
            existing_id: "p1".into()
        }
    );
    r.cluster.fail_status_writes_with_conflict(1);
    assert_eq!(
        r.store.put_proposal(&p2, Some("dk2")).await.unwrap(),
        ProposalPut::Stored
    );
    let listed = r
        .store
        .list_proposals(&ProposalFilter::default())
        .await
        .unwrap();
    assert_eq!(listed, [p2.clone(), p1.clone()], "newest first");
    assert_eq!(r.store.get_proposal("p1").await.unwrap(), p1);
    assert_eq!(
        r.store.get_proposal("nope").await,
        Err(StoreError::NotFound)
    );
    let obj = r.cluster.charter("shop", "support").unwrap();
    assert_eq!(obj["status"]["proposals"][0]["dedup_key"], "dk1");
    // replacing by id (no dedup key) keeps the dedup key
    let mut p1b = p1.clone();
    p1b.rationale = "better".into();
    r.store.put_proposal(&p1b, None).await.unwrap();
    assert_eq!(
        r.store.get_proposal("p1").await.unwrap().rationale,
        "better"
    );
    let obj = r.cluster.charter("shop", "support").unwrap();
    assert_eq!(obj["status"]["proposals"][0]["dedup_key"], "dk1");
    assert_eq!(
        r.store
            .put_proposal(&proposal("ghost", "x", ProposalStatus::Pending), None)
            .await,
        Err(StoreError::NotFound)
    );

    // approve: the note lands in memory with a new version, atomically with the decision
    let (mem, decided) = r
        .store
        .approve_proposal(&key(), "p1", "1", &alice())
        .await
        .unwrap();
    assert_eq!(decided.status, ProposalStatus::Approved);
    assert_eq!(mem.version, "2");
    let notes = &mem.agents["support-agent"];
    assert_eq!(notes.len(), 2);
    assert_eq!(
        (notes[1].text.as_str(), notes[1].approved_by.as_deref()),
        ("lesson p1", Some("alice"))
    );
    assert_eq!(r.store.get_memory(&key()).await.unwrap(), mem);
    // the loser of approve/reject learns it is decided; stale memory versions conflict
    assert_eq!(
        r.store.reject_proposal(&key(), "p1", "2", &alice()).await,
        Err(StoreError::NotPending {
            status: ProposalStatus::Approved
        })
    );
    assert_eq!(
        r.store.reject_proposal(&key(), "p2", "1", &alice()).await,
        Err(StoreError::Conflict {
            current: "2".into()
        })
    );
    let (mem2, rejected) = r
        .store
        .reject_proposal(&key(), "p2", "2", &alice())
        .await
        .unwrap();
    assert_eq!(
        (mem2.version.as_str(), rejected.status),
        ("2", ProposalStatus::Rejected)
    );
    let pending = r
        .store
        .list_proposals(&ProposalFilter {
            status: Some(ProposalStatus::Pending),
            namespace: Some("shop".into()),
            service: Some("support".into()),
        })
        .await
        .unwrap();
    assert!(pending.is_empty());

    let events = drain(&mut r.events);
    assert!(events.contains(&StoreEvent::MemoryChanged {
        key: key(),
        version: "2".into()
    }));
    assert!(events.contains(&StoreEvent::ProposalChanged {
        key: key(),
        id: "p2".into()
    }));

    // turning learning off drops the agent's notes in the same change (new memory version)
    r.store
        .put_charter(
            &key(),
            &Precondition::Version("1".into()),
            write(charter("m", false)),
        )
        .await
        .unwrap();
    let mem = r.store.get_memory(&key()).await.unwrap();
    assert_eq!(mem.version, "3");
    assert!(mem.agents.is_empty());
    let events = drain(&mut r.events);
    assert!(events.contains(&StoreEvent::MemoryChanged {
        key: key(),
        version: "3".into()
    }));
    // approving now is refused: learning is off in the stored charter
    r.store
        .put_proposal(
            &proposal("p3", "2026-10-21T10:00:03.000Z", ProposalStatus::Pending),
            Some("dk3"),
        )
        .await
        .unwrap();
    let e = r
        .store
        .approve_proposal(&key(), "p3", "3", &alice())
        .await
        .unwrap_err();
    assert!(
        matches!(e, StoreError::Invalid(ref m) if m[0].contains("does not enable learning")),
        "{e:?}"
    );
    // proposals need a Charter to live in
    let mut orphan = proposal("o", "x", ProposalStatus::Pending);
    orphan.service = "orders".into();
    assert_eq!(
        r.store.put_proposal(&orphan, Some("o")).await,
        Err(StoreError::NotFound)
    );
}

#[tokio::test]
async fn a_decision_racing_a_spec_change_decides_again() {
    let r = rig();
    put(&r.store, Precondition::NotExists, "m").await;
    r.store
        .put_proposal(
            &proposal("p1", "2026-10-21T10:00:01.000Z", ProposalStatus::Pending),
            Some("dk1"),
        )
        .await
        .unwrap();
    // the status replace carrying the decision conflicts once (the spec changed meanwhile)
    r.cluster.fail_status_writes_with_conflict(1);
    let (mem, decided) = r
        .store
        .approve_proposal(&key(), "p1", "0", &alice())
        .await
        .unwrap();
    assert_eq!(
        (mem.version.as_str(), decided.status),
        ("1", ProposalStatus::Approved)
    );
    assert_eq!(
        r.store.get_memory(&key()).await.unwrap().agents["support-agent"].len(),
        1
    );
}

#[tokio::test]
async fn the_status_stays_within_the_object_budget() {
    let r = rig();
    put(&r.store, Precondition::NotExists, "m").await;
    let big = "x".repeat(100_000);
    let mk = |i: usize, status: ProposalStatus| {
        let mut p = proposal(
            &format!("p{i:02}"),
            &format!("2026-10-21T10:00:{i:02}.000Z"),
            status,
        );
        p.rationale = big.clone();
        p
    };
    let size = |r: &Rig| {
        serde_json::to_vec(&r.cluster.charter("shop", "support").unwrap())
            .unwrap()
            .len()
    };
    // decided proposals are kept until the object would outgrow the budget...
    for i in 0..20 {
        r.store
            .put_proposal(&mk(i, ProposalStatus::Rejected), Some(&format!("d{i}")))
            .await
            .unwrap();
        assert!(size(&r) <= MAX_OBJECT_BYTES, "{}", size(&r));
    }
    let all = r
        .store
        .list_proposals(&ProposalFilter::default())
        .await
        .unwrap();
    assert!((10..20).contains(&all.len()), "{}", all.len());
    // ...then the oldest go first
    assert_eq!(all[0].id, "p19");
    assert_eq!(all.last().unwrap().id, format!("p{:02}", 20 - all.len()));

    // pending proposals are never dropped: they push the decided ones out, then are refused
    let mut stored = 0;
    let err = loop {
        match r
            .store
            .put_proposal(
                &mk(30 + stored, ProposalStatus::Pending),
                Some(&format!("q{stored}")),
            )
            .await
        {
            Ok(_) => stored += 1,
            Err(e) => break e,
        }
        assert!(stored < 20);
    };
    assert!(
        matches!(err, StoreError::Invalid(ref m) if m[0].contains("pending proposals") && m[0].contains("more than")),
        "{err:?}"
    );
    let all = r
        .store
        .list_proposals(&ProposalFilter::default())
        .await
        .unwrap();
    assert_eq!(all.len(), stored);
    assert!(all.iter().all(|p| p.status == ProposalStatus::Pending));
    assert!(size(&r) <= MAX_OBJECT_BYTES);
    // memory writes that do not fit are refused the same way, before etcd would
    let huge = Note {
        id: "n".into(),
        text: "y".repeat(200_000),
        source: crate::store::NoteSource::Manual,
        request_id: None,
        trace_id: None,
        approved_by: Some("alice".into()),
        ts: "2026-10-21T10:00:00.000Z".into(),
        expires_at: None,
    };
    let e = r
        .store
        .put_memory(
            &key(),
            "0",
            BTreeMap::from([("support-agent".to_string(), vec![huge])]),
            &alice(),
        )
        .await
        .unwrap_err();
    assert!(matches!(e, StoreError::Invalid(_)), "{e:?}");
    // bookkeeping is never refused, and deciding makes room again
    r.store
        .set_synced(&key(), &[("p".into(), "e".into())])
        .await
        .unwrap();
    r.store
        .reject_proposal(&key(), "p30", "0", &alice())
        .await
        .unwrap();
    r.store
        .put_proposal(
            &proposal("small", "2026-10-21T10:00:59.000Z", ProposalStatus::Pending),
            Some("again"),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn a_kubectl_edit_becomes_the_next_version_with_the_managers_name() {
    let mut r = rig();
    let first = put(&r.store, Precondition::NotExists, "claude-opus-5-5").await;
    drain(&mut r.events);
    r.cluster.kubectl("shop", "support", "kubectl-edit", |o| {
        o["spec"]["agents"][0]["model"] = json!("claude-sonnet-5-5");
    });
    let obj = r.cluster.charter("shop", "support").unwrap();
    assert!(needs_processing(&obj));
    assert_eq!(last_manager(&obj), "kubectl-edit");
    r.store.observe(&obj).await;

    let got = r.store.get_charter(&key()).await.unwrap();
    assert_eq!(
        (got.version.as_str(), got.epoch.as_str()),
        ("2", first.epoch.as_str())
    );
    assert_eq!(got.charter_json["agents"][0]["model"], "claude-sonnet-5-5");
    // the plain form, namespace from metadata
    assert_eq!(got.charter_json["service"]["namespace"], "shop");
    assert_eq!(got.charter_json["kind"], "Charter");
    let obj = r.cluster.charter("shop", "support").unwrap();
    assert!(!needs_processing(&obj));
    assert_eq!(obj["status"]["appliedVersion"], "2");
    let history = r.store.history(&key()).await.unwrap();
    assert_eq!(history[0].actor, "k8s:kubectl-edit");

    let k8s = Actor {
        name: "k8s:kubectl-edit".into(),
        kind: ActorKind::K8s,
        role: None,
    };
    let events = drain(&mut r.events);
    assert!(
        events.contains(&StoreEvent::CharterChanged {
            key: key(),
            epoch: first.epoch.clone(),
            version: "2".into(),
            actor: k8s,
            source: ChangeSource::Kubernetes
        }),
        "{events:?}"
    );
    let audits: Vec<&CpAuditRecord> = events
        .iter()
        .filter_map(|e| match e {
            StoreEvent::CpAudit(r) => Some(&**r),
            _ => None,
        })
        .collect();
    assert_eq!(audits.len(), 1);
    let a = audits[0];
    assert_eq!(
        (a.action, a.result),
        (CpAction::CrExternalEdit, CpResult::Ok)
    );
    assert_eq!(
        (a.actor.as_str(), a.actor_kind),
        ("k8s:kubectl-edit", ActorKind::K8s)
    );
    assert_eq!(
        (a.from_version.as_deref(), a.to_version.as_deref()),
        (Some("1"), Some("2"))
    );
    assert_eq!(a.sha256_after.as_deref(), Some(history[0].sha256.as_str()));
    assert!(a.sha256_before.is_some());
    // ...and one JSON line on stdout
    assert_eq!(r.out.records(), std::slice::from_ref(a));

    // seen again (a watch repeat or resync): nothing new
    r.store.observe(&obj).await;
    assert!(drain(&mut r.events).is_empty());
    assert_eq!(r.store.get_charter(&key()).await.unwrap().version, "2");
}

#[tokio::test]
async fn an_invalid_kubectl_edit_is_marked_and_never_served() {
    let mut r = rig();
    put(&r.store, Precondition::NotExists, "claude-opus-5-5").await;
    drain(&mut r.events);
    r.cluster
        .kubectl("shop", "support", "kubectl-client-side-apply", |o| {
            o["spec"]["agents"][0]["modle"] = json!("typo");
        });
    let obj = r.cluster.charter("shop", "support").unwrap();
    r.store.observe(&obj).await;

    let obj = r.cluster.charter("shop", "support").unwrap();
    let valid = condition(&obj, "Valid");
    assert_eq!(
        (valid.status.as_str(), valid.reason.as_deref()),
        ("False", Some("Invalid"))
    );
    assert!(
        valid.message.as_deref().unwrap().contains("modle"),
        "{valid:?}"
    );
    assert!(!needs_processing(&obj));
    // the stored charter is still version 1
    let got = r.store.get_charter(&key()).await.unwrap();
    assert_eq!(got.version, "1");
    assert!(got.charter_json["agents"][0].get("modle").is_none());
    let events = drain(&mut r.events);
    assert_eq!(events.len(), 1, "{events:?}");
    let StoreEvent::CpAudit(a) = &events[0] else {
        panic!("{events:?}")
    };
    assert_eq!(
        (a.result, a.actor.as_str()),
        (CpResult::Invalid, "k8s:kubectl-client-side-apply")
    );
    assert!(a.to_version.is_none());

    // an API write over it applies and clears Valid=False
    put(
        &r.store,
        Precondition::Version("1".into()),
        "claude-haiku-5-5",
    )
    .await;
    let obj = r.cluster.charter("shop", "support").unwrap();
    assert_eq!(condition(&obj, "Valid").status, "True");
    assert_eq!(r.store.get_charter(&key()).await.unwrap().version, "2");
}

#[tokio::test]
async fn writes_process_an_unseen_kubectl_edit_first() {
    let r = rig();
    put(&r.store, Precondition::NotExists, "m1").await;
    r.cluster.kubectl("shop", "support", "kubectl-edit", |o| {
        o["spec"]["agents"][0]["model"] = json!("m-kubectl");
    });
    // the API client still thinks version 1 is current: a conflict naming version 2
    let e = r
        .store
        .put_charter(
            &key(),
            &Precondition::Version("1".into()),
            write(charter("m2", true)),
        )
        .await
        .unwrap_err();
    assert_eq!(
        e,
        StoreError::Conflict {
            current: "2".into()
        }
    );
    assert_eq!(
        r.store.get_charter(&key()).await.unwrap().charter_json["agents"][0]["model"],
        "m-kubectl"
    );
}

#[tokio::test]
async fn a_status_write_lost_after_our_own_spec_write_is_finished_quietly() {
    let mut r = rig();
    put(&r.store, Precondition::NotExists, "m1").await;
    // simulate embassy stopping between its spec write and its status write
    let mut obj = r.cluster.charter("shop", "support").unwrap();
    obj["status"]["observedGeneration"] = json!(0);
    r.cluster
        .replace_status("shop", "support", &obj)
        .await
        .unwrap();
    drain(&mut r.events);
    r.store
        .observe(&r.cluster.charter("shop", "support").unwrap())
        .await;
    let obj = r.cluster.charter("shop", "support").unwrap();
    assert!(!needs_processing(&obj));
    assert_eq!(r.store.get_charter(&key()).await.unwrap().version, "1");
    // not an external edit: no new version, no audit
    assert!(drain(&mut r.events).is_empty());
    assert!(r.out.records().is_empty());
}

#[tokio::test]
async fn a_charter_created_with_kubectl_is_adopted_as_version_1() {
    let mut r = rig();
    let mut spec = charter("m", false);
    let spec_map = spec.as_object_mut().unwrap();
    spec_map.remove("apiVersion");
    spec_map.remove("kind");
    spec_map["service"]
        .as_object_mut()
        .unwrap()
        .remove("namespace");
    r.cluster
        .kubectl("shop", "support", "kubectl-client-side-apply", |o| {
            o["spec"] = spec.clone();
        });
    assert_eq!(r.store.get_charter(&key()).await, Err(StoreError::NotFound));
    assert!(r.store.list_services().await.unwrap().is_empty());
    r.store
        .observe(&r.cluster.charter("shop", "support").unwrap())
        .await;
    let got = r.store.get_charter(&key()).await.unwrap();
    assert_eq!(got.version, "1");
    assert_eq!(got.charter_json["service"]["namespace"], "shop");
    assert_eq!(r.store.list_services().await.unwrap(), [key()]);
    let events = drain(&mut r.events);
    assert!(events.iter().any(|e| matches!(e,
        StoreEvent::CharterChanged { version, source: ChangeSource::Kubernetes, .. } if version == "1")));
}

#[tokio::test]
async fn deleting_and_recreating_gives_a_new_epoch() {
    let mut r = rig();
    let first = put(&r.store, Precondition::NotExists, "m").await;
    put(&r.store, Precondition::Version("1".into()), "m2").await;
    assert_eq!(
        r.store.delete_service(&key(), "1", &alice()).await,
        Err(StoreError::Conflict {
            current: "2".into()
        })
    );
    drain(&mut r.events);
    r.store.delete_service(&key(), "2", &alice()).await.unwrap();
    assert!(r.cluster.charter("shop", "support").is_none());
    assert!(r.cluster.revision_names("shop").is_empty());
    assert_eq!(
        drain(&mut r.events),
        [StoreEvent::ServiceDeleted {
            key: key(),
            actor: alice()
        }]
    );
    assert_eq!(r.store.get_charter(&key()).await, Err(StoreError::NotFound));
    assert_eq!(
        r.store.delete_service(&key(), "2", &alice()).await,
        Err(StoreError::NotFound)
    );

    let again = put(&r.store, Precondition::NotExists, "m3").await;
    assert_eq!(again.version, "1");
    assert_ne!(again.epoch, first.epoch);
}

#[tokio::test]
async fn kubectl_deletes_are_reported_once() {
    let mut r = rig();
    put(&r.store, Precondition::NotExists, "m").await;
    drain(&mut r.events);
    let gone = r.cluster.kubectl_delete("shop", "support").unwrap();
    r.store.observe_deleted(&gone);
    r.store.observe_deleted(&gone);
    let events = drain(&mut r.events);
    assert_eq!(events.len(), 1);
    assert!(matches!(&events[0],
        StoreEvent::ServiceDeleted { key: k, actor } if *k == key() && actor.kind == ActorKind::K8s));

    // deleted while not watching: the next full list reports it
    put(&r.store, Precondition::NotExists, "m").await;
    drain(&mut r.events);
    r.cluster.kubectl_delete("shop", "support");
    r.store.observe_listed(&BTreeSet::new());
    assert!(matches!(
        drain(&mut r.events).as_slice(),
        [StoreEvent::ServiceDeleted { .. }]
    ));
}

#[tokio::test]
async fn synced_condition() {
    let r = rig();
    put(&r.store, Precondition::NotExists, "m").await;
    r.store
        .set_synced(
            &key(),
            &[("support-0".into(), "config.invalid: tool x".into())],
        )
        .await
        .unwrap();
    let obj = r.cluster.charter("shop", "support").unwrap();
    let synced = condition(&obj, "Synced");
    assert_eq!(synced.status, "False");
    assert!(
        synced
            .message
            .as_deref()
            .unwrap()
            .contains("support-0: config.invalid")
    );
    r.store.set_synced(&key(), &[]).await.unwrap();
    let obj = r.cluster.charter("shop", "support").unwrap();
    assert_eq!(condition(&obj, "Synced").status, "True");
    // the other condition is untouched
    assert_eq!(condition(&obj, "Valid").status, "True");
    assert_eq!(
        r.store.set_synced(&ServiceKey::new("shop", "x"), &[]).await,
        Err(StoreError::NotFound)
    );
}

#[tokio::test]
async fn pending_adoptions_are_kept_in_memory() {
    let mut r = rig();
    let a = PendingAdoption {
        key: key(),
        sha256: "ab".repeat(32),
        pod: "support-0".into(),
        ts: "2026-10-21T10:00:00.000Z".into(),
        yaml: "x".into(),
    };
    r.store.put_pending_adoption(a.clone()).await.unwrap();
    assert_eq!(
        r.store.list_pending_adoptions().await.unwrap(),
        std::slice::from_ref(&a)
    );
    assert_eq!(
        drain(&mut r.events),
        [StoreEvent::AdoptionPending {
            key: key(),
            sha256: a.sha256.clone()
        }]
    );
    assert_eq!(
        r.store.take_pending_adoption(&key(), "cd").await,
        Err(StoreError::NotFound)
    );
    assert_eq!(
        r.store
            .take_pending_adoption(&key(), &a.sha256)
            .await
            .unwrap(),
        a
    );
    assert!(r.store.list_pending_adoptions().await.unwrap().is_empty());
}

fn audits(events: &[StoreEvent]) -> Vec<&CpAuditRecord> {
    events
        .iter()
        .filter_map(|e| match e {
            StoreEvent::CpAudit(r) => Some(&**r),
            _ => None,
        })
        .collect()
}

fn changed_to(events: &[StoreEvent]) -> Vec<(String, String, String)> {
    events
        .iter()
        .filter_map(|e| match e {
            StoreEvent::CharterChanged {
                epoch,
                version,
                actor,
                ..
            } => Some((epoch.clone(), version.clone(), actor.name.clone())),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn a_version_annotation_set_back_with_kubectl_never_reuses_a_version() {
    let mut r = rig();
    let first = put(&r.store, Precondition::NotExists, "m1").await;
    let exported_v1 = r.cluster.charter("shop", "support").unwrap();
    put(&r.store, Precondition::Version("1".into()), "m2").await;
    put(&r.store, Precondition::Version("2".into()), "m3").await;
    drain(&mut r.events);

    // a kubectl edit that also sets the version annotation back (the validating webhook
    // refuses that; the store does not rely on it)
    r.cluster.kubectl("shop", "support", "kubectl-edit", |o| {
        o["spec"]["agents"][0]["model"] = json!("m-kubectl");
        o["metadata"]["annotations"][VERSION_ANNOTATION] = json!("1");
    });
    r.store
        .observe(&r.cluster.charter("shop", "support").unwrap())
        .await;
    let got = r.store.get_charter(&key()).await.unwrap();
    assert_eq!(
        (got.version.as_str(), got.epoch.as_str()),
        ("4", first.epoch.as_str())
    );
    assert_eq!(got.charter_json["agents"][0]["model"], "m-kubectl");
    assert!(
        r.store
            .get_revision(&key(), "2")
            .await
            .unwrap()
            .contains("m2")
    );
    let events = drain(&mut r.events);
    assert_eq!(
        changed_to(&events),
        [(first.epoch.clone(), "4".into(), "k8s:kubectl-edit".into())]
    );
    let a = audits(&events);
    assert_eq!(a.len(), 1);
    assert_eq!(
        (a[0].from_version.as_deref(), a[0].to_version.as_deref()),
        (Some("3"), Some("4"))
    );

    // an old export re-applied whole (spec and annotations of version 1)
    r.cluster
        .kubectl("shop", "support", "kubectl-client-side-apply", |o| {
            o["spec"] = exported_v1["spec"].clone();
            o["metadata"]["annotations"] = exported_v1["metadata"]["annotations"].clone();
        });
    r.store
        .observe(&r.cluster.charter("shop", "support").unwrap())
        .await;
    let got = r.store.get_charter(&key()).await.unwrap();
    assert_eq!(got.version, "5");
    assert_eq!(got.charter_json["agents"][0]["model"], "m1");
    let events = drain(&mut r.events);
    assert_eq!(
        changed_to(&events),
        [(
            first.epoch.clone(),
            "5".into(),
            "k8s:kubectl-client-side-apply".into()
        )]
    );
    assert_eq!(audits(&events).len(), 1);

    // only the annotation changed (no new generation): what is served does not move
    r.cluster
        .kubectl("shop", "support", "kubectl-annotate", |o| {
            o["metadata"]["annotations"][VERSION_ANNOTATION] = json!("2");
        });
    let obj = r.cluster.charter("shop", "support").unwrap();
    assert!(!needs_processing(&obj));
    r.store.observe(&obj).await;
    assert!(drain(&mut r.events).is_empty());
    let got = r.store.get_charter(&key()).await.unwrap();
    assert_eq!(
        (
            got.version.as_str(),
            &got.charter_json["agents"][0]["model"]
        ),
        ("5", &json!("m1"))
    );
    // and the next write goes above every version this epoch ever had
    let next = put(&r.store, Precondition::Version("5".into()), "m6").await;
    assert_eq!(next.version, "6");
    let versions: Vec<String> = r
        .store
        .history(&key())
        .await
        .unwrap()
        .into_iter()
        .map(|h| h.version)
        .collect();
    assert_eq!(versions, ["6", "5", "4", "3", "2", "1"]);
}

#[tokio::test]
async fn a_charter_recreated_with_its_old_annotations_is_a_new_epoch_and_audited() {
    let mut r = rig();
    let first = put(&r.store, Precondition::NotExists, "m1").await;
    let exported_v1 = r.cluster.charter("shop", "support").unwrap();
    put(&r.store, Precondition::Version("1".into()), "m2").await;
    let exported_v2 = r.cluster.charter("shop", "support").unwrap();

    for (export, manager, model) in [
        (&exported_v2, "velero-server", "m2"),
        // version 1's annotations look like embassy's own first write: they are not
        (&exported_v1, "kubectl-client-side-apply", "m1"),
    ] {
        let gone = r.cluster.kubectl_delete("shop", "support").unwrap();
        r.store.observe_deleted(&gone);
        drain(&mut r.events);
        // a restore or a re-applied export: spec and annotations, no status
        r.cluster.kubectl("shop", "support", manager, |o| {
            o["spec"] = export["spec"].clone();
            o["metadata"]["annotations"] = export["metadata"]["annotations"].clone();
        });
        let obj = r.cluster.charter("shop", "support").unwrap();
        assert!(needs_processing(&obj));
        // nothing is served before it was validated
        assert_eq!(r.store.get_charter(&key()).await, Err(StoreError::NotFound));
        r.store.observe(&obj).await;

        let got = r.store.get_charter(&key()).await.unwrap();
        assert_ne!(got.epoch, first.epoch);
        assert_eq!(got.version, "1", "{manager}");
        assert_eq!(got.charter_json["agents"][0]["model"], model);
        let history = r.store.history(&key()).await.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].actor, format!("k8s:{manager}"));
        let events = drain(&mut r.events);
        assert_eq!(
            changed_to(&events),
            [(got.epoch.clone(), "1".into(), format!("k8s:{manager}"))]
        );
        let a = audits(&events);
        assert_eq!(a.len(), 1, "{manager}: {events:?}");
        assert_eq!(
            (a[0].action, a[0].result, a[0].actor.as_str()),
            (
                CpAction::CrExternalEdit,
                CpResult::Ok,
                format!("k8s:{manager}").as_str()
            )
        );
        assert_eq!(
            (a[0].from_version.as_deref(), a[0].to_version.as_deref()),
            (None, Some("1"))
        );
    }
}

#[tokio::test]
async fn our_own_spec_write_whose_revision_was_lost_is_finished_and_pushed() {
    let mut r = rig();
    let first = put(&r.store, Precondition::NotExists, "m1").await;
    drain(&mut r.events);
    // embassy wrote version 2's spec and annotations, then stopped before the revision
    let mut obj = r.cluster.charter("shop", "support").unwrap();
    obj["spec"]["agents"][0]["model"] = json!("m2");
    let hash = spec_sha256(&obj["spec"]);
    set_annotations(&mut obj, 2, &hash);
    let obj = r.cluster.replace("shop", "support", &obj).await.unwrap();
    assert!(needs_processing(&obj));
    assert_eq!(r.store.get_charter(&key()).await.unwrap().version, "1");

    r.store.observe(&obj).await;
    let got = r.store.get_charter(&key()).await.unwrap();
    assert_eq!(
        (
            got.version.as_str(),
            &got.charter_json["agents"][0]["model"]
        ),
        ("2", &json!("m2"))
    );
    assert_eq!(r.store.history(&key()).await.unwrap()[0].actor, "system");
    // the served version moved, so subscribers hear of it; it is not an external edit
    let events = drain(&mut r.events);
    assert_eq!(
        changed_to(&events),
        [(first.epoch.clone(), "2".into(), "system".into())]
    );
    assert!(audits(&events).is_empty());
    assert!(r.out.records().is_empty());
}

#[tokio::test]
async fn an_existing_revision_is_never_overwritten() {
    let r = rig();
    put(&r.store, Precondition::NotExists, "m1").await;
    let obj = r.cluster.charter("shop", "support").unwrap();
    let other = Applied {
        yaml: "other".into(),
        actor: alice(),
        source: ChangeSource::Api,
        spec_sha256: "0".repeat(64),
    };
    let e = r
        .store
        .inner
        .record_revision(&obj, &key(), 1, &other)
        .await
        .unwrap_err();
    assert!(
        matches!(e, StoreError::Io(ref m) if m.contains("exists with another spec")),
        "{e:?}"
    );
    assert!(
        r.store
            .get_revision(&key(), "1")
            .await
            .unwrap()
            .contains("m1")
    );
    // the same write again (a retry) is fine
    let same = Applied {
        yaml: "again".into(),
        actor: alice(),
        source: ChangeSource::Api,
        spec_sha256: spec_sha256(&obj["spec"]),
    };
    r.store
        .inner
        .record_revision(&obj, &key(), 1, &same)
        .await
        .unwrap();
    assert!(
        r.store
            .get_revision(&key(), "1")
            .await
            .unwrap()
            .contains("m1")
    );
}

#[tokio::test]
async fn a_kubectl_edit_racing_our_status_write_stays_unobserved() {
    let mut r = rig();
    let first = put(&r.store, Precondition::NotExists, "m1").await;
    // the edit lands between embassy's spec write and its status write
    r.cluster
        .kubectl_before_next_status_write("shop", "support", "kubectl-edit", |o| {
            o["spec"]["agents"][0]["model"] = json!("m-kubectl");
        });
    let second = put(&r.store, Precondition::Version("1".into()), "m2").await;
    assert_eq!(second.version, "2");
    let obj = r.cluster.charter("shop", "support").unwrap();
    let generation = obj["metadata"]["generation"].as_i64().unwrap();
    assert_eq!(obj["status"]["appliedVersion"], "2");
    assert_eq!(obj["status"]["observedGeneration"], json!(generation - 1));
    assert_eq!(
        condition(&obj, "Valid").observed_generation,
        Some(generation - 1)
    );
    assert!(needs_processing(&obj), "the kubectl edit is still to do");
    assert_eq!(
        r.store.get_charter(&key()).await.unwrap().charter_json["agents"][0]["model"],
        "m2"
    );
    drain(&mut r.events);

    r.store.observe(&obj).await;
    let got = r.store.get_charter(&key()).await.unwrap();
    assert_eq!(
        (
            got.version.as_str(),
            &got.charter_json["agents"][0]["model"]
        ),
        ("3", &json!("m-kubectl"))
    );
    let events = drain(&mut r.events);
    assert_eq!(
        changed_to(&events),
        [(first.epoch.clone(), "3".into(), "k8s:kubectl-edit".into())]
    );
    assert_eq!(audits(&events).len(), 1);
    assert!(!needs_processing(
        &r.cluster.charter("shop", "support").unwrap()
    ));
}

#[tokio::test]
async fn an_edit_racing_the_invalid_mark_is_processed_too() {
    let mut r = rig();
    put(&r.store, Precondition::NotExists, "m1").await;
    drain(&mut r.events);
    r.cluster.kubectl("shop", "support", "kubectl-edit", |o| {
        o["spec"]["agents"][0]["modle"] = json!("typo");
    });
    let invalid = r.cluster.charter("shop", "support").unwrap();
    // the fix lands while embassy marks the typo invalid
    r.cluster
        .kubectl_before_next_status_write("shop", "support", "kubectl-edit", |o| {
            let agent = o["spec"]["agents"][0].as_object_mut().unwrap();
            agent.remove("modle");
            agent.insert("model".into(), json!("m-fixed"));
        });
    r.store.observe(&invalid).await;

    let obj = r.cluster.charter("shop", "support").unwrap();
    assert!(!needs_processing(&obj));
    assert_eq!(condition(&obj, "Valid").status, "True");
    let got = r.store.get_charter(&key()).await.unwrap();
    assert_eq!(
        (
            got.version.as_str(),
            &got.charter_json["agents"][0]["model"]
        ),
        ("2", &json!("m-fixed"))
    );
    let events = drain(&mut r.events);
    let results: Vec<CpResult> = audits(&events).iter().map(|a| a.result).collect();
    assert_eq!(results, [CpResult::Invalid, CpResult::Ok]);
}

#[tokio::test]
async fn report_synced_reaches_the_kubernetes_store_behind_dyn_store() {
    let cluster = Arc::new(FakeCluster::new());
    let kube = Arc::new(KubeStore::with_writer(
        cluster.clone(),
        Box::new(std::io::sink()),
    ));
    crate::k8s::register_kube_store(&kube);
    put(&kube, Precondition::NotExists, "m").await;
    let store: Arc<dyn Store> = kube.clone();
    let failures = [(
        "support-0".to_string(),
        "config.invalid: tool x".to_string(),
    )];
    crate::k8s::report_synced(&store, &key(), &failures)
        .await
        .unwrap();
    let obj = cluster.charter("shop", "support").unwrap();
    let synced = condition(&obj, "Synced");
    assert_eq!(synced.status, "False");
    assert!(
        synced
            .message
            .as_deref()
            .unwrap()
            .contains("support-0: config.invalid")
    );
    // the same report again writes nothing
    let status_writes = |c: &FakeCluster| {
        c.calls()
            .iter()
            .filter(|c| c.starts_with("replace status"))
            .count()
    };
    let before = status_writes(&cluster);
    crate::k8s::report_synced(&store, &key(), &failures)
        .await
        .unwrap();
    assert_eq!(status_writes(&cluster), before);
    crate::k8s::report_synced(&store, &key(), &[])
        .await
        .unwrap();
    assert_eq!(
        condition(&cluster.charter("shop", "support").unwrap(), "Synced").status,
        "True"
    );
    // any other store: nothing happens
    let other_cluster = Arc::new(FakeCluster::new());
    let other: Arc<dyn Store> = Arc::new(KubeStore::with_writer(
        other_cluster.clone(),
        Box::new(std::io::sink()),
    ));
    crate::k8s::report_synced(&other, &key(), &failures)
        .await
        .unwrap();
    assert!(other_cluster.calls().is_empty());
}

#[test]
fn embassy_wrote_last_needs_a_strictly_newer_entry() {
    let fields = |entries: Value| json!({"metadata": {"managedFields": entries}});
    assert!(embassy_wrote_last(&fields(json!([
        {"manager": "kubectl-edit", "time": "2026-10-21T10:00:00Z"},
        {"manager": "embassy", "time": "2026-10-21T10:00:01Z"},
        {"manager": "kubectl-edit", "time": "2026-10-21T10:00:05Z", "subresource": "status"}
    ]))));
    // a tie, kubectl newer, or no entry of embassy's
    for entries in [
        json!([{"manager": "kubectl-edit", "time": "2026-10-21T10:00:01Z"},
               {"manager": "embassy", "time": "2026-10-21T10:00:01Z"}]),
        json!([{"manager": "embassy", "time": "2026-10-21T10:00:01Z"},
               {"manager": "kubectl-edit", "time": "2026-10-21T10:00:02Z"}]),
        json!([{"manager": "velero-server", "time": "2026-10-21T10:00:01Z"}]),
        json!([]),
    ] {
        assert!(!embassy_wrote_last(&fields(entries.clone())), "{entries}");
    }
    // a restored status whose observedGeneration is above the fresh generation is processed
    assert!(needs_processing(
        &json!({"metadata": {"generation": 1}, "status": {"observedGeneration": 7}})
    ));
}

#[test]
fn the_spec_hash_survives_an_api_server_round_trip() {
    let sent = json!({"service": {"name": "a", "app_port": 8080}, "budgets": {"cost": 10.0, "x": null}, "list": [1, 2.5]});
    // keys re-ordered, 10.0 written as 10, the null member pruned
    let back = json!({"list": [1, 2.5], "budgets": {"cost": 10}, "service": {"app_port": 8080, "name": "a"}});
    assert_eq!(spec_sha256(&sent), spec_sha256(&back));
    assert_ne!(
        spec_sha256(&sent),
        spec_sha256(&json!({"service": {"name": "b"}}))
    );
}

#[test]
fn writes_are_checked_against_the_service() {
    let k = key();
    // CR form
    let cr = json!({"apiVersion": "attache.io/v1alpha1", "kind": "Charter",
        "metadata": {"name": "support", "namespace": "shop"}, "spec": {"service": {"name": "support"}}});
    assert_eq!(
        spec_from_write(&k, &cr).unwrap(),
        json!({"service": {"name": "support"}})
    );
    let mut wrong = cr.clone();
    wrong["metadata"]["namespace"] = json!("other");
    assert!(spec_from_write(&k, &wrong).is_err());
    // plain form
    let plain = charter("m", true);
    let spec = spec_from_write(&k, &plain).unwrap();
    assert!(spec.get("apiVersion").is_none() && spec.get("kind").is_none());
    let mut wrong = plain.clone();
    wrong["service"]["namespace"] = json!("other");
    assert!(spec_from_write(&k, &wrong).is_err());
    assert!(spec_from_write(&k, &json!("text")).is_err());
}

#[test]
fn the_last_manager_skips_embassy_and_status_writers() {
    let obj = json!({"metadata": {"managedFields": [
        {"manager": "kubectl-client-side-apply", "time": "2026-10-21T10:00:00Z"},
        {"manager": "kubectl-edit", "time": "2026-10-21T10:05:00Z"},
        {"manager": "embassy", "time": "2026-10-21T10:06:00Z"},
        {"manager": "status-writer", "time": "2026-10-21T10:07:00Z", "subresource": "status"}
    ]}});
    assert_eq!(last_manager(&obj), "kubectl-edit");
    assert_eq!(last_manager(&json!({})), "unknown");
    assert_eq!(
        revision_name("orders", "0f1e2d3c-aaaa-4000-8000-000000000001", 7),
        "orders-0f1e2d3c-7"
    );
}
