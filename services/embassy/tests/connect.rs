//! `ControlPlane.Connect` over mTLS with test certificates (design §7): identity, Hello,
//! adoption, pushes, acks, the audit drop rules, span starts and proposals.
mod common;

use std::time::Duration;

use agentsc_proto::{
    AuditBatch, ConfigAck, ControlMessage, Heartbeat, LearningProposal, SpanStart, control_message,
    sidecar_message,
};
use common::{
    Env, NS, Opts, SseReader, eventually, hello, inventory_yaml, orders_yaml, rec, support_yaml,
};
use embassy::api::types::{ServiceStatus, ServiceSummary};
use serde_json::{Value, json};

fn charter_of(m: &ControlMessage) -> Option<(String, String, String)> {
    match &m.msg {
        Some(control_message::Msg::Charter(c)) => {
            Some((c.epoch.clone(), c.version.clone(), c.charter_yaml.clone()))
        }
        _ => None,
    }
}

fn memory_of(m: &ControlMessage) -> Option<agentsc_proto::MemoryUpdate> {
    match &m.msg {
        Some(control_message::Msg::Memory(u)) => Some(u.clone()),
        _ => None,
    }
}

async fn services(env: &Env) -> Vec<ServiceSummary> {
    serde_json::from_value(env.get("/services", "alice").await.body).unwrap()
}

async fn service(env: &Env, svc: &str) -> Option<ServiceSummary> {
    services(env).await.into_iter().find(|s| s.service == svc)
}

fn audit_actions(env: &Env) -> Vec<Value> {
    std::fs::read_to_string(env.store_dir.join(".audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

async fn events(env: &Env, who: &str, query: &str) -> SseReader {
    let resp = env
        .req("GET", &format!("/api/v1/events{query}"), Some(who))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    SseReader::new(resp)
}

#[tokio::test]
async fn the_certificate_decides_the_identity() {
    let env = Env::start().await;
    // Hello names another service than the certificate
    let err = env
        .sidecar(NS, "orders", hello(NS, "inventory", "orders-0"))
        .await
        .err()
        .expect("refused");
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err}");
    eventually("connect_denied in the audit", || async {
        audit_actions(&env).iter().any(|l| {
            l["action"] == "connect_denied"
                && l["actor"] == "sidecar:spiffe://agentsc/ns/shop/svc/orders/orders-0"
                && l["actor_kind"] == "sidecar"
                && l["result"] == "denied"
        })
    })
    .await;
    // no client certificate: the TLS listener refuses it
    let channel = tokio::time::timeout(Duration::from_secs(5), async {
        let tls = tonic::transport::ClientTlsConfig::new()
            .ca_certificate(tonic::transport::Certificate::from_pem(env.ca.roots_pem()))
            .domain_name("localhost");
        tonic::transport::Endpoint::from_shared(format!(
            "https://localhost:{}",
            env.grpc.unwrap().port()
        ))
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
    })
    .await
    .unwrap();
    if let Ok(channel) = channel {
        let r = common::Sidecar::open(channel, hello(NS, "orders", "x")).await;
        assert!(r.is_err(), "a stream without a client certificate");
    }
    // a certificate from another CA
    let other = agentsc_pki::ca_init().unwrap();
    let other = embassy::ca::CaMaterial::from_pems(&other.cert_pem, &other.key_pem).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let csr = rcgen::CertificateParams::default()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap();
    let leaf = other
        .sign_workload(
            &agentsc_pki::verify_csr_p256(&csr).unwrap(),
            NS,
            "orders",
            Duration::from_secs(600),
        )
        .unwrap();
    let tls = tonic::transport::ClientTlsConfig::new()
        .ca_certificate(tonic::transport::Certificate::from_pem(env.ca.roots_pem()))
        .identity(tonic::transport::Identity::from_pem(
            leaf.cert_pem,
            key.serialize_pem(),
        ))
        .domain_name("localhost");
    let endpoint = tonic::transport::Endpoint::from_shared(format!(
        "https://localhost:{}",
        env.grpc.unwrap().port()
    ))
    .unwrap()
    .tls_config(tls)
    .unwrap();
    if let Ok(channel) = endpoint.connect().await {
        assert!(
            common::Sidecar::open(channel, hello(NS, "orders", "x"))
                .await
                .is_err()
        );
    }
    // the right certificate and Hello
    let mut sc = env
        .sidecar(NS, "orders", hello(NS, "orders", "orders-0"))
        .await
        .unwrap();
    assert!(
        sc.next_within(Duration::from_millis(300)).await.is_none(),
        "no charter, nothing pushed"
    );
    let s = service(&env, "orders").await.unwrap();
    assert_eq!((s.status, s.instances.len()), (ServiceStatus::NoCharter, 1));
    assert_eq!(s.instances[0].pod, "orders-0");
    uuid::Uuid::parse_str(&s.instances[0].instance_id).unwrap();
    assert!(
        audit_actions(&env)
            .iter()
            .any(|l| l["action"] == "connect" && l["result"] == "ok")
    );
    env.stop().await;
}

#[tokio::test]
async fn a_start_up_charter_waits_for_adoption() {
    let env = Env::start().await;
    let mut h = hello(NS, "orders", "orders-0");
    h.charter_yaml = orders_yaml();
    let mut sc = env.sidecar(NS, "orders", h).await.unwrap();
    let sha = embassy::store::file::sha256_hex(&orders_yaml());
    eventually("a pending adoption", || async {
        service(&env, "orders")
            .await
            .and_then(|s| s.pending_adoption)
            .is_some_and(|p| p.sha256 == sha && p.pod == "orders-0")
    })
    .await;
    assert!(
        sc.next_within(Duration::from_millis(200)).await.is_none(),
        "nothing is pushed"
    );
    assert!(
        audit_actions(&env)
            .iter()
            .any(|l| l["action"] == "adopt_pending"
                && l["actor"] == "sidecar:spiffe://agentsc/ns/shop/svc/orders/orders-0")
    );
    // adopting: editor, the matching hash
    let path = format!("/services/{NS}/orders/adopt");
    let r = env
        .call("POST", &path, "carol", Some(json!({"sha256": sha})), None)
        .await;
    assert_eq!(r.status, 403);
    let r = env
        .call(
            "POST",
            &path,
            "bob",
            Some(json!({"sha256": "0".repeat(64)})),
            None,
        )
        .await;
    assert_eq!(r.status, 404);
    let r = env
        .call("POST", &path, "bob", Some(json!({"sha256": sha})), None)
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.version(), "1");
    // the instance gets the charter
    let m = sc.next().await;
    let (epoch, version, yaml) = charter_of(&m).expect("a charter update");
    assert_eq!(
        (version.as_str(), yaml.as_str()),
        ("1", orders_yaml().as_str())
    );
    uuid::Uuid::parse_str(&epoch).unwrap();
    let s = service(&env, "orders").await.unwrap();
    assert!(s.pending_adoption.is_none());
    let r = env
        .call("POST", &path, "bob", Some(json!({"sha256": sha})), None)
        .await;
    assert_eq!((r.status, r.error()), (409, "version_conflict"));
    assert!(
        audit_actions(&env)
            .iter()
            .any(|l| l["action"] == "adopt_approve" && l["actor"] == "bob")
    );
    // an invalid start-up charter is not adoptable
    let mut h = hello(NS, "inventory", "inventory-0");
    h.charter_yaml = "service: {}".into();
    let _sc2 = env.sidecar(NS, "inventory", h).await.unwrap();
    eventually("an invalid adoption audited", || async {
        audit_actions(&env)
            .iter()
            .any(|l| l["action"] == "adopt_pending" && l["result"] == "invalid")
    })
    .await;
    assert!(
        service(&env, "inventory")
            .await
            .unwrap()
            .pending_adoption
            .is_none()
    );
    env.stop().await;
}

#[tokio::test]
async fn auto_adopt_stores_the_start_up_charter() {
    let env = Env::start_with(Opts {
        auto_adopt: true,
        ..Default::default()
    })
    .await;
    let mut h = hello(NS, "orders", "orders-0");
    h.charter_yaml = orders_yaml();
    let mut sc = env.sidecar(NS, "orders", h).await.unwrap();
    let m = sc.next().await;
    assert_eq!(charter_of(&m).unwrap().1, "1");
    let (v, _) = env.charter("orders").await;
    assert_eq!(v, "1");
    let hist: Vec<embassy::api::types::HistoryEntry> = serde_json::from_value(
        env.get(&format!("/services/{NS}/orders/charter/history"), "alice")
            .await
            .body,
    )
    .unwrap();
    assert_eq!(
        hist[0].actor,
        "sidecar:spiffe://agentsc/ns/shop/svc/orders/orders-0"
    );
    assert!(
        audit_actions(&env)
            .iter()
            .any(|l| l["action"] == "adopt_approve"
                && l["actor_kind"] == "sidecar"
                && l["result"] == "ok")
    );
    env.stop().await;
}

#[tokio::test]
async fn hello_gets_the_charter_when_versions_differ_then_the_memory() {
    let env = Env::start().await;
    let v = env.create("support", &support_yaml(true)).await;
    let epoch = env
        .get(&format!("/services/{NS}/support/charter"), "alice")
        .await
        .body["epoch"]
        .as_str()
        .unwrap()
        .to_string();
    // a sidecar with another version: charter, then memory
    let mut sc = env
        .sidecar(NS, "support", hello(NS, "support", "support-0"))
        .await
        .unwrap();
    let first = sc.next().await;
    assert_eq!(charter_of(&first).unwrap().1, v);
    let second = sc.next().await;
    assert_eq!(memory_of(&second).unwrap().version, "0");
    // a sidecar that runs the stored version: only the memory; it counts as acked
    let mut h = hello(NS, "support", "support-1");
    h.charter_epoch = epoch;
    h.charter_version = v.clone();
    let mut sc2 = env.sidecar(NS, "support", h).await.unwrap();
    let only = sc2.next().await;
    assert!(memory_of(&only).is_some(), "{only:?}");
    assert!(sc2.next_within(Duration::from_millis(200)).await.is_none());
    let s = service(&env, "support").await.unwrap();
    let i = s.instances.iter().find(|i| i.pod == "support-1").unwrap();
    assert_eq!(i.acked_version.as_deref(), Some(v.as_str()));
    env.stop().await;
}

#[tokio::test]
async fn store_changes_are_pushed_to_connected_instances() {
    let env = Env::start().await;
    let v = env.create("support", &support_yaml(true)).await;
    let mut sc = env
        .sidecar(NS, "support", hello(NS, "support", "support-0"))
        .await
        .unwrap();
    sc.next().await; // charter
    sc.next().await; // memory
    // a charter write
    let (_, mut c) = env.charter("support").await;
    c["agents"][1]["system"] = json!("Answer FAQs.");
    let r = env
        .call(
            "PUT",
            &format!("/services/{NS}/support/charter"),
            "bob",
            Some(json!({"yaml": c.to_string()})),
            Some(&v),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let m = sc.next().await;
    let (_, version, yaml) = charter_of(&m).unwrap();
    assert_eq!(version, "2");
    assert!(yaml.contains("Answer FAQs."));
    // a memory write
    let r = env
        .call(
            "PUT",
            &format!("/services/{NS}/support/memory"),
            "bob",
            Some(json!({"agents": {"helper": [{"text": "Look it up."}]}})),
            Some("0"),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let m = sc.next().await;
    let u = memory_of(&m).unwrap();
    assert_eq!(u.version, "1");
    assert_eq!(u.agents["helper"].notes[0].text, "Look it up.");
    assert_eq!(u.agents["helper"].notes[0].source, "manual");
    // another service's change reaches no one here
    env.create("orders", &orders_yaml()).await;
    assert!(sc.next_within(Duration::from_millis(300)).await.is_none());
    env.stop().await;
}

#[tokio::test]
async fn acks_heartbeats_and_registry_events() {
    let env = Env::start().await;
    let v = env.create("orders", &orders_yaml()).await;
    let mut sse = events(&env, "alice", "").await;
    let mut sc = env
        .sidecar(NS, "orders", hello(NS, "orders", "orders-0"))
        .await
        .unwrap();
    let reg = sse.until("registry").await;
    assert_eq!(
        (reg.data["status"].as_str(), reg.data["pod"].as_str()),
        (Some("connected"), Some("orders-0"))
    );
    let instance = reg.data["instance_id"].as_str().unwrap().to_string();
    sc.next().await;
    sc.next().await;
    // not yet acked, runtime not ready: degraded
    assert_eq!(
        service(&env, "orders").await.unwrap().status,
        ServiceStatus::Degraded
    );
    sc.send(sidecar_message::Msg::Heartbeat(Heartbeat {
        seq: 1,
        runtime_ready: true,
        charter_version: v.clone(),
        audit_dropped: 3,
        cert_expires_in_s: 3600,
    }))
    .await;
    sc.send(sidecar_message::Msg::Ack(ConfigAck {
        epoch: String::new(),
        version: v.clone(),
        applied: true,
        error: String::new(),
        kind: "charter".into(),
    }))
    .await;
    let ack = sse.until("ack").await;
    assert_eq!(
        ack.data,
        json!({"namespace": NS, "service": "orders", "instance_id": instance, "pod": "orders-0", "kind": "charter", "version": v, "applied": true, "error": null})
    );
    eventually("connected", || async {
        service(&env, "orders").await.unwrap().status == ServiceStatus::Connected
    })
    .await;
    let s = service(&env, "orders").await.unwrap();
    let i = &s.instances[0];
    assert!(i.runtime_ready && i.last_heartbeat.is_some());
    assert_eq!((i.audit_dropped, i.cert_expires_in_s), (3, Some(3600)));
    // a failed ack: the error shows, the service is degraded
    sc.send(sidecar_message::Msg::Ack(ConfigAck {
        epoch: String::new(),
        version: v.clone(),
        applied: false,
        error: "disk full".into(),
        kind: "charter".into(),
    }))
    .await;
    let ack = sse.until("ack").await;
    assert_eq!(
        (ack.data["applied"].as_bool(), ack.data["error"].as_str()),
        (Some(false), Some("disk full"))
    );
    eventually("degraded", || async {
        let s = service(&env, "orders").await.unwrap();
        s.status == ServiceStatus::Degraded
            && s.instances[0].ack_error.as_deref() == Some("disk full")
    })
    .await;
    // a memory ack is an event too
    sc.send(sidecar_message::Msg::Ack(ConfigAck {
        epoch: String::new(),
        version: "0".into(),
        applied: true,
        error: String::new(),
        kind: "memory".into(),
    }))
    .await;
    assert_eq!(sse.until("ack").await.data["kind"], "memory");
    // closing the stream removes the instance
    drop(sc);
    let reg = sse.until("registry").await;
    assert_eq!(
        (
            reg.data["status"].as_str(),
            reg.data["instance_id"].as_str()
        ),
        (Some("disconnected"), Some(instance.as_str()))
    );
    eventually("no instance", || async {
        service(&env, "orders").await.unwrap().instances.is_empty()
    })
    .await;
    env.stop().await;
}

#[tokio::test]
async fn audit_records_follow_the_drop_rules() {
    let env = Env::start().await;
    env.create("orders", &orders_yaml()).await;
    let sc = env
        .sidecar(NS, "orders", hello(NS, "orders", "orders-0"))
        .await
        .unwrap();
    let big = rec(
        "model_call",
        json!({"agent": "ops", "callee": "mock", "direction": "outbound", "request_id": "big", "input": "x".repeat(70 * 1024)}),
    );
    let records = vec![
        // claims to be another service: overwritten with the stream's identity
        rec("agent_invocation", json!({"service": "billing", "namespace": "evil", "request_id": "kept-1"})).to_string(),
        // over 64 KiB
        big.to_string(),
        // an agent the stored charter does not have, not inbound
        rec("model_call", json!({"agent": "ghost", "callee": "mock", "direction": "outbound", "request_id": "ghost"})).to_string(),
        // inbound records carry the calling peer's agent: kept
        rec("service_call", json!({"agent": "payer", "direction": "inbound", "caller": "spiffe://agentsc/ns/shop/svc/billing", "callee": "orders POST /refund", "request_id": "kept-2"})).to_string(),
        // no agent: kept
        rec("config", json!({"agent": null, "caller": "control-plane", "callee": "charter", "direction": "internal", "request_id": "kept-3", "kind": "config"})).to_string(),
        // not an audit record
        "{\"level\":\"info\"}".to_string(),
        // a kind this build does not know: kept as it is
        rec("teleport", json!({"request_id": "kept-4", "agent": "triage"})).to_string(),
    ];
    sc.send(sidecar_message::Msg::Audit(AuditBatch {
        records_json: records,
    }))
    .await;
    eventually("four records", || async {
        env.get("/events/recent", "alice")
            .await
            .body
            .as_array()
            .unwrap()
            .len()
            == 4
    })
    .await;
    let recent = env.get("/events/recent", "alice").await.body;
    let mut ids: Vec<&str> = recent
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["request_id"].as_str().unwrap())
        .collect();
    ids.sort();
    assert_eq!(ids, ["kept-1", "kept-2", "kept-3", "kept-4"]);
    for r in recent.as_array().unwrap() {
        assert_eq!(
            (r["namespace"].as_str(), r["service"].as_str()),
            (Some(NS), Some("orders")),
            "{r}"
        );
    }
    env.stop().await;
}

#[tokio::test]
async fn span_starts_become_events_and_running_spans() {
    let env = Env::start().await;
    env.create("orders", &orders_yaml()).await;
    env.create("inventory", &inventory_yaml()).await;
    let mut sse = events(&env, "carol", "").await;
    let sc = env
        .sidecar(NS, "orders", hello(NS, "orders", "orders-0"))
        .await
        .unwrap();
    let start = |span: &str, kind: &str, callee: &str| SpanStart {
        request_id: "q".into(),
        trace_id: "6e2d9ff960031afca28de8fa28704004".into(),
        span_id: span.into(),
        parent_span_id: String::new(),
        kind: kind.into(),
        agent: "ops".into(),
        caller: "local".into(),
        caller_agent: String::new(),
        callee: callee.into(),
        direction: "outbound".into(),
        ts: common::now_ts(),
    };
    sc.send(sidecar_message::Msg::SpanStart(start(
        "aaaaaaaaaaaaaaaa",
        "agent_invocation",
        "ops",
    )))
    .await;
    sc.send(sidecar_message::Msg::SpanStart(start(
        "bbbbbbbbbbbbbbbb",
        "agent_call",
        "inventory/stock",
    )))
    .await;
    sc.send(sidecar_message::Msg::SpanStart(start(
        "cccccccccccccccc",
        "agent_call",
        "inventory/stock",
    )))
    .await;
    let e = sse.until("span_start").await;
    assert_eq!(e.data["agent_node"], "agent:shop/orders/ops");
    assert_eq!(e.data["callee_node"], "agent:shop/orders/ops");
    assert_eq!(
        (e.data["service"].as_str(), e.data["call_index"].as_u64()),
        (Some("orders"), Some(1))
    );
    assert!(e.data["parent_span_id"].is_null());
    let e = sse.until("span_start").await;
    assert_eq!(
        (
            e.data["callee_node"].as_str(),
            e.data["call_index"].as_u64()
        ),
        (Some("agent:shop/inventory/stock"), Some(1))
    );
    let e = sse.until("span_start").await;
    assert_eq!(
        e.data["call_index"], 2,
        "the second call to the same callee"
    );
    let t = env
        .get("/traces/6e2d9ff960031afca28de8fa28704004", "carol")
        .await;
    assert_eq!(t.body["spans"].as_array().unwrap().len(), 3);
    assert!(
        t.body["spans"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["status"] == "running")
    );
    // another namespace's viewer sees nothing
    assert_eq!(
        env.get("/traces/6e2d9ff960031afca28de8fa28704004", "dave")
            .await
            .status,
        404
    );
    env.stop().await;
}

fn proposal(dedup: &str, agent: &str, note: &str, auto: bool) -> sidecar_message::Msg {
    sidecar_message::Msg::Proposal(LearningProposal {
        dedup_key: dedup.into(),
        agent: agent.into(),
        note: note.into(),
        rationale: "r".into(),
        request_id: "0c4a3f8e-1111-4222-8333-444455556666".into(),
        trace_id: "6e2d9ff960031afca28de8fa28704004".into(),
        auto,
    })
}

#[tokio::test]
async fn learning_proposals_are_checked_deduplicated_and_auto_noted() {
    let env = Env::start().await;
    let v = env.create("support", &support_yaml(true)).await;
    let mut sse = events(&env, "alice", "").await;
    let mut sc = env
        .sidecar(NS, "support", hello(NS, "support", "support-0"))
        .await
        .unwrap();
    sc.next().await;
    sc.next().await;
    sc.send(proposal("k1", "helper", "Read the ticket first.", false))
        .await;
    sc.send(proposal("k1", "helper", "Read the ticket first.", false))
        .await;
    sc.send(proposal("k2", "faq", "faq does not learn", false))
        .await;
    sc.send(proposal("k3", "helper", &"x".repeat(61), false))
        .await;
    sc.send(proposal(
        "k4",
        "helper",
        "auto, but the mode is review",
        true,
    ))
    .await;
    let p = sse.until("proposal").await;
    assert_eq!(
        (p.data["status"].as_str(), p.data["auto"].as_bool()),
        (Some("pending"), Some(false))
    );
    eventually("two proposals", || async {
        env.get("/proposals", "alice")
            .await
            .body
            .as_array()
            .unwrap()
            .len()
            == 2
    })
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let list = env.get("/proposals", "alice").await.body;
    assert_eq!(list.as_array().unwrap().len(), 2, "{list}");
    assert!(
        list.as_array()
            .unwrap()
            .iter()
            .all(|p| p["status"] == "pending" && p["agent"] == "helper")
    );
    // auto mode (an admin turns it on): the note is stored at once and pushed
    let (_, mut c) = env.charter("support").await;
    c["agents"][0]["learning"]["mode"] = json!("auto");
    c["agents"][0]["learning"]["note_ttl_days"] = json!(3);
    let r = env
        .call(
            "PUT",
            &format!("/services/{NS}/support/charter"),
            "alice",
            Some(json!({"yaml": c.to_string()})),
            Some(&v),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    sc.next().await; // the new charter
    sc.send(proposal("k5", "helper", "An auto lesson.", true))
        .await;
    let m = sc.next().await;
    let u = memory_of(&m).expect("a memory update");
    let note = &u.agents["helper"].notes[0];
    assert_eq!(
        (
            note.text.as_str(),
            note.source.as_str(),
            note.approved_by.as_str()
        ),
        ("An auto lesson.", "auto", "")
    );
    let expires = chrono::DateTime::parse_from_rfc3339(&note.expires_at).unwrap();
    let days = (expires.with_timezone(&chrono::Utc) - chrono::Utc::now()).num_hours();
    assert!((70..=72).contains(&days), "{days} hours");
    let auto: Vec<Value> = env
        .get("/proposals?status=approved", "alice")
        .await
        .body
        .as_array()
        .unwrap()
        .clone();
    assert_eq!((auto.len(), auto[0]["auto"].as_bool()), (1, Some(true)));
    assert!(
        audit_actions(&env)
            .iter()
            .any(|l| l["action"] == "note_auto" && l["result"] == "ok" && l["agent"] == "helper")
    );
    env.stop().await;
}

#[tokio::test]
async fn skew_and_restart_only_fields_while_instances_are_connected() {
    let env = Env::start().await;
    let v = env.create("orders", &orders_yaml()).await;
    let mut h = hello(NS, "orders", "orders-old");
    h.charter_schema_level = 1;
    let mut sc = env.sidecar(NS, "orders", h).await.unwrap();
    sc.next().await;
    let (_, base) = env.charter("orders").await;
    // a v0.2 field while a level-1 instance is connected
    let mut c = base.clone();
    c["agents"][1]["harness"] = json!({"max_retries": 1});
    let r = env
        .call(
            "PUT",
            &format!("/services/{NS}/orders/charter"),
            "bob",
            Some(json!({"yaml": c.to_string()})),
            Some(&v),
        )
        .await;
    assert_eq!((r.status, r.error()), (400, "version_skew"), "{}", r.text);
    assert!(
        r.details()
            .contains("agents.triage.harness needs charter_schema_level 2"),
        "{}",
        r.details()
    );
    assert!(
        r.details().contains("orders-old (level 1)"),
        "{}",
        r.details()
    );
    let r = env
        .call(
            "POST",
            &format!("/services/{NS}/orders/charter/validate"),
            "bob",
            Some(json!({"yaml": c.to_string()})),
            None,
        )
        .await;
    assert_eq!(r.error(), "version_skew");
    // a restart-only field while connected
    let mut c = base.clone();
    c["service"]["app_port"] = json!(9090);
    let r = env
        .call(
            "PUT",
            &format!("/services/{NS}/orders/charter"),
            "alice",
            Some(json!({"yaml": c.to_string()})),
            Some(&v),
        )
        .await;
    assert_eq!(
        (r.status, r.error()),
        (400, "config.restart_required"),
        "{}",
        r.text
    );
    assert!(r.details().contains("service.app_port"));
    // without instances both go through
    drop(sc);
    eventually("disconnected", || async {
        service(&env, "orders").await.unwrap().instances.is_empty()
    })
    .await;
    let r = env
        .call(
            "PUT",
            &format!("/services/{NS}/orders/charter"),
            "alice",
            Some(json!({"yaml": c.to_string()})),
            Some(&v),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    env.stop().await;
}

#[tokio::test]
async fn connect_shares_the_grpc_address_with_the_ca_component() {
    let env = Env::start_with(Opts {
        with_ca: true,
        ..Default::default()
    })
    .await;
    // client certificates are optional on the listener; Connect still needs one
    let channel = env.channel(None).await;
    let err = common::Sidecar::open(channel, hello(NS, "orders", "x"))
        .await
        .err()
        .expect("refused");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    let mut sc = env
        .sidecar(NS, "orders", hello(NS, "orders", "orders-0"))
        .await
        .unwrap();
    assert!(sc.next_within(Duration::from_millis(200)).await.is_none());
    assert_eq!(service(&env, "orders").await.unwrap().instances.len(), 1);
    env.stop().await;
}

fn auto_note(id: &str, text: &str, expires_at: &str) -> embassy::store::Note {
    embassy::store::Note {
        id: id.into(),
        text: text.into(),
        source: embassy::store::NoteSource::Auto,
        request_id: None,
        trace_id: None,
        approved_by: None,
        ts: "2026-10-01T10:00:00.000Z".into(),
        expires_at: Some(expires_at.into()),
    }
}

fn manual_note(id: &str, text: &str) -> embassy::store::Note {
    embassy::store::Note {
        id: id.into(),
        text: text.into(),
        source: embassy::store::NoteSource::Manual,
        request_id: None,
        trace_id: None,
        approved_by: Some("bob".into()),
        ts: "2026-10-01T10:00:00.000Z".into(),
        expires_at: None,
    }
}

#[tokio::test]
async fn expired_auto_notes_are_removed_and_pushed() {
    let env = Env::start().await;
    env.create("support", &support_yaml(true)).await;
    let mut sc = env
        .sidecar(NS, "support", hello(NS, "support", "support-0"))
        .await
        .unwrap();
    sc.next().await;
    sc.next().await;
    let key = embassy::store::ServiceKey::new(NS, "support");
    let actor = embassy::hub::system_actor();
    env.hub
        .store
        .put_memory(
            &key,
            "0",
            std::collections::BTreeMap::from([(
                "helper".to_string(),
                vec![
                    auto_note("old", "expired", "2020-01-01T00:00:00.000Z"),
                    manual_note("keep", "kept"),
                ],
            )]),
            &actor,
        )
        .await
        .unwrap();
    // the push leaves the expired note out already
    let u = memory_of(&sc.next().await).unwrap();
    assert_eq!(u.version, "1");
    assert_eq!(u.agents["helper"].notes.len(), 1);
    // the sweep removes it from the store, which pushes again
    assert_eq!(embassy::hub::expire_once(&env.hub).await.unwrap(), 1);
    let u = memory_of(&sc.next().await).unwrap();
    assert_eq!(u.version, "2");
    let m = env.hub.store.get_memory(&key).await.unwrap();
    assert_eq!(m.agents["helper"].len(), 1);
    assert_eq!(m.agents["helper"][0].id, "keep");
    assert_eq!(embassy::hub::expire_once(&env.hub).await.unwrap(), 0);
    env.stop().await;
}

async fn propose_auto(env: &Env, dedup: &str, note: &str) {
    let key = embassy::store::ServiceKey::new(NS, "support");
    let sidecar_message::Msg::Proposal(p) = proposal(dedup, "helper", note, true) else {
        unreachable!()
    };
    embassy::controlplane::ingest_proposal(&env.hub, &key, &embassy::hub::system_actor(), p).await;
}

#[tokio::test]
async fn auto_notes_make_room_or_wait_for_review() {
    let env = Env::start().await;
    let v = env.create("support", &support_yaml(true)).await;
    let (_, mut c) = env.charter("support").await;
    c["agents"][0]["learning"]["mode"] = json!("auto");
    let r = env
        .call(
            "PUT",
            &format!("/services/{NS}/support/charter"),
            "alice",
            Some(json!({"yaml": c.to_string()})),
            Some(&v),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let key = embassy::store::ServiceKey::new(NS, "support");
    let actor = embassy::hub::system_actor();
    let far = "2099-01-01T00:00:00.000Z";
    // full (max_notes 2) with an auto note: the oldest auto note makes room
    env.hub
        .store
        .put_memory(
            &key,
            "0",
            std::collections::BTreeMap::from([(
                "helper".to_string(),
                vec![
                    auto_note("a1", "first auto", far),
                    manual_note("m1", "manual"),
                ],
            )]),
            &actor,
        )
        .await
        .unwrap();
    propose_auto(&env, "d1", "second auto").await;
    let m = env.hub.store.get_memory(&key).await.unwrap();
    let texts: Vec<&str> = m.agents["helper"].iter().map(|n| n.text.as_str()).collect();
    assert_eq!(texts, ["manual", "second auto"]);
    // full of manual notes: the lesson waits for a review instead
    env.hub
        .store
        .put_memory(
            &key,
            &m.version,
            std::collections::BTreeMap::from([(
                "helper".to_string(),
                vec![manual_note("m1", "manual"), manual_note("m2", "manual 2")],
            )]),
            &actor,
        )
        .await
        .unwrap();
    propose_auto(&env, "d2", "no room").await;
    let pending = env.get("/proposals?status=pending", "alice").await.body;
    assert_eq!(pending.as_array().unwrap().len(), 1, "{pending}");
    assert_eq!(pending[0]["note"], "no room");
    assert_eq!(pending[0]["auto"], false);
    env.stop().await;
}
