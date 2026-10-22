//! Managed mode against in-process fakes of embassy's `ControlPlane` and `CertificateAuthority`
//! (design §6.3, §6.4, §7): issuance with a join token, `Hello`, heartbeats, `CharterUpdate` and
//! `MemoryUpdate` applied and acknowledged (stale versions ignored), reconnects that keep the
//! configuration, persisted state reused after a restart (and replaced by the control plane's
//! charter, restart-only fields included), a renewal that swaps the mesh certificate without a
//! restart, an expired certificate dropped and obtained anew, the Kubernetes token path, the
//! control plane's URI SAN, span starts with their parentage, audit batches with payloads
//! nulled (also before the first charter), dropped records in heartbeats, and learning
//! proposals.
mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use agentsc_charter::{Charter, LearningMode, LearningSpec, TelemetrySpec};
use agentsc_common::audit::sha256_hex;
use agentsc_pki::PemBundle;
use agentsc_proto::{
    CharterUpdate, ControlMessage, LessonRequest, MemoryUpdate, Note, NoteList, ToolAgentRequest,
    ToolServiceRequest, control_message,
};
use agentscd::loaded::Source;
use agentscd::{Config, Sidecar};
use common::cp::{FakeCp, JOIN_TOKEN, K8S_TOKEN};
use common::*;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde_json::{Value, json};

const ORDERS_ID: &str = "spiffe://agentsc/ns/agentsc-demo/svc/orders";

struct Managed {
    _tmp: tempfile::TempDir,
    sidecar: Sidecar,
    runtime: FakeRuntime,
    sock: PathBuf,
    charter_path: PathBuf,
    token_file: PathBuf,
}

impl Managed {
    fn state(&self) -> &Arc<agentscd::AppState> {
        &self.sidecar.state
    }

    async fn invoke(&self, agent: &str, input: &str) -> (u16, Value) {
        let r = reqwest::Client::new()
            .post(format!(
                "http://{}/v1/agents/{agent}/invoke",
                self.sidecar.http_addr
            ))
            .json(&json!({ "input": input }))
            .send()
            .await
            .unwrap();
        (r.status().as_u16(), r.json().await.unwrap())
    }

    async fn readyz(&self) -> (u16, Value) {
        let r = reqwest::get(format!("http://{}/readyz", self.sidecar.http_addr))
            .await
            .unwrap();
        (r.status().as_u16(), r.json().await.unwrap())
    }
}

/// A managed sidecar for orders/agentsc-demo against `cp_addr`, with `state_dir`.
async fn start_managed(
    cp_addr: SocketAddr,
    ca: &PemBundle,
    state_dir: &Path,
    file: Option<&Charter>,
    make_runtime: impl FnOnce(PathBuf) -> FakeRuntime,
    tweak: impl FnOnce(&mut Config),
) -> Managed {
    let tmp = tempfile::tempdir().unwrap();
    let sock = tmp.path().join("sock");
    let runtime = make_runtime(sock.clone());
    serve_runtime(&sock, runtime.clone());
    let charter_path = tmp.path().join("charter.yaml");
    if let Some(c) = file {
        write_charter(&charter_path, c);
    }
    let token_file = tmp.path().join("join-token");
    std::fs::write(&token_file, format!("{JOIN_TOKEN}\n")).unwrap();
    let mut cfg = Config::for_test(
        charter_path.clone(),
        tmp.path().join("no-tls"),
        sock.clone(),
    );
    cfg.control_plane = Some(cp_addr.to_string());
    cfg.service = Some("orders".into());
    cfg.namespace = Some("agentsc-demo".into());
    cfg.app_port = Some(18081);
    cfg.pod_name = Some("orders-0".into());
    cfg.ca_pem = Some(ca.cert_pem.clone());
    cfg.join_token_file = Some(token_file.clone());
    cfg.state_dir = Some(state_dir.to_path_buf());
    cfg.timing = fast_timing();
    tweak(&mut cfg);
    let sidecar = agentscd::start(cfg).await.expect("managed sidecar starts");
    Managed {
        _tmp: tmp,
        sidecar,
        runtime,
        sock,
        charter_path,
        token_file,
    }
}

/// The orders charter with learning on for ops-assistant and its audit log in `audit`.
fn charter(audit: &Path) -> Charter {
    let mut c = orders(audit);
    c.agents[0].learning = Some(LearningSpec {
        enabled: true,
        mode: LearningMode::Auto,
        ..Default::default()
    });
    c
}

fn charter_update(epoch: &str, version: &str, c: &Charter) -> ControlMessage {
    ControlMessage {
        msg: Some(control_message::Msg::Charter(CharterUpdate {
            epoch: epoch.into(),
            version: version.into(),
            charter_yaml: c.to_yaml().unwrap(),
        })),
    }
}

fn memory_update(version: &str, notes: &[(&str, &str)]) -> ControlMessage {
    let mut agents = HashMap::new();
    agents.insert(
        "ops-assistant".to_string(),
        NoteList {
            notes: notes
                .iter()
                .map(|(id, text)| Note {
                    id: id.to_string(),
                    text: text.to_string(),
                    source: "review".into(),
                    ts: "2026-10-21T10:00:00.000Z".into(),
                    ..Default::default()
                })
                .collect(),
        },
    );
    ControlMessage {
        msg: Some(control_message::Msg::Memory(MemoryUpdate {
            version: version.into(),
            agents,
        })),
    }
}

/// The ack with `kind` and `version`, waiting for it.
async fn ack(cp: &FakeCp, kind: &str, version: &str) -> agentsc_proto::ConfigAck {
    eventually(&format!("{kind} ack {version}"), || {
        cp.acks()
            .iter()
            .any(|a| a.kind == kind && a.version == version)
    })
    .await;
    cp.acks()
        .into_iter()
        .rev()
        .find(|a| a.kind == kind && a.version == version)
        .unwrap()
}

#[tokio::test]
async fn issuance_hello_heartbeats_and_updates() {
    let ca = agentsc_pki::ca_init().unwrap();
    let cp = FakeCp::start(ca.clone()).await;
    let state_dir = tempfile::tempdir().unwrap();
    let audit_dir = tempfile::tempdir().unwrap();
    let audit = audit_dir.path().join("audit.jsonl");
    let file = charter(&audit);
    let m = start_managed(
        cp.addr,
        &ca,
        state_dir.path(),
        Some(&file),
        |_| FakeRuntime::answering("done"),
        |_| {},
    )
    .await;

    // 1. issuance with the join token, a P-256 CSR, persisted with a private key file
    eventually("a certificate", || m.state().tls().is_some()).await;
    let issued = cp.shared.issued.lock().unwrap().clone();
    assert_eq!(issued[0].join_token, JOIN_TOKEN);
    assert!(issued[0].kubernetes_token.is_empty());
    assert_eq!(
        (issued[0].service.as_str(), issued[0].namespace.as_str()),
        ("orders", "agentsc-demo")
    );
    let csr = rcgen::CertificateSigningRequestParams::from_pem(&issued[0].csr_pem).unwrap();
    assert_eq!(csr.public_key.algorithm(), &rcgen::PKCS_ECDSA_P256_SHA256);
    assert_eq!(m.state().tls().unwrap().material.identity.uri(), ORDERS_ID);
    for f in ["tls.key", "tls.crt", "ca.crt"] {
        assert!(state_dir.path().join(f).exists(), "{f}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(state_dir.path().join("tls.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let certs = wait_audit(&audit, 1, |v| v["rule"] == "cert.issued").await;
    assert_eq!(certs[0]["kind"], "config");
    assert_eq!(certs[0]["callee"], "certificate");

    // 2. ready once it has a certificate and a charter (and the runtime answers)
    eventually("ready", || m.state().is_ready()).await;
    let (status, body) = m.readyz().await;
    assert_eq!(status, 200, "{body}");
    let left = body["cert_expires_in_s"].as_i64().unwrap();
    assert!(left > 3500 && left <= 3600, "{left}");

    // 3. Hello first, every field
    eventually("hello", || !cp.hellos().is_empty()).await;
    let received = cp.received();
    assert!(matches!(
        received[0].1.msg,
        Some(agentsc_proto::sidecar_message::Msg::Hello(_))
    ));
    let h = cp.hellos()[0].clone();
    assert_eq!(h.service, "orders");
    assert_eq!(h.namespace, "agentsc-demo");
    assert_eq!(h.pod, "orders-0");
    assert_eq!(h.sidecar_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(
        (h.charter_epoch.as_str(), h.charter_version.as_str()),
        ("", "")
    );
    assert_eq!(
        h.charter_yaml,
        std::fs::read_to_string(&m.charter_path).unwrap()
    );
    assert_eq!(h.app_port, 18081);
    assert_eq!(h.mesh_port, u32::from(m.sidecar.mesh_addr.unwrap().port()));
    assert_eq!(
        h.charter_schema_level,
        agentsc_charter::CHARTER_SCHEMA_LEVEL
    );
    assert_eq!(h.charter_schema_level, 3);
    assert_eq!(h.memory_version, "");
    assert_eq!(
        cp.shared.peers.lock().unwrap()[0],
        ORDERS_ID,
        "mTLS with the workload cert"
    );

    // 4. heartbeats
    eventually("a heartbeat with the runtime ready", || {
        cp.heartbeats().iter().any(|b| b.runtime_ready)
    })
    .await;
    let hb = cp.heartbeats().last().unwrap().clone();
    assert!(hb.seq > 0);
    assert_eq!(hb.audit_dropped, 0);
    assert!(hb.cert_expires_in_s > 3500, "{}", hb.cert_expires_in_s);
    assert_eq!(hb.charter_version, "");

    // 5. a CharterUpdate is applied, acknowledged, audited and persisted
    let mut v3 = charter(&audit);
    v3.agents[0].system = "version three".into();
    cp.push(charter_update("e1", "3", &v3)).await;
    let a = ack(&cp, "charter", "3").await;
    assert!(a.applied, "{}", a.error);
    assert_eq!(a.epoch, "e1");
    let l = m.state().loaded().unwrap();
    assert_eq!((l.epoch.as_str(), l.version.as_str()), ("e1", "3"));
    assert_eq!(l.source, Source::ControlPlane);
    assert_eq!(l.charter.agents[0].system, "version three");
    let rec = wait_audit(&audit, 1, |v| {
        v["kind"] == "config" && v["input"]["version"] == "3"
    })
    .await;
    assert_eq!(rec[0]["caller"], "control-plane");
    assert_eq!(rec[0]["input"]["source"], "control-plane");
    assert_eq!(rec[0]["input"]["epoch"], "e1");
    assert_eq!(rec[0]["rule"], "config.applied");
    let meta: Value =
        serde_json::from_slice(&std::fs::read(state_dir.path().join("charter.meta.json")).unwrap())
            .unwrap();
    assert_eq!(meta, json!({"epoch": "e1", "version": "3"}));
    eventually("the heartbeat carries the version", || {
        cp.heartbeats()
            .last()
            .is_some_and(|b| b.charter_version == "3")
    })
    .await;

    // 6. stale and duplicate versions of the same epoch are not applied; the ack of a stale one
    //    names the version in force, so the instance never shows the stale one with an error
    let mut v2 = charter(&audit);
    v2.agents[0].system = "version two".into();
    let before = cp.acks().len();
    cp.push(charter_update("e1", "2", &v2)).await;
    eventually("the stale update's ack", || cp.acks().len() > before).await;
    let a = cp.acks().last().unwrap().clone();
    assert_eq!(
        (a.kind.as_str(), a.epoch.as_str(), a.version.as_str()),
        ("charter", "e1", "3")
    );
    assert!(a.applied && a.error.is_empty(), "{a:?}");
    assert!(!cp.acks().iter().any(|a| a.version == "2"));
    cp.push(charter_update("e1", "3", &v2)).await;
    eventually("duplicate ack", || {
        cp.acks()
            .iter()
            .filter(|a| a.kind == "charter" && a.version == "3")
            .count()
            == 3
    })
    .await;
    assert_eq!(
        m.state().loaded().unwrap().charter.agents[0].system,
        "version three"
    );
    assert_eq!(
        wait_audit(&audit, 1, |v| v["rule"] == "config.stale")
            .await
            .len(),
        1
    );

    // 7. a restart-only change from the control plane is refused (config.invalid)
    let mut v4 = charter(&audit);
    v4.service.app_port = 9999;
    cp.push(charter_update("e1", "4", &v4)).await;
    let a = ack(&cp, "charter", "4").await;
    assert!(!a.applied && a.error.contains("service.app_port"), "{a:?}");
    assert_eq!(m.state().loaded().unwrap().version, "3");

    // 8. unknown control messages are ignored; the stream stays up
    cp.push(ControlMessage { msg: None }).await;

    // 9. a MemoryUpdate replaces the memory; the runtime gets the notes
    cp.push(memory_update("1", &[("n1", "Look up the order first.")]))
        .await;
    let a = ack(&cp, "memory", "1").await;
    assert!(a.applied, "{}", a.error);
    assert_eq!(a.epoch, "e1");
    assert_eq!(m.state().memory_version(), "1");
    let (status, _) = m.invoke("ops-assistant", "hi").await;
    assert_eq!(status, 200);
    assert_eq!(
        m.runtime.last_spec("ops-assistant")["memory"],
        json!([{"id": "n1", "text": "Look up the order first."}])
    );
    let before = cp.acks().len();
    cp.push(memory_update("0", &[])).await;
    eventually("the stale memory ack", || cp.acks().len() > before).await;
    let a = cp.acks().last().unwrap().clone();
    assert_eq!((a.kind.as_str(), a.version.as_str()), ("memory", "1"));
    assert!(a.applied && a.error.is_empty(), "{a:?}");
    assert_eq!(m.state().memory_version(), "1");
    assert_eq!(cp.connections(), 1, "one stream all along");

    // 10. the --charter file no longer counts once a control-plane charter is in force
    let mut edited = charter(&audit);
    edited.agents[0].system = "edited on disk".into();
    write_charter(&m.charter_path, &edited);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        m.state().loaded().unwrap().charter.agents[0].system,
        "version three"
    );

    // 11. a new epoch (the service was deleted and created again) applies whatever its version,
    //     and the old service's memory goes with it — also on disk
    cp.push(charter_update("e2", "1", &charter(&audit))).await;
    let a = ack(&cp, "charter", "1").await;
    assert!(a.applied && a.epoch == "e2", "{a:?}");
    let l = m.state().loaded().unwrap();
    assert_eq!((l.epoch.as_str(), l.version.as_str()), ("e2", "1"));
    assert!(l.memory.agents.is_empty() && l.memory.version.is_empty());
    let on_disk: Value =
        serde_json::from_slice(&std::fs::read(state_dir.path().join("memory.json")).unwrap())
            .unwrap();
    assert_eq!(on_disk["version"], "");
    // the new service's memory counter starts over
    cp.push(memory_update("1", &[("n9", "New service, new notes.")]))
        .await;
    eventually("memory of the new service", || {
        m.state()
            .loaded()
            .unwrap()
            .memory
            .agents
            .contains_key("ops-assistant")
    })
    .await;
    m.sidecar.abort();
}

#[tokio::test]
async fn issuance_is_retried_with_a_fresh_token_and_a_foreign_start_up_charter_is_refused() {
    let ca = agentsc_pki::ca_init().unwrap();
    let cp = FakeCp::start(ca.clone()).await;
    let state_dir = tempfile::tempdir().unwrap();
    let audit_dir = tempfile::tempdir().unwrap();
    let audit = audit_dir.path().join("audit.jsonl");
    let mut foreign = charter(&audit);
    foreign.service.name = "billing".into();
    let token = state_dir.path().join("token-of-the-test");
    std::fs::write(&token, "wrong").unwrap();
    let token_path = token.clone();
    let m = start_managed(
        cp.addr,
        &ca,
        state_dir.path(),
        Some(&foreign),
        |_| FakeRuntime::answering("done"),
        move |cfg| cfg.join_token_file = Some(token_path),
    )
    .await;
    assert!(
        m.state().loaded().is_none(),
        "a charter for another workload"
    );
    let mut rx = m.state().audit.subscribe();
    let failed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let r = rx.recv().await.unwrap();
            if r.rule.as_deref() == Some("cert.issue_failed") {
                return r;
            }
        }
    })
    .await
    .expect("a cert.issue_failed record");
    assert_eq!(failed.kind, agentsc_common::audit::Kind::Config);
    assert_eq!(failed.callee, "certificate");
    assert_eq!(failed.decision, "allow", "a failure, not a policy denial");
    assert!(failed.error.as_deref().unwrap().contains("join token"));
    eventually("retried issuances", || {
        cp.shared.issued.lock().unwrap().len() >= 2
    })
    .await;
    assert!(m.state().tls().is_none());
    std::fs::write(&token, JOIN_TOKEN).unwrap();
    eventually("a certificate", || m.state().tls().is_some()).await;
    eventually("hello", || !cp.hellos().is_empty()).await;
    assert_eq!(
        cp.hellos()[0].charter_yaml,
        "",
        "never offered for adoption"
    );
    // the control plane's charter applies; until then nothing was ready
    assert!(!m.state().is_ready());
    cp.push(charter_update("e1", "1", &charter(&audit))).await;
    assert!(ack(&cp, "charter", "1").await.applied);
    eventually("ready", || m.state().is_ready()).await;
    m.sidecar.abort();
}

#[tokio::test]
async fn reconnects_keep_the_configuration_and_a_restart_reuses_persisted_state() {
    let ca = agentsc_pki::ca_init().unwrap();
    let cp = FakeCp::start(ca.clone()).await;
    let state_dir = tempfile::tempdir().unwrap();
    let audit_dir = tempfile::tempdir().unwrap();
    let audit = audit_dir.path().join("audit.jsonl");

    // no start-up charter: not ready until the control plane sends one
    let m = start_managed(
        cp.addr,
        &ca,
        state_dir.path(),
        None,
        |_| FakeRuntime::answering("done"),
        |_| {},
    )
    .await;
    eventually("hello", || !cp.hellos().is_empty()).await;
    assert_eq!(cp.hellos()[0].charter_yaml, "");
    eventually("a certificate", || m.state().tls().is_some()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (status, body) = m.readyz().await;
    assert_eq!(status, 503, "{body}");
    assert_eq!(body["charter"], false);
    let (status, body) = m.invoke("ops-assistant", "too early").await;
    assert_eq!(status, 502, "{body}");
    assert_eq!(body["rule"], "config.no_charter");

    cp.push(charter_update("e1", "5", &charter(&audit))).await;
    assert!(ack(&cp, "charter", "5").await.applied);
    cp.push(memory_update("2", &[("n1", "Answer in one line.")]))
        .await;
    assert!(ack(&cp, "memory", "2").await.applied);
    eventually("ready", || m.state().is_ready()).await;
    // the first charter named the audit file: records go there from now on
    assert!(
        !wait_audit(&audit, 1, |v| v["input"]["version"] == "5")
            .await
            .is_empty()
    );
    // written before any charter, so without its redaction: exported without payloads (hashes
    // stay); config records keep their metadata
    eventually("the early records exported", || {
        let r = cp.audit_records();
        r.iter().any(|(_, v)| v["rule"] == "config.no_charter")
            && r.iter().any(|(_, v)| v["input"]["version"] == "5")
    })
    .await;
    let exported = cp.audit_records();
    let early = &exported
        .iter()
        .find(|(_, v)| v["rule"] == "config.no_charter")
        .unwrap()
        .1;
    assert!(
        early["input"].is_null() && early["output"].is_null(),
        "{early}"
    );
    assert!(early["input_sha256"].is_string());
    let applied = &exported
        .iter()
        .find(|(_, v)| v["input"]["version"] == "5")
        .unwrap()
        .1;
    assert_eq!(applied["input"]["epoch"], "e1");

    // the control plane drops the stream: the sidecar reconnects and keeps its configuration
    cp.drop_streams();
    let (status, _) = m.invoke("ops-assistant", "while reconnecting").await;
    assert_eq!(status, 200);
    eventually("a second stream", || cp.hellos().len() >= 2).await;
    let h = cp.hellos()[1].clone();
    assert_eq!(
        (h.charter_epoch.as_str(), h.charter_version.as_str()),
        ("e1", "5")
    );
    assert_eq!(h.memory_version, "2");
    let l = m.state().loaded().unwrap();
    assert_eq!((l.version.as_str(), l.memory.version.as_str()), ("5", "2"));
    assert!(
        m.state().is_ready(),
        "readiness never depends on the stream"
    );
    // under a charter (control_plane_payloads by default) records keep their payloads
    eventually("a record with its payload", || {
        cp.audit_records()
            .iter()
            .any(|(_, v)| v["input"] == "while reconnecting")
    })
    .await;

    // restart: the control plane is gone; the persisted certificate, charter and memory serve
    let cert_before = m.state().tls().unwrap().cert_sha256.clone();
    m.sidecar.abort();
    let addr = cp.addr;
    cp.stop();
    drop(cp);
    let m2 = start_managed(
        addr,
        &ca,
        state_dir.path(),
        None,
        |_| FakeRuntime::answering("done again"),
        |_| {},
    )
    .await;
    let l = m2.state().loaded().expect("the persisted charter");
    assert_eq!((l.epoch.as_str(), l.version.as_str()), ("e1", "5"));
    assert_eq!(l.source, Source::State);
    assert_eq!(l.memory.version, "2");
    assert_eq!(
        m2.state().tls().unwrap().cert_sha256,
        cert_before,
        "no new issuance"
    );
    eventually("ready without the control plane", || m2.state().is_ready()).await;
    let (status, _) = m2.invoke("ops-assistant", "after restart").await;
    assert_eq!(status, 200);
    assert_eq!(
        m2.runtime.last_spec("ops-assistant")["memory"][0]["text"],
        "Answer in one line."
    );

    // the control plane comes back on the same address: Hello says what runs
    let cp2 = FakeCp::start_on(&addr.to_string(), ca.clone()).await;
    eventually("hello after restart", || !cp2.hellos().is_empty()).await;
    let h = cp2.hellos()[0].clone();
    assert_eq!(
        (h.charter_epoch.as_str(), h.charter_version.as_str()),
        ("e1", "5")
    );
    assert_eq!(h.memory_version, "2");
    assert!(cp2.shared.issued.lock().unwrap().is_empty());
    m2.sidecar.abort();
}

/// The SHA-256 of the certificate the mesh server presents, seen by a peer with its own leaf.
async fn mesh_cert_sha(mesh: SocketAddr, ca: &PemBundle) -> String {
    let peer = agentsc_pki::issue_leaf(ca, "agentsc-demo", "inventory", 1).unwrap();
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(peer.cert_pem.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
    let key = PrivateKeyDer::from_pem_slice(peer.key_pem.as_bytes()).unwrap();
    let roots = agentscd::tls::roots_from_pem(&ca.cert_pem).unwrap();
    let mut cfg = rustls::ClientConfig::builder_with_provider(agentscd::tls::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .unwrap();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let tcp = tokio::net::TcpStream::connect(mesh).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(
            ServerName::try_from("orders.agentsc-demo.svc.cluster.local").unwrap(),
            tcp,
        )
        .await
        .unwrap();
    let leaf = tls.get_ref().1.peer_certificates().unwrap()[0].clone();
    sha256_hex(&leaf)
}

#[tokio::test]
async fn renewal_swaps_the_mesh_certificate_without_a_restart() {
    let ca = agentsc_pki::ca_init().unwrap();
    let cp = FakeCp::start(ca.clone()).await;
    *cp.shared.ttl.lock().unwrap() = Duration::from_secs(9);
    let state_dir = tempfile::tempdir().unwrap();
    let audit_dir = tempfile::tempdir().unwrap();
    let audit = audit_dir.path().join("audit.jsonl");
    let m = start_managed(
        cp.addr,
        &ca,
        state_dir.path(),
        Some(&charter(&audit)),
        |_| FakeRuntime::answering("done"),
        |_| {},
    )
    .await;
    eventually("a certificate", || m.state().tls().is_some()).await;
    let first = m.state().tls().unwrap().cert_sha256.clone();
    let mesh = m.sidecar.mesh_addr.unwrap();
    assert_eq!(mesh_cert_sha(mesh, &ca).await, first);
    let snap = m.state().loaded().unwrap();
    m.state().mesh_client(&snap, "inventory").unwrap();
    assert_eq!(m.state().mesh_clients_cached(), 1);

    // the token file is read for every request: a wrong one makes the renewal fail ...
    std::fs::write(&m.token_file, "not-the-token").unwrap();
    let failed = wait_audit(&audit, 1, |v| v["rule"] == "cert.renew_failed").await;
    assert_eq!(
        failed.len(),
        1,
        "renewal starts at two thirds of the lifetime"
    );
    assert_eq!(failed[0]["kind"], "config");
    assert!(
        failed[0]["error"].as_str().unwrap().contains("join token"),
        "{}",
        failed[0]
    );
    assert_eq!(
        m.state().tls().unwrap().cert_sha256,
        first,
        "the old certificate stays"
    );
    // ... and the right one, a minute (here: moments) later, works
    std::fs::write(&m.token_file, JOIN_TOKEN).unwrap();
    eventually("a renewed certificate", || {
        m.state().tls().is_some_and(|t| t.cert_sha256 != first)
    })
    .await;
    let second = m.state().tls().unwrap().cert_sha256.clone();
    assert_eq!(
        mesh_cert_sha(mesh, &ca).await,
        second,
        "the mesh serves the new one"
    );
    assert_eq!(m.state().mesh_clients_cached(), 0, "peer channels dropped");
    assert_eq!(
        wait_audit(&audit, 2, |v| v["rule"] == "cert.issued")
            .await
            .len(),
        2
    );
    let issued = cp.shared.issued.lock().unwrap().clone();
    assert!(issued.iter().any(|r| r.join_token == "not-the-token"));
    assert_eq!(issued.last().unwrap().join_token, JOIN_TOKEN);
    // persisted, so a restart picks the renewed one
    let on_disk = std::fs::read_to_string(state_dir.path().join("tls.crt")).unwrap();
    let der = CertificateDer::from_pem_slice(on_disk.as_bytes()).unwrap();
    assert_eq!(sha256_hex(&der), second);
    m.sidecar.abort();
}

#[tokio::test]
async fn span_starts_audit_batches_and_learning_proposals() {
    let ca = agentsc_pki::ca_init().unwrap();
    let cp = FakeCp::start(ca.clone()).await;
    let state_dir = tempfile::tempdir().unwrap();
    let audit_dir = tempfile::tempdir().unwrap();
    let audit = audit_dir.path().join("audit.jsonl");
    let mut file = charter(&audit);
    file.telemetry = Some(TelemetrySpec {
        control_plane_payloads: false,
        ..Default::default()
    });
    // ops-assistant hands over to the local order-triage agent while it runs
    let m = start_managed(
        cp.addr,
        &ca,
        state_dir.path(),
        Some(&file),
        |sock| {
            FakeRuntime::with(move |req| {
                let sock = sock.clone();
                Box::pin(async move {
                    let spec: Value = serde_json::from_str(&req.agent_spec_json).unwrap();
                    if spec["name"] == "ops-assistant" {
                        let mut tools = tools(&sock).await;
                        // a service call first (no app listens: it fails, after it began)
                        let _ = tools
                            .invoke_service(ToolServiceRequest {
                                ctx: ctx_for(&req, "ops-assistant", "lookup_order"),
                                service: "orders".into(),
                                method: "GET".into(),
                                path: "/orders/1001".into(),
                                headers: Default::default(),
                                body: vec![],
                            })
                            .await;
                        let out = tools
                            .invoke_agent(ToolAgentRequest {
                                ctx: ctx_for(&req, "ops-assistant", "order_triage"),
                                target_service: String::new(),
                                target_agent: "order-triage".into(),
                                input: "classify: late delivery".into(),
                            })
                            .await
                            .unwrap()
                            .into_inner();
                        ok(&format!("triage said {}", out.output))
                    } else {
                        ok("P2")
                    }
                })
            })
        },
        |_| {},
    )
    .await;
    eventually("ready and connected", || {
        m.state().is_ready() && !cp.hellos().is_empty()
    })
    .await;

    let parent = "b7ad6b7169203331";
    let r = reqwest::Client::new()
        .post(format!(
            "http://{}/v1/agents/ops-assistant/invoke",
            m.sidecar.http_addr
        ))
        .header("traceparent", format!("00-{TRACE_ID}-{parent}-01"))
        .json(&json!({"input": "is order 1001 late?"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["output"], "triage said P2");
    let request_id = body["request_id"].as_str().unwrap().to_string();

    // span starts: the invocation on receipt, the agent call when it begins, the nested
    // invocation with a new span id whose parent is the agent call's
    eventually("four span starts", || cp.span_starts().len() >= 4).await;
    let s = cp.span_starts();
    let kinds: Vec<(&str, &str)> = s
        .iter()
        .map(|x| (x.kind.as_str(), x.agent.as_str()))
        .collect();
    assert_eq!(
        kinds,
        [
            ("agent_invocation", "ops-assistant"),
            ("service_call", "ops-assistant"),
            ("agent_call", "ops-assistant"),
            ("agent_invocation", "order-triage")
        ]
    );
    assert!(
        s.iter()
            .all(|x| x.request_id == request_id && x.trace_id == TRACE_ID)
    );
    assert!(s.windows(2).all(|w| w[0].ts <= w[1].ts));
    let (inv, svc, call, nested) = (&s[0], &s[1], &s[2], &s[3]);
    assert_eq!(
        (
            svc.caller.as_str(),
            svc.caller_agent.as_str(),
            svc.callee.as_str(),
            svc.direction.as_str()
        ),
        (
            "local",
            "ops-assistant",
            "orders GET /orders/1001",
            "internal"
        )
    );
    assert_eq!(inv.parent_span_id, parent);
    assert_eq!(
        (
            inv.caller.as_str(),
            inv.caller_agent.as_str(),
            inv.callee.as_str(),
            inv.direction.as_str()
        ),
        ("local", "", "ops-assistant", "inbound")
    );
    assert_eq!(
        (
            call.caller_agent.as_str(),
            call.callee.as_str(),
            call.direction.as_str()
        ),
        ("ops-assistant", "order-triage", "internal")
    );
    assert_eq!(nested.parent_span_id, call.span_id);
    assert_ne!(nested.span_id, call.span_id, "never a reused id");
    assert_eq!(
        (nested.caller.as_str(), nested.caller_agent.as_str()),
        ("local", "ops-assistant")
    );

    // the span ids are the ones the closing audit records carry
    let recs = wait_audit(&audit, 6, |v| v["request_id"] == request_id.as_str()).await;
    let find = |kind: &str, agent: &str| {
        recs.iter()
            .find(|v| v["kind"] == kind && v["agent"] == agent)
            .unwrap_or_else(|| panic!("{kind} {agent}"))
            .clone()
    };
    let inv_rec = find("agent_invocation", "ops-assistant");
    let call_rec = find("agent_call", "ops-assistant");
    let tool_rec = recs
        .iter()
        .find(|v| v["kind"] == "tool_call" && v["callee"] == "order_triage")
        .unwrap()
        .clone();
    let nested_rec = find("agent_invocation", "order-triage");
    let svc_rec = find("service_call", "ops-assistant");
    assert_eq!(svc_rec["span_id"], svc.span_id.as_str());
    assert!(svc_rec["error"].is_string(), "the app is not there");
    let svc_tool = recs
        .iter()
        .find(|v| v["kind"] == "tool_call" && v["callee"] == "lookup_order")
        .unwrap();
    assert_eq!(svc.parent_span_id, svc_tool["span_id"].as_str().unwrap());
    assert_eq!(inv_rec["span_id"], inv.span_id.as_str());
    assert_eq!(call_rec["span_id"], call.span_id.as_str());
    assert_eq!(call.parent_span_id, tool_rec["span_id"].as_str().unwrap());
    assert_eq!(nested_rec["span_id"], nested.span_id.as_str());
    assert_eq!(nested_rec["parent_span_id"], call.span_id.as_str());

    // every span start reached the control plane before the record that closes it
    eventually("the invocation record exported", || {
        cp.audit_records()
            .iter()
            .any(|(_, v)| v["span_id"] == inv.span_id.as_str() && v["kind"] == "agent_invocation")
    })
    .await;
    let order: Vec<(usize, String)> = cp
        .received()
        .iter()
        .enumerate()
        .flat_map(|(i, (_, msg))| match &msg.msg {
            Some(agentsc_proto::sidecar_message::Msg::SpanStart(x)) => {
                vec![(i, format!("start {}", x.span_id))]
            }
            Some(agentsc_proto::sidecar_message::Msg::Audit(b)) => b
                .records_json
                .iter()
                .map(|j| {
                    let v: Value = serde_json::from_str(j).unwrap();
                    (i, format!("record {}", v["span_id"].as_str().unwrap_or("")))
                })
                .collect(),
            _ => vec![],
        })
        .collect();
    for span in [&inv.span_id, &svc.span_id, &call.span_id, &nested.span_id] {
        let start = order
            .iter()
            .position(|(_, x)| *x == format!("start {span}"))
            .unwrap();
        let end = order
            .iter()
            .position(|(_, x)| *x == format!("record {span}"))
            .unwrap();
        assert!(start < end, "{span}: {order:?}");
    }
    // span starts are not audit records: never in the log
    assert!(read_audit(&audit).iter().all(|v| v["kind"] != "span_start"));

    // audit batches: at most 256 records each, payloads nulled (control_plane_payloads: false),
    // hashes kept
    let exported = cp.audit_records();
    assert!(exported.iter().all(|(n, _)| *n <= 256));
    let inv_exported = &exported
        .iter()
        .find(|(_, v)| v["span_id"] == inv.span_id.as_str() && v["kind"] == "agent_invocation")
        .unwrap()
        .1;
    assert!(inv_exported["input"].is_null() && inv_exported["output"].is_null());
    assert_eq!(inv_exported["input_sha256"], inv_rec["input_sha256"]);
    assert_eq!(
        inv_rec["input"], "is order 1001 late?",
        "the local log keeps it"
    );
    assert!(
        exported.iter().any(|(_, v)| v["kind"] == "config"),
        "config records too"
    );

    // the control plane turns payloads back on
    let mut with_payloads = charter(&audit);
    with_payloads.telemetry = Some(TelemetrySpec::default());
    cp.push(charter_update("e1", "1", &with_payloads)).await;
    assert!(ack(&cp, "charter", "1").await.applied);
    let (_, body) = m.invoke("order-triage", "payloads now").await;
    let id = body["request_id"].as_str().unwrap().to_string();
    eventually("a record with its payload", || {
        cp.audit_records()
            .iter()
            .any(|(_, v)| v["request_id"] == id.as_str() && v["input"] == "payloads now")
    })
    .await;

    // a lesson goes to the control plane (the only writer of memory), never to local memory
    let mut tools = tools(&m.sock).await;
    let resp = tools
        .propose_lesson(LessonRequest {
            ctx: ctx("ops-assistant", "", &request_id, &inv.span_id),
            note: "Ask triage before answering about late orders.".into(),
            rationale: "the run used order_triage".into(),
            run_request_id: request_id.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (resp.decision.as_str(), resp.rule.as_str()),
        ("allow", "learning.proposed")
    );
    eventually("a proposal", || !cp.proposals().is_empty()).await;
    let p = cp.proposals()[0].clone();
    assert!(
        uuid::Uuid::parse_str(&p.dedup_key).is_ok(),
        "{}",
        p.dedup_key
    );
    assert_eq!(p.agent, "ops-assistant");
    assert_eq!(p.note, "Ask triage before answering about late orders.");
    assert_eq!(p.rationale, "the run used order_triage");
    assert_eq!(p.request_id, request_id);
    assert_eq!(p.trace_id, TRACE_ID);
    assert!(p.auto, "mode: auto");
    assert!(m.state().loaded().unwrap().memory.agents.is_empty());
    m.sidecar.abort();
}

/// The OpenTelemetry endpoint the running exporter was started with.
fn otel_endpoint(m: &Managed) -> Option<String> {
    m.state()
        .otel
        .lock()
        .unwrap()
        .as_ref()
        .map(|r| r.config.endpoint.clone())
}

fn with_endpoint(mut c: Charter, endpoint: &str) -> Charter {
    c.telemetry = Some(TelemetrySpec {
        otlp_endpoint: Some(endpoint.into()),
        ..Default::default()
    });
    c
}

#[tokio::test]
async fn the_control_planes_charter_replaces_the_start_up_charter_restart_only_fields_included() {
    let ca = agentsc_pki::ca_init().unwrap();
    let cp = FakeCp::start(ca.clone()).await;
    let state_dir = tempfile::tempdir().unwrap();
    let audit_dir = tempfile::tempdir().unwrap();
    let audit = audit_dir.path().join("audit.jsonl");
    let moved = audit_dir.path().join("moved/audit.jsonl");
    let allow = |cfg: &mut Config| cfg.otlp_endpoint_allow = vec!["http://127.0.0.1:*".into()];
    // the --charter file (Compose mounts one) differs from the stored charter in restart-only
    // fields: the stored charter still applies, as at a restart
    let file = with_endpoint(charter(&audit), "http://127.0.0.1:9");
    let m = start_managed(
        cp.addr,
        &ca,
        state_dir.path(),
        Some(&file),
        |_| FakeRuntime::answering("done"),
        allow,
    )
    .await;
    assert_eq!(otel_endpoint(&m).as_deref(), Some("http://127.0.0.1:9"));
    eventually("hello", || !cp.hellos().is_empty()).await;
    let mut v1 = with_endpoint(charter(&audit), "http://127.0.0.1:10");
    v1.mesh.port = 50111;
    cp.push(charter_update("e1", "1", &v1)).await;
    let a = ack(&cp, "charter", "1").await;
    assert!(a.applied, "{}", a.error);
    let l = m.state().loaded().unwrap();
    assert_eq!(
        (l.source, l.charter.mesh.port),
        (Source::ControlPlane, 50111)
    );
    assert_eq!(
        otel_endpoint(&m).as_deref(),
        Some("http://127.0.0.1:10"),
        "the exporter follows the endpoint"
    );
    // from now on the baseline is the control plane's charter: a restart-only change made while
    // this instance is connected is refused
    let mut v2 = v1.clone();
    v2.mesh.port = 50112;
    cp.push(charter_update("e1", "2", &v2)).await;
    let a = ack(&cp, "charter", "2").await;
    assert!(!a.applied && a.error.contains("mesh.port"), "{a:?}");

    // the sidecar stops; with no instance connected the control plane accepts restart-only
    // changes (design §4): another audit file and mesh port
    let Managed { sidecar, .. } = m;
    sidecar.shutdown().await;
    let mut v3 = v1.clone();
    v3.mesh.port = 50113;
    v3.audit.file = Some(moved.to_string_lossy().into_owned());
    v3.agents[0].system = "after the restart".into();

    // the restart starts from the persisted charter ...
    let m = start_managed(
        cp.addr,
        &ca,
        state_dir.path(),
        Some(&file),
        |_| FakeRuntime::answering("done"),
        allow,
    )
    .await;
    let l = m.state().loaded().unwrap();
    assert_eq!((l.source, l.version.as_str()), (Source::State, "1"));
    eventually("a second hello", || cp.hellos().len() >= 2).await;
    let h = cp.hellos()[1].clone();
    assert_eq!(
        (h.charter_epoch.as_str(), h.charter_version.as_str()),
        ("e1", "1")
    );
    // ... and the stored charter replaces it, the restart-only changes too
    cp.push(charter_update("e1", "3", &v3)).await;
    let a = ack(&cp, "charter", "3").await;
    assert!(a.applied, "{}", a.error);
    let l = m.state().loaded().unwrap();
    assert_eq!(
        (
            l.source,
            l.charter.mesh.port,
            l.charter.agents[0].system.as_str()
        ),
        (Source::ControlPlane, 50113, "after the restart")
    );
    let rec = wait_audit(&moved, 1, |v| {
        v["rule"] == "config.applied" && v["input"]["version"] == "3"
    })
    .await;
    assert_eq!(rec.len(), 1, "records go to the new audit file");
    let meta: Value =
        serde_json::from_slice(&std::fs::read(state_dir.path().join("charter.meta.json")).unwrap())
            .unwrap();
    assert_eq!(meta["version"], "3");
    // and is the baseline from then on
    let mut v4 = v3.clone();
    v4.audit.file = Some(audit.to_string_lossy().into_owned());
    cp.push(charter_update("e1", "4", &v4)).await;
    let a = ack(&cp, "charter", "4").await;
    assert!(!a.applied && a.error.contains("audit.file"), "{a:?}");
    let Managed { sidecar, .. } = m;
    sidecar.shutdown().await;
}

#[tokio::test]
async fn an_expired_certificate_is_dropped_and_obtained_anew() {
    let ca = agentsc_pki::ca_init().unwrap();
    let cp = FakeCp::start(ca.clone()).await;
    *cp.shared.ttl.lock().unwrap() = Duration::from_secs(3);
    let state_dir = tempfile::tempdir().unwrap();
    let audit_dir = tempfile::tempdir().unwrap();
    let audit = audit_dir.path().join("audit.jsonl");
    let m = start_managed(
        cp.addr,
        &ca,
        state_dir.path(),
        Some(&charter(&audit)),
        |_| FakeRuntime::answering("done"),
        |_| {},
    )
    .await;
    eventually("a certificate", || m.state().tls().is_some()).await;
    // every renewal fails, until the certificate expires
    std::fs::write(&m.token_file, "not-the-token").unwrap();
    let expired = wait_audit(&audit, 1, |v| v["rule"] == "cert.expired").await;
    assert_eq!(expired.len(), 1, "the certificate expired");
    assert_eq!(expired[0]["kind"], "config");
    assert_eq!(expired[0]["decision"], "allow");
    assert!(expired[0]["error"].is_string());
    let gone = expired[0]["input"]["sha256"].as_str().unwrap().to_string();
    assert!(
        !wait_audit(&audit, 1, |v| v["rule"] == "cert.renew_failed")
            .await
            .is_empty()
    );
    // without a valid certificate the sidecar is not ready, and says why
    assert!(m.state().tls().is_none_or(|t| t.cert_sha256 != gone));
    assert!(!m.state().is_ready());
    let (status, body) = m.readyz().await;
    assert_eq!(status, 503, "{body}");
    assert_eq!(body["mesh"], false);
    assert!(body["cert_expires_in_s"].as_i64().unwrap() <= 0, "{body}");
    // it obtains a new one as at start-up
    let failed = wait_audit(&audit, 1, |v| {
        v["rule"] == "cert.issue_failed" && v["input"]["sha256"].is_null()
    })
    .await;
    assert!(!failed.is_empty(), "issuance after expiry");
    std::fs::write(&m.token_file, JOIN_TOKEN).unwrap();
    eventually("a new certificate", || m.state().tls().is_some()).await;
    assert_ne!(m.state().tls().unwrap().cert_sha256, gone);
    eventually("ready again", || m.state().is_ready()).await;
    m.sidecar.abort();
}

#[tokio::test]
async fn the_kubernetes_token_is_read_for_every_issuance() {
    let ca = agentsc_pki::ca_init().unwrap();
    let cp = FakeCp::start(ca.clone()).await;
    let state_dir = tempfile::tempdir().unwrap();
    let audit_dir = tempfile::tempdir().unwrap();
    let audit = audit_dir.path().join("audit.jsonl");
    // the projected token in its file, not yet one the TokenReview accepts
    let token = audit_dir.path().join("projected/token");
    std::fs::create_dir_all(token.parent().unwrap()).unwrap();
    std::fs::write(&token, "a-stale-projected-token\n").unwrap();
    let path = token.clone();
    let m = start_managed(
        cp.addr,
        &ca,
        state_dir.path(),
        Some(&charter(&audit)),
        |_| FakeRuntime::answering("done"),
        move |cfg| {
            cfg.join_token_file = None;
            cfg.k8s_token_file = path;
        },
    )
    .await;
    let failed = wait_audit(&audit, 1, |v| v["rule"] == "cert.issue_failed").await;
    assert!(
        failed[0]["error"]
            .as_str()
            .unwrap()
            .contains("Kubernetes token"),
        "{}",
        failed[0]
    );
    assert!(m.state().tls().is_none());
    // the kubelet rotates the token: the next attempt reads the new one
    std::fs::write(&token, format!("{K8S_TOKEN}\n")).unwrap();
    eventually("a certificate", || m.state().tls().is_some()).await;
    assert_eq!(m.state().tls().unwrap().material.identity.uri(), ORDERS_ID);
    let issued = cp.shared.issued.lock().unwrap().clone();
    assert!(issued.len() >= 2);
    assert!(issued.iter().all(|r| r.join_token.is_empty()));
    assert_eq!(issued[0].kubernetes_token, "a-stale-projected-token");
    assert_eq!(issued.last().unwrap().kubernetes_token, K8S_TOKEN);
    m.sidecar.abort();
}

fn flood_record(i: usize) -> agentsc_common::audit::AuditRecord {
    agentsc_common::audit::AuditRecord::new(
        agentsc_common::audit::Kind::ToolCall,
        agentsc_common::audit::Direction::Internal,
        &format!("flood-{i}"),
        &agentsc_common::trace::TraceContext::new_root(),
        Some("ops-assistant"),
        "local",
        None,
        "lookup_order",
        json!("x"),
        Value::Null,
    )
}

#[tokio::test]
async fn the_control_plane_and_its_ca_must_carry_the_control_plane_uri_san() {
    let ca = agentsc_pki::ca_init().unwrap();
    // a server of the same CA, but a workload's certificate: not the control plane
    let impostor_uri = "spiffe://agentsc/ns/agentsc-demo/svc/inventory";

    // 1. IssueCertificate: the CSR never reaches a CA without the URI SAN
    let impostor = FakeCp::start_with("127.0.0.1:0", ca.clone(), impostor_uri).await;
    let audit_dir = tempfile::tempdir().unwrap();
    let audit = audit_dir.path().join("audit.jsonl");
    let state_dir = tempfile::tempdir().unwrap();
    let m = start_managed(
        impostor.addr,
        &ca,
        state_dir.path(),
        Some(&charter(&audit)),
        |_| FakeRuntime::answering("done"),
        |_| {},
    )
    .await;
    let failed = wait_audit(&audit, 2, |v| v["rule"] == "cert.issue_failed").await;
    assert!(failed.len() >= 2, "retried");
    assert!(
        impostor.shared.issued.lock().unwrap().is_empty(),
        "refused in the handshake, before any request"
    );
    assert!(m.state().tls().is_none());
    m.sidecar.abort();

    // 2. Connect: with a certificate from the real CA, no stream is opened to the impostor
    let real_ca = FakeCp::start(ca.clone()).await;
    let audit2 = audit_dir.path().join("audit2.jsonl");
    let state_dir = tempfile::tempdir().unwrap();
    let ca_addr = real_ca.addr.to_string();
    let m = start_managed(
        impostor.addr,
        &ca,
        state_dir.path(),
        Some(&charter(&audit2)),
        |_| FakeRuntime::answering("done"),
        move |cfg| cfg.ca_address = Some(ca_addr),
    )
    .await;
    eventually("a certificate", || m.state().tls().is_some()).await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(impostor.connections(), 0);
    assert!(impostor.received().is_empty());
    eventually("ready without the control plane", || m.state().is_ready()).await;

    // 3. meanwhile the audit queue fills: at most 4096 records, the oldest dropped and counted
    for i in 0..(4096 + 200) {
        m.state().audit.write(flood_record(i));
    }
    // the real control plane answers on that address: the first heartbeat reports the drops
    let addr = impostor.addr;
    impostor.stop();
    drop(impostor);
    let cp = FakeCp::start_on(&addr.to_string(), ca.clone()).await;
    eventually("a heartbeat", || !cp.heartbeats().is_empty()).await;
    let hb = cp.heartbeats()[0].clone();
    assert!(hb.audit_dropped >= 200, "{hb:?}");
    // the newest records were kept and arrive
    eventually("the last record", || {
        cp.audit_records()
            .iter()
            .any(|(_, v)| v["request_id"] == "flood-4295")
    })
    .await;
    let dropped = m.state().outbox.audit_dropped();
    eventually("a heartbeat with every drop", || {
        cp.heartbeats()
            .last()
            .is_some_and(|b| b.audit_dropped == dropped)
    })
    .await;
    assert!(
        !cp.audit_records()
            .iter()
            .any(|(_, v)| v["request_id"] == "flood-0"),
        "the oldest were dropped"
    );
    m.sidecar.abort();
}
