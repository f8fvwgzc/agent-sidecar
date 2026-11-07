//! Tutela's audit log forwarded to attache's evidence ledger, end to end (Tutela ADR-0039 and
//! ADR-0045, CONTRACTS.md 9.3 and 9.4; CONTRACT.md §6.3 Append API): a real `tutelad` v0.2.0
//! forwards to embassy's real `POST /api/v1/ledger/append` as the operator sets it up
//! (docs/operations.md "Forwarding audit records to the ledger"). Every record of every chain
//! arrives once, in order, signed by `tutelad`'s producer key; the ledger's bundle verifies
//! offline; and forwarding resumes where it stopped after `tutelad` restarts and after embassy
//! restarts.
//!
//! Needs `ATTACHE_TUTELAD_BIN` and a PostgreSQL (tests/tutelad/mod.rs); without them the test says
//! so and passes, unless `ATTACHE_REQUIRE_TUTELAD=1`.
mod common;
mod tutelad;

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use agentsc_ledger::{Bundle, Jwks, SigningKey, canonical_json, kid_of, verify_bundle};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::{Env, Opts};
use embassy::config::LedgerProducer;
use serde_json::Value;
use tutelad::Tutelad;

/// The tenant id of the deployment's own chain (Tutela CONTRACTS.md 9.4).
const DEPLOYMENT: &str = "ten_00000000-0000-7000-8000-000000000000";

async fn embassy(port: u16, dir: &Path, public: &str, token: &str) -> Env {
    Env::start_with(Opts {
        args: vec![
            "--ledger-seal-after".into(),
            "0".into(),
            "--ledger-key-file".into(),
            dir.join("ledger.key").display().to_string(),
        ],
        producers: vec![LedgerProducer {
            service: "tutelad".into(),
            token: "tutela-forwarder".into(),
            keys: vec![public.to_string()],
        }],
        forwarder_token: Some(token.to_string()),
        http_addr: Some(format!("127.0.0.1:{port}")),
        store_dir: Some(dir.join("store")),
        ..Opts::default()
    })
    .await
}

/// The forwarded chains in the ledger: tenant id → (chain, entries).
async fn forwarded(env: &Env) -> BTreeMap<String, (String, u64)> {
    let r = env
        .get("/ledger/runs?namespace=forwarded&limit=500", "alice")
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    r.body
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| {
            let chain = c["chain"].as_str()?.to_string();
            let tid = chain
                .strip_prefix("forwarded:tutelad:")?
                .split(':')
                .next()?
                .to_string();
            Some((tid, (chain, c["entries"].as_u64()?)))
        })
        .collect()
}

/// Wait until every chain of `tutelad` is shipped to its last record and the ledger holds all of
/// them; the heads (tenant id → last seq).
async fn until_all_forwarded(t: &Tutelad, env: &Env) -> BTreeMap<String, i64> {
    let start = std::time::Instant::now();
    loop {
        let heads = t.audit_heads().await;
        let ledger = forwarded(env).await;
        let done = !heads.is_empty()
            && heads.iter().all(|(tid, (last, shipped))| {
                shipped == last
                    && ledger
                        .get(tid)
                        .is_some_and(|(_, n)| i64::try_from(*n).unwrap() == *last)
            });
        if done {
            return heads.into_iter().map(|(k, (last, _))| (k, last)).collect();
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "not forwarded: tutelad {heads:?}, ledger {ledger:?}\n{}",
            t.log()
                .lines()
                .filter(|l| l.contains("ledger") || l.contains("forward"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// The bundle of `chain` verifies offline with the ledger's keys, and every record in it is
/// `tutelad`'s, signed by the producer key, with `seq` 1, 2, 3, ... and no id twice.
async fn verified(env: &Env, chain: &str, producer: &[u8; 32]) -> Vec<Value> {
    let r = env
        .get(&format!("/ledger/runs/{chain}/bundle"), "alice")
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let bundle: Bundle = serde_json::from_str(&r.text).unwrap();
    let keys: Jwks = serde_json::from_str(&env.get("/ledger/keys", "alice").await.text).unwrap();
    let report = verify_bundle(&bundle, &keys);
    assert!(report.ok, "{}", report.text());
    let mut ids = std::collections::BTreeSet::new();
    let records: Vec<Value> = bundle.entries.iter().map(|e| e.record.clone()).collect();
    for (i, rec) in records.iter().enumerate() {
        assert_eq!(rec["service"], "tutelad");
        assert_eq!(rec["seq"], i as u64 + 1, "in order, no gap: {rec}");
        assert!(ids.insert(rec["id"].as_str().unwrap().to_string()), "once");
        let sig = &rec["signature"];
        assert_eq!(sig["key_id"], kid_of(producer).as_str());
        let mut body = rec.clone();
        body.as_object_mut().unwrap().remove("signature");
        let value = URL_SAFE_NO_PAD
            .decode(sig["value"].as_str().unwrap())
            .unwrap();
        assert!(
            agentsc_ledger::verify_signature(producer, canonical_json(&body).as_bytes(), &value),
            "tutelad's signature: {rec}"
        );
    }
    records
}

#[tokio::test]
async fn tutelads_audit_log_arrives_signed_verifies_and_resumes_after_restarts() {
    let seed = SigningKey::generate_seed_text().unwrap();
    let producer = SigningKey::from_seed_text(&seed).unwrap().public_key();
    let public = STANDARD.encode(producer);
    let token = embassy::token::generate().unwrap();
    let port = tutelad::free_port();
    let Some(mut t) = Tutelad::start_with(
        tutelad::free_port(),
        vec![
            (
                "TUTELA_LEDGER_URL".into(),
                format!("http://127.0.0.1:{port}/api/v1/ledger/append"),
            ),
            ("TUTELA_LEDGER_TOKEN".into(), token.clone()),
            ("TUTELA_AUDIT_KEY".into(), seed.clone()),
        ],
    )
    .await
    else {
        return;
    };
    // tutelad says which key it forwards with, for attache's ledger.producers
    let log = t.log();
    assert!(
        log.contains(&public),
        "tutelad logs its producer key:\n{log}"
    );
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("ledger.key"),
        SigningKey::generate_seed_text().unwrap(),
    )
    .unwrap();
    let env = embassy(port, dir.path(), &public, &token).await;

    // what tutelad recorded so far (the tenants, their apps and roles, the keys) arrives
    let heads = until_all_forwarded(&t, &env).await;
    assert!(
        heads.contains_key(&t.a.tid)
            && heads.contains_key(&t.b.tid)
            && heads.contains_key(DEPLOYMENT),
        "{heads:?}"
    );
    let chains = forwarded(&env).await;
    for (tid, (chain, _)) in &chains {
        verified(&env, chain, &producer).await;
        assert!(heads.contains_key(tid));
    }
    let records = verified(&env, &chains[&t.a.tid].0, &producer).await;
    assert!(
        records
            .iter()
            .all(|r| r["tenant"]["tid"] == t.a.tid.as_str())
    );
    let audit = std::fs::read_to_string(dir.path().join("store/.audit.jsonl")).unwrap();
    assert!(audit.contains("\"ledger_append\""));

    // tutelad restarts: it goes on after the last acknowledged record, nothing twice, no gap
    let app = embassy::tutela::client::Client::new(
        &t.config(&t.a.attache),
        embassy::tutela::Credentials::read(&t.a.attache).unwrap(),
    )
    .unwrap();
    t.stop().await;
    t.serve().await;
    app.register_agent().await.unwrap();
    app.register_agent().await.unwrap();
    let after = until_all_forwarded(&t, &env).await;
    assert!(
        after[&t.a.tid] >= heads[&t.a.tid] + 2,
        "{heads:?} {after:?}"
    );
    let records = verified(&env, &chains[&t.a.tid].0, &producer).await;
    assert!(
        records
            .iter()
            .any(|r| r["action"] == "tutela_principal:register"),
        "{records:?}"
    );

    // embassy is down: tutelad keeps its records and waits; embassy back on the same store, they
    // arrive, after the ones it already had
    env.stop().await;
    app.register_agent().await.unwrap();
    app.register_agent().await.unwrap();
    tokio::time::sleep(Duration::from_secs(5)).await;
    let (last, shipped) = t.audit_heads().await[&t.a.tid];
    assert!(
        shipped < last,
        "nothing was acknowledged while embassy was down"
    );
    let env = embassy(port, dir.path(), &public, &token).await;
    let back = until_all_forwarded(&t, &env).await;
    assert_eq!(back[&t.a.tid], last);
    let records = verified(&env, &chains[&t.a.tid].0, &producer).await;
    assert_eq!(records.len() as i64, last);
    env.stop().await;
    t.finish().await;
}
