//! The acknowledged Append API on the evidence ledger (Tutela INTEGRATION §3 step 7, CONTRACTS.md
//! 9.3 and 9.4): the store's rules (SQLite always, PostgreSQL with `AGENTSC_TEST_POSTGRES_URL`),
//! then forwarded records through the API, down to a bundle that verifies offline.
mod common;

use std::sync::Arc;

use agentsc_ledger::{Bundle, Jwks, SigningKey, canonical_json, kid_of, verify_bundle};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::{Env, Opts};
use embassy::config::LedgerProducer;
use embassy::secops::ledger::{FORWARDED_KIND, FORWARDED_NAMESPACE};
use embassy::secops::{ForwardedRecord, LedgerRecord, SecOpsStore};
use embassy::store::StoreError;
use embassy::store::postgres::{PgOptions, PgStore};
use embassy::store::sqlite::SqliteStore;
use serde_json::{Value, json};

const SERVICE: &str = "tutelad";
const TID: &str = "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b";

fn forwarded(id: &str, seq: u64, digest_seed: &str) -> ForwardedRecord {
    let chain = format!("forwarded:{SERVICE}:{TID}:2026-11-02");
    ForwardedRecord {
        id: id.into(),
        tenant: TID.into(),
        producer_seq: seq,
        digest: agentsc_ledger::sha256_hex(digest_seed.as_bytes()),
        record: LedgerRecord {
            chain,
            namespace: FORWARDED_NAMESPACE.into(),
            service: SERVICE.into(),
            agent_id: None,
            kind: FORWARDED_KIND.into(),
            record: json!({"id": id, "payload": digest_seed}),
        },
    }
}

async fn forward_rules(s: Arc<dyn SecOpsStore>) {
    let at = "2026-11-02T00:00:00.000Z";
    let a = s
        .ledger_forward(at, &[forwarded("a", 1, "one"), forwarded("b", 2, "two")])
        .await
        .unwrap();
    assert_eq!((a[0].seq, a[1].seq), (0, 1));
    assert!(!a[0].duplicate && !a[0].gap && !a[1].gap);

    // a retry gets the place it has, and writes nothing
    let again = s
        .ledger_forward(at, &[forwarded("a", 1, "one")])
        .await
        .unwrap();
    assert!(again[0].duplicate);
    assert_eq!((again[0].seq, &again[0].hash), (0, &a[0].hash));
    let chain = &a[0].chain;
    assert_eq!(s.ledger_head(chain).await.unwrap().entries, 2);

    // the same key with another payload is refused, and the whole request goes
    let e = s
        .ledger_forward(
            at,
            &[forwarded("c", 3, "three"), forwarded("a", 1, "rewritten")],
        )
        .await
        .unwrap_err();
    assert!(
        matches!(&e, StoreError::Invalid(w) if w[0].contains("another payload")),
        "{e}"
    );
    assert_eq!(s.ledger_head(chain).await.unwrap().entries, 2);

    // the retry of the part that was fine still works: nothing of it stayed behind
    let c = s
        .ledger_forward(at, &[forwarded("c", 3, "three")])
        .await
        .unwrap();
    assert!(!c[0].duplicate && !c[0].gap);

    // a gap in the producer's seq is reported, and the record is kept
    let d = s
        .ledger_forward(at, &[forwarded("d", 9, "nine")])
        .await
        .unwrap();
    assert!(d[0].gap);
    assert_eq!(s.ledger_head(chain).await.unwrap().entries, 4);

    // the chain is an ordinary chain
    let entries = s.ledger_entries(chain).await.unwrap();
    agentsc_ledger::check_chain(chain, &entries).unwrap();
}

#[tokio::test]
async fn forward_rules_on_sqlite() {
    forward_rules(SqliteStore::open_in_memory().unwrap()).await;
}

#[tokio::test]
async fn forward_rules_on_postgres() {
    let Ok(base) = std::env::var("AGENTSC_TEST_POSTGRES_URL") else {
        eprintln!("AGENTSC_TEST_POSTGRES_URL is not set: the PostgreSQL test did not run");
        return;
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
    let s = PgStore::open(PgOptions {
        url: url.clone(),
        ca_file: None,
        pool_size: 4,
        application_name: schema.clone(),
        allow_plaintext: false,
    })
    .await
    .unwrap();
    forward_rules(s).await;
    // append-only below the API too
    let (raw, conn) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(conn);
    for sql in [
        "UPDATE ledger_forwarded SET digest = repeat('0', 64)",
        "DELETE FROM ledger_forwarded",
        "TRUNCATE ledger_forwarded",
    ] {
        assert!(raw.batch_execute(sql).await.is_err(), "{sql}");
    }
}

/// A signed `audit.v1` record, CONTRACTS.md 9.2's example with this producer's fields.
fn record(signer: &SigningKey, seq: u64, service: &str) -> Value {
    let mut v = json!({
        "schema": "audit.v1",
        "id": format!("0193a1b2-c3d5-7001-8000-{seq:012x}"),
        "time": "2026-10-25T09:31:12.345Z",
        "tenant": { "iss": "https://auth.example.test", "tid": TID },
        "org": "org_0193a1b2-c3d4-7f00-9a00-000000000002",
        "actor": {
            "kind": "agent",
            "id": "agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102",
            "on_behalf_of": "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081"
        },
        "action": "invoice:approve",
        "resource": { "type": "invoice", "id": "inv-881" },
        "decision": { "effect": "deny", "rule_ids": ["ra_1"], "rev": 42 },
        "outcome": "denied",
        "reason": "delegation_overlap: agent has read at project p-77",
        "service": service,
        "labels": ["internal"],
        "seq": seq,
        "a_field_of_a_newer_writer": "kept",
    });
    sign(signer, &mut v);
    v
}

fn sign(signer: &SigningKey, v: &mut Value) {
    v.as_object_mut().unwrap().remove("signature");
    let sig = signer.sign(canonical_json(v).as_bytes());
    v["signature"] = json!({
        "key_id": kid_of(&signer.public_key()),
        "value": URL_SAFE_NO_PAD.encode(sig),
    });
}

struct Rig {
    env: Env,
    signer: SigningKey,
}

impl Rig {
    async fn start() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("ledger.key");
        std::fs::write(&key, SigningKey::generate_seed_text().unwrap()).unwrap();
        let signer =
            SigningKey::from_seed_text(&SigningKey::generate_seed_text().unwrap()).unwrap();
        let env = Env::start_with(Opts {
            args: vec![
                "--ledger-seal-after".into(),
                "0".into(),
                "--ledger-key-file".into(),
                key.display().to_string(),
            ],
            producers: vec![LedgerProducer {
                service: SERVICE.into(),
                token: "bob".into(),
                keys: vec![STANDARD.encode(signer.public_key())],
            }],
            ..Default::default()
        })
        .await;
        std::mem::forget(dir);
        Rig { env, signer }
    }

    async fn append(&self, who: &str, records: Vec<Value>) -> (u16, Value) {
        let r = self
            .env
            .call(
                "POST",
                "/ledger/append",
                who,
                Some(json!({ "records": records })),
                None,
            )
            .await;
        (
            r.status,
            serde_json::from_str(&r.text).unwrap_or(Value::Null),
        )
    }
}

#[tokio::test]
async fn forwarded_records_are_acknowledged_and_end_in_a_bundle_that_verifies() {
    let rig = Rig::start().await;
    let (a, b) = (
        record(&rig.signer, 1, SERVICE),
        record(&rig.signer, 2, SERVICE),
    );
    let (status, v) = rig.append("bob", vec![a.clone(), b]).await;
    assert_eq!(status, 200, "{v}");
    let acks = v["acknowledged"].as_array().unwrap();
    assert_eq!(acks.len(), 2);
    assert_eq!(acks[0]["seq"], 0);
    assert_eq!(acks[1]["seq"], 1);
    assert_eq!(acks[0]["duplicate"], false);
    let chain = acks[0]["chain"].as_str().unwrap().to_string();
    assert!(
        chain.starts_with(&format!("forwarded:{SERVICE}:{TID}:")),
        "{chain}"
    );

    // a retry after a lost answer: the same place, nothing new
    let (status, again) = rig.append("bob", vec![a.clone()]).await;
    assert_eq!(status, 200, "{again}");
    assert_eq!(again["acknowledged"][0]["duplicate"], true);
    assert_eq!(again["acknowledged"][0]["hash"], acks[0]["hash"]);

    // the bundle verifies offline, and holds the record as it came, unknown field and all
    let r = rig
        .env
        .get(&format!("/ledger/runs/{chain}/bundle"), "alice")
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let bundle: Bundle = serde_json::from_str(&r.text).unwrap();
    assert_eq!(bundle.entries.len(), 2);
    assert_eq!(
        bundle.entries[0].record["a_field_of_a_newer_writer"],
        "kept"
    );
    let keys: Jwks =
        serde_json::from_str(&rig.env.get("/ledger/keys", "alice").await.text).unwrap();
    let report = verify_bundle(&bundle, &keys);
    assert!(report.ok, "{}", report.text());

    // a caller of one namespace does not read it
    let r = rig
        .env
        .get(&format!("/ledger/runs/{chain}/bundle"), "carol")
        .await;
    assert_ne!(r.status, 200, "{}", r.text);

    let audit = std::fs::read_to_string(rig.env.store_dir.join(".audit.jsonl")).unwrap();
    assert!(audit.contains("\"ledger_append\""), "{audit}");
    rig.env.stop().await;
}

#[tokio::test]
async fn only_the_producer_may_append_and_only_what_it_signed() {
    let rig = Rig::start().await;
    let good = record(&rig.signer, 1, SERVICE);

    // another token, even an admin's
    let (status, v) = rig.append("alice", vec![good.clone()]).await;
    assert_eq!(status, 403, "{v}");

    // not the producer's service
    let other = record(&rig.signer, 1, "another-service");
    let (status, v) = rig.append("bob", vec![other]).await;
    assert_eq!(status, 400, "{v}");
    assert!(v.to_string().contains("producer"), "{v}");

    // a record changed after it was signed
    let mut changed = good.clone();
    changed["outcome"] = json!("success");
    changed["decision"]["effect"] = json!("allow");
    let (status, v) = rig.append("bob", vec![changed]).await;
    assert_eq!(status, 400, "{v}");
    assert!(v.to_string().contains("does not verify"), "{v}");

    // signed with a key the producer does not have
    let stranger = SigningKey::from_seed_text(&SigningKey::generate_seed_text().unwrap()).unwrap();
    let (status, v) = rig.append("bob", vec![record(&stranger, 1, SERVICE)]).await;
    assert_eq!(status, 400, "{v}");
    assert!(v.to_string().contains("not a key of this producer"), "{v}");

    // not an audit.v1 record
    let (status, v) = rig.append("bob", vec![json!({"hello": "world"})]).await;
    assert_eq!(status, 400, "{v}");
    assert!(v.to_string().contains("audit.v1"), "{v}");

    // one bad record refuses the whole request: nothing is half shipped
    let (status, v) = rig
        .append("bob", vec![good.clone(), json!({"hello": "world"})])
        .await;
    assert_eq!(status, 400, "{v}");
    let (status, v) = rig.append("bob", vec![good.clone()]).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["acknowledged"][0]["duplicate"], false);

    // the same id with another payload, properly signed
    let mut rewritten = good.clone();
    rewritten["reason"] = json!("delegation_overlap: something else");
    sign(&rig.signer, &mut rewritten);
    let (status, v) = rig.append("bob", vec![rewritten]).await;
    assert_eq!(status, 400, "{v}");
    assert!(v.to_string().contains("another payload"), "{v}");

    let (status, v) = rig.append("bob", vec![]).await;
    assert_eq!(status, 400, "{v}");
    rig.env.stop().await;
}

#[tokio::test]
async fn a_gap_in_the_producers_seq_is_reported() {
    let rig = Rig::start().await;
    let (status, v) = rig
        .append(
            "bob",
            vec![
                record(&rig.signer, 1, SERVICE),
                record(&rig.signer, 5, SERVICE),
            ],
        )
        .await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["acknowledged"][0]["gap"], false);
    assert_eq!(v["acknowledged"][1]["gap"], true);
    rig.env.stop().await;
}

#[test]
fn the_producers_are_checked() {
    use embassy::config::{ControlPlaneConfig, Role, TokenEntry};
    let key = STANDARD.encode(
        SigningKey::from_seed_text(&SigningKey::generate_seed_text().unwrap())
            .unwrap()
            .public_key(),
    );
    let check = |p: LedgerProducer| {
        let mut c = ControlPlaneConfig::default();
        c.auth.tokens.push(TokenEntry {
            name: "forwarder".into(),
            role: Role::Viewer,
            sha256: "a".repeat(64),
            namespaces: vec!["forwarded".into()],
            payloads: false,
        });
        c.ledger.producers.push(p);
        c.validate("agentsc-system")
            .err()
            .unwrap_or_default()
            .join("; ")
    };
    let good = LedgerProducer {
        service: SERVICE.into(),
        token: "forwarder".into(),
        keys: vec![key],
    };
    assert_eq!(check(good.clone()), "");
    let bad = check(LedgerProducer {
        token: "nobody".into(),
        ..good.clone()
    });
    assert!(bad.contains("is not in auth.tokens"), "{bad}");
    let bad = check(LedgerProducer {
        service: "Not A Service".into(),
        ..good.clone()
    });
    assert!(bad.contains("not a service name"), "{bad}");
    let bad = check(LedgerProducer {
        keys: vec![],
        ..good.clone()
    });
    assert!(bad.contains("keys is empty"), "{bad}");
    let bad = check(LedgerProducer {
        keys: vec!["nonsense".into()],
        ..good
    });
    assert!(bad.contains("keys[0]"), "{bad}");
}
