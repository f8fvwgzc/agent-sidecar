//! The ledger format (CONTRACT.md §6.3): golden vectors, every check, and what each tampering
//! breaks.
use agentsc_ledger::*;
use serde_json::{Value, json};

const SEED: [u8; 32] = [7u8; 32];
const CHAIN: &str = "0c4a3f8e-1111-4222-8333-444455556666";

fn record(kind: &str, i: usize) -> Value {
    json!({
        "ts": format!("2026-10-29T10:00:0{i}.000Z"), "kind": kind, "request_id": CHAIN,
        "trace_id": "6e2d9ff960031afca28de8fa28704004", "span_id": format!("00f067aa0ba902b{i}"),
        "service": "orders", "namespace": "shop", "agent": "ops",
        "agent_id": "agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102",
        "caller": "local", "callee": "ops", "direction": "inbound",
        "input": null, "output": null, "input_sha256": "ab", "cost_usd": 0.0052,
        "latency_ms": 100 + i, "decision": "allow", "rule": null
    })
}

fn chain_of_three() -> Vec<Entry> {
    let mut out: Vec<Entry> = Vec::new();
    for (i, kind) in ["model_call", "tool_call", "agent_invocation"]
        .into_iter()
        .enumerate()
    {
        let e = Entry::next(
            out.last(),
            CHAIN,
            &format!("2026-10-29T10:00:1{i}.000Z"),
            record(kind, i),
        );
        out.push(e);
    }
    out
}

fn sealed_bundle(key: &SigningKey) -> Bundle {
    let entries = chain_of_three();
    let first = seal(key, CHAIN, 2, &entries[1].hash, "2026-10-29T10:00:20.000Z");
    let last = seal(key, CHAIN, 3, &entries[2].hash, "2026-10-29T10:00:30.000Z");
    Bundle {
        format: BUNDLE_FORMAT.into(),
        exported_at: "2026-10-29T10:01:00.000Z".into(),
        chain: CHAIN.into(),
        entries,
        seals: vec![first, last],
    }
}

fn failed(r: &Report) -> Vec<&str> {
    r.checks
        .iter()
        .filter(|c| !c.ok)
        .map(|c| c.name.as_str())
        .collect()
}

#[test]
fn the_kid_is_the_rfc_7638_thumbprint() {
    // nexc-engine's vector (security/signing.rs), from RFC 8037 appendix A.3
    let x = parse_public_key("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo").unwrap();
    assert_eq!(kid_of(&x), "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
    // RFC 8032 test 1: that public key's seed
    let seed =
        hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
    let key = SigningKey::from_seed(&seed.try_into().unwrap());
    assert_eq!(key.kid(), "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
    assert_eq!(
        hex::encode(key.sign(b"")),
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        "RFC 8032 test 1"
    );
}

#[test]
fn canonical_json_sorts_keys_bytewise_and_is_compact() {
    let v = json!({"b": 1, "a": {"z": [1, 2.5, "x"], "B": null}, "é": true, "Z": "\u{7}"});
    assert_eq!(
        canonical_json(&v),
        r#"{"Z":"\u0007","a":{"B":null,"z":[1,2.5,"x"]},"b":1,"é":true}"#
    );
    // a re-indented or reordered copy has the same canonical form
    let pretty = serde_json::to_string_pretty(&v).unwrap();
    assert_eq!(
        canonical_json(&serde_json::from_str(&pretty).unwrap()),
        canonical_json(&v)
    );
}

#[test]
fn an_entry_hash_is_pinned() {
    // a change of this value is a change of the ledger format: a new ENTRY_TAG, never an edit.
    // Also: python3 -c 'import hashlib; print(hashlib.sha256(b"agentsc-ledger-entry-v1\x00" + bytes(32)
    //   + b"{\"chain\":\"r1\",\"ingested_at\":\"2026-10-29T10:00:00.000Z\",\"record\":{\"kind\":\"config\"},\"seq\":0}").hexdigest())'
    let h = entry_hash(
        GENESIS,
        "r1",
        0,
        "2026-10-29T10:00:00.000Z",
        &json!({"kind": "config"}),
    );
    assert_eq!(
        h.as_deref(),
        Some("009e71f75f2c235c84dbc008a33f0237742e3ef5e0e37feb530ebeb8b3571b1d")
    );
    assert_eq!(entry_hash("00", "r1", 0, "t", &json!(null)), None);
}

#[test]
fn a_sealed_bundle_verifies_with_the_public_key_alone_and_survives_json() {
    let key = SigningKey::from_seed(&SEED);
    let bundle = sealed_bundle(&key);
    let keys = Jwks::single(&key.public_key());
    let r = verify_bundle(&bundle, &keys);
    assert!(r.ok, "{}", r.text());
    assert_eq!(
        r.checks.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
        ["format", "chain", "seals"]
    );
    assert!(r.text().ends_with("the bundle verifies\n"));
    // pretty-printed and read back
    let pretty = serde_json::to_string_pretty(&bundle).unwrap();
    let back: Bundle = serde_json::from_str(&pretty).unwrap();
    assert!(verify_bundle(&back, &keys).ok);
    // the JWKS round trips and a retired key still verifies
    let mut jwks = Jwks {
        keys: vec![
            SigningKey::from_seed(&[1; 32]).jwk(KeyStatus::Current),
            key.jwk(KeyStatus::Retired),
        ],
    };
    jwks = serde_json::from_str(&serde_json::to_string(&jwks).unwrap()).unwrap();
    assert!(verify_bundle(&bundle, &jwks).ok);
    // the wrong key
    let other = Jwks::single(&SigningKey::from_seed(&[1; 32]).public_key());
    assert_eq!(failed(&verify_bundle(&bundle, &other)), ["seals"]);
}

#[test]
fn tampering_is_found() {
    let key = SigningKey::from_seed(&SEED);
    let keys = Jwks::single(&key.public_key());
    let good = sealed_bundle(&key);
    type Edit = fn(&mut Bundle);
    let cases: Vec<(&str, Edit, &[&str])> = vec![
        // the stored hashes still match the seals: the chain check is what catches an edit
        (
            "a record edited",
            |b| b.entries[1].record["decision"] = json!("deny"),
            &["chain"],
        ),
        (
            "a record edited and its hash recomputed",
            |b| {
                b.entries[2].record["output"] = json!("forged");
                b.entries[2].hash = entry_hash(
                    &b.entries[2].prev_hash,
                    CHAIN,
                    2,
                    &b.entries[2].ingested_at,
                    &b.entries[2].record,
                )
                .unwrap();
            },
            &["seals"],
        ),
        (
            "the middle entry removed",
            |b| {
                b.entries.remove(1);
            },
            &["chain", "seals"],
        ),
        (
            "the last entry removed",
            |b| {
                b.entries.pop();
            },
            &["seals"],
        ),
        (
            "an entry added after the seal",
            |b| {
                let e = Entry::next(
                    b.entries.last(),
                    CHAIN,
                    "2026-10-29T10:00:40.000Z",
                    json!({"kind": "tool_call"}),
                );
                b.entries.push(e);
            },
            &["seals"],
        ),
        (
            "two entries swapped",
            |b| b.entries.swap(0, 1),
            &["chain", "seals"],
        ),
        (
            "ingested_at changed",
            |b| b.entries[0].ingested_at = "2026-10-29T09:00:00.000Z".into(),
            &["chain"],
        ),
        (
            "the seal's statement edited",
            |b| {
                b.seals[1].statement = b.seals[1]
                    .statement
                    .replace("\"entries\":3", "\"entries\":2");
            },
            &["seals"],
        ),
        (
            "one space added to a statement",
            |b| b.seals[1].statement.push(' '),
            &["seals"],
        ),
        ("the seals stripped", |b| b.seals.clear(), &["seals"]),
        (
            "the last seal stripped",
            |b| {
                b.seals.pop();
            },
            &["seals"],
        ),
        (
            "another chain's name",
            |b| b.chain = "other".into(),
            &["chain", "seals"],
        ),
        (
            "the format",
            |b| b.format = "nexc-evidence-bundle/v1".into(),
            &["format"],
        ),
        (
            "no entries at all",
            |b| {
                b.entries.clear();
                b.seals.clear();
            },
            &["chain", "seals"],
        ),
    ];
    for (what, edit, expected) in cases {
        let mut b = good.clone();
        edit(&mut b);
        let r = verify_bundle(&b, &keys);
        assert!(!r.ok, "{what}");
        assert_eq!(failed(&r), expected, "{what}: {}", r.text());
    }
}

#[test]
fn a_seal_holds_for_its_chain_and_key_only() {
    let key = SigningKey::from_seed(&SEED);
    let keys = Jwks::single(&key.public_key());
    let entries = chain_of_three();
    let s = seal(&key, CHAIN, 3, &entries[2].hash, "2026-10-29T10:00:30.000Z");
    assert!(s.statement.starts_with("{\"chain\":"));
    assert!(s.statement.contains("\"type\":\"agentsc.ledger_seal.v1\""));
    let st = check_seal(&s, &keys, CHAIN, &entries).unwrap();
    assert_eq!((st.entries, st.kid.as_str()), (3, key.kid()));
    let err =
        |s: &Seal, chain: &str, keys: &Jwks| check_seal(s, keys, chain, &entries).unwrap_err();
    assert!(err(&s, "other", &keys).contains("about chain"));
    assert!(err(&s, CHAIN, &Jwks::default()).contains("no published key"));
    let mut forged = s.clone();
    forged.signature = hex::encode([0u8; 64]);
    assert!(err(&forged, CHAIN, &keys).contains("does not verify"));
    let mut other_kid = s.clone();
    other_kid.kid = "x".into();
    assert!(err(&other_kid, CHAIN, &keys).contains("another key"));
    // a key published under another key's id is not that key
    let mut lying = Jwks::single(&SigningKey::from_seed(&[1; 32]).public_key());
    lying.keys[0].kid = key.kid().into();
    assert!(err(&s, CHAIN, &lying).contains("no published key"));
}

#[test]
fn key_text() {
    let text = SigningKey::generate_seed_text().unwrap();
    let k = SigningKey::from_seed_text(&format!("{text}\n")).unwrap();
    assert_eq!(k.kid().len(), 43);
    assert_eq!(
        SigningKey::from_seed_text("not base64").unwrap_err(),
        KeyError::Seed
    );
    let p = k.public_key();
    for form in [
        hex::encode(p),
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, p),
        k.jwk(KeyStatus::Current).x,
    ] {
        assert_eq!(parse_public_key(&form).unwrap(), p, "{form}");
    }
    assert!(parse_public_key("abcd").is_err());
    assert_eq!(chain_of("", "shop", "orders"), "service:shop/orders");
    assert_eq!(chain_of("r1", "shop", "orders"), "r1");
}
