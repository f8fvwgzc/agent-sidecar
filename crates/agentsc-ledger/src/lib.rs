//! The evidence ledger's format (CONTRACT.md §6.3, docs/design/evidence-ledger.md): what embassy
//! writes and what `agentsc verify` checks, with the public keys alone.
//!
//! - [`canonical_json`]: JSON with object keys sorted bytewise, compact. Every hash and every
//!   signed statement is over these bytes, so a bundle that a tool re-indents or reorders still
//!   verifies.
//! - A **chain** is one run's audit records (their `request_id`), in the order embassy took them
//!   in: entry `seq` (from 0) hashes the previous entry's hash and its own content
//!   ([`entry_hash`]); the first entry's previous hash is [`GENESIS`].
//! - A **seal** ([`seal`]) is an Ed25519 signature over a statement naming the chain, how many
//!   entries it covers and the head hash then. The key id is the RFC 7638 thumbprint of the
//!   public key ([`kid_of`]); keys are published as a JWKS ([`Jwks`]).
//! - A **bundle** ([`Bundle`]) is one chain's entries and seals; [`verify_bundle`] runs every
//!   check and says which failed.
//!
//! The shape follows nexc-engine's ledger (`domain/trace.rs`, `domain/seal.rs`,
//! `security/signing.rs`, `bin/nexc_verify.rs`): a SHA-256 chain from 32 zero bytes over sorted
//! JSON, Ed25519 over the exact statement bytes, RFC 7638 key ids, and a verifier that runs every
//! check and exits 0, 1 or 2.
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The previous hash of a chain's first entry: 32 zero bytes, as hex.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// What every entry hash starts with, so a ledger hash is never another protocol's.
pub const ENTRY_TAG: &[u8] = b"agentsc-ledger-entry-v1\0";
/// `type` of a seal statement.
pub const SEAL_TYPE: &str = "agentsc.ledger_seal.v1";
/// `format` of a bundle.
pub const BUNDLE_FORMAT: &str = "agentsc-evidence-bundle/v1";
/// The chain of a service's records that belong to no run (`config` records): `service:<ns>/<svc>`.
pub const SERVICE_CHAIN_PREFIX: &str = "service:";

/// The chain a record goes into: its `request_id`, or [`SERVICE_CHAIN_PREFIX`] + `<ns>/<svc>`
/// for a record without one.
pub fn chain_of(request_id: &str, namespace: &str, service: &str) -> String {
    if request_id.is_empty() {
        format!("{SERVICE_CHAIN_PREFIX}{namespace}/{service}")
    } else {
        request_id.to_string()
    }
}

// ---- canonical JSON -------------------------------------------------------------------------

/// `v` as compact JSON with every object's keys sorted bytewise (strings and numbers as
/// `serde_json` writes them).
pub fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap_or_default());
                out.push(':');
                write_canonical(&map[k], out);
            }
            out.push('}');
        }
        scalar => out.push_str(&serde_json::to_string(scalar).unwrap_or_default()),
    }
}

/// SHA-256 of `bytes`, lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

// ---- the chain ------------------------------------------------------------------------------

/// The hash of entry `seq` of `chain`: SHA-256 of [`ENTRY_TAG`], the previous entry's hash (32
/// bytes) and the canonical JSON of `{chain, ingested_at, record, seq}`, as lowercase hex.
/// `None` when `prev_hash` is not 64 hex digits.
pub fn entry_hash(
    prev_hash: &str,
    chain: &str,
    seq: u64,
    ingested_at: &str,
    record: &Value,
) -> Option<String> {
    let prev = hex::decode(prev_hash).ok().filter(|b| b.len() == 32)?;
    let body = canonical_json(&json!({
        "chain": chain,
        "ingested_at": ingested_at,
        "record": record,
        "seq": seq,
    }));
    let mut h = Sha256::new();
    h.update(ENTRY_TAG);
    h.update(&prev);
    h.update(body.as_bytes());
    Some(hex::encode(h.finalize()))
}

/// One entry of a chain, as a bundle carries it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub seq: u64,
    /// When embassy took the record in (RFC 3339, UTC).
    pub ingested_at: String,
    /// The audit record (CONTRACT.md §6), as embassy stored it.
    pub record: Value,
    pub prev_hash: String,
    pub hash: String,
}

impl Entry {
    /// The entry after `prev` (`None`: the first) of `chain`, for `record` taken in at
    /// `ingested_at`.
    pub fn next(prev: Option<&Entry>, chain: &str, ingested_at: &str, record: Value) -> Entry {
        let (seq, prev_hash) = match prev {
            Some(p) => (p.seq + 1, p.hash.clone()),
            None => (0, GENESIS.to_string()),
        };
        let hash =
            entry_hash(&prev_hash, chain, seq, ingested_at, &record).expect("prev_hash is a hash");
        Entry {
            seq,
            ingested_at: ingested_at.to_string(),
            record,
            prev_hash,
            hash,
        }
    }
}

/// Why a chain does not hold: the first broken entry.
pub fn check_chain(chain: &str, entries: &[Entry]) -> Result<(), String> {
    let mut prev = GENESIS.to_string();
    for (i, e) in entries.iter().enumerate() {
        if e.seq != i as u64 {
            return Err(format!("entry {i} has seq {}", e.seq));
        }
        if e.prev_hash != prev {
            return Err(format!(
                "entry {i} does not follow entry {}",
                i.saturating_sub(1)
            ));
        }
        match entry_hash(&e.prev_hash, chain, e.seq, &e.ingested_at, &e.record) {
            Some(h) if h == e.hash => {}
            _ => return Err(format!("entry {i} does not hash to its hash")),
        }
        prev = e.hash.clone();
    }
    Ok(())
}

// ---- keys -----------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("a signing key is a 32-byte Ed25519 seed in standard base64")]
    Seed,
    #[error("a public key is 32 bytes in hex, base64 or base64url")]
    Public,
}

/// The RFC 7638 thumbprint of an Ed25519 public key: base64url (no padding) of the SHA-256 of
/// `{"crv":"Ed25519","kty":"OKP","x":"<base64url public key>"}`.
pub fn kid_of(public: &[u8]) -> String {
    let jwk = format!(
        r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(public)
    );
    URL_SAFE_NO_PAD.encode(Sha256::digest(jwk.as_bytes()))
}

/// An Ed25519 signing key and its id.
pub struct SigningKey {
    pair: Ed25519KeyPair,
    kid: String,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("kid", &self.kid)
            .finish()
    }
}

impl SigningKey {
    pub fn from_seed(seed: &[u8; 32]) -> SigningKey {
        // a 32-byte seed always makes a key pair
        let pair = Ed25519KeyPair::from_seed_unchecked(seed).expect("a 32-byte Ed25519 seed");
        let kid = kid_of(pair.public_key().as_ref());
        SigningKey { pair, kid }
    }

    /// A key file's text: a 32-byte seed in standard base64 (surrounding whitespace ignored).
    pub fn from_seed_text(text: &str) -> Result<SigningKey, KeyError> {
        let bytes = STANDARD.decode(text.trim()).map_err(|_| KeyError::Seed)?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| KeyError::Seed)?;
        Ok(SigningKey::from_seed(&seed))
    }

    /// A new random seed, as a key file holds it.
    pub fn generate_seed_text() -> Result<String, KeyError> {
        let mut seed = [0u8; 32];
        aws_lc_rs::rand::SecureRandom::fill(&aws_lc_rs::rand::SystemRandom::new(), &mut seed)
            .map_err(|_| KeyError::Seed)?;
        Ok(STANDARD.encode(seed))
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn public_key(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.pair.public_key().as_ref());
        out
    }

    /// The JWK of the public key.
    pub fn jwk(&self, status: KeyStatus) -> Jwk {
        Jwk::of(&self.public_key(), status)
    }

    /// The 64-byte signature of `msg`.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.pair.sign(msg).as_ref().to_vec()
    }
}

/// A public key in hex, standard base64 or base64url (no padding), as `--key` and
/// `--ledger-retired-key` take it.
pub fn parse_public_key(text: &str) -> Result<[u8; 32], KeyError> {
    let t = text.trim();
    let bytes = hex::decode(t)
        .ok()
        .or_else(|| STANDARD.decode(t).ok())
        .or_else(|| URL_SAFE_NO_PAD.decode(t).ok())
        .ok_or(KeyError::Public)?;
    bytes.try_into().map_err(|_| KeyError::Public)
}

/// Whether `signature` is `public`'s Ed25519 signature of `msg`.
pub fn verify_signature(public: &[u8; 32], msg: &[u8], signature: &[u8]) -> bool {
    UnparsedPublicKey::new(&ED25519, public)
        .verify(msg, signature)
        .is_ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    /// The key embassy signs with now.
    Current,
    /// A key that signed before; its seals still verify.
    Retired,
}

/// One public key of a [`Jwks`] (RFC 7517, RFC 8037).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub kid: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub status: KeyStatus,
}

impl Jwk {
    pub fn of(public: &[u8; 32], status: KeyStatus) -> Jwk {
        Jwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: URL_SAFE_NO_PAD.encode(public),
            kid: kid_of(public),
            alg: "EdDSA".into(),
            use_: "sig".into(),
            status,
        }
    }
}

/// The published keys: the current one first, then the retired ones.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwks {
    /// The public key with id `kid`: an OKP / Ed25519 key whose `x` is 32 bytes and whose
    /// thumbprint is `kid` (a key published under another key's id is not found).
    pub fn find(&self, kid: &str) -> Option<[u8; 32]> {
        self.keys.iter().find_map(|k| {
            if k.kid != kid || k.kty != "OKP" || k.crv != "Ed25519" {
                return None;
            }
            let x: [u8; 32] = URL_SAFE_NO_PAD.decode(&k.x).ok()?.try_into().ok()?;
            (kid_of(&x) == kid).then_some(x)
        })
    }

    /// One current key, as `--key` gives it.
    pub fn single(public: &[u8; 32]) -> Jwks {
        Jwks {
            keys: vec![Jwk::of(public, KeyStatus::Current)],
        }
    }
}

// ---- seals ----------------------------------------------------------------------------------

/// What a seal signs. Its bytes are [`canonical_json`] of it, so they are the same whatever
/// order a reader keeps the fields in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealStatement {
    pub chain: String,
    /// How many entries it covers: entries `0..entries`.
    pub entries: u64,
    /// The hash of entry `entries - 1`.
    pub head: String,
    pub kid: String,
    /// RFC 3339, UTC.
    pub sealed_at: String,
    #[serde(rename = "type")]
    pub kind: String,
}

impl SealStatement {
    pub fn text(&self) -> String {
        canonical_json(&serde_json::to_value(self).unwrap_or(Value::Null))
    }
}

/// A signed statement, as embassy stores it and a bundle carries it: the statement's exact text,
/// the signature over those bytes (hex) and the key id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seal {
    pub statement: String,
    pub signature: String,
    pub kid: String,
}

/// Seal entries `0..entries` of `chain`, whose last hash is `head`.
pub fn seal(key: &SigningKey, chain: &str, entries: u64, head: &str, sealed_at: &str) -> Seal {
    let statement = SealStatement {
        chain: chain.to_string(),
        entries,
        head: head.to_string(),
        kid: key.kid().to_string(),
        sealed_at: sealed_at.to_string(),
        kind: SEAL_TYPE.to_string(),
    }
    .text();
    Seal {
        signature: hex::encode(key.sign(statement.as_bytes())),
        kid: key.kid().to_string(),
        statement,
    }
}

/// Check one seal against the chain's entries, in this order: the statement parses and is a
/// seal; it names the seal's key; that key is published; the signature holds over the exact
/// statement bytes; it is about `chain`; it covers entries that exist and its head is theirs.
pub fn check_seal(
    seal: &Seal,
    keys: &Jwks,
    chain: &str,
    entries: &[Entry],
) -> Result<SealStatement, String> {
    let st: SealStatement = serde_json::from_str(&seal.statement)
        .map_err(|e| format!("the statement does not parse: {e}"))?;
    if st.kind != SEAL_TYPE {
        return Err(format!("the statement is a {:?}, not a seal", st.kind));
    }
    if st.kid != seal.kid {
        return Err(format!(
            "the statement names key {}, the seal another key",
            st.kid
        ));
    }
    let Some(public) = keys.find(&seal.kid) else {
        return Err(format!("no published key {}", seal.kid));
    };
    let sig = hex::decode(&seal.signature).map_err(|_| "the signature is not hex".to_string())?;
    if !verify_signature(&public, seal.statement.as_bytes(), &sig) {
        return Err(format!(
            "the signature does not verify with key {}",
            seal.kid
        ));
    }
    if st.chain != chain {
        return Err(format!("the seal is about chain {}", st.chain));
    }
    let n = usize::try_from(st.entries).unwrap_or(usize::MAX);
    if n == 0 || n > entries.len() {
        return Err(format!(
            "the seal covers {} entries, the chain has {}",
            st.entries,
            entries.len()
        ));
    }
    if entries[n - 1].hash != st.head {
        return Err(format!("the seal's head is not entry {}'s hash", n - 1));
    }
    Ok(st)
}

// ---- bundles --------------------------------------------------------------------------------

/// One chain's evidence, as `GET /api/v1/ledger/runs/{request_id}/bundle` exports it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub format: String,
    pub exported_at: String,
    pub chain: String,
    pub entries: Vec<Entry>,
    /// Oldest first; the last covers every entry when the export sealed the chain first.
    pub seals: Vec<Seal>,
}

/// One check of [`verify_bundle`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

/// What [`verify_bundle`] found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub ok: bool,
    pub chain: String,
    pub checks: Vec<Check>,
}

/// Run every check on `bundle` with the public keys `keys`, each whatever the others found:
///
/// - `format`: the bundle's format is [`BUNDLE_FORMAT`];
/// - `chain`: the entries are `0..n` in order, each follows the one before and hashes to its hash,
///   and there is at least one;
/// - `seals`: every seal holds ([`check_seal`]), and one covers every entry (so no entry was
///   added or taken off the end since it was sealed).
pub fn verify_bundle(bundle: &Bundle, keys: &Jwks) -> Report {
    let mut checks = Vec::new();
    let mut push = |name: &str, r: Result<String, String>| {
        let (ok, detail) = match r {
            Ok(d) => (true, d),
            Err(d) => (false, d),
        };
        checks.push(Check {
            name: name.to_string(),
            ok,
            detail,
        });
    };
    push(
        "format",
        if bundle.format == BUNDLE_FORMAT {
            Ok(bundle.format.clone())
        } else {
            Err(format!("{:?} is not {BUNDLE_FORMAT}", bundle.format))
        },
    );
    let chain_ok = if bundle.entries.is_empty() {
        Err("the bundle has no entries".to_string())
    } else {
        check_chain(&bundle.chain, &bundle.entries).map(|()| {
            format!(
                "{} entries, head {}",
                bundle.entries.len(),
                bundle.entries.last().map_or("", |e| e.hash.as_str())
            )
        })
    };
    push("chain", chain_ok);
    let mut seals = Ok(());
    let mut covered = 0u64;
    for (i, s) in bundle.seals.iter().enumerate() {
        match check_seal(s, keys, &bundle.chain, &bundle.entries) {
            Ok(st) => covered = covered.max(st.entries),
            Err(e) => {
                seals = Err(format!("seal {i}: {e}"));
                break;
            }
        }
    }
    let seals = seals.and_then(|()| {
        if bundle.seals.is_empty() {
            Err("the bundle has no seal".to_string())
        } else if covered != bundle.entries.len() as u64 {
            Err(format!(
                "the seals cover {covered} of {} entries",
                bundle.entries.len()
            ))
        } else {
            Ok(format!(
                "{} seal(s), the last by {}",
                bundle.seals.len(),
                bundle.seals.last().map_or("", |s| s.kid.as_str())
            ))
        }
    });
    push("seals", seals);
    Report {
        ok: checks.iter().all(|c| c.ok),
        chain: bundle.chain.clone(),
        checks,
    }
}

impl Report {
    /// The verifier's text: `chain <id>`, one line per check (`ok  ` or `FAIL`), and the verdict.
    pub fn text(&self) -> String {
        let mut out = format!("chain {}\n", self.chain);
        for c in &self.checks {
            let mark = if c.ok { "ok  " } else { "FAIL" };
            out.push_str(&format!("  {mark} {:<12} {}\n", c.name, c.detail));
        }
        out.push_str(if self.ok {
            "the bundle verifies\n"
        } else {
            "the bundle does NOT verify\n"
        });
        out
    }
}
