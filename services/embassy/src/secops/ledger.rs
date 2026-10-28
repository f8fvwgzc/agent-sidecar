//! The evidence ledger in embassy (docs/design/evidence-ledger.md, CONTRACT.md §6.3).
//!
//! - **Appending.** Every audit record a sidecar sends, after the drop rules of design §7 and
//!   with `agent_id` filled, goes into its run's chain ([`append`], called from
//!   `controlplane::ingest_batch`): one transaction per batch.
//! - **Sealing.** With a signing key (`--ledger-key-file`), [`sealer`] seals every chain whose
//!   newest entries no seal covers once it has had no new entry for `--ledger-seal-after`;
//!   [`seal_now`] seals a chain at once (before an export). Replicas may seal the same chain at the
//!   same time: the store keeps the first seal of each length. Without a key, chains are kept and
//!   nothing is sealed (embassy says so at start).
//! - **Keys.** The current key and the retired public keys are published as a JWKS
//!   ([`LedgerKeys::jwks`]): `GET /.well-known/jwks.json` and `GET /api/v1/ledger/keys`.
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use agentsc_ledger::{Jwks, KeyStatus, SigningKey};
use anyhow::Context;
use tokio_util::sync::CancellationToken;

use super::{ChainHead, LedgerRecord, SecOpsStore};
use crate::api::types::AuditRecord;
use crate::hub::Hub;
use crate::store::StoreError;

/// How often [`sealer`] looks for chains to seal.
pub const SEAL_TICK: Duration = Duration::from_secs(1);
/// The default `--ledger-seal-after`: how long a chain has no new entry before it is sealed.
pub const DEFAULT_SEAL_AFTER: Duration = Duration::from_secs(10);
/// Chains sealed per tick.
const SEAL_BATCH: usize = 200;

/// The signing key (if any) and the retired public keys.
#[derive(Debug, Default)]
pub struct LedgerKeys {
    signer: Option<SigningKey>,
    retired: Vec<[u8; 32]>,
}

impl LedgerKeys {
    /// `--ledger-key-file` (a 32-byte Ed25519 seed in standard base64, as
    /// `embassy ledger-key create` writes it) and `--ledger-retired-key` (public keys).
    pub fn load(key_file: Option<&Path>, retired: &[String]) -> anyhow::Result<LedgerKeys> {
        let signer = match key_file {
            Some(path) => {
                let text = std::fs::read_to_string(path)
                    .with_context(|| format!("--ledger-key-file {}", path.display()))?;
                Some(
                    SigningKey::from_seed_text(&text)
                        .with_context(|| format!("--ledger-key-file {}", path.display()))?,
                )
            }
            None => None,
        };
        let retired = retired
            .iter()
            .map(|k| agentsc_ledger::parse_public_key(k).context("--ledger-retired-key"))
            .collect::<anyhow::Result<Vec<_>>>()?;
        if let Some(s) = &signer
            && retired.iter().any(|r| *r == s.public_key())
        {
            anyhow::bail!("--ledger-retired-key names the current key {}", s.kid());
        }
        Ok(LedgerKeys { signer, retired })
    }

    pub fn with_signer(signer: SigningKey) -> LedgerKeys {
        LedgerKeys {
            signer: Some(signer),
            retired: Vec::new(),
        }
    }

    pub fn signer(&self) -> Option<&SigningKey> {
        self.signer.as_ref()
    }

    /// The current key first, then the retired ones.
    pub fn jwks(&self) -> Jwks {
        let mut keys: Vec<_> = self
            .signer
            .iter()
            .map(|s| s.jwk(KeyStatus::Current))
            .collect();
        keys.extend(
            self.retired
                .iter()
                .map(|p| agentsc_ledger::Jwk::of(p, KeyStatus::Retired)),
        );
        Jwks { keys }
    }
}

/// The ledger record of one audit record as embassy took it in.
pub fn record_of(rec: &AuditRecord) -> Option<LedgerRecord> {
    let record = serde_json::to_value(rec).ok()?;
    Some(LedgerRecord {
        chain: agentsc_ledger::chain_of(&rec.request_id, &rec.namespace, &rec.service),
        namespace: rec.namespace.clone(),
        service: rec.service.clone(),
        agent_id: rec.agent_id.clone(),
        kind: rec.kind.clone(),
        record,
    })
}

/// Append the records of one batch to their chains. A failure is logged and counted, never
/// returned: the records still reach the ring, the traces and SSE.
pub async fn append(hub: &Hub, records: &[AuditRecord]) {
    let Some(store) = hub.secops() else {
        return;
    };
    let recs: Vec<LedgerRecord> = records.iter().filter_map(record_of).collect();
    if recs.is_empty() {
        return;
    }
    if let Err(e) = store.ledger_append(&crate::cp_audit::now_ts(), &recs).await {
        hub.ledger_failures
            .fetch_add(recs.len() as u64, std::sync::atomic::Ordering::Relaxed);
        tracing::error!(error = %e, records = recs.len(), "the evidence ledger did not take a batch");
    }
}

/// Seal `head` (its entries now) with the signing key. `Ok(false)` when there is no key, nothing
/// to seal, or another replica sealed it first.
pub async fn seal_head(
    store: &dyn SecOpsStore,
    keys: &LedgerKeys,
    head: &ChainHead,
) -> Result<bool, StoreError> {
    let Some(signer) = keys.signer() else {
        return Ok(false);
    };
    if head.entries == 0 || head.sealed >= head.entries {
        return Ok(false);
    }
    let sealed_at = crate::cp_audit::now_ts();
    let seal = agentsc_ledger::seal(signer, &head.chain, head.entries, &head.head, &sealed_at);
    store
        .ledger_put_seal(&head.chain, head.entries, &sealed_at, &seal)
        .await
}

/// Seal `chain` up to its newest entry now (an export calls this first).
pub async fn seal_now(hub: &Hub, chain: &str) -> Result<(), StoreError> {
    let (Some(store), Some(keys)) = (hub.secops(), hub.ledger.get()) else {
        return Ok(());
    };
    let head = store.ledger_head(chain).await?;
    seal_head(store.as_ref(), keys, &head).await.map(|_| ())
}

/// Seal the chains that have been quiet for `seal_after`, every [`SEAL_TICK`], until shutdown.
pub async fn sealer(hub: Arc<Hub>, seal_after: Duration, shutdown: CancellationToken) {
    let (Some(store), Some(keys)) = (hub.secops().cloned(), hub.ledger.get().cloned()) else {
        return;
    };
    if keys.signer().is_none() {
        return;
    }
    let mut tick = tokio::time::interval(SEAL_TICK);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            () = shutdown.cancelled() => return,
        }
        let quiet_before = chrono::Utc::now()
            - chrono::Duration::from_std(seal_after).unwrap_or(chrono::Duration::zero());
        let quiet_before = quiet_before.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let heads = match store.ledger_unsealed(&quiet_before, SEAL_BATCH).await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(error = %e, "ledger sealer: listing the unsealed chains failed");
                continue;
            }
        };
        for head in &heads {
            if let Err(e) = seal_head(store.as_ref(), &keys, head).await {
                tracing::warn!(chain = head.chain, error = %e, "ledger sealer: sealing failed");
            }
        }
    }
}
