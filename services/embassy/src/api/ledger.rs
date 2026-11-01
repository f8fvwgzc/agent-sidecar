//! The evidence ledger's endpoints (docs/design/evidence-ledger.md, CONTRACT.md §6.3): the runs
//! it holds, one run's head, its bundle, and the public keys. A chain is visible to a caller who
//! may see every namespace it has records of (else 404, as for one that does not exist); a bundle
//! whose records carry payloads needs the payload permission too.
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};

use super::agents::secops;
use super::error::Fail;
use super::types::{CpAction, CpResult};
use super::{Authed, Query};
use crate::auth::Identity;
use crate::cp_audit::CpAudit;
use crate::hub::Hub;
use crate::secops::ledger::MAX_APPEND;
use crate::secops::{ChainFilter, ChainHead};
use crate::store::StoreError;

/// Runs listed at most, and by default.
pub const MAX_RUNS: usize = 500;
pub const DEFAULT_RUNS: usize = 50;

fn visible(ident: &Identity, head: &ChainHead) -> bool {
    head.services
        .iter()
        .all(|s| ident.allows_namespace(&s.namespace))
}

async fn visible_head(hub: &Hub, ident: &Identity, chain: &str) -> Result<ChainHead, Fail> {
    let missing = || Fail::not_found(format!("no run {chain} in the ledger"));
    let store = secops(hub)?;
    match store.ledger_head(chain).await {
        Ok(h) if visible(ident, &h) => Ok(h),
        Ok(_) => Err(missing()),
        Err(StoreError::NotFound) => match store.ledger_purged(chain).await {
            // only callers who may see some namespace learn that it was purged, and when
            Ok(Some(p)) if !ident.namespaces.is_empty() => Err(Fail::not_found(format!(
                "run {chain} was purged at {} ({} entries, head {}); a bundle exported before still verifies",
                p.purged_at, p.entries, p.head
            ))),
            _ => Err(missing()),
        },
        Err(e) => Err(Fail::store(e, "")),
    }
}

/// `GET /ledger/runs?namespace=&service=&limit=`: the most recently appended runs first.
pub async fn list_runs(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    axum::extract::Query(q): Query,
) -> Result<Response, Fail> {
    let limit = match q.get("limit").filter(|s| !s.is_empty()) {
        None => DEFAULT_RUNS,
        Some(l) => match l.parse::<usize>() {
            Ok(n) if (1..=MAX_RUNS).contains(&n) => n,
            _ => {
                return Err(Fail::invalid([format!(
                    "limit {l:?} is not 1..={MAX_RUNS}"
                )]));
            }
        },
    };
    let filter = ChainFilter {
        namespace: q.get("namespace").filter(|s| !s.is_empty()).cloned(),
        service: q.get("service").filter(|s| !s.is_empty()).cloned(),
        limit,
    };
    let runs: Vec<ChainHead> = secops(&hub)?
        .ledger_chains(&filter)
        .await
        .map_err(|e| Fail::store(e, ""))?
        .into_iter()
        .filter(|h| visible(&ident, h))
        .collect();
    Ok(Json(runs).into_response())
}

/// `GET /ledger/runs/{chain}`: the head.
pub async fn get_run(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path(chain): Path<String>,
) -> Result<Response, Fail> {
    Ok(Json(visible_head(&hub, &ident, &chain).await?).into_response())
}

/// `GET /ledger/runs/{chain}/bundle`: the run's evidence, sealed up to its newest entry first
/// (with a signing key). Audited as `ledger_export`.
pub async fn bundle(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path(chain): Path<String>,
) -> Result<Response, Fail> {
    let store = secops(&hub)?;
    visible_head(&hub, &ident, &chain).await?;
    let result: Result<agentsc_ledger::Bundle, Fail> = async {
        crate::secops::ledger::seal_now(&hub, &chain)
            .await
            .map_err(|e| Fail::store(e, ""))?;
        let entries = store
            .ledger_entries(&chain)
            .await
            .map_err(|e| Fail::store(e, ""))?;
        if !ident.payloads
            && entries
                .iter()
                .any(|e| !e.record["input"].is_null() || !e.record["output"].is_null())
        {
            return Err(Fail::forbidden([format!(
                "run {chain} has records with payloads: its evidence needs the payload permission"
            )]));
        }
        let seals = store
            .ledger_seals(&chain)
            .await
            .map_err(|e| Fail::store(e, ""))?;
        Ok(agentsc_ledger::Bundle {
            format: agentsc_ledger::BUNDLE_FORMAT.into(),
            exported_at: crate::cp_audit::now_ts(),
            chain: chain.clone(),
            entries,
            seals,
        })
    }
    .await;
    let (res, reason) = match &result {
        Ok(b) => (
            CpResult::Ok,
            format!(
                "run {chain}: {} entries, {} seals",
                b.entries.len(),
                b.seals.len()
            ),
        ),
        Err(f) => (CpResult::Denied, format!("run {chain}: {}", f.reason())),
    };
    let mut rec = CpAudit::entry(CpAction::LedgerExport, &ident.actor(), res);
    rec.reason = Some(reason);
    hub.cp_audit.record(rec).await;
    let bundle = result?;
    let mut resp = Json(bundle).into_response();
    let name = format!(
        "attachment; filename=\"run-{}.evidence.json\"",
        chain.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-', "_")
    );
    if let Ok(v) = HeaderValue::from_str(&name) {
        resp.headers_mut().insert(header::CONTENT_DISPOSITION, v);
    }
    Ok(resp)
}

/// The published keys, current first (`GET /ledger/keys` and the public
/// `GET /.well-known/jwks.json`).
fn jwks(hub: &Hub) -> agentsc_ledger::Jwks {
    hub.ledger.get().map(|k| k.jwks()).unwrap_or_default()
}

pub async fn keys(State(hub): State<Arc<Hub>>, Authed(_): Authed) -> Response {
    Json(jwks(&hub)).into_response()
}

/// Public keys are public: no authentication.
pub async fn well_known_jwks(State(hub): State<Arc<Hub>>) -> Response {
    Json(jwks(&hub)).into_response()
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppendRequest {
    records: Vec<serde_json::Value>,
}

/// `POST /ledger/append`: the acknowledged Append API (CONTRACT.md §6.3). A record counts as
/// shipped only once this answers 200: every record of the request is committed by then, or none
/// is. A retry of the same `(service, id)` gets the place the record already has.
pub async fn append(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    super::JsonBody(req): super::JsonBody<AppendRequest>,
) -> Result<Response, Fail> {
    let store = secops(&hub)?;
    let config = hub.config.load();
    let producer = config
        .ledger
        .producers
        .iter()
        .find(|p| ident.oidc.is_none() && p.token == ident.name)
        .ok_or_else(|| Fail::forbidden(["this caller is not a producer in ledger.producers"]))?;
    if req.records.is_empty() || req.records.len() > MAX_APPEND {
        return Err(Fail::invalid([format!(
            "records must hold 1 to {MAX_APPEND} records, not {}",
            req.records.len()
        )]));
    }
    let now = crate::cp_audit::now_ts();
    let day = now.get(..10).unwrap_or(&now);
    let mut problems = Vec::new();
    let mut records = Vec::with_capacity(req.records.len());
    for (i, raw) in req.records.iter().enumerate() {
        match crate::secops::ledger::forwarded(producer, raw, day) {
            Ok(r) => records.push(r),
            Err(e) => problems.push(format!("records[{i}]: {e}")),
        }
    }
    let audit = |result, reason: String| {
        let mut rec = CpAudit::entry(CpAction::LedgerAppend, &ident.actor(), result);
        rec.reason = Some(reason);
        rec
    };
    if !problems.is_empty() {
        tracing::warn!(
            producer = producer.service,
            ?problems,
            "ledger: forwarded records refused"
        );
        hub.cp_audit
            .record(audit(CpResult::Denied, problems.join("; ")))
            .await;
        return Err(Fail::invalid(problems));
    }
    let acks = match store.ledger_forward(&now, &records).await {
        Ok(acks) => acks,
        Err(StoreError::Invalid(why)) => {
            // the same key with another payload: someone rewrote a record, or the producer is broken
            tracing::error!(
                producer = producer.service,
                ?why,
                "ledger: forwarded records refused"
            );
            hub.cp_audit
                .record(audit(CpResult::Denied, why.join("; ")))
                .await;
            return Err(Fail::invalid(why));
        }
        Err(e) => return Err(Fail::store(e, "")),
    };
    let duplicates = acks.iter().filter(|a| a.duplicate).count();
    let gaps = acks.iter().filter(|a| a.gap).count();
    if gaps > 0 {
        tracing::warn!(
            producer = producer.service,
            gaps,
            "ledger: a producer's seq has a gap: records are lost or held back"
        );
    }
    hub.cp_audit
        .record(audit(
            CpResult::Ok,
            format!(
                "{} record(s), {duplicates} already here, {gaps} after a gap",
                acks.len()
            ),
        ))
        .await;
    Ok(Json(serde_json::json!({ "acknowledged": acks })).into_response())
}
