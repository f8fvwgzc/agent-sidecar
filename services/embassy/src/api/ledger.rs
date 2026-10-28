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
