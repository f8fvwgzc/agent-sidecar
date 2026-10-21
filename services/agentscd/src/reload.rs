//! Hot reload (design §6.2). A candidate charter is fully validated, restart-only changes are
//! refused, and the new [`Loaded`] replaces the old one whole. Budgets live outside `Loaded`, so
//! they survive; a removed agent simply is not found (404). Every attempt — applied or refused —
//! writes a `config` record (design §5).
//!
//! The first control-plane charter after start-up is not checked for restart-only changes
//! against the start-up charter (the `--charter` file, or the one persisted in the state dir): it
//! takes that charter's place as a restart would, sink and OpenTelemetry endpoint included. The
//! control plane accepts restart-only changes while no instance is connected (design §4), so the
//! charter persisted before a restart may differ from the stored one in exactly those fields; a
//! restart is how such a change is applied, and must not lock the instance out of it (§6.3.5).
use std::sync::Arc;

use agentsc_charter::{Charter, diff};
use agentsc_common::audit::{AuditRecord, Direction, Kind, sha256_hex};
use agentsc_common::authz::Verdict;
use agentsc_common::guardrails::CompiledGuardrails;
use agentsc_common::trace::TraceContext;
use serde_json::{Value, json};

use crate::audit::SinkTarget;
use crate::loaded::{Loaded, Memory, Source};
use crate::persist::CharterMeta;
use crate::state::{AppState, lock};

pub const RULE_APPLIED: &str = "config.applied";
pub const RULE_INVALID: &str = "config.invalid";
pub const RULE_STALE: &str = "config.stale";

/// A charter to try, as received.
#[derive(Debug, Clone)]
pub struct CharterCandidate {
    pub text: String,
    pub epoch: String,
    pub version: String,
    pub source: Source,
}

fn opt(s: &str) -> Value {
    if s.is_empty() {
        Value::Null
    } else {
        Value::String(s.to_string())
    }
}

/// A `config` record (design §5): agent null, caller `control-plane` or `file`, callee `charter`
/// / `memory` / `certificate`, input `{source, epoch, version, sha256, weakened}`. It belongs to
/// no trace.
#[allow(clippy::too_many_arguments)]
pub fn build_config_record(
    caller: &str,
    callee: &str,
    source: &str,
    epoch: &str,
    version: &str,
    sha256: &str,
    weakened: &[String],
    v: &Verdict,
) -> AuditRecord {
    let mut rec = AuditRecord::new(
        Kind::Config,
        Direction::Internal,
        "",
        &TraceContext::new_root(),
        None,
        caller,
        None,
        callee,
        json!({
            "source": source,
            "epoch": opt(epoch),
            "version": opt(version),
            "sha256": opt(sha256),
            "weakened": weakened,
        }),
        Value::Null,
    )
    .verdict(v);
    rec.trace_id = String::new();
    rec.span_id = String::new();
    rec.parent_span_id = None;
    rec
}

/// [`build_config_record`], written.
#[allow(clippy::too_many_arguments)]
pub fn config_record(
    state: &AppState,
    caller: &str,
    callee: &str,
    source: &str,
    epoch: &str,
    version: &str,
    sha256: &str,
    weakened: &[String],
    v: &Verdict,
) {
    state.audit.write(build_config_record(
        caller, callee, source, epoch, version, sha256, weakened, v,
    ));
}

fn check_identity(state: &AppState, charter: &Charter) -> Result<(), String> {
    if charter.service.name != state.service || charter.service.namespace != state.namespace {
        return Err(format!(
            "charter is for {}/{}, this sidecar is {}/{}",
            charter.service.namespace, charter.service.name, state.namespace, state.service
        ));
    }
    Ok(())
}

/// Validate and apply a charter; `Err` carries the reason it was refused.
pub fn apply_charter(state: &AppState, cand: CharterCandidate) -> Result<Arc<Loaded>, String> {
    let _serial = lock(&state.apply_lock);
    let sha = sha256_hex(cand.text.as_bytes());
    let current = state.loaded();
    let replaces_startup = cand.source == Source::ControlPlane
        && current
            .as_ref()
            .is_some_and(|c| c.source != Source::ControlPlane);
    let checked = (|| {
        let charter = Charter::from_yaml(&cand.text).map_err(|e| e.to_string())?;
        check_identity(state, &charter)?;
        if let Some(cur) = &current
            && !replaces_startup
        {
            let fields = diff::restart_required(&cur.charter, &charter);
            if !fields.is_empty() {
                return Err(format!(
                    "a restart is required to change {}",
                    fields.join(", ")
                ));
            }
        }
        let guardrails = CompiledGuardrails::compile(&charter.guardrails)
            .map_err(|e| format!("guardrail regex: {e}"))?;
        Ok((charter, guardrails))
    })();
    let (charter, guardrails) = match checked {
        Ok(x) => x,
        Err(reason) => {
            tracing::warn!(source = cand.source.as_str(), %reason, "charter refused");
            config_record(
                state,
                cand.source.caller(),
                "charter",
                cand.source.as_str(),
                &cand.epoch,
                &cand.version,
                &sha,
                &[],
                &Verdict::deny(RULE_INVALID, reason.clone()),
            );
            return Err(reason);
        }
    };

    let weakened = current
        .as_ref()
        .map(|c| diff::weakened(&c.charter, &charter))
        .unwrap_or_default();
    let mut memory = match &current {
        Some(c) => c.memory.clone(),
        None => lock(&state.pending_memory).take().unwrap_or_default(),
    };
    // A new epoch from the control plane is a recreated service: its memory starts over.
    if let Some(c) = &current
        && c.source.from_control_plane()
        && cand.source.from_control_plane()
        && c.epoch != cand.epoch
    {
        memory = Memory::default();
        if let Err(e) = state.state_dir.save_memory(&memory) {
            tracing::warn!(error = %e, "cannot persist memory in the state dir");
        }
    }
    let first = current.is_none();
    // `mesh.port` fills `{port}` of the peer address template (it changes only here, when the
    // start-up charter is replaced)
    let peers_changed = current.as_ref().is_some_and(|c| {
        c.charter.mesh.peers != charter.mesh.peers || c.charter.mesh.port != charter.mesh.port
    });
    let loaded = Arc::new(Loaded {
        charter,
        guardrails: Arc::new(guardrails),
        epoch: cand.epoch.clone(),
        version: cand.version.clone(),
        sha256: sha.clone(),
        source: cand.source,
        memory,
    });
    state.store_loaded(loaded.clone());
    state.audit.set_redaction(
        loaded.charter.audit.redact.clone(),
        loaded.charter.guardrails.pii_redact,
    );
    if (first || replaces_startup)
        && let Err(e) = state.audit.set_sink(SinkTarget::of(&loaded.charter.audit))
    {
        tracing::error!(error = %e, "cannot open the charter's audit sink; keeping the current one");
    }
    if peers_changed {
        state.clear_mesh_clients();
    }
    crate::otel::on_charter(state, &loaded.charter, replaces_startup);
    match cand.source {
        Source::File => *lock(&state.file_yaml) = Some(cand.text.clone()),
        Source::ControlPlane => {
            let meta = CharterMeta {
                epoch: cand.epoch.clone(),
                version: cand.version.clone(),
            };
            if let Err(e) = state.state_dir.save_charter(&cand.text, &meta) {
                tracing::warn!(error = %e, "cannot persist the charter in the state dir");
            }
        }
        Source::State | Source::Learning => {}
    }
    tracing::info!(
        source = cand.source.as_str(),
        epoch = %cand.epoch,
        version = %cand.version,
        agents = loaded.charter.agents.len(),
        replaces_startup,
        ?weakened,
        "charter applied"
    );
    config_record(
        state,
        cand.source.caller(),
        "charter",
        cand.source.as_str(),
        &cand.epoch,
        &cand.version,
        &sha,
        &weakened,
        &Verdict::allow(RULE_APPLIED),
    );
    Ok(loaded)
}

/// Replace the service's memory (a `MemoryUpdate`, or a note the sidecar learned itself).
pub fn apply_memory(state: &AppState, memory: Memory, source: Source) {
    update_memory(state, source, |_| memory);
}

/// Replace the service's memory with `f(current)`, under the reload lock, so concurrent
/// updates are never lost; persisted in the state dir and audited as a `config` record.
pub fn update_memory(state: &AppState, source: Source, f: impl FnOnce(&Memory) -> Memory) {
    let _serial = lock(&state.apply_lock);
    let current = state.loaded();
    let memory = match &current {
        Some(cur) => f(&cur.memory),
        None => f(&lock(&state.pending_memory).clone().unwrap_or_default()),
    };
    let sha = memory.sha256();
    let version = memory.version.clone();
    let epoch = match current {
        Some(cur) => {
            let next = Arc::new(Loaded {
                charter: cur.charter.clone(),
                guardrails: cur.guardrails.clone(),
                epoch: cur.epoch.clone(),
                version: cur.version.clone(),
                sha256: cur.sha256.clone(),
                source: cur.source,
                memory: memory.clone(),
            });
            state.store_loaded(next);
            cur.epoch.clone()
        }
        None => {
            *lock(&state.pending_memory) = Some(memory.clone());
            String::new()
        }
    };
    if let Err(e) = state.state_dir.save_memory(&memory) {
        tracing::warn!(error = %e, "cannot persist memory in the state dir");
    }
    config_record(
        state,
        source.caller(),
        "memory",
        source.as_str(),
        &epoch,
        &version,
        &sha,
        &[],
        &Verdict::allow(RULE_APPLIED),
    );
}

/// Poll the `--charter` file's content hash and apply a changed file (design §6.2). Once a
/// control-plane charter is in force the file is only the start-up charter: changes are ignored.
pub async fn watch_file(state: Arc<AppState>, mut last: Option<String>) {
    let mut tick = tokio::time::interval(state.config.timing.charter_poll);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    let mut told = false;
    loop {
        tick.tick().await;
        let text = match tokio::fs::read_to_string(&state.config.charter).await {
            Ok(t) => t,
            Err(_) => continue, // missing for a moment (a ConfigMap swap), or never there
        };
        let hash = sha256_hex(text.as_bytes());
        if last.as_deref() == Some(hash.as_str()) {
            continue;
        }
        last = Some(hash);
        if state
            .loaded()
            .is_some_and(|l| l.source.from_control_plane())
        {
            if !told {
                tracing::info!(
                    "the --charter file changed; ignored while a control-plane charter is in force"
                );
                told = true;
            }
            continue;
        }
        let _ = apply_charter(
            &state,
            CharterCandidate {
                text,
                epoch: String::new(),
                version: String::new(),
                source: Source::File,
            },
        );
    }
}
