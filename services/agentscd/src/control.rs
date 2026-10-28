//! Managed mode: the `Connect` stream to the control plane (design §6.3.3–6, §6.4, §7).
//!
//! mTLS with the workload certificate; the server must chain to the trust roots and carry the URI
//! SAN `spiffe://<trust domain>/control-plane` (`--trust-domain`). The first message is `Hello`,
//! then heartbeats every 10 s, audit batches, span starts and learning proposals. `AgentIds` (the agents'
//! registry ids) is installed in the audit writer. `CharterUpdate` and `MemoryUpdate` are
//! applied (charter: when the epoch differs or the version is greater) and acknowledged; a stale
//! one is not applied and is acknowledged with the version in force, so the control plane shows
//! what runs. Unknown message variants are ignored (logged once). A lost stream is reconnected
//! with full-jitter backoff from 1 s to 60 s and never changes the running charter or memory.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agentsc_common::authz::Verdict;
use agentsc_proto::control_plane_client::ControlPlaneClient;
use agentsc_proto::{
    AgentIds, AuditBatch, CharterUpdate, ConfigAck, ControlMessage, Heartbeat, Hello, MemoryUpdate,
    SidecarMessage, control_message, sidecar_message,
};
use tokio_stream::wrappers::ReceiverStream;

use crate::loaded::{Memory, Source};
use crate::reload::{self, CharterCandidate, RULE_STALE};
use crate::state::{AppState, lock};
use crate::tls::CurrentCert;

/// gRPC message limit on the `Connect` stream (design §3).
pub const MAX_MESSAGE: usize = 4 * 1024 * 1024;
/// How long opening the stream (up to the response headers) may take.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

static UNKNOWN_LOGGED: AtomicBool = AtomicBool::new(false);
static HEARTBEAT_SEQ: AtomicU64 = AtomicU64::new(0);

pub fn hello(state: &AppState) -> Hello {
    let snap = state.loaded();
    let (epoch, version) = match &snap {
        Some(l) if l.source.from_control_plane() => (l.epoch.clone(), l.version.clone()),
        _ => (String::new(), String::new()),
    };
    let app_port = match (&snap, state.config.app_port) {
        (_, Some(p)) => u32::from(p),
        (Some(l), None) => u32::from(l.charter.service.app_port),
        (None, None) => 0,
    };
    Hello {
        service: state.service.clone(),
        namespace: state.namespace.clone(),
        pod: state.pod.clone(),
        sidecar_version: env!("CARGO_PKG_VERSION").to_string(),
        charter_epoch: epoch,
        charter_version: version,
        charter_yaml: lock(&state.file_yaml).clone().unwrap_or_default(),
        app_port,
        mesh_port: u32::from(state.mesh_port.load(Ordering::Relaxed)),
        charter_schema_level: agentsc_charter::CHARTER_SCHEMA_LEVEL,
        memory_version: state.memory_version(),
    }
}

pub fn heartbeat(state: &AppState) -> Heartbeat {
    Heartbeat {
        seq: HEARTBEAT_SEQ.fetch_add(1, Ordering::Relaxed) + 1,
        runtime_ready: state.runtime_ready.load(Ordering::Relaxed),
        charter_version: state
            .loaded()
            .map(|l| l.version.clone())
            .unwrap_or_default(),
        audit_dropped: state.outbox.audit_dropped(),
        cert_expires_in_s: state.cert_expires_in_s().unwrap_or(0),
    }
}

fn ack(epoch: &str, version: &str, kind: &str, result: Result<(), String>) -> SidecarMessage {
    let (applied, error) = match result {
        Ok(()) => (true, String::new()),
        Err(e) => (false, e),
    };
    SidecarMessage {
        msg: Some(sidecar_message::Msg::Ack(ConfigAck {
            epoch: epoch.to_string(),
            version: version.to_string(),
            applied,
            error,
            kind: kind.to_string(),
        })),
    }
}

/// Apply a `CharterUpdate` by the rule of design §3: only if its epoch differs from the current
/// one or its version is greater. Returns the ack.
pub fn apply_charter_update(state: &AppState, u: &CharterUpdate) -> SidecarMessage {
    let reply = |r| ack(&u.epoch, &u.version, "charter", r);
    if u.version.parse::<u64>().is_err() {
        let reason = format!("version {:?} is not a decimal u64", u.version);
        reload::config_record(
            state,
            "control-plane",
            "charter",
            Source::ControlPlane.as_str(),
            &u.epoch,
            &u.version,
            "",
            &[],
            &Verdict::deny(reload::RULE_INVALID, reason.clone()),
        );
        return reply(Err(reason));
    }
    let version: u64 = u.version.parse().unwrap_or(0);
    if let Some(cur) = state.loaded()
        && cur.source.from_control_plane()
        && cur.epoch == u.epoch
    {
        let current: u64 = cur.version.parse().unwrap_or(0);
        if version == current {
            // what runs already
            return reply(Ok(()));
        }
        if version < current {
            let reason =
                format!("stale: version {version} is older than the applied version {current}");
            tracing::info!(%reason, "charter update ignored");
            reload::config_record(
                state,
                "control-plane",
                "charter",
                Source::ControlPlane.as_str(),
                &u.epoch,
                &u.version,
                "",
                &[],
                &Verdict::deny(RULE_STALE, reason),
            );
            // not applied (design §3); the ack names what runs, so the instance never shows the
            // stale version with an error while it runs a newer one
            return ack(&cur.epoch, &cur.version, "charter", Ok(()));
        }
    }
    let result = reload::apply_charter(
        state,
        CharterCandidate {
            text: u.charter_yaml.clone(),
            epoch: u.epoch.clone(),
            version: u.version.clone(),
            source: Source::ControlPlane,
        },
    )
    .map(|_| ());
    reply(result)
}

/// Apply a `MemoryUpdate` (a full replacement) when its version is greater than the applied one.
pub fn apply_memory_update(state: &AppState, u: &MemoryUpdate) -> SidecarMessage {
    let epoch = state.loaded().map(|l| l.epoch.clone()).unwrap_or_default();
    let reply = |r| ack(&epoch, &u.version, "memory", r);
    let Ok(version) = u.version.parse::<u64>() else {
        let reason = format!("memory version {:?} is not a decimal u64", u.version);
        reload::config_record(
            state,
            "control-plane",
            "memory",
            Source::ControlPlane.as_str(),
            &epoch,
            &u.version,
            "",
            &[],
            &Verdict::deny(reload::RULE_INVALID, reason.clone()),
        );
        return reply(Err(reason));
    };
    let current_version = state.memory_version();
    if !current_version.is_empty() {
        let current: u64 = current_version.parse().unwrap_or(0);
        if version == current {
            return reply(Ok(()));
        }
        if version < current {
            let reason = format!(
                "stale: memory version {version} is older than the applied version {current}"
            );
            tracing::info!(%reason, "memory update ignored");
            reload::config_record(
                state,
                "control-plane",
                "memory",
                Source::ControlPlane.as_str(),
                &epoch,
                &u.version,
                "",
                &[],
                &Verdict::deny(RULE_STALE, reason),
            );
            return ack(&epoch, &current_version, "memory", Ok(()));
        }
    }
    reload::apply_memory(state, Memory::from_update(u), Source::ControlPlane);
    reply(Ok(()))
}

/// Install the agents' registry ids (CONTRACT.md §5.3): from now on every audit record of one
/// of these agents carries its `agent_id`. A full replacement; nothing is acknowledged.
pub fn apply_agent_ids(state: &AppState, u: AgentIds) {
    let ids: std::collections::HashMap<String, String> = u
        .ids
        .into_iter()
        .filter(|(_, id)| agentsc_common::principal::AgentId::parse(id).is_ok())
        .collect();
    tracing::debug!(agents = ids.len(), "agent registry ids applied");
    state.audit.writer().set_agent_ids(ids);
}

/// The reply to one control message, if any.
pub fn handle(state: &AppState, msg: ControlMessage) -> Option<SidecarMessage> {
    match msg.msg {
        Some(control_message::Msg::Charter(u)) => Some(apply_charter_update(state, &u)),
        Some(control_message::Msg::Memory(u)) => Some(apply_memory_update(state, &u)),
        Some(control_message::Msg::AgentIds(u)) => {
            apply_agent_ids(state, u);
            None
        }
        None => {
            if !UNKNOWN_LOGGED.swap(true, Ordering::Relaxed) {
                tracing::info!("ignoring a control message of a kind this sidecar does not know");
            }
            None
        }
    }
}

/// Wait until a workload certificate is installed.
async fn wait_for_cert(state: &AppState) {
    let mut rx = state.tls_generation.subscribe();
    while state.tls().is_none() {
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// One `Connect` stream, until it ends. Returns whether it got as far as an open stream.
async fn session(state: &Arc<AppState>, addr: &str) -> (bool, anyhow::Result<()>) {
    let setup = || -> anyhow::Result<_> {
        let roots = state
            .trust_roots
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no trust roots for the control plane"))?;
        let cfg = crate::tls::control_plane_client_config(
            roots,
            Some(Arc::new(CurrentCert(state.tls.clone()))),
            &state.trust_domain,
        )?;
        // no per-request timeout: it would cut the stream
        crate::tls::tls_channel(addr, crate::tls::server_name_of(addr)?, cfg, None)
    };
    let channel = match setup() {
        Ok(c) => c,
        Err(e) => return (false, Err(e)),
    };
    let mut client = ControlPlaneClient::new(channel)
        .max_decoding_message_size(MAX_MESSAGE)
        .max_encoding_message_size(MAX_MESSAGE);
    let (tx, rx) = tokio::sync::mpsc::channel::<SidecarMessage>(256);
    let hello = SidecarMessage {
        msg: Some(sidecar_message::Msg::Hello(hello(state))),
    };
    if tx.send(hello).await.is_err() {
        return (false, Err(anyhow::anyhow!("stream closed before hello")));
    }
    let opened = tokio::time::timeout(CONNECT_TIMEOUT, client.connect(ReceiverStream::new(rx)));
    let mut inbound = match opened.await {
        Ok(Ok(r)) => r.into_inner(),
        Ok(Err(st)) => {
            return (
                false,
                Err(anyhow::anyhow!("Connect: {} {}", st.code(), st.message())),
            );
        }
        Err(_) => {
            return (
                false,
                Err(anyhow::anyhow!("Connect: no answer in {CONNECT_TIMEOUT:?}")),
            );
        }
    };
    tracing::info!(%addr, "connected to the control plane");
    let timing = state.config.timing.clone();
    let mut beat = tokio::time::interval(timing.heartbeat);
    beat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    beat.tick().await;
    let send = |m: SidecarMessage| {
        let tx = tx.clone();
        async move {
            tx.send(m)
                .await
                .map_err(|_| anyhow::anyhow!("the Connect stream closed"))
        }
    };
    // No `biased`: each ready branch gets its turn, so a steady flow of span starts cannot
    // starve the audit batches (whose queue would then overflow while the stream is up). Every
    // branch is cancel-safe: the outbox hands out its entries only when the future completes.
    loop {
        let out = tokio::select! {
            msg = inbound.message() => match msg {
                Ok(Some(m)) => match handle(state, m) {
                    Some(reply) => send(reply).await,
                    None => Ok(()),
                },
                Ok(None) => return (true, Ok(())),
                Err(st) => return (true, Err(anyhow::anyhow!("Connect: {} {}", st.code(), st.message()))),
            },
            _ = beat.tick() => {
                send(SidecarMessage { msg: Some(sidecar_message::Msg::Heartbeat(heartbeat(state))) }).await
            },
            spans = state.outbox.next_spans() => {
                let mut r = Ok(());
                for s in spans {
                    r = send(SidecarMessage { msg: Some(sidecar_message::Msg::SpanStart(s)) }).await;
                    if r.is_err() { break; }
                }
                r
            },
            proposals = state.outbox.next_proposals() => {
                let mut r = Ok(());
                for p in proposals {
                    r = send(SidecarMessage { msg: Some(sidecar_message::Msg::Proposal(p)) }).await;
                    if r.is_err() { break; }
                }
                r
            },
            batch = state.outbox.next_audit_batch(timing.audit_flush) => {
                // span starts queued so far go first: a start always precedes the record that
                // closes its span (it was queued before that record was written)
                let mut r = Ok(());
                for s in state.outbox.take_spans() {
                    r = send(SidecarMessage { msg: Some(sidecar_message::Msg::SpanStart(s)) }).await;
                    if r.is_err() { break; }
                }
                if r.is_ok() {
                    r = send(SidecarMessage { msg: Some(sidecar_message::Msg::Audit(AuditBatch { records_json: batch })) }).await;
                }
                r
            },
        };
        if let Err(e) = out {
            return (true, Err(e));
        }
    }
}

/// Keep a `Connect` stream up for the life of the sidecar.
pub async fn run(state: Arc<AppState>) {
    let Some(addr) = state.config.control_plane_addr().map(str::to_string) else {
        return;
    };
    let timing = state.config.timing.clone();
    let mut attempt = 0u32;
    loop {
        wait_for_cert(&state).await;
        let (connected, result) = session(&state, &addr).await;
        match result {
            Ok(()) => tracing::warn!(%addr, "the control plane closed the Connect stream"),
            Err(e) => tracing::warn!(%addr, error = %format!("{e:#}"), "Connect failed"),
        }
        if connected {
            attempt = 0;
        }
        let delay = crate::identity::backoff(timing.reconnect_min, timing.reconnect_max, attempt);
        attempt = attempt.saturating_add(1);
        tokio::time::sleep(delay).await;
    }
}
