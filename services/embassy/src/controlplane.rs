//! The `controlplane` component: `ControlPlane.Connect` (design §7).
//!
//! - mTLS is required: the listener asks for a client certificate from the CA
//!   ([`ClientAuth::Required`]; [`ClientAuth::Optional`] when it shares `--grpc-addr` with
//!   `IssueCertificate`, and then a stream without a verified certificate is refused here). The
//!   service and namespace come from the certificate's SPIFFE id, which must be in
//!   `--trust-domain`; `Hello` must name the same (else `PERMISSION_DENIED`, audited as
//!   `connect_denied`).
//! - Each stream is an instance with its own UUID; closing a stream removes only that instance.
//! - On `Hello`: a stored charter whose (epoch, version) differs from the sidecar's is pushed,
//!   then always the stored memory. Without a stored charter, a valid `Hello.charter_yaml` is a
//!   pending adoption (audited as `adopt_pending`), or adopted at once with `--auto-adopt`.
//! - Store changes push `CharterUpdate` / `MemoryUpdate` to every instance of the service (from
//!   the hub's store pump: [`push_charter`], [`push_memory`]).
//! - Acks update the instance (`acked_version`, `ack_error`) and become `ack` events.
//! - Audit records: `service`/`namespace` overwritten with the stream's identity; records over
//!   64 KiB dropped; records whose `agent` is not in the stored charter dropped unless inbound.
//! - Learning proposals: accepted only when the stored charter enables learning for the agent;
//!   deduplicated by `dedup_key`; `auto` ones (mode `auto`) become notes at once.
//! - Span starts become `span_start` events and running spans of the traces.
//! - Keepalive 30 s, `max_connection_age` 30 min, at most 4 MiB per message.
use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use agentsc_common::identity::SpiffeId;
use agentsc_proto::control_plane_server::{ControlPlane, ControlPlaneServer};
use agentsc_proto::{
    AgentIds, AuditBatch, CharterUpdate, ConfigAck, ControlMessage, Heartbeat, Hello,
    LearningProposal, MemoryUpdate, NoteList, SidecarMessage, SpanStart, control_message,
    sidecar_message,
};
use chrono::Utc;
use futures::StreamExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status, Streaming};

use crate::api::types::{
    AckEvent, AckKind, AuditRecord, CpAction, CpResult, Instance, NoteSource, Proposal,
    ProposalStatus, RegistryEvent, RegistryStatus, SpanStartEvent, SseEvent,
};
use crate::api::write::{self, Via, Writer};
use crate::cp_audit::{CpAudit, now_ts};
use crate::events::Scope;
use crate::hub::Hub;
use crate::registry::{Connected, Outbox};
use crate::servingcert::{ClientAuth, ServingCertSource, peer_identity_in};
use crate::store::file::sha256_hex;
use crate::store::{
    Actor, ActorKind, AgentLearning, ChangeSource, MemoryDoc, Note, PendingAdoption, Precondition,
    ProposalPut, ServiceKey, StoreError,
};
use crate::traces::StartInfo;

/// The largest message a sidecar may send.
pub const MAX_DECODE: usize = 4 * 1024 * 1024;
/// HTTP/2 keepalive pings.
pub const KEEPALIVE: Duration = Duration::from_secs(30);
/// Streams are closed after this long (the sidecar reconnects).
pub const MAX_CONNECTION_AGE: Duration = Duration::from_secs(30 * 60);
/// Audit records larger than this are dropped.
pub const MAX_RECORD_BYTES: usize = 64 * 1024;
/// How long a new stream may take to send `Hello`.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(30);
/// Messages queued per instance.
const OUTBOX: usize = 64;

/// `sidecar:<spiffe id>/<pod>`.
pub fn sidecar_actor(id: &SpiffeId, pod: &str) -> Actor {
    Actor {
        name: format!("sidecar:{}/{pod}", id.uri()),
        kind: ActorKind::Sidecar,
        role: None,
    }
}

fn non_empty(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

/// The `Connect` service; see the module docs.
#[derive(Debug, Clone)]
pub struct ConnectService {
    hub: Arc<Hub>,
}

/// The gRPC service, with the decode limit.
pub fn service(hub: Arc<Hub>) -> ControlPlaneServer<ConnectService> {
    ControlPlaneServer::new(ConnectService { hub }).max_decoding_message_size(MAX_DECODE)
}

/// Serve `Connect` (plus `extra` routes, e.g. `IssueCertificate` when both share the address)
/// on `listener` over TLS until `shutdown`.
pub fn serve(
    hub: Arc<Hub>,
    listener: TcpListener,
    serving: &ServingCertSource,
    client_auth: ClientAuth,
    extra: Option<tonic::service::Routes>,
    shutdown: CancellationToken,
) -> JoinHandle<anyhow::Result<()>> {
    let config = serving.rustls_server_config(client_auth);
    let rx = crate::serve::tls::spawn_acceptor(listener, config, shutdown.clone());
    let incoming = ReceiverStream::new(rx).map(|(s, _)| Ok::<_, std::io::Error>(s));
    let mut builder = tonic::transport::Server::builder()
        .http2_keepalive_interval(Some(KEEPALIVE))
        .http2_keepalive_timeout(Some(Duration::from_secs(20)))
        .max_connection_age(MAX_CONNECTION_AGE);
    let router = match extra {
        Some(r) => builder.add_routes(r).add_service(service(hub.clone())),
        None => builder.add_service(service(hub.clone())),
    };
    hub.ready.set("controlplane", true);
    tokio::spawn(async move {
        let r = router
            .serve_with_incoming_shutdown(incoming, shutdown.cancelled_owned())
            .await;
        hub.ready.set("controlplane", false);
        r.map_err(|e| anyhow::anyhow!("the Connect server failed: {e}"))
    })
}

/// Bind `addr` and [`serve`]; returns the bound address.
pub async fn bind_and_serve(
    hub: Arc<Hub>,
    addr: SocketAddr,
    serving: &ServingCertSource,
    client_auth: ClientAuth,
    extra: Option<tonic::service::Routes>,
    shutdown: CancellationToken,
) -> anyhow::Result<(SocketAddr, JoinHandle<anyhow::Result<()>>)> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("bind --grpc-addr {addr}: {e}"))?;
    let bound = listener.local_addr()?;
    Ok((
        bound,
        serve(hub, listener, serving, client_auth, extra, shutdown),
    ))
}

#[tonic::async_trait]
impl ControlPlane for ConnectService {
    type ConnectStream = ReceiverStream<Result<ControlMessage, Status>>;

    async fn connect(
        &self,
        req: Request<Streaming<SidecarMessage>>,
    ) -> Result<Response<Self::ConnectStream>, Status> {
        let hub = &self.hub;
        let trust_domain = &hub.opts.trust_domain;
        let id = req
            .peer_certs()
            .and_then(|c| peer_identity_in(&c, trust_domain))
            .ok_or_else(|| {
                Status::permission_denied(format!(
                    "Connect needs a workload certificate from the agentsc CA with an identity \
                     in trust domain {trust_domain:?}"
                ))
            })?;
        let mut inbound = req.into_inner();
        let first = tokio::time::timeout(HELLO_TIMEOUT, inbound.message())
            .await
            .map_err(|_| Status::deadline_exceeded("no Hello"))??;
        let hello = match first {
            Some(SidecarMessage {
                msg: Some(sidecar_message::Msg::Hello(h)),
            }) => h,
            _ => return Err(Status::invalid_argument("the first message must be Hello")),
        };
        let key = ServiceKey::new(&id.namespace, &id.service);
        let actor = sidecar_actor(&id, &hello.pod);
        if hello.service != key.service || hello.namespace != key.namespace {
            let reason = format!(
                "Hello names {}/{}, the certificate is {}",
                hello.namespace,
                hello.service,
                id.uri()
            );
            let mut rec = CpAudit::entry(CpAction::ConnectDenied, &actor, CpResult::Denied);
            rec.namespace = Some(key.namespace.clone());
            rec.service = Some(key.service.clone());
            rec.reason = Some(reason.clone());
            hub.cp_audit.record(rec).await;
            return Err(Status::permission_denied(reason));
        }
        let (tx, rx) = mpsc::channel(OUTBOX);
        let instance_id = uuid::Uuid::new_v4().to_string();
        hub.registry.add(
            key.clone(),
            Connected {
                info: Instance {
                    instance_id: instance_id.clone(),
                    pod: hello.pod.clone(),
                    sidecar_version: hello.sidecar_version.clone(),
                    connected_at: now_ts(),
                    last_heartbeat: None,
                    runtime_ready: false,
                    acked_version: None,
                    ack_error: None,
                    cert_expires_in_s: None,
                    audit_dropped: 0,
                },
                schema_level: hello.charter_schema_level,
                app_port: hello.app_port,
                outbox: tx.clone(),
            },
        );
        hub.publish(
            SseEvent::Registry(RegistryEvent {
                namespace: key.namespace.clone(),
                service: key.service.clone(),
                instance_id: instance_id.clone(),
                pod: hello.pod.clone(),
                status: RegistryStatus::Connected,
            }),
            scope(&key),
        );
        let mut rec = CpAudit::entry(CpAction::Connect, &actor, CpResult::Ok);
        rec.namespace = Some(key.namespace.clone());
        rec.service = Some(key.service.clone());
        rec.reason = Some(format!("instance {instance_id}"));
        hub.cp_audit.record(rec).await;
        hub.graph.bump();
        on_hello(hub, &key, &instance_id, &hello, &actor, &tx).await;
        let hub = hub.clone();
        tokio::spawn(async move {
            run_stream(&hub, &key, &instance_id, &actor, inbound).await;
            if let Some(gone) = hub.registry.remove(&key, &instance_id) {
                hub.publish(
                    SseEvent::Registry(RegistryEvent {
                        namespace: key.namespace.clone(),
                        service: key.service.clone(),
                        instance_id: instance_id.clone(),
                        pod: gone.info.pod,
                        status: RegistryStatus::Disconnected,
                    }),
                    scope(&key),
                );
            }
            hub.graph.bump();
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

fn scope(key: &ServiceKey) -> Scope {
    Scope::Service {
        namespace: key.namespace.clone(),
        service: key.service.clone(),
    }
}

/// Send to one instance without holding up the caller: a full outbox is waited on in the
/// background (at most 30 s).
fn send(outbox: &Outbox, msg: ControlMessage) {
    match outbox.try_send(Ok(msg)) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(m)) => {
            let outbox = outbox.clone();
            tokio::spawn(async move {
                let _ = tokio::time::timeout(Duration::from_secs(30), outbox.send(m)).await;
            });
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {}
    }
}

/// The plain charter text a sidecar gets (a custom-resource document is converted).
fn plain_yaml(stored: &crate::store::StoredCharter) -> Option<String> {
    if agentsc_charter::resource::is_resource(&stored.charter_json) {
        agentsc_charter::Charter::from_yaml(&stored.yaml)
            .ok()?
            .to_yaml()
            .ok()
    } else {
        Some(stored.yaml.clone())
    }
}

fn charter_message(stored: &crate::store::StoredCharter) -> Option<ControlMessage> {
    Some(ControlMessage {
        msg: Some(control_message::Msg::Charter(CharterUpdate {
            epoch: stored.epoch.clone(),
            version: stored.version.clone(),
            charter_yaml: plain_yaml(stored)?,
        })),
    })
}

/// The `MemoryUpdate` of a memory document (expired notes left out).
pub fn memory_message(doc: &MemoryDoc) -> ControlMessage {
    let now = Utc::now();
    let agents = doc
        .agents
        .iter()
        .map(|(agent, notes)| {
            let notes = notes
                .iter()
                .filter(|n| {
                    n.expires_at
                        .as_deref()
                        .and_then(crate::traces::parse_ts)
                        .is_none_or(|t| t > now)
                })
                .map(|n| agentsc_proto::Note {
                    id: n.id.clone(),
                    text: n.text.clone(),
                    source: match n.source {
                        NoteSource::Review => "review",
                        NoteSource::Auto => "auto",
                        NoteSource::Manual => "manual",
                    }
                    .into(),
                    request_id: n.request_id.clone().unwrap_or_default(),
                    trace_id: n.trace_id.clone().unwrap_or_default(),
                    approved_by: n.approved_by.clone().unwrap_or_default(),
                    ts: n.ts.clone(),
                    expires_at: n.expires_at.clone().unwrap_or_default(),
                })
                .collect();
            (agent.clone(), NoteList { notes })
        })
        .collect();
    ControlMessage {
        msg: Some(control_message::Msg::Memory(MemoryUpdate {
            version: doc.version.clone(),
            agents,
        })),
    }
}

/// Push the stored charter to every instance of `key`.
pub async fn push_charter(hub: &Hub, key: &ServiceKey) {
    let outboxes = hub.registry.outboxes(key);
    if outboxes.is_empty() {
        return;
    }
    let Ok(stored) = hub.store.get_charter(key).await else {
        return;
    };
    if let Some(msg) = charter_message(&stored) {
        for o in &outboxes {
            send(o, msg.clone());
        }
    }
}

/// Push the stored memory to every instance of `key` (only services with a stored charter).
pub async fn push_memory(hub: &Hub, key: &ServiceKey) {
    let outboxes = hub.registry.outboxes(key);
    if outboxes.is_empty() || hub.store.get_charter(key).await.is_err() {
        return;
    }
    let Ok(doc) = hub.store.get_memory(key).await else {
        return;
    };
    let msg = memory_message(&doc);
    for o in &outboxes {
        send(o, msg.clone());
    }
}

/// The `AgentIds` of `key`'s active agents (CONTRACT.md §5.3); `None` without a SecOps store or
/// when the registry cannot be read now.
pub async fn agent_ids_message(hub: &Hub, key: &ServiceKey) -> Option<ControlMessage> {
    hub.secops()?;
    let ids = crate::secops::registry::active_ids(hub, key).await.ok()?;
    Some(ControlMessage {
        msg: Some(control_message::Msg::AgentIds(AgentIds {
            ids: ids.into_iter().collect(),
        })),
    })
}

/// Push the agents' registry ids to every instance of `key`.
pub async fn push_agent_ids(hub: &Hub, key: &ServiceKey) {
    let outboxes = hub.registry.outboxes(key);
    if outboxes.is_empty() {
        return;
    }
    if let Some(msg) = agent_ids_message(hub, key).await {
        for o in &outboxes {
            send(o, msg.clone());
        }
    }
}

/// Push charter, memory and agent ids to every instance (after missed store events).
pub async fn push_all(hub: &Hub) {
    let keys: std::collections::BTreeSet<ServiceKey> =
        hub.registry.all().into_iter().map(|(k, _)| k).collect();
    for key in keys {
        push_charter(hub, &key).await;
        push_memory(hub, &key).await;
        push_agent_ids(hub, &key).await;
    }
}

/// Check a sidecar's start-up charter for adoption: validator, path, policy, skew (against
/// the instances connected now, this one included).
fn adoptable(hub: &Hub, key: &ServiceKey, yaml: &str) -> Result<write::Candidate, Vec<String>> {
    let cand = write::candidate(key, yaml.to_string()).map_err(|f| f.body.details)?;
    let policy = write::policy_problems(hub.config.load().policy.as_ref(), &cand.charter);
    if !policy.is_empty() {
        return Err(policy);
    }
    let skew = write::skew_problems(&hub.registry, key, &cand.charter);
    if !skew.is_empty() {
        return Err(skew);
    }
    Ok(cand)
}

async fn on_hello(
    hub: &Arc<Hub>,
    key: &ServiceKey,
    instance_id: &str,
    hello: &Hello,
    actor: &Actor,
    tx: &Outbox,
) {
    match hub.store.get_charter(key).await {
        Ok(stored) => {
            if stored.epoch != hello.charter_epoch || stored.version != hello.charter_version {
                if let Some(msg) = charter_message(&stored) {
                    send(tx, msg);
                }
            } else {
                // it runs the stored version already
                hub.registry.update(key, instance_id, |c| {
                    c.info.acked_version = Some(stored.version.clone());
                });
            }
            if let Ok(doc) = hub.store.get_memory(key).await {
                send(tx, memory_message(&doc));
            }
            if let Some(msg) = agent_ids_message(hub, key).await {
                send(tx, msg);
            }
        }
        Err(StoreError::NotFound) => {
            if hello.charter_yaml.is_empty() {
                return;
            }
            let sha = sha256_hex(&hello.charter_yaml);
            match adoptable(hub, key, &hello.charter_yaml) {
                Ok(cand) if hub.opts.auto_adopt => {
                    let writer = Writer {
                        actor: actor.clone(),
                        role: None,
                    };
                    let result = write::write(
                        hub,
                        &writer,
                        key,
                        Precondition::NotExists,
                        None,
                        cand,
                        Via::Adopt,
                        ChangeSource::Adopt,
                    )
                    .await;
                    write::audit_write(
                        hub,
                        CpAction::AdoptApprove,
                        actor,
                        key,
                        None,
                        None,
                        &result,
                    )
                    .await;
                    if let Err(f) = result {
                        tracing::warn!(service = %key, error = %f.reason(), "auto-adopting failed");
                    }
                }
                Ok(_) => {
                    let pending = PendingAdoption {
                        key: key.clone(),
                        sha256: sha.clone(),
                        pod: hello.pod.clone(),
                        ts: now_ts(),
                        yaml: hello.charter_yaml.clone(),
                    };
                    let stored = hub.store.put_pending_adoption(pending).await;
                    let mut rec = CpAudit::entry(
                        CpAction::AdoptPending,
                        actor,
                        if stored.is_ok() {
                            CpResult::Ok
                        } else {
                            CpResult::Error
                        },
                    );
                    rec.namespace = Some(key.namespace.clone());
                    rec.service = Some(key.service.clone());
                    rec.sha256_after = Some(sha);
                    if let Err(e) = stored {
                        rec.reason = Some(e.to_string());
                    }
                    hub.cp_audit.record(rec).await;
                }
                Err(problems) => {
                    let mut rec = CpAudit::entry(CpAction::AdoptPending, actor, CpResult::Invalid);
                    rec.namespace = Some(key.namespace.clone());
                    rec.service = Some(key.service.clone());
                    rec.sha256_after = Some(sha);
                    rec.reason = Some(problems.join("; "));
                    hub.cp_audit.record(rec).await;
                }
            }
        }
        Err(e) => tracing::error!(service = %key, error = %e, "reading the stored charter failed"),
    }
}

async fn run_stream(
    hub: &Arc<Hub>,
    key: &ServiceKey,
    instance_id: &str,
    actor: &Actor,
    mut inbound: Streaming<SidecarMessage>,
) {
    let mut warned = false;
    loop {
        let msg = tokio::select! {
            m = inbound.message() => m,
            () = hub.shutdown.cancelled() => return,
        };
        let msg = match msg {
            Ok(Some(m)) => m,
            Ok(None) => return,
            Err(status) => {
                tracing::debug!(service = %key, instance_id, error = %status, "Connect stream ended");
                return;
            }
        };
        match msg.msg {
            Some(sidecar_message::Msg::Heartbeat(h)) => heartbeat(hub, key, instance_id, h),
            Some(sidecar_message::Msg::Audit(batch)) => ingest_batch(hub, key, batch).await,
            Some(sidecar_message::Msg::Ack(ack)) => on_ack(hub, key, instance_id, ack),
            Some(sidecar_message::Msg::Proposal(p)) => ingest_proposal(hub, key, actor, p).await,
            Some(sidecar_message::Msg::SpanStart(s)) => ingest_span_start(hub, key, s),
            Some(sidecar_message::Msg::Hello(_)) | None => {
                if !warned {
                    tracing::warn!(service = %key, instance_id, "ignoring an unexpected message");
                    warned = true;
                }
            }
        }
    }
}

fn heartbeat(hub: &Hub, key: &ServiceKey, instance_id: &str, h: Heartbeat) {
    let changed = hub.registry.update(key, instance_id, |c| {
        let before = c.info.runtime_ready;
        c.info.last_heartbeat = Some(now_ts());
        c.info.runtime_ready = h.runtime_ready;
        c.info.audit_dropped = h.audit_dropped;
        c.info.cert_expires_in_s = Some(h.cert_expires_in_s);
        before != h.runtime_ready
    });
    if changed == Some(true) {
        hub.graph.bump();
    }
}

fn on_ack(hub: &Hub, key: &ServiceKey, instance_id: &str, ack: ConfigAck) {
    let kind = match ack.kind.as_str() {
        "memory" => AckKind::Memory,
        "charter" | "" => AckKind::Charter,
        other => {
            tracing::debug!(service = %key, kind = other, "ignoring an ack of an unknown kind");
            return;
        }
    };
    let error = (!ack.applied).then(|| {
        if ack.error.is_empty() {
            "not applied".to_string()
        } else {
            ack.error.clone()
        }
    });
    let pod = hub.registry.update(key, instance_id, |c| {
        if kind == AckKind::Charter {
            c.info.acked_version = Some(ack.version.clone());
            c.info.ack_error = error.clone();
        }
        c.info.pod.clone()
    });
    let Some(pod) = pod else { return };
    hub.publish(
        SseEvent::Ack(AckEvent {
            namespace: key.namespace.clone(),
            service: key.service.clone(),
            instance_id: instance_id.to_string(),
            pod,
            kind,
            version: ack.version,
            applied: ack.applied,
            error,
        }),
        scope(key),
    );
    hub.graph.bump();
}

/// Take in a batch of audit records with the drop rules of design §7.
pub async fn ingest_batch(hub: &Hub, key: &ServiceKey, batch: AuditBatch) {
    let agents: HashSet<String> = match hub.store.get_charter(key).await {
        Ok(c) => crate::graph::parse_stored(&c)
            .map(|c| c.agents.into_iter().map(|a| a.name).collect())
            .unwrap_or_default(),
        Err(_) => HashSet::new(),
    };
    // a record of an older sidecar, or one sent before its AgentIds arrived, gets the id here
    let ids = crate::secops::registry::active_ids(hub, key)
        .await
        .unwrap_or_default();
    let mut kept = Vec::new();
    for json in batch.records_json {
        if json.len() > MAX_RECORD_BYTES {
            tracing::debug!(service = %key, bytes = json.len(), "dropping an audit record over 64 KiB");
            continue;
        }
        let Ok(mut rec) = serde_json::from_str::<AuditRecord>(&json) else {
            tracing::debug!(service = %key, "dropping a line that is not an audit record");
            continue;
        };
        rec.service = key.service.clone();
        rec.namespace = key.namespace.clone();
        if rec.agent_id.is_none() {
            rec.agent_id = rec.agent.as_ref().and_then(|a| ids.get(a)).cloned();
        }
        if let Some(agent) = &rec.agent
            && rec.direction != "inbound"
            && !agents.contains(agent)
        {
            tracing::debug!(service = %key, agent, "dropping a record of an agent the stored charter does not have");
            continue;
        }
        kept.push(rec.clone());
        hub.ingest_record(rec);
    }
    crate::secops::ledger::append(hub, &kept).await;
}

/// A span start: the traces and a `span_start` event.
pub fn ingest_span_start(hub: &Hub, key: &ServiceKey, s: SpanStart) {
    let info = StartInfo {
        namespace: key.namespace.clone(),
        service: key.service.clone(),
        request_id: s.request_id,
        trace_id: s.trace_id,
        span_id: s.span_id,
        parent_span_id: non_empty(s.parent_span_id),
        kind: s.kind,
        agent: non_empty(s.agent),
        caller: s.caller,
        caller_agent: non_empty(s.caller_agent),
        callee: s.callee,
        direction: s.direction,
        ts: if s.ts.is_empty() { now_ts() } else { s.ts },
    };
    let call_index = hub.traces.add_start(info.clone());
    hub.publish(
        SseEvent::SpanStart(SpanStartEvent {
            agent_node: info.agent_node(),
            callee_node: info.callee_node(),
            namespace: info.namespace,
            service: info.service,
            request_id: info.request_id,
            trace_id: info.trace_id,
            span_id: info.span_id,
            parent_span_id: info.parent_span_id,
            kind: info.kind,
            agent: info.agent,
            caller: info.caller,
            caller_agent: info.caller_agent,
            callee: info.callee,
            ts: info.ts,
            call_index,
        }),
        scope(key),
    );
}

/// A lesson an agent proposed (design §7).
pub async fn ingest_proposal(hub: &Hub, key: &ServiceKey, actor: &Actor, p: LearningProposal) {
    let Ok(stored) = hub.store.get_charter(key).await else {
        tracing::debug!(service = %key, "dropping a proposal: no stored charter");
        return;
    };
    let Some(spec) = crate::graph::parse_stored(&stored)
        .and_then(|c| c.agent(&p.agent).cloned())
        .filter(|a| a.learning_enabled())
    else {
        tracing::debug!(service = %key, agent = p.agent, "dropping a proposal: learning is not enabled");
        return;
    };
    let learning = spec.learning_or_default();
    let limits = AgentLearning::from_charter(&stored.charter_json, &p.agent);
    if p.note.trim().is_empty() || limits.is_some_and(|l| p.note.chars().count() > l.max_note_chars)
    {
        tracing::debug!(service = %key, agent = p.agent, "dropping a proposal: empty or too long");
        return;
    }
    let mut auto = p.auto && learning.mode == agentsc_charter::LearningMode::Auto;
    let ts = now_ts();
    if auto {
        // room for the note: at max_notes the oldest auto note goes; without one it waits
        let memory = hub.store.get_memory(key).await.unwrap_or(MemoryDoc {
            version: "0".into(),
            agents: BTreeMap::new(),
        });
        let notes = memory.agents.get(&p.agent).cloned().unwrap_or_default();
        let max = usize::try_from(learning.max_notes).unwrap_or(usize::MAX);
        if notes.len() >= max && !notes.iter().any(|n| n.source == NoteSource::Auto) {
            auto = false;
        }
    }
    let proposal = Proposal {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: key.namespace.clone(),
        service: key.service.clone(),
        agent: p.agent.clone(),
        note: p.note.clone(),
        rationale: p.rationale.clone(),
        request_id: p.request_id.clone(),
        trace_id: p.trace_id.clone(),
        ts: ts.clone(),
        status: if auto {
            ProposalStatus::Approved
        } else {
            ProposalStatus::Pending
        },
        auto,
    };
    let dedup = if p.dedup_key.is_empty() {
        proposal.id.clone()
    } else {
        p.dedup_key.clone()
    };
    match hub.store.put_proposal(&proposal, Some(&dedup)).await {
        Ok(ProposalPut::Stored) => {}
        Ok(ProposalPut::Duplicate { .. }) => return,
        Err(e) => {
            tracing::warn!(service = %key, error = %e, "storing a proposal failed");
            return;
        }
    }
    if !auto {
        return;
    }
    let expires = Utc::now() + chrono::Duration::days(i64::from(learning.note_ttl_days));
    let note = Note {
        id: uuid::Uuid::new_v4().to_string(),
        text: p.note.clone(),
        source: NoteSource::Auto,
        request_id: non_empty(p.request_id.clone()),
        trace_id: non_empty(p.trace_id.clone()),
        approved_by: None,
        ts: ts.clone(),
        expires_at: Some(crate::traces::fmt_ts(expires)),
    };
    let max = usize::try_from(learning.max_notes).unwrap_or(usize::MAX);
    let mut result = Err(StoreError::Io("not tried".into()));
    for _ in 0..5 {
        let Ok(memory) = hub.store.get_memory(key).await else {
            break;
        };
        let mut agents = memory.agents.clone();
        let list = agents.entry(p.agent.clone()).or_default();
        while list.len() >= max {
            match list.iter().position(|n| n.source == NoteSource::Auto) {
                Some(i) => {
                    list.remove(i);
                }
                None => break,
            }
        }
        list.push(note.clone());
        result = hub
            .store
            .put_memory(key, &memory.version, agents, actor)
            .await;
        if !matches!(result, Err(StoreError::Conflict { .. })) {
            break;
        }
    }
    let mut rec = CpAudit::entry(
        CpAction::NoteAuto,
        actor,
        if result.is_ok() {
            CpResult::Ok
        } else {
            CpResult::Error
        },
    );
    rec.namespace = Some(key.namespace.clone());
    rec.service = Some(key.service.clone());
    rec.agent = Some(p.agent.clone());
    match &result {
        Ok(m) => rec.to_version = Some(m.version.clone()),
        Err(e) => rec.reason = Some(e.to_string()),
    }
    hub.cp_audit.record(rec).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_updates_carry_every_field_and_skip_expired_notes() {
        let doc = MemoryDoc {
            version: "3".into(),
            agents: BTreeMap::from([(
                "a".to_string(),
                vec![
                    Note {
                        id: "n1".into(),
                        text: "t".into(),
                        source: NoteSource::Review,
                        request_id: Some("q".into()),
                        trace_id: None,
                        approved_by: Some("bob".into()),
                        ts: "2026-10-21T10:00:00.000Z".into(),
                        expires_at: None,
                    },
                    Note {
                        id: "n2".into(),
                        text: "old".into(),
                        source: NoteSource::Auto,
                        request_id: None,
                        trace_id: None,
                        approved_by: None,
                        ts: "2020-01-01T00:00:00.000Z".into(),
                        expires_at: Some("2020-01-08T00:00:00.000Z".into()),
                    },
                ],
            )]),
        };
        let Some(control_message::Msg::Memory(m)) = memory_message(&doc).msg else {
            panic!("not a memory update")
        };
        assert_eq!(m.version, "3");
        let notes = &m.agents["a"].notes;
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].source, "review");
        assert_eq!(notes[0].approved_by, "bob");
        assert_eq!(notes[0].trace_id, "");
    }

    #[test]
    fn sidecar_actors_name_identity_and_pod() {
        let id = SpiffeId::new("agentsc", "shop", "orders");
        let a = sidecar_actor(&id, "orders-0");
        assert_eq!(
            a.name,
            "sidecar:spiffe://agentsc/ns/shop/svc/orders/orders-0"
        );
        assert_eq!(a.kind, ActorKind::Sidecar);
        assert!(a.role.is_none());
    }
}
