//! The state the `controlplane`, `api` and `ui` components share (design §8, §10): the store,
//! the config, the control-plane audit, the live events, the audit ring, the graph stats, the
//! traces and the connected instances — and the tasks that keep them in step.
//!
//! Store changes reach everything from one place ([`Hub::start`]'s store pump): SSE `config`,
//! `proposal` and store-produced `cp_audit` events, the declared edges of the graph, and the
//! charter and memory pushes to the connected instances of the service.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::Utc;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::api::types::{
    AuditEvent, AuditRecord, ConfigEvent, CpAuditRecord, GraphEvent, NoteSource, SseEvent,
};
use crate::auth::{Auth, Identity};
use crate::config::ControlPlaneConfig;
use crate::cp_audit::CpAudit;
use crate::events::{AuditRing, EventHub, Scope};
use crate::graph::GraphState;
use crate::registry::Registry;
use crate::store::{Actor, ActorKind, ServiceKey, Store, StoreError, StoreEvent};
use crate::traces::TraceStore;

/// At most one `graph` event per this interval (design §10.2).
pub const GRAPH_EVENT_INTERVAL: Duration = Duration::from_secs(2);
/// How often expired `auto` notes are removed.
pub const EXPIRY_INTERVAL: Duration = Duration::from_secs(60);

/// Flags of `embassy serve` the shared state needs.
#[derive(Debug, Clone)]
pub struct HubOptions {
    /// `--dns-name`: allowed Host headers besides the loopback names.
    pub dns_names: Vec<String>,
    /// `--auto-adopt`.
    pub auto_adopt: bool,
    /// The SSE keep-alive comment interval (design §10.2: 15 s).
    pub keepalive: Duration,
    /// `--trust-domain`: the only trust domain `Connect` accepts sidecar identities in, and the
    /// one the API writes peer identities in.
    pub trust_domain: String,
    /// `--api-rate-limit` / `--api-burst` (ratelimit.rs).
    pub api_rate_limit: crate::ratelimit::RateLimit,
    /// `--ledger-seal-after`: how long a ledger chain has no new entry before it is sealed.
    pub ledger_seal_after: Duration,
}

impl Default for HubOptions {
    fn default() -> Self {
        Self {
            dns_names: Vec::new(),
            auto_adopt: false,
            keepalive: crate::api::KEEPALIVE,
            trust_domain: agentsc_common::identity::DEFAULT_TRUST_DOMAIN.into(),
            api_rate_limit: crate::ratelimit::API_DEFAULT,
            ledger_seal_after: crate::secops::ledger::DEFAULT_SEAL_AFTER,
        }
    }
}

/// Readiness per component (`GET /readyz`).
#[derive(Debug, Default)]
pub struct Readiness {
    flags: Mutex<BTreeMap<String, bool>>,
}

impl Readiness {
    pub fn set(&self, component: &str, ready: bool) {
        self.flags
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(component.to_string(), ready);
    }

    /// Every component and whether it is ready.
    pub fn snapshot(&self) -> BTreeMap<String, bool> {
        self.flags.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

/// See the module docs.
pub struct Hub {
    pub store: Arc<dyn Store>,
    /// The AgentSecOps data (crate::secops), set once at start; unset without a SQL store.
    pub secops: std::sync::OnceLock<Arc<dyn crate::secops::SecOpsStore>>,
    /// The evidence ledger's keys (crate::secops::ledger), set once at start.
    pub ledger: std::sync::OnceLock<Arc<crate::secops::ledger::LedgerKeys>>,
    /// Audit records the ledger did not take (a store error).
    pub ledger_failures: std::sync::atomic::AtomicU64,
    pub config: Arc<ArcSwap<ControlPlaneConfig>>,
    pub cp_audit: Arc<CpAudit>,
    pub auth: Auth,
    pub events: EventHub,
    pub ring: AuditRing,
    pub graph: GraphState,
    pub traces: TraceStore,
    pub registry: Registry,
    pub opts: HubOptions,
    pub ready: Readiness,
    /// The REST API's rate limit, one bucket per client (ratelimit.rs).
    pub api_limiter: crate::ratelimit::RateLimiter,
    /// Cancelled on shutdown: live streams end.
    pub shutdown: CancellationToken,
}

impl std::fmt::Debug for Hub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hub")
            .field("opts", &self.opts)
            .finish_non_exhaustive()
    }
}

/// The store of a process that serves only the console (`--components ui` without `--store`):
/// nothing is stored and nothing can be written. The API is not mounted in such a process.
#[derive(Debug)]
pub struct NoStore {
    tx: broadcast::Sender<StoreEvent>,
}

impl Default for NoStore {
    fn default() -> Self {
        Self {
            tx: broadcast::channel(1).0,
        }
    }
}

#[async_trait::async_trait]
impl Store for NoStore {
    async fn list_services(&self) -> Result<Vec<ServiceKey>, StoreError> {
        Ok(Vec::new())
    }
    async fn get_charter(&self, _: &ServiceKey) -> Result<crate::store::StoredCharter, StoreError> {
        Err(StoreError::NotFound)
    }
    async fn put_charter(
        &self,
        _: &ServiceKey,
        _: &crate::store::Precondition,
        _: crate::store::CharterWrite,
    ) -> Result<crate::store::StoredCharter, StoreError> {
        Err(StoreError::Io("this process has no store".into()))
    }
    async fn history(&self, _: &ServiceKey) -> Result<Vec<crate::store::HistoryEntry>, StoreError> {
        Err(StoreError::NotFound)
    }
    async fn get_revision(&self, _: &ServiceKey, _: &str) -> Result<String, StoreError> {
        Err(StoreError::NotFound)
    }
    async fn delete_service(&self, _: &ServiceKey, _: &str, _: &Actor) -> Result<(), StoreError> {
        Err(StoreError::NotFound)
    }
    async fn get_memory(&self, _: &ServiceKey) -> Result<crate::store::MemoryDoc, StoreError> {
        Ok(crate::store::MemoryDoc {
            version: "0".into(),
            agents: BTreeMap::new(),
        })
    }
    async fn put_memory(
        &self,
        _: &ServiceKey,
        _: &str,
        _: BTreeMap<String, Vec<crate::store::Note>>,
        _: &Actor,
    ) -> Result<crate::store::MemoryDoc, StoreError> {
        Err(StoreError::Io("this process has no store".into()))
    }
    async fn list_proposals(
        &self,
        _: &crate::store::ProposalFilter,
    ) -> Result<Vec<crate::store::Proposal>, StoreError> {
        Ok(Vec::new())
    }
    async fn get_proposal(&self, _: &str) -> Result<crate::store::Proposal, StoreError> {
        Err(StoreError::NotFound)
    }
    async fn put_proposal(
        &self,
        _: &crate::store::Proposal,
        _: Option<&str>,
    ) -> Result<crate::store::ProposalPut, StoreError> {
        Err(StoreError::Io("this process has no store".into()))
    }
    async fn approve_proposal(
        &self,
        _: &ServiceKey,
        _: &str,
        _: &str,
        _: &Actor,
    ) -> Result<(crate::store::MemoryDoc, crate::store::Proposal), StoreError> {
        Err(StoreError::NotFound)
    }
    async fn reject_proposal(
        &self,
        _: &ServiceKey,
        _: &str,
        _: &str,
        _: &Actor,
    ) -> Result<(crate::store::MemoryDoc, crate::store::Proposal), StoreError> {
        Err(StoreError::NotFound)
    }
    async fn list_pending_adoptions(
        &self,
    ) -> Result<Vec<crate::store::PendingAdoption>, StoreError> {
        Ok(Vec::new())
    }
    async fn put_pending_adoption(
        &self,
        _: crate::store::PendingAdoption,
    ) -> Result<(), StoreError> {
        Err(StoreError::Io("this process has no store".into()))
    }
    async fn take_pending_adoption(
        &self,
        _: &ServiceKey,
        _: &str,
    ) -> Result<crate::store::PendingAdoption, StoreError> {
        Err(StoreError::NotFound)
    }
    // nothing is kept: say so (CpAudit logs and counts it) instead of pretending
    async fn append_cp_audit(&self, _: &crate::cp_audit::CpAuditRecord) -> Result<(), StoreError> {
        Err(StoreError::Io("this process has no store".into()))
    }
    async fn cp_audit(&self, _: usize) -> Result<Vec<crate::cp_audit::CpAuditRecord>, StoreError> {
        Ok(Vec::new())
    }
    fn subscribe(&self) -> broadcast::Receiver<StoreEvent> {
        self.tx.subscribe()
    }
}

/// The actor of what the control plane does by itself.
pub fn system_actor() -> Actor {
    Actor {
        name: "system".into(),
        kind: ActorKind::System,
        role: None,
    }
}

impl Hub {
    pub fn new(
        store: Arc<dyn Store>,
        config: Arc<ArcSwap<ControlPlaneConfig>>,
        cp_audit: Arc<CpAudit>,
        auth: Auth,
        opts: HubOptions,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            secops: std::sync::OnceLock::new(),
            ledger: std::sync::OnceLock::new(),
            ledger_failures: std::sync::atomic::AtomicU64::new(0),
            config,
            cp_audit,
            auth,
            events: EventHub::default(),
            ring: AuditRing::default(),
            graph: GraphState::default(),
            traces: TraceStore::default(),
            registry: Registry::default(),
            api_limiter: crate::ratelimit::RateLimiter::new(opts.api_rate_limit),
            opts,
            ready: Readiness::default(),
            shutdown,
        })
    }

    /// The AgentSecOps store, when this embassy keeps one (crate::secops).
    pub fn secops(&self) -> Option<&Arc<dyn crate::secops::SecOpsStore>> {
        self.secops.get()
    }

    /// Publish a live event.
    pub fn publish(&self, event: SseEvent, scope: Scope) -> u64 {
        self.events.publish(event, scope)
    }

    /// Whether `ident` may see namespace `ns`.
    pub fn allows(ident: &Identity) -> impl Fn(&str) -> bool + Send + Sync + '_ {
        move |ns: &str| ident.allows_namespace(ns)
    }

    /// Take in one audit record a sidecar sent (after the drop rules): graph stats, the ring,
    /// the traces, and the `audit` event.
    pub fn ingest_record(&self, rec: AuditRecord) {
        let size = serde_json::to_vec(&rec).map(|v| v.len()).unwrap_or(0);
        let obs = self.graph.observe(&rec, Utc::now());
        let scope = Scope::Service {
            namespace: rec.namespace.clone(),
            service: rec.service.clone(),
        };
        let rec = Arc::new(rec);
        let retain = self.config.load().events.retain_bytes;
        let evicted = self.ring.push(rec.clone(), size, retain);
        self.traces.add_record(rec.clone());
        self.traces.forget(&evicted);
        self.events.publish_sized(
            SseEvent::Audit(Box::new(AuditEvent {
                record: (*rec).clone(),
                animate: obs.edge_id.is_some(),
                edge_id: obs.edge_id,
            })),
            scope,
            size,
        );
    }

    /// Recompute the declared edges from the stored charters.
    pub async fn refresh_declared(&self) {
        let declared = crate::graph::all_declared(self.store.as_ref()).await;
        self.graph.set_declared(declared);
    }

    /// Start the tasks that keep the shared state in step; they stop on `shutdown`.
    pub fn start(self: &Arc<Self>, shutdown: CancellationToken) -> Vec<JoinHandle<()>> {
        let rx = self.store.subscribe();
        let cp_rx = self.cp_audit.subscribe();
        vec![
            tokio::spawn(store_pump(self.clone(), rx, shutdown.clone())),
            tokio::spawn(cp_audit_pump(self.clone(), cp_rx, shutdown.clone())),
            tokio::spawn(graph_events(self.clone(), shutdown.clone())),
            tokio::spawn(minute_ticks(self.clone(), shutdown.clone())),
            tokio::spawn(expire_notes(self.clone(), shutdown.clone())),
            tokio::spawn(crate::secops::approvals::expirer(
                self.clone(),
                shutdown.clone(),
            )),
            tokio::spawn(crate::secops::risk::scorer(
                self.clone(),
                self.opts.ledger_seal_after,
                shutdown.clone(),
            )),
            tokio::spawn(crate::secops::ledger::purger(
                self.clone(),
                shutdown.clone(),
            )),
            tokio::spawn(crate::secops::ledger::sealer(
                self.clone(),
                self.opts.ledger_seal_after,
                shutdown,
            )),
        ]
    }
}

fn cp_scope(rec: &CpAuditRecord) -> Scope {
    Scope::Admin {
        namespace: rec.namespace.clone(),
        service: rec.service.clone(),
    }
}

async fn on_store_event(hub: &Arc<Hub>, ev: StoreEvent) {
    match ev {
        StoreEvent::CharterChanged {
            key,
            version,
            actor,
            source,
            ..
        } => {
            hub.publish(
                SseEvent::Config(ConfigEvent {
                    namespace: key.namespace.clone(),
                    service: key.service.clone(),
                    version,
                    actor: actor.name.clone(),
                    source,
                }),
                Scope::Service {
                    namespace: key.namespace.clone(),
                    service: key.service.clone(),
                },
            );
            hub.refresh_declared().await;
            hub.graph.bump();
            crate::controlplane::push_charter(hub, &key).await;
            crate::secops::registry::sync_service(hub, &key, &actor).await;
        }
        StoreEvent::ServiceDeleted { key, actor } => {
            hub.refresh_declared().await;
            hub.graph.bump();
            crate::secops::registry::sync_service(hub, &key, &actor).await;
        }
        StoreEvent::MemoryChanged { key, .. } => {
            hub.graph.bump();
            crate::controlplane::push_memory(hub, &key).await;
        }
        StoreEvent::ProposalChanged { key, id } => {
            if let Ok(p) = hub.store.get_proposal(&id).await {
                hub.publish(
                    SseEvent::Proposal(p),
                    Scope::Service {
                        namespace: key.namespace,
                        service: key.service,
                    },
                );
            }
            hub.graph.bump();
        }
        StoreEvent::AdoptionPending { .. } => {
            hub.graph.bump();
        }
        StoreEvent::AgentsChanged { key } => {
            crate::controlplane::push_agents(hub, &key).await;
        }
        StoreEvent::ApprovalDecided { key, id } => {
            crate::secops::approvals::push_decision_of(hub, &key, &id).await;
        }
        StoreEvent::CpAudit(rec) => {
            let scope = cp_scope(&rec);
            hub.publish(SseEvent::CpAudit(*rec), scope);
        }
    }
}

async fn store_pump(
    hub: Arc<Hub>,
    mut rx: broadcast::Receiver<StoreEvent>,
    shutdown: CancellationToken,
) {
    hub.refresh_declared().await;
    // what changed while this embassy was down; events from now on are in `rx` already
    crate::secops::registry::reconcile_all(&hub).await;
    loop {
        let ev = tokio::select! {
            r = rx.recv() => r,
            () = shutdown.cancelled() => return,
        };
        match ev {
            Ok(ev) => on_store_event(&hub, ev).await,
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!(missed = n, "store events lagged; resyncing");
                hub.refresh_declared().await;
                hub.graph.bump();
                crate::secops::registry::reconcile_all(&hub).await;
                crate::controlplane::push_all(&hub).await;
            }
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}

async fn cp_audit_pump(
    hub: Arc<Hub>,
    mut rx: broadcast::Receiver<Arc<CpAuditRecord>>,
    shutdown: CancellationToken,
) {
    loop {
        let rec = tokio::select! {
            r = rx.recv() => r,
            () = shutdown.cancelled() => return,
        };
        match rec {
            Ok(rec) => {
                let scope = cp_scope(&rec);
                hub.publish(SseEvent::CpAudit((*rec).clone()), scope);
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!(missed = n, "control-plane audit events lagged");
            }
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}

/// `graph` events: one when the version changed, at most one per [`GRAPH_EVENT_INTERVAL`].
async fn graph_events(hub: Arc<Hub>, shutdown: CancellationToken) {
    let mut last = hub.graph.version();
    loop {
        tokio::select! {
            () = hub.graph.changed.notified() => {}
            () = shutdown.cancelled() => return,
        }
        loop {
            let v = hub.graph.version();
            if v == last {
                break;
            }
            hub.publish(
                SseEvent::Graph(GraphEvent {
                    version: v.to_string(),
                }),
                Scope::All,
            );
            last = v;
            tokio::select! {
                () = tokio::time::sleep(GRAPH_EVENT_INTERVAL) => {}
                () = shutdown.cancelled() => return,
            }
        }
    }
}

/// Stats leave the window minute by minute: a new graph version when they do.
async fn minute_ticks(hub: Arc<Hub>, shutdown: CancellationToken) {
    let mut every = tokio::time::interval(Duration::from_secs(60));
    every.tick().await;
    loop {
        tokio::select! {
            _ = every.tick() => { hub.graph.tick(Utc::now()); }
            () = shutdown.cancelled() => return,
        }
    }
}

/// Remove `auto` notes whose `expires_at` passed (design §15 rule 7).
pub async fn expire_once(hub: &Hub) -> Result<usize, StoreError> {
    let now = Utc::now();
    let mut removed = 0;
    for key in hub.store.list_services().await? {
        let memory = hub.store.get_memory(&key).await?;
        let expired = |n: &crate::store::Note| {
            n.source == NoteSource::Auto
                && n.expires_at
                    .as_deref()
                    .and_then(crate::traces::parse_ts)
                    .is_some_and(|t| t <= now)
        };
        let count: usize = memory
            .agents
            .values()
            .map(|notes| notes.iter().filter(|n| expired(n)).count())
            .sum();
        if count == 0 {
            continue;
        }
        let agents = memory
            .agents
            .iter()
            .map(|(a, notes)| {
                (
                    a.clone(),
                    notes.iter().filter(|n| !expired(n)).cloned().collect(),
                )
            })
            .collect();
        match hub
            .store
            .put_memory(&key, &memory.version, agents, &system_actor())
            .await
        {
            Ok(_) => removed += count,
            // a concurrent write: the next sweep looks again
            Err(StoreError::Conflict { .. }) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(removed)
}

async fn expire_notes(hub: Arc<Hub>, shutdown: CancellationToken) {
    let mut every = tokio::time::interval(EXPIRY_INTERVAL);
    loop {
        tokio::select! {
            _ = every.tick() => {
                if let Err(e) = expire_once(&hub).await {
                    tracing::warn!(error = %e, "removing expired notes failed");
                }
            }
            () = shutdown.cancelled() => return,
        }
    }
}
