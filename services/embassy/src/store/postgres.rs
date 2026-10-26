//! The `postgres` store (docs/design/agentsecops-merge.md §7): everything the SQLite store keeps,
//! in PostgreSQL, for one or many embassy replicas.
//!
//! **Schema.** Numbered migrations ([`MIGRATIONS`]; 1 is `postgres_schema_v1.sql`: the SQLite
//! tables in PostgreSQL types with the same invariants as triggers, plus `pending_adoptions`).
//! [`PgStore::open`] applies the missing ones, each in its own transaction, under an advisory lock
//! (per schema), so replicas that start together apply each once. The applied ones are in
//! `agentsc_schema_migrations`. A database a newer embassy migrated is refused.
//!
//! **Many replicas.** Every write is one transaction that locks its service's row first
//! (`SELECT ... FOR UPDATE`) and then checks its precondition, so two replicas writing one
//! service serialize and the loser gets the usual conflict. A write `NOTIFY`s [`CHANNEL`] in its
//! transaction (delivered on commit) with the event, the writing replica's id and the schema.
//! Each replica `LISTEN`s on a connection of its own and turns the other replicas' notifications
//! into store events. A listen connection that breaks is opened again, and the replica then
//! emits every live service's charter and memory again ([`PgStore::resync`]), so what it missed
//! meanwhile is not lost.
//!
//! **Connection.** A `postgres://` connection string (from a file or the environment, never
//! argv: it holds a password). `sslmode=require` (or `prefer`) speaks TLS through rustls,
//! verifying the server against the system roots or, with a CA file, only that file's.
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use deadpool_postgres::{GenericClient, Manager, ManagerConfig, Pool, RecyclingMethod};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::broadcast;
use tokio_postgres::tls::{ChannelBinding, MakeTlsConnect, TlsConnect, TlsStream};
use tokio_postgres::{AsyncMessage, Row};

use super::{
    Actor, ActorKind, ChangeSource, CharterWrite, HistoryEntry, LearningState, MemoryDoc, Note,
    NoteSource, PendingAdoption, Precondition, Proposal, ProposalFilter, ProposalPut,
    ProposalStatus, ProposalVerdict, ServiceKey, Store, StoreError, StoreEvent, StoredCharter,
    decide_proposal, prune_memory,
};
use crate::api::types::CpAuditRecord;
use crate::config::Role;
use crate::names::is_dns_label;

/// The migrations, in order: `(version, SQL)`.
pub const MIGRATIONS: &[(i64, &str)] = &[(1, include_str!("postgres_schema_v1.sql"))];
/// The channel of the store's notifications.
pub const CHANNEL: &str = "agentsc_store";
/// Store events a slow subscriber may fall behind before it loses some.
pub const EVENTS_CAPACITY: usize = 1024;
/// The default number of connections per replica.
pub const DEFAULT_POOL_SIZE: usize = 8;
/// A notification's payload is at most 8000 bytes; a larger event is sent as a resync.
const MAX_PAYLOAD: usize = 7900;

/// How to reach the database.
#[derive(Clone)]
pub struct PgOptions {
    /// `postgres://user:password@host:5432/db?sslmode=require` (never logged).
    pub url: String,
    /// The CA certificates (PEM) the server's must chain to, instead of the system roots.
    pub ca_file: Option<PathBuf>,
    pub pool_size: usize,
    /// `application_name` of the connections (`pg_stat_activity`).
    pub application_name: String,
}

impl std::fmt::Debug for PgOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgOptions")
            .field("url", &"<redacted>")
            .field("ca_file", &self.ca_file)
            .field("pool_size", &self.pool_size)
            .finish()
    }
}

fn pg_err(e: impl std::fmt::Display) -> StoreError {
    StoreError::Io(format!("postgres: {e}"))
}

impl From<tokio_postgres::Error> for StoreError {
    fn from(e: tokio_postgres::Error) -> Self {
        pg_err(e)
    }
}

fn checked_key(key: &ServiceKey) -> Result<(), StoreError> {
    if is_dns_label(&key.namespace) && is_dns_label(&key.service) {
        Ok(())
    } else {
        Err(StoreError::NotFound)
    }
}

fn now_ts() -> String {
    crate::cp_audit::now_ts()
}

fn parse_version(v: &str) -> Result<u64, StoreError> {
    v.parse::<u64>()
        .map_err(|_| StoreError::Io(format!("version {v:?} is not a decimal u64")))
}

fn next_version(v: u64) -> Result<u64, StoreError> {
    v.checked_add(1)
        .ok_or_else(|| StoreError::Io(format!("version {v} is u64::MAX")))
}

fn db_int(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Io(format!("version {v} is beyond bigint")))
}

fn unsigned(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn enum_text<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn kind_str(k: ActorKind) -> &'static str {
    match k {
        ActorKind::Session => "session",
        ActorKind::Token => "token",
        ActorKind::Sidecar => "sidecar",
        ActorKind::K8s => "k8s",
        ActorKind::System => "system",
    }
}

fn source_str(s: ChangeSource) -> &'static str {
    match s {
        ChangeSource::Api => "api",
        ChangeSource::Kubernetes => "kubernetes",
        ChangeSource::Adopt => "adopt",
        ChangeSource::Rollback => "rollback",
        ChangeSource::File => "file",
    }
}

fn note_source_str(s: NoteSource) -> &'static str {
    match s {
        NoteSource::Review => "review",
        NoteSource::Auto => "auto",
        NoteSource::Manual => "manual",
    }
}

fn note_source_of(s: &str) -> NoteSource {
    match s {
        "review" => NoteSource::Review,
        "auto" => NoteSource::Auto,
        _ => NoteSource::Manual,
    }
}

fn status_str(s: ProposalStatus) -> &'static str {
    match s {
        ProposalStatus::Pending => "pending",
        ProposalStatus::Approved => "approved",
        ProposalStatus::Rejected => "rejected",
    }
}

fn status_of(s: &str) -> ProposalStatus {
    match s {
        "approved" => ProposalStatus::Approved,
        "rejected" => ProposalStatus::Rejected,
        _ => ProposalStatus::Pending,
    }
}

// ---- TLS ------------------------------------------------------------------------------------

/// `sslmode=require`/`prefer` through rustls: the server is verified against `roots`.
#[derive(Clone)]
pub struct MakeRustls {
    config: Arc<rustls::ClientConfig>,
}

impl MakeRustls {
    /// The system roots, or only `ca_file`'s certificates when given.
    pub fn new(ca_file: Option<&std::path::Path>) -> Result<Self, StoreError> {
        let mut roots = rustls::RootCertStore::empty();
        match ca_file {
            Some(path) => {
                let pem = std::fs::read_to_string(path)
                    .map_err(|e| StoreError::Io(format!("{}: {e}", path.display())))?;
                let certs = agentsc_pki::certs_from_pem(&pem)
                    .map_err(|e| StoreError::Io(format!("{}: {e}", path.display())))?;
                for c in certs {
                    roots
                        .add(c)
                        .map_err(|e| StoreError::Io(format!("{}: {e}", path.display())))?;
                }
            }
            None => {
                for c in rustls_native_certs::load_native_certs().certs {
                    let _ = roots.add(c);
                }
            }
        }
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(pg_err)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(Self {
            config: Arc::new(config),
        })
    }
}

impl<S> MakeTlsConnect<S> for MakeRustls
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = RustlsStream<S>;
    type TlsConnect = RustlsConnect;
    type Error = rustls::pki_types::InvalidDnsNameError;

    fn make_tls_connect(&mut self, domain: &str) -> Result<RustlsConnect, Self::Error> {
        Ok(RustlsConnect {
            config: self.config.clone(),
            name: rustls::pki_types::ServerName::try_from(domain.to_string())?,
        })
    }
}

pub struct RustlsConnect {
    config: Arc<rustls::ClientConfig>,
    name: rustls::pki_types::ServerName<'static>,
}

impl<S> TlsConnect<S> for RustlsConnect
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = RustlsStream<S>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = std::io::Result<RustlsStream<S>>> + Send>>;

    fn connect(self, stream: S) -> Self::Future {
        Box::pin(async move {
            let tls = tokio_rustls::TlsConnector::from(self.config)
                .connect(self.name, stream)
                .await?;
            Ok(RustlsStream(tls))
        })
    }
}

pub struct RustlsStream<S>(tokio_rustls::client::TlsStream<S>);

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for RustlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RustlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> TlsStream for RustlsStream<S> {
    fn channel_binding(&self) -> ChannelBinding {
        ChannelBinding::none()
    }
}

// ---- migrations -----------------------------------------------------------------------------

/// Apply the missing [`MIGRATIONS`] under the schema's advisory lock; the version now.
pub async fn migrate(client: &mut tokio_postgres::Client) -> Result<i64, StoreError> {
    client
        .execute(
            "SELECT pg_advisory_lock(hashtext('agentsc-embassy:' || current_schema()))",
            &[],
        )
        .await?;
    let result = apply_migrations(client).await;
    let unlock = client
        .execute(
            "SELECT pg_advisory_unlock(hashtext('agentsc-embassy:' || current_schema()))",
            &[],
        )
        .await;
    let version = result?;
    unlock?;
    Ok(version)
}

async fn apply_migrations(client: &mut tokio_postgres::Client) -> Result<i64, StoreError> {
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS agentsc_schema_migrations (\
               version bigint PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())",
        )
        .await?;
    let current: i64 = client
        .query_one(
            "SELECT COALESCE(max(version), 0) FROM agentsc_schema_migrations",
            &[],
        )
        .await?
        .get(0);
    let known = MIGRATIONS.last().map_or(0, |(v, _)| *v);
    if current > known {
        return Err(StoreError::Io(format!(
            "the database is at schema version {current}, written by a newer embassy (this one knows {known})"
        )));
    }
    for (version, sql) in MIGRATIONS.iter().filter(|(v, _)| *v > current) {
        let tx = client.transaction().await?;
        tx.batch_execute(sql)
            .await
            .map_err(|e| StoreError::Io(format!("postgres: migration {version}: {e}")))?;
        tx.execute(
            "INSERT INTO agentsc_schema_migrations (version) VALUES ($1)",
            &[version],
        )
        .await?;
        tx.commit().await?;
        tracing::info!(version, "postgres store: migration applied");
    }
    Ok(known)
}

// ---- rows -----------------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ServiceRow {
    id: i64,
    epoch: Option<String>,
    version: u64,
    memory_version: u64,
}

impl ServiceRow {
    fn has_charter(&self) -> bool {
        self.epoch.is_some()
    }

    fn from_row(r: &Row) -> Self {
        Self {
            id: r.get(0),
            epoch: r.get(1),
            version: unsigned(r.get(2)),
            memory_version: unsigned(r.get(3)),
        }
    }
}

/// The row of `key`; `lock`: hold it for the transaction (`FOR UPDATE`).
async fn find_service<C: GenericClient + Sync>(
    c: &C,
    key: &ServiceKey,
    lock: bool,
) -> Result<Option<ServiceRow>, StoreError> {
    let sql = if lock {
        "SELECT id, epoch, version, memory_version FROM services \
         WHERE namespace = $1 AND service = $2 FOR UPDATE"
    } else {
        "SELECT id, epoch, version, memory_version FROM services \
         WHERE namespace = $1 AND service = $2"
    };
    Ok(c.query_opt(sql, &[&key.namespace, &key.service])
        .await?
        .map(|r| ServiceRow::from_row(&r)))
}

/// The row of `key`, created (without a charter) when there is none, locked.
async fn ensure_service<C: GenericClient + Sync>(
    c: &C,
    key: &ServiceKey,
) -> Result<ServiceRow, StoreError> {
    c.execute(
        "INSERT INTO services (namespace, service) VALUES ($1, $2) \
         ON CONFLICT (namespace, service) DO NOTHING",
        &[&key.namespace, &key.service],
    )
    .await?;
    find_service(c, key, true)
        .await?
        .ok_or_else(|| StoreError::Io("the service row vanished".into()))
}

async fn current_charter<C: GenericClient + Sync>(
    c: &C,
    row: &ServiceRow,
) -> Result<Option<(String, Value)>, StoreError> {
    if !row.has_charter() {
        return Ok(None);
    }
    let found = c
        .query_opt(
            "SELECT yaml, json::text FROM charter_versions WHERE service_id = $1 AND version = $2",
            &[&row.id, &db_int(row.version)?],
        )
        .await?;
    match found {
        None => Ok(None),
        Some(r) => {
            let json: Value = serde_json::from_str(r.get::<_, &str>(1)).map_err(pg_err)?;
            Ok(Some((r.get(0), json)))
        }
    }
}

async fn memory_of<C: GenericClient + Sync>(
    c: &C,
    row: &ServiceRow,
) -> Result<MemoryDoc, StoreError> {
    let rows = c
        .query(
            "SELECT agent, id, text, source, request_id, trace_id, approved_by, ts, expires_at \
             FROM notes WHERE service_id = $1 ORDER BY agent, seq",
            &[&row.id],
        )
        .await?;
    let mut agents: BTreeMap<String, Vec<Note>> = BTreeMap::new();
    for r in rows {
        agents.entry(r.get(0)).or_default().push(Note {
            id: r.get(1),
            text: r.get(2),
            source: note_source_of(r.get(3)),
            request_id: r.get(4),
            trace_id: r.get(5),
            approved_by: r.get(6),
            ts: r.get(7),
            expires_at: r.get(8),
        });
    }
    Ok(MemoryDoc {
        version: row.memory_version.to_string(),
        agents,
    })
}

async fn write_notes<C: GenericClient + Sync>(
    c: &C,
    service_id: i64,
    doc: &MemoryDoc,
) -> Result<(), StoreError> {
    c.execute("DELETE FROM notes WHERE service_id = $1", &[&service_id])
        .await?;
    for (agent, notes) in &doc.agents {
        for (seq, n) in notes.iter().enumerate() {
            c.execute(
                "INSERT INTO notes (service_id, agent, seq, id, text, source, request_id, \
                 trace_id, approved_by, ts, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
                &[
                    &service_id,
                    agent,
                    &(seq as i64),
                    &n.id,
                    &n.text,
                    &note_source_str(n.source),
                    &n.request_id,
                    &n.trace_id,
                    &n.approved_by,
                    &n.ts,
                    &n.expires_at,
                ],
            )
            .await?;
        }
    }
    let version = db_int(parse_version(&doc.version)?)?;
    c.execute(
        "UPDATE services SET memory_version = $2 WHERE id = $1",
        &[&service_id, &version],
    )
    .await?;
    Ok(())
}

const PROPOSAL_SELECT: &str = "SELECT p.id, s.namespace, s.service, p.agent, p.note, p.rationale, \
     p.request_id, p.trace_id, p.ts, p.status, p.auto \
     FROM proposals p JOIN services s ON s.id = p.service_id";

fn proposal_of(r: &Row) -> Proposal {
    Proposal {
        id: r.get(0),
        namespace: r.get(1),
        service: r.get(2),
        agent: r.get(3),
        note: r.get(4),
        rationale: r.get(5),
        request_id: r.get(6),
        trace_id: r.get(7),
        ts: r.get(8),
        status: status_of(r.get(9)),
        auto: r.get(10),
    }
}

// ---- events between replicas ----------------------------------------------------------------

/// A [`StoreEvent`] as it travels in a notification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WireEvent {
    CharterChanged {
        key: ServiceKey,
        epoch: String,
        version: String,
        actor: Actor,
        source: ChangeSource,
    },
    ServiceDeleted {
        key: ServiceKey,
        actor: Actor,
    },
    MemoryChanged {
        key: ServiceKey,
        version: String,
    },
    ProposalChanged {
        key: ServiceKey,
        id: String,
    },
    AdoptionPending {
        key: ServiceKey,
        sha256: String,
    },
    /// The event did not fit a notification: re-read everything.
    Resync,
}

impl WireEvent {
    fn of(e: &StoreEvent) -> Option<Self> {
        Some(match e.clone() {
            StoreEvent::CharterChanged {
                key,
                epoch,
                version,
                actor,
                source,
            } => Self::CharterChanged {
                key,
                epoch,
                version,
                actor,
                source,
            },
            StoreEvent::ServiceDeleted { key, actor } => Self::ServiceDeleted { key, actor },
            StoreEvent::MemoryChanged { key, version } => Self::MemoryChanged { key, version },
            StoreEvent::ProposalChanged { key, id } => Self::ProposalChanged { key, id },
            StoreEvent::AdoptionPending { key, sha256 } => Self::AdoptionPending { key, sha256 },
            // this store writes no record of its own
            StoreEvent::CpAudit(_) => return None,
        })
    }

    fn into_event(self) -> Option<StoreEvent> {
        Some(match self {
            Self::CharterChanged {
                key,
                epoch,
                version,
                actor,
                source,
            } => StoreEvent::CharterChanged {
                key,
                epoch,
                version,
                actor,
                source,
            },
            Self::ServiceDeleted { key, actor } => StoreEvent::ServiceDeleted { key, actor },
            Self::MemoryChanged { key, version } => StoreEvent::MemoryChanged { key, version },
            Self::ProposalChanged { key, id } => StoreEvent::ProposalChanged { key, id },
            Self::AdoptionPending { key, sha256 } => StoreEvent::AdoptionPending { key, sha256 },
            Self::Resync => return None,
        })
    }
}

/// A notification: the writing replica, the schema, the event.
#[derive(Debug, Serialize, Deserialize)]
struct Notice {
    origin: String,
    schema: String,
    event: WireEvent,
}

/// The actor of the events a resync emits.
fn resync_actor() -> Actor {
    Actor {
        name: "store:postgres".into(),
        kind: ActorKind::System,
        role: None,
    }
}

/// The `postgres` store; see the module docs.
pub struct PgStore {
    pool: Pool,
    tx: broadcast::Sender<StoreEvent>,
    /// This replica's id in notifications (its own are not emitted twice).
    origin: String,
    schema: String,
    listener: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for PgStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgStore")
            .field("schema", &self.schema)
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl Drop for PgStore {
    fn drop(&mut self) {
        self.listener.abort();
    }
}

impl PgStore {
    /// Connect, migrate, and listen (module docs). Returns once this replica listens, so a
    /// change another replica makes from then on reaches its subscribers.
    pub async fn open(opts: PgOptions) -> Result<Arc<Self>, StoreError> {
        let mut config: tokio_postgres::Config = opts
            .url
            .parse()
            .map_err(|_| StoreError::Io("postgres: the connection string is invalid".into()))?;
        config.application_name(&opts.application_name);
        let tls = MakeRustls::new(opts.ca_file.as_deref())?;
        let manager = Manager::from_config(
            config.clone(),
            tls.clone(),
            ManagerConfig {
                recycling_method: RecyclingMethod::Fast,
            },
        );
        let pool = Pool::builder(manager)
            .max_size(opts.pool_size.max(1))
            .build()
            .map_err(pg_err)?;
        let mut client = pool.get().await.map_err(pg_err)?;
        migrate(&mut client).await?;
        let schema: String = client
            .query_one("SELECT current_schema()", &[])
            .await?
            .get(0);
        drop(client);
        let (tx, _) = broadcast::channel(EVENTS_CAPACITY);
        let origin = uuid::Uuid::new_v4().to_string();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let mut listen_config = config;
        listen_config.application_name(format!("{}-listen", opts.application_name));
        let listener = tokio::spawn(listen(
            listen_config,
            tls,
            pool.clone(),
            tx.clone(),
            origin.clone(),
            schema.clone(),
            ready_tx,
        ));
        match tokio::time::timeout(Duration::from_secs(30), ready_rx).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => {
                listener.abort();
                return Err(e);
            }
            _ => {
                listener.abort();
                return Err(StoreError::Io(
                    "postgres: the listen connection did not start".into(),
                ));
            }
        }
        Ok(Arc::new(Self {
            pool,
            tx,
            origin,
            schema,
            listener,
        }))
    }

    /// The schema this store's tables are in.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    async fn client(&self) -> Result<deadpool_postgres::Object, StoreError> {
        self.pool.get().await.map_err(pg_err)
    }

    fn emit(&self, event: StoreEvent) {
        let _ = self.tx.send(event);
    }

    /// The notification of `event`, sent in `c`'s transaction (delivered on commit).
    async fn notify<C: GenericClient + Sync>(
        &self,
        c: &C,
        event: &StoreEvent,
    ) -> Result<(), StoreError> {
        let Some(wire) = WireEvent::of(event) else {
            return Ok(());
        };
        let mut payload = serde_json::to_string(&Notice {
            origin: self.origin.clone(),
            schema: self.schema.clone(),
            event: wire,
        })
        .map_err(pg_err)?;
        if payload.len() > MAX_PAYLOAD {
            payload = serde_json::to_string(&Notice {
                origin: self.origin.clone(),
                schema: self.schema.clone(),
                event: WireEvent::Resync,
            })
            .map_err(pg_err)?;
        }
        c.execute("SELECT pg_notify($1, $2)", &[&CHANNEL, &payload])
            .await?;
        Ok(())
    }

    async fn notify_all<C: GenericClient + Sync>(
        &self,
        c: &C,
        events: &[StoreEvent],
    ) -> Result<(), StoreError> {
        for e in events {
            self.notify(c, e).await?;
        }
        Ok(())
    }

    async fn decide(
        &self,
        key: &ServiceKey,
        id: &str,
        verdict: ProposalVerdict,
        if_match: &str,
        actor: &Actor,
    ) -> Result<(MemoryDoc, Proposal), StoreError> {
        checked_key(key)?;
        let mut client = self.client().await?;
        let tx = client.transaction().await?;
        let row = find_service(&tx, key, true)
            .await?
            .ok_or(StoreError::NotFound)?;
        let proposal = tx
            .query_opt(
                &format!("{PROPOSAL_SELECT} WHERE p.id = $1 AND p.service_id = $2"),
                &[&id, &row.id],
            )
            .await?
            .map(|r| proposal_of(&r))
            .ok_or(StoreError::NotFound)?;
        let charter = current_charter(&tx, &row).await?.map(|(_, json)| json);
        let memory = memory_of(&tx, &row).await?;
        let now = now_ts();
        let (new_memory, decided) = decide_proposal(
            LearningState {
                charter: charter.as_ref(),
                memory: &memory,
                proposal: &proposal,
            },
            verdict,
            if_match,
            actor,
            &now,
            uuid::Uuid::new_v4().to_string(),
        )?;
        let memory_changed = new_memory.version != memory.version;
        if memory_changed {
            write_notes(&tx, row.id, &new_memory).await?;
        }
        tx.execute(
            "UPDATE proposals SET status = $2, decided_at = $3, decided_by = $4 WHERE id = $1",
            &[&decided.id, &status_str(decided.status), &now, &actor.name],
        )
        .await?;
        let mut events = Vec::new();
        if memory_changed {
            events.push(StoreEvent::MemoryChanged {
                key: key.clone(),
                version: new_memory.version.clone(),
            });
        }
        events.push(StoreEvent::ProposalChanged {
            key: key.clone(),
            id: decided.id.clone(),
        });
        self.notify_all(&tx, &events).await?;
        tx.commit().await?;
        for e in events {
            self.emit(e);
        }
        Ok((new_memory, decided))
    }
}

/// Every live service's charter and memory again, as events: after a listen connection broke,
/// or when another replica's event did not fit a notification.
async fn resync(pool: &Pool, tx: &broadcast::Sender<StoreEvent>) -> Result<(), StoreError> {
    let client = pool.get().await.map_err(pg_err)?;
    let rows = client
        .query(
            "SELECT namespace, service, epoch, version, memory_version FROM services \
             WHERE epoch IS NOT NULL ORDER BY namespace, service",
            &[],
        )
        .await?;
    for r in rows {
        let key = ServiceKey::new(r.get::<_, String>(0), r.get::<_, String>(1));
        let _ = tx.send(StoreEvent::CharterChanged {
            key: key.clone(),
            epoch: r.get(2),
            version: unsigned(r.get(3)).to_string(),
            actor: resync_actor(),
            source: ChangeSource::Api,
        });
        let _ = tx.send(StoreEvent::MemoryChanged {
            key,
            version: unsigned(r.get(4)).to_string(),
        });
    }
    Ok(())
}

/// The listen loop (module docs): connect, `LISTEN`, turn the other replicas' notifications into
/// events; on a broken connection, connect again with backoff and resync.
async fn listen(
    config: tokio_postgres::Config,
    tls: MakeRustls,
    pool: Pool,
    tx: broadcast::Sender<StoreEvent>,
    origin: String,
    schema: String,
    ready: tokio::sync::oneshot::Sender<Result<(), StoreError>>,
) {
    let mut ready = Some(ready);
    let mut backoff = Duration::from_millis(250);
    loop {
        match listen_once(&config, &tls, &pool, &tx, &origin, &schema, &mut ready).await {
            Ok(()) => backoff = Duration::from_millis(250),
            Err(e) => {
                if let Some(r) = ready.take() {
                    let _ = r.send(Err(e));
                    return;
                }
                tracing::warn!(error = %e, "postgres store: listening failed; trying again");
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(10));
    }
}

/// One listen connection, until it ends (`Ok`: it listened, then ended). The first one tells
/// `ready`; a later one resyncs first, for what was missed while there was none.
async fn listen_once(
    config: &tokio_postgres::Config,
    tls: &MakeRustls,
    pool: &Pool,
    tx: &broadcast::Sender<StoreEvent>,
    origin: &str,
    schema: &str,
    ready: &mut Option<tokio::sync::oneshot::Sender<Result<(), StoreError>>>,
) -> Result<(), StoreError> {
    use futures::StreamExt;
    let (client, mut connection) = config.connect(tls.clone()).await?;
    let (msg_tx, mut msg_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let driver = tokio::spawn(async move {
        let mut messages = futures::stream::poll_fn(move |cx| connection.poll_message(cx));
        while let Some(m) = messages.next().await {
            match m {
                Ok(AsyncMessage::Notification(n)) => {
                    if msg_tx.send(n.payload().to_string()).is_err() {
                        return;
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "postgres store: the listen connection failed");
                    return;
                }
            }
        }
    });
    if let Err(e) = client.batch_execute(&format!("LISTEN {CHANNEL}")).await {
        driver.abort();
        return Err(e.into());
    }
    match ready.take() {
        Some(r) => {
            let _ = r.send(Ok(()));
        }
        None => {
            tracing::info!("postgres store: listening again; resyncing");
            if let Err(e) = resync(pool, tx).await {
                tracing::warn!(error = %e, "postgres store: resync failed");
            }
        }
    }
    while let Some(payload) = msg_rx.recv().await {
        let notice: Notice = match serde_json::from_str(&payload) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(error = %e, "postgres store: an unreadable notification");
                continue;
            }
        };
        if notice.schema != schema || notice.origin == origin {
            continue;
        }
        match notice.event.into_event() {
            Some(e) => {
                let _ = tx.send(e);
            }
            None => {
                if let Err(e) = resync(pool, tx).await {
                    tracing::warn!(error = %e, "postgres store: resync failed");
                }
            }
        }
    }
    drop(client);
    driver.abort();
    Ok(())
}

#[async_trait]
impl Store for PgStore {
    async fn list_services(&self) -> Result<Vec<ServiceKey>, StoreError> {
        let client = self.client().await?;
        Ok(client
            .query(
                "SELECT namespace, service FROM services WHERE epoch IS NOT NULL \
                 ORDER BY namespace, service",
                &[],
            )
            .await?
            .iter()
            .map(|r| ServiceKey::new(r.get::<_, String>(0), r.get::<_, String>(1)))
            .collect())
    }

    async fn get_charter(&self, key: &ServiceKey) -> Result<StoredCharter, StoreError> {
        checked_key(key)?;
        let client = self.client().await?;
        let row = find_service(&client, key, false)
            .await?
            .ok_or(StoreError::NotFound)?;
        let (yaml, json) = current_charter(&client, &row)
            .await?
            .ok_or(StoreError::NotFound)?;
        Ok(StoredCharter {
            epoch: row.epoch.unwrap_or_default(),
            version: row.version.to_string(),
            yaml,
            charter_json: json,
        })
    }

    async fn put_charter(
        &self,
        key: &ServiceKey,
        precondition: &Precondition,
        write: CharterWrite,
    ) -> Result<StoredCharter, StoreError> {
        checked_key(key)?;
        let mut client = self.client().await?;
        let tx = client.transaction().await?;
        let row = ensure_service(&tx, key).await?;
        let current = row.has_charter().then(|| row.version.to_string());
        match (precondition, &current) {
            (Precondition::NotExists, Some(v)) => {
                return Err(StoreError::Conflict { current: v.clone() });
            }
            (Precondition::Version(_), None) => return Err(StoreError::NotFound),
            (Precondition::Version(want), Some(v)) if want != v => {
                return Err(StoreError::Conflict { current: v.clone() });
            }
            _ => {}
        }
        let version = next_version(row.version)?;
        let epoch = row
            .epoch
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let sha = super::file::sha256_hex(&write.yaml);
        let json = serde_json::to_string(&write.charter_json).map_err(pg_err)?;
        tx.execute(
            "INSERT INTO charter_versions (service_id, version, epoch, yaml, json, sha256, ts, \
             actor, actor_kind, actor_role, source) \
             VALUES ($1, $2, $3, $4, $5::text::jsonb, $6, $7, $8, $9, $10, $11)",
            &[
                &row.id,
                &db_int(version)?,
                &epoch,
                &write.yaml,
                &json,
                &sha,
                &now_ts(),
                &write.actor.name,
                &kind_str(write.actor.kind),
                &write.actor.role.map(Role::as_str),
                &source_str(write.source),
            ],
        )
        .await?;
        let memory = memory_of(&tx, &row).await?;
        let pruned = prune_memory(&memory, &write.charter_json);
        if let Some(m) = &pruned {
            write_notes(&tx, row.id, m).await?;
        }
        tx.execute(
            "DELETE FROM pending_adoptions WHERE namespace = $1 AND service = $2",
            &[&key.namespace, &key.service],
        )
        .await?;
        let mut events = vec![StoreEvent::CharterChanged {
            key: key.clone(),
            epoch: epoch.clone(),
            version: version.to_string(),
            actor: write.actor,
            source: write.source,
        }];
        if let Some(m) = pruned {
            events.push(StoreEvent::MemoryChanged {
                key: key.clone(),
                version: m.version,
            });
        }
        self.notify_all(&tx, &events).await?;
        tx.commit().await?;
        for e in events {
            self.emit(e);
        }
        Ok(StoredCharter {
            epoch,
            version: version.to_string(),
            yaml: write.yaml,
            charter_json: write.charter_json,
        })
    }

    async fn history(&self, key: &ServiceKey) -> Result<Vec<HistoryEntry>, StoreError> {
        checked_key(key)?;
        let client = self.client().await?;
        let row = find_service(&client, key, false)
            .await?
            .filter(ServiceRow::has_charter)
            .ok_or(StoreError::NotFound)?;
        Ok(client
            .query(
                "SELECT version, ts, actor, sha256 FROM charter_versions \
                 WHERE service_id = $1 ORDER BY version DESC",
                &[&row.id],
            )
            .await?
            .iter()
            .map(|r| HistoryEntry {
                version: unsigned(r.get(0)).to_string(),
                ts: r.get(1),
                actor: r.get(2),
                sha256: r.get(3),
            })
            .collect())
    }

    async fn get_revision(&self, key: &ServiceKey, version: &str) -> Result<String, StoreError> {
        checked_key(key)?;
        let Ok(version) = version.parse::<i64>() else {
            return Err(StoreError::NotFound);
        };
        let client = self.client().await?;
        let row = find_service(&client, key, false)
            .await?
            .filter(ServiceRow::has_charter)
            .ok_or(StoreError::NotFound)?;
        client
            .query_opt(
                "SELECT yaml FROM charter_versions WHERE service_id = $1 AND version = $2",
                &[&row.id, &version],
            )
            .await?
            .map(|r| r.get(0))
            .ok_or(StoreError::NotFound)
    }

    async fn delete_service(
        &self,
        key: &ServiceKey,
        if_match: &str,
        actor: &Actor,
    ) -> Result<(), StoreError> {
        checked_key(key)?;
        let mut client = self.client().await?;
        let tx = client.transaction().await?;
        let row = find_service(&tx, key, true)
            .await?
            .filter(ServiceRow::has_charter)
            .ok_or(StoreError::NotFound)?;
        if row.version.to_string() != if_match {
            return Err(StoreError::Conflict {
                current: row.version.to_string(),
            });
        }
        // the trigger `services_retired` drops the history, the notes and the proposals
        tx.execute("UPDATE services SET epoch = NULL WHERE id = $1", &[&row.id])
            .await?;
        let event = StoreEvent::ServiceDeleted {
            key: key.clone(),
            actor: actor.clone(),
        };
        self.notify(&tx, &event).await?;
        tx.commit().await?;
        self.emit(event);
        Ok(())
    }

    async fn get_memory(&self, key: &ServiceKey) -> Result<MemoryDoc, StoreError> {
        checked_key(key)?;
        let client = self.client().await?;
        match find_service(&client, key, false).await? {
            Some(row) => memory_of(&client, &row).await,
            None => Ok(MemoryDoc {
                version: "0".into(),
                agents: BTreeMap::new(),
            }),
        }
    }

    async fn put_memory(
        &self,
        key: &ServiceKey,
        if_match: &str,
        agents: BTreeMap<String, Vec<Note>>,
        _actor: &Actor,
    ) -> Result<MemoryDoc, StoreError> {
        checked_key(key)?;
        let mut client = self.client().await?;
        let tx = client.transaction().await?;
        let row = ensure_service(&tx, key).await?;
        let current = memory_of(&tx, &row).await?;
        if current.version != if_match {
            return Err(StoreError::Conflict {
                current: current.version,
            });
        }
        let doc = MemoryDoc {
            version: next_version(row.memory_version)?.to_string(),
            agents: agents.into_iter().filter(|(_, n)| !n.is_empty()).collect(),
        };
        write_notes(&tx, row.id, &doc).await?;
        let event = StoreEvent::MemoryChanged {
            key: key.clone(),
            version: doc.version.clone(),
        };
        self.notify(&tx, &event).await?;
        tx.commit().await?;
        self.emit(event);
        Ok(doc)
    }

    async fn list_proposals(&self, filter: &ProposalFilter) -> Result<Vec<Proposal>, StoreError> {
        let mut sql = String::from(PROPOSAL_SELECT);
        let mut clauses: Vec<String> = Vec::new();
        let mut args: Vec<String> = Vec::new();
        if let Some(s) = filter.status {
            args.push(status_str(s).to_string());
            clauses.push(format!("p.status = ${}", args.len()));
        }
        if let Some(ns) = &filter.namespace {
            args.push(ns.clone());
            clauses.push(format!("s.namespace = ${}", args.len()));
        }
        if let Some(svc) = &filter.service {
            args.push(svc.clone());
            clauses.push(format!("s.service = ${}", args.len()));
        }
        if !clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&clauses.join(" AND "));
        }
        sql.push_str(" ORDER BY p.ts DESC, p.id DESC");
        let params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = args
            .iter()
            .map(|a| a as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect();
        let client = self.client().await?;
        Ok(client
            .query(&sql, &params)
            .await?
            .iter()
            .map(proposal_of)
            .collect())
    }

    async fn get_proposal(&self, id: &str) -> Result<Proposal, StoreError> {
        let client = self.client().await?;
        client
            .query_opt(&format!("{PROPOSAL_SELECT} WHERE p.id = $1"), &[&id])
            .await?
            .map(|r| proposal_of(&r))
            .ok_or(StoreError::NotFound)
    }

    async fn put_proposal(
        &self,
        proposal: &Proposal,
        dedup_key: Option<&str>,
    ) -> Result<ProposalPut, StoreError> {
        let key = ServiceKey::new(&proposal.namespace, &proposal.service);
        checked_key(&key)?;
        let p = proposal;
        let mut client = self.client().await?;
        let tx = client.transaction().await?;
        let row = ensure_service(&tx, &key).await?;
        // a decided proposal carries its decision time from the start (the CHECK)
        let decided_at = (p.status != ProposalStatus::Pending).then(|| p.ts.clone());
        match dedup_key {
            Some(dk) => {
                if let Some(existing) = tx
                    .query_opt(
                        "SELECT id FROM proposals WHERE service_id = $1 AND dedup_key = $2",
                        &[&row.id, &dk],
                    )
                    .await?
                {
                    return Ok(ProposalPut::Duplicate {
                        existing_id: existing.get(0),
                    });
                }
                tx.execute(
                    "INSERT INTO proposals (id, service_id, agent, note, rationale, request_id, \
                     trace_id, ts, status, auto, dedup_key, decided_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
                    &[
                        &p.id,
                        &row.id,
                        &p.agent,
                        &p.note,
                        &p.rationale,
                        &p.request_id,
                        &p.trace_id,
                        &p.ts,
                        &status_str(p.status),
                        &p.auto,
                        &dk,
                        &decided_at,
                    ],
                )
                .await?;
            }
            None => {
                let changed = tx
                    .execute(
                        "UPDATE proposals SET agent = $3, note = $4, rationale = $5, request_id = $6, \
                         trace_id = $7, ts = $8, status = $9, auto = $10, \
                         decided_at = CASE WHEN $9 = 'pending' THEN NULL ELSE COALESCE(decided_at, $11) END \
                         WHERE id = $1 AND service_id = $2",
                        &[
                            &p.id,
                            &row.id,
                            &p.agent,
                            &p.note,
                            &p.rationale,
                            &p.request_id,
                            &p.trace_id,
                            &p.ts,
                            &status_str(p.status),
                            &p.auto,
                            &decided_at.clone().unwrap_or_else(now_ts),
                        ],
                    )
                    .await?;
                if changed == 0 {
                    return Err(StoreError::NotFound);
                }
            }
        }
        let event = StoreEvent::ProposalChanged {
            key,
            id: proposal.id.clone(),
        };
        self.notify(&tx, &event).await?;
        tx.commit().await?;
        self.emit(event);
        Ok(ProposalPut::Stored)
    }

    async fn approve_proposal(
        &self,
        key: &ServiceKey,
        id: &str,
        if_match_memory: &str,
        actor: &Actor,
    ) -> Result<(MemoryDoc, Proposal), StoreError> {
        self.decide(key, id, ProposalVerdict::Approve, if_match_memory, actor)
            .await
    }

    async fn reject_proposal(
        &self,
        key: &ServiceKey,
        id: &str,
        if_match_memory: &str,
        actor: &Actor,
    ) -> Result<(MemoryDoc, Proposal), StoreError> {
        self.decide(key, id, ProposalVerdict::Reject, if_match_memory, actor)
            .await
    }

    async fn list_pending_adoptions(&self) -> Result<Vec<PendingAdoption>, StoreError> {
        let client = self.client().await?;
        Ok(client
            .query(
                "SELECT namespace, service, sha256, pod, ts, yaml FROM pending_adoptions \
                 ORDER BY namespace, service",
                &[],
            )
            .await?
            .iter()
            .map(|r| PendingAdoption {
                key: ServiceKey::new(r.get::<_, String>(0), r.get::<_, String>(1)),
                sha256: r.get(2),
                pod: r.get(3),
                ts: r.get(4),
                yaml: r.get(5),
            })
            .collect())
    }

    async fn put_pending_adoption(&self, adoption: PendingAdoption) -> Result<(), StoreError> {
        checked_key(&adoption.key)?;
        let key = &adoption.key;
        let mut client = self.client().await?;
        let tx = client.transaction().await?;
        let row = ensure_service(&tx, key).await?;
        if row.has_charter() {
            return Err(StoreError::Conflict {
                current: row.version.to_string(),
            });
        }
        tx.execute(
            "INSERT INTO pending_adoptions (namespace, service, sha256, pod, ts, yaml) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (namespace, service) DO UPDATE SET sha256 = EXCLUDED.sha256, \
             pod = EXCLUDED.pod, ts = EXCLUDED.ts, yaml = EXCLUDED.yaml",
            &[
                &key.namespace,
                &key.service,
                &adoption.sha256,
                &adoption.pod,
                &adoption.ts,
                &adoption.yaml,
            ],
        )
        .await?;
        let event = StoreEvent::AdoptionPending {
            key: key.clone(),
            sha256: adoption.sha256.clone(),
        };
        self.notify(&tx, &event).await?;
        tx.commit().await?;
        self.emit(event);
        Ok(())
    }

    async fn take_pending_adoption(
        &self,
        key: &ServiceKey,
        sha256: &str,
    ) -> Result<PendingAdoption, StoreError> {
        let client = self.client().await?;
        client
            .query_opt(
                "DELETE FROM pending_adoptions WHERE namespace = $1 AND service = $2 \
                 AND sha256 = $3 RETURNING sha256, pod, ts, yaml",
                &[&key.namespace, &key.service, &sha256],
            )
            .await?
            .map(|r| PendingAdoption {
                key: key.clone(),
                sha256: r.get(0),
                pod: r.get(1),
                ts: r.get(2),
                yaml: r.get(3),
            })
            .ok_or(StoreError::NotFound)
    }

    async fn append_cp_audit(&self, record: &CpAuditRecord) -> Result<(), StoreError> {
        let json = serde_json::to_string(record).map_err(pg_err)?;
        let client = self.client().await?;
        client
            .execute(
                "INSERT INTO cp_audit (ts, actor, actor_kind, role, action, namespace, service, \
                 agent, from_version, to_version, sha256_before, sha256_after, result, reason, \
                 record) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
                 $15::text::jsonb)",
                &[
                    &record.ts,
                    &record.actor,
                    &kind_str(record.actor_kind),
                    &record.role.map(Role::as_str),
                    &enum_text(&record.action),
                    &record.namespace,
                    &record.service,
                    &record.agent,
                    &record.from_version,
                    &record.to_version,
                    &record.sha256_before,
                    &record.sha256_after,
                    &enum_text(&record.result),
                    &record.reason,
                    &json,
                ],
            )
            .await?;
        Ok(())
    }

    async fn cp_audit(&self, limit: usize) -> Result<Vec<CpAuditRecord>, StoreError> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let client = self.client().await?;
        client
            .query(
                "SELECT record::text FROM (SELECT seq, record FROM cp_audit \
                 ORDER BY seq DESC LIMIT $1) newest ORDER BY seq",
                &[&limit],
            )
            .await?
            .iter()
            .map(|r| serde_json::from_str(r.get::<_, &str>(0)).map_err(pg_err))
            .collect()
    }

    fn subscribe(&self) -> broadcast::Receiver<StoreEvent> {
        self.tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_survive_the_notification_round_trip() {
        let key = ServiceKey::new("shop", "orders");
        let actor = Actor {
            name: "alice".into(),
            kind: ActorKind::Token,
            role: Some(Role::Admin),
        };
        for e in [
            StoreEvent::CharterChanged {
                key: key.clone(),
                epoch: "e".into(),
                version: "3".into(),
                actor: actor.clone(),
                source: ChangeSource::Rollback,
            },
            StoreEvent::ServiceDeleted {
                key: key.clone(),
                actor,
            },
            StoreEvent::MemoryChanged {
                key: key.clone(),
                version: "2".into(),
            },
            StoreEvent::ProposalChanged {
                key: key.clone(),
                id: "p1".into(),
            },
            StoreEvent::AdoptionPending {
                key,
                sha256: "a".repeat(64),
            },
        ] {
            let text = serde_json::to_string(&Notice {
                origin: "o".into(),
                schema: "s".into(),
                event: WireEvent::of(&e).unwrap(),
            })
            .unwrap();
            assert!(text.len() < MAX_PAYLOAD);
            let back: Notice = serde_json::from_str(&text).unwrap();
            assert_eq!(back.event.into_event(), Some(e));
        }
    }

    #[test]
    fn the_connection_string_never_shows() {
        let opts = PgOptions {
            url: "postgres://embassy:s3cret@db:5432/agentsc".into(),
            ca_file: None,
            pool_size: 2,
            application_name: "embassy".into(),
        };
        assert!(!format!("{opts:?}").contains("s3cret"));
    }
}
