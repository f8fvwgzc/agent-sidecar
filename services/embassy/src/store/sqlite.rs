//! The `sqlite:<path>` store (docs/adr/0003-sqlite-store-schema.md).
//!
//! Everything the file store keeps, in one database file: the schema is `schema.sql`
//! ([`SCHEMA`]), applied when the file is new (`PRAGMA user_version` 0 → 1), then the
//! [`MIGRATIONS`] up to [`SCHEMA_VERSION`]. Migration 2 adds the agent registry of
//! [`crate::secops`] (`agents`, `agent_aliases`; implemented in `sqlite_secops.rs`).
//!
//! | Table | Key | What |
//! | --- | --- | --- |
//! | `services` | `id`; `UNIQUE (namespace, service)` | one row per service ever seen; `epoch` NULL = no charter; the version counters |
//! | `charter_versions` | `(service_id, version)` | every stored version, immutable; the current one is `services.version` |
//! | `notes` | `(service_id, agent, seq)` | the memory, one row per note; its version is `services.memory_version` |
//! | `proposals` | `id`; `UNIQUE (service_id, dedup_key)` | lesson proposals and their decision |
//! | `cp_audit` | `seq` | the control-plane audit, append-only |
//!
//! Every child table references `services (id) ON DELETE CASCADE`. Triggers keep the counters
//! monotonic, make a stored version exactly the next one, refuse a second decision on a
//! proposal, and refuse `UPDATE`/`DELETE` on the audit. The Rust side still checks every
//! precondition first, so the triggers are a floor, not the error path.
//!
//! One connection behind one mutex (WAL, `synchronous=NORMAL`, foreign keys on); every call
//! runs its statements inside one transaction on the blocking pool, so a `Store` call is one
//! critical section like the file store's. Pending adoptions are in memory, like the file
//! store's: a sidecar reports its start-up charter again whenever it connects. The database has
//! no external editor, so there is no poll and no external-edit audit.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::broadcast;

use super::{
    Actor, ActorKind, ChangeSource, CharterWrite, HistoryEntry, LearningState, MemoryDoc, Note,
    NoteSource, PendingAdoption, Precondition, Proposal, ProposalFilter, ProposalPut,
    ProposalStatus, ProposalVerdict, ServiceKey, Store, StoreError, StoreEvent, StoredCharter,
    decide_proposal, prune_memory,
};
use crate::api::types::CpAuditRecord;
use crate::config::Role;
use crate::names::is_dns_label;

/// The schema (`schema.sql`), applied to a new database as version 1.
pub const SCHEMA: &str = include_str!("schema.sql");
/// The migrations after version 1, in order: `(version, SQL)`. 2 is the agent registry
/// (`schema_v2.sql`, [`crate::secops`]).
pub const MIGRATIONS: &[(i64, &str)] = &[(2, include_str!("schema_v2.sql"))];
/// The `PRAGMA user_version` this code writes and expects.
pub const SCHEMA_VERSION: i64 = 2;
/// Store events a slow subscriber may fall behind before it loses some.
pub const EVENTS_CAPACITY: usize = 1024;
/// How long a statement waits for a lock held by another connection (a CLI reading the file).
pub const BUSY_TIMEOUT_MS: u64 = 5_000;

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Io(format!("sqlite: {e}"))
    }
}

fn io_err(what: impl std::fmt::Display, e: impl std::fmt::Display) -> StoreError {
    StoreError::Io(format!("{what}: {e}"))
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

fn unsigned(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

/// An enum's serde name (`actor_kind`, `action`, `result` of the audit record).
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

/// A `services` row.
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
}

fn find_service(conn: &Connection, key: &ServiceKey) -> Result<Option<ServiceRow>, StoreError> {
    let row = conn
        .query_row(
            "SELECT id, epoch, version, memory_version FROM services \
             WHERE namespace = ?1 AND service = ?2",
            params![key.namespace, key.service],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    Ok(row.map(|(id, epoch, version, memory_version)| ServiceRow {
        id,
        epoch,
        version: unsigned(version),
        memory_version: unsigned(memory_version),
    }))
}

/// The row of `key`, created (without a charter) when there is none.
fn ensure_service(conn: &Connection, key: &ServiceKey) -> Result<ServiceRow, StoreError> {
    conn.execute(
        "INSERT OR IGNORE INTO services (namespace, service) VALUES (?1, ?2)",
        params![key.namespace, key.service],
    )?;
    find_service(conn, key)?.ok_or_else(|| StoreError::Io("the service row vanished".into()))
}

/// The current charter of a service: `(yaml, json, sha256)`; `None` without one.
fn current_charter(
    conn: &Connection,
    row: &ServiceRow,
) -> Result<Option<(String, Value, String)>, StoreError> {
    if !row.has_charter() {
        return Ok(None);
    }
    let found = conn
        .query_row(
            "SELECT yaml, json, sha256 FROM charter_versions WHERE service_id = ?1 AND version = ?2",
            params![row.id, row.version as i64],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    match found {
        None => Ok(None),
        Some((yaml, json, sha)) => {
            let json: Value =
                serde_json::from_str(&json).map_err(|e| io_err("stored charter json", e))?;
            Ok(Some((yaml, json, sha)))
        }
    }
}

fn read_notes(
    conn: &Connection,
    service_id: i64,
) -> Result<BTreeMap<String, Vec<Note>>, StoreError> {
    let mut stmt = conn.prepare_cached(
        "SELECT agent, id, text, source, request_id, trace_id, approved_by, ts, expires_at \
         FROM notes WHERE service_id = ?1 ORDER BY agent, seq",
    )?;
    let rows = stmt.query_map(params![service_id], |r| {
        Ok((
            r.get::<_, String>(0)?,
            Note {
                id: r.get(1)?,
                text: r.get(2)?,
                source: note_source_of(&r.get::<_, String>(3)?),
                request_id: r.get(4)?,
                trace_id: r.get(5)?,
                approved_by: r.get(6)?,
                ts: r.get(7)?,
                expires_at: r.get(8)?,
            },
        ))
    })?;
    let mut agents: BTreeMap<String, Vec<Note>> = BTreeMap::new();
    for row in rows {
        let (agent, note) = row?;
        agents.entry(agent).or_default().push(note);
    }
    Ok(agents)
}

fn memory_of(conn: &Connection, row: &ServiceRow) -> Result<MemoryDoc, StoreError> {
    Ok(MemoryDoc {
        version: row.memory_version.to_string(),
        agents: read_notes(conn, row.id)?,
    })
}

/// Replace the notes of a service with `doc`'s and set its memory version.
fn write_notes(conn: &Connection, service_id: i64, doc: &MemoryDoc) -> Result<(), StoreError> {
    conn.execute(
        "DELETE FROM notes WHERE service_id = ?1",
        params![service_id],
    )?;
    let mut insert = conn.prepare_cached(
        "INSERT INTO notes (service_id, agent, seq, id, text, source, request_id, trace_id, \
         approved_by, ts, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
    )?;
    for (agent, notes) in &doc.agents {
        for (seq, n) in notes.iter().enumerate() {
            insert.execute(params![
                service_id,
                agent,
                seq as i64,
                n.id,
                n.text,
                note_source_str(n.source),
                n.request_id,
                n.trace_id,
                n.approved_by,
                n.ts,
                n.expires_at,
            ])?;
        }
    }
    let version = parse_version(&doc.version)?;
    conn.execute(
        "UPDATE services SET memory_version = ?2 WHERE id = ?1",
        params![service_id, version as i64],
    )?;
    Ok(())
}

const PROPOSAL_SELECT: &str = "SELECT p.id, s.namespace, s.service, p.agent, p.note, p.rationale, \
     p.request_id, p.trace_id, p.ts, p.status, p.auto \
     FROM proposals p JOIN services s ON s.id = p.service_id";

fn proposal_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Proposal> {
    Ok(Proposal {
        id: r.get(0)?,
        namespace: r.get(1)?,
        service: r.get(2)?,
        agent: r.get(3)?,
        note: r.get(4)?,
        rationale: r.get(5)?,
        request_id: r.get(6)?,
        trace_id: r.get(7)?,
        ts: r.get(8)?,
        status: status_of(&r.get::<_, String>(9)?),
        auto: r.get::<_, i64>(10)? != 0,
    })
}

/// Store `write` as the next version of the service `row` (the precondition was checked):
/// the version row (the trigger moves the counter and epoch), then the pruned memory.
fn commit(
    conn: &Connection,
    row: &ServiceRow,
    key: &ServiceKey,
    write: CharterWrite,
) -> Result<(StoredCharter, Vec<StoreEvent>), StoreError> {
    let version = next_version(row.version)?;
    let epoch = row
        .epoch
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let sha = super::file::sha256_hex(&write.yaml);
    let json = serde_json::to_string(&write.charter_json).map_err(|e| io_err("charter json", e))?;
    conn.execute(
        "INSERT INTO charter_versions (service_id, version, epoch, yaml, json, sha256, ts, actor, \
         actor_kind, actor_role, source) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            row.id,
            version as i64,
            epoch,
            write.yaml,
            json,
            sha,
            now_ts(),
            write.actor.name,
            kind_str(write.actor.kind),
            write.actor.role.map(Role::as_str),
            source_str(write.source),
        ],
    )?;
    let memory = memory_of(conn, row)?;
    let pruned = prune_memory(&memory, &write.charter_json);
    if let Some(m) = &pruned {
        write_notes(conn, row.id, m)?;
    }
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
    Ok((
        StoredCharter {
            epoch,
            version: version.to_string(),
            yaml: write.yaml,
            charter_json: write.charter_json,
        },
        events,
    ))
}

/// Open the database at `path` (created with the schema when new) and check its version.
fn open_connection(path: &Path) -> Result<Connection, StoreError> {
    let conn = Connection::open(path).map_err(|e| io_err(path.display(), e))?;
    prepare(&conn).map_err(|e| io_err(path.display(), e))?;
    Ok(conn)
}

/// Pragmas and the schema, on any connection.
fn prepare(conn: &Connection) -> Result<(), StoreError> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.pragma_update(None, "busy_timeout", BUSY_TIMEOUT_MS as i64)?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    let mut version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(StoreError::Io(format!(
            "schema version {version} was written by a newer embassy (this one knows {SCHEMA_VERSION})"
        )));
    }
    if version == 0 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(SCHEMA)?;
        tx.pragma_update(None, "user_version", 1)?;
        tx.commit()?;
        version = 1;
    }
    // each migration and its version in one transaction, so a crash leaves the old version
    for (v, sql) in MIGRATIONS.iter().filter(|(v, _)| *v > version) {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(sql)
            .map_err(|e| StoreError::Io(format!("sqlite: migration {v}: {e}")))?;
        tx.pragma_update(None, "user_version", v)?;
        tx.commit()?;
    }
    Ok(())
}

#[path = "sqlite_secops.rs"]
mod secops;

/// The `sqlite:<path>` store; see the module docs.
pub struct SqliteStore {
    path: PathBuf,
    conn: Arc<Mutex<Connection>>,
    tx: broadcast::Sender<StoreEvent>,
    pending: Mutex<BTreeMap<ServiceKey, PendingAdoption>>,
}

impl std::fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteStore")
            .field("path", &self.path)
            .finish()
    }
}

impl SqliteStore {
    /// Open (or create) the database file at `path`; its directory is created when missing.
    pub fn open(path: impl Into<PathBuf>) -> Result<Arc<Self>, StoreError> {
        let path = path.into();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| io_err(parent.display(), e))?;
        }
        let conn = open_connection(&path)?;
        Ok(Self::with_connection(conn, path))
    }

    /// A store in memory, gone when dropped (tests).
    pub fn open_in_memory() -> Result<Arc<Self>, StoreError> {
        let conn = Connection::open_in_memory()?;
        prepare(&conn)?;
        Ok(Self::with_connection(conn, PathBuf::from(":memory:")))
    }

    fn with_connection(conn: Connection, path: PathBuf) -> Arc<Self> {
        let (tx, _) = broadcast::channel(EVENTS_CAPACITY);
        Arc::new(Self {
            path,
            conn: Arc::new(Mutex::new(conn)),
            tx,
            pending: Mutex::new(BTreeMap::new()),
        })
    }

    /// The database file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn emit(&self, event: StoreEvent) {
        // no subscriber is not an error
        let _ = self.tx.send(event);
    }

    /// Run `f` on the connection, on the blocking pool, under the store's lock.
    async fn run<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock().unwrap_or_else(PoisonError::into_inner);
            f(&mut guard)
        })
        .await
        .map_err(|e| StoreError::Io(format!("sqlite worker: {e}")))?
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
        let (k, id, if_match, actor) = (
            key.clone(),
            id.to_string(),
            if_match.to_string(),
            actor.clone(),
        );
        let (memory, decided, memory_changed) = self
            .run(move |conn| {
                let tx = conn.transaction()?;
                let row = find_service(&tx, &k)?.ok_or(StoreError::NotFound)?;
                let proposal = tx
                    .query_row(
                        &format!("{PROPOSAL_SELECT} WHERE p.id = ?1 AND p.service_id = ?2"),
                        params![id, row.id],
                        proposal_from_row,
                    )
                    .optional()?
                    .ok_or(StoreError::NotFound)?;
                let charter = current_charter(&tx, &row)?.map(|(_, json, _)| json);
                let memory = memory_of(&tx, &row)?;
                let now = now_ts();
                let (new_memory, decided) = decide_proposal(
                    LearningState {
                        charter: charter.as_ref(),
                        memory: &memory,
                        proposal: &proposal,
                    },
                    verdict,
                    &if_match,
                    &actor,
                    &now,
                    uuid::Uuid::new_v4().to_string(),
                )?;
                let memory_changed = new_memory.version != memory.version;
                if memory_changed {
                    write_notes(&tx, row.id, &new_memory)?;
                }
                tx.execute(
                    "UPDATE proposals SET status = ?2, decided_at = ?3, decided_by = ?4 WHERE id = ?1",
                    params![decided.id, status_str(decided.status), now, actor.name],
                )?;
                tx.commit()?;
                Ok((new_memory, decided, memory_changed))
            })
            .await?;
        if memory_changed {
            self.emit(StoreEvent::MemoryChanged {
                key: key.clone(),
                version: memory.version.clone(),
            });
        }
        self.emit(StoreEvent::ProposalChanged {
            key: key.clone(),
            id: decided.id.clone(),
        });
        Ok((memory, decided))
    }
}

#[async_trait]
impl Store for SqliteStore {
    async fn list_services(&self) -> Result<Vec<ServiceKey>, StoreError> {
        self.run(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT namespace, service FROM services WHERE epoch IS NOT NULL \
                 ORDER BY namespace, service",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(ServiceKey::new(
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                ))
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
        .await
    }

    async fn get_charter(&self, key: &ServiceKey) -> Result<StoredCharter, StoreError> {
        checked_key(key)?;
        let k = key.clone();
        self.run(move |conn| {
            let row = find_service(conn, &k)?.ok_or(StoreError::NotFound)?;
            let (yaml, json, _) = current_charter(conn, &row)?.ok_or(StoreError::NotFound)?;
            Ok(StoredCharter {
                epoch: row.epoch.unwrap_or_default(),
                version: row.version.to_string(),
                yaml,
                charter_json: json,
            })
        })
        .await
    }

    async fn put_charter(
        &self,
        key: &ServiceKey,
        precondition: &Precondition,
        write: CharterWrite,
    ) -> Result<StoredCharter, StoreError> {
        checked_key(key)?;
        let (k, precondition) = (key.clone(), precondition.clone());
        let (stored, events) = self
            .run(move |conn| {
                let tx = conn.transaction()?;
                let row = ensure_service(&tx, &k)?;
                let current = row.has_charter().then(|| row.version.to_string());
                match (&precondition, &current) {
                    (Precondition::NotExists, Some(v)) => {
                        return Err(StoreError::Conflict { current: v.clone() });
                    }
                    (Precondition::Version(_), None) => return Err(StoreError::NotFound),
                    (Precondition::Version(want), Some(v)) if want != v => {
                        return Err(StoreError::Conflict { current: v.clone() });
                    }
                    _ => {}
                }
                let out = commit(&tx, &row, &k, write)?;
                tx.commit()?;
                Ok(out)
            })
            .await?;
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(key);
        for e in events {
            self.emit(e);
        }
        Ok(stored)
    }

    async fn history(&self, key: &ServiceKey) -> Result<Vec<HistoryEntry>, StoreError> {
        checked_key(key)?;
        let k = key.clone();
        self.run(move |conn| {
            let row = find_service(conn, &k)?
                .filter(ServiceRow::has_charter)
                .ok_or(StoreError::NotFound)?;
            let mut stmt = conn.prepare_cached(
                "SELECT version, ts, actor, sha256 FROM charter_versions \
                 WHERE service_id = ?1 ORDER BY version DESC",
            )?;
            let rows = stmt.query_map(params![row.id], |r| {
                Ok(HistoryEntry {
                    version: unsigned(r.get::<_, i64>(0)?).to_string(),
                    ts: r.get(1)?,
                    actor: r.get(2)?,
                    sha256: r.get(3)?,
                })
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
        .await
    }

    async fn get_revision(&self, key: &ServiceKey, version: &str) -> Result<String, StoreError> {
        checked_key(key)?;
        let Ok(version) = version.parse::<i64>() else {
            return Err(StoreError::NotFound);
        };
        let k = key.clone();
        self.run(move |conn| {
            let row = find_service(conn, &k)?
                .filter(ServiceRow::has_charter)
                .ok_or(StoreError::NotFound)?;
            conn.query_row(
                "SELECT yaml FROM charter_versions WHERE service_id = ?1 AND version = ?2",
                params![row.id, version],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .ok_or(StoreError::NotFound)
        })
        .await
    }

    async fn delete_service(
        &self,
        key: &ServiceKey,
        if_match: &str,
        actor: &Actor,
    ) -> Result<(), StoreError> {
        checked_key(key)?;
        let (k, if_match) = (key.clone(), if_match.to_string());
        self.run(move |conn| {
            let tx = conn.transaction()?;
            let row = find_service(&tx, &k)?
                .filter(ServiceRow::has_charter)
                .ok_or(StoreError::NotFound)?;
            if row.version.to_string() != if_match {
                return Err(StoreError::Conflict {
                    current: row.version.to_string(),
                });
            }
            // the trigger `services_retired` drops the history, the notes and the proposals
            tx.execute(
                "UPDATE services SET epoch = NULL WHERE id = ?1",
                params![row.id],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await?;
        self.emit(StoreEvent::ServiceDeleted {
            key: key.clone(),
            actor: actor.clone(),
        });
        Ok(())
    }

    async fn get_memory(&self, key: &ServiceKey) -> Result<MemoryDoc, StoreError> {
        checked_key(key)?;
        let k = key.clone();
        self.run(move |conn| match find_service(conn, &k)? {
            Some(row) => memory_of(conn, &row),
            None => Ok(MemoryDoc {
                version: "0".into(),
                agents: BTreeMap::new(),
            }),
        })
        .await
    }

    async fn put_memory(
        &self,
        key: &ServiceKey,
        if_match: &str,
        agents: BTreeMap<String, Vec<Note>>,
        _actor: &Actor,
    ) -> Result<MemoryDoc, StoreError> {
        checked_key(key)?;
        let (k, if_match) = (key.clone(), if_match.to_string());
        let doc = self
            .run(move |conn| {
                let tx = conn.transaction()?;
                let row = ensure_service(&tx, &k)?;
                let current = memory_of(&tx, &row)?;
                if current.version != if_match {
                    return Err(StoreError::Conflict {
                        current: current.version,
                    });
                }
                let doc = MemoryDoc {
                    version: next_version(row.memory_version)?.to_string(),
                    agents: agents.into_iter().filter(|(_, n)| !n.is_empty()).collect(),
                };
                write_notes(&tx, row.id, &doc)?;
                tx.commit()?;
                Ok(doc)
            })
            .await?;
        self.emit(StoreEvent::MemoryChanged {
            key: key.clone(),
            version: doc.version.clone(),
        });
        Ok(doc)
    }

    async fn list_proposals(&self, filter: &ProposalFilter) -> Result<Vec<Proposal>, StoreError> {
        let filter = filter.clone();
        self.run(move |conn| {
            let mut sql = String::from(PROPOSAL_SELECT);
            let mut clauses: Vec<&str> = Vec::new();
            let mut args: Vec<String> = Vec::new();
            if let Some(s) = filter.status {
                clauses.push("p.status = ?");
                args.push(status_str(s).to_string());
            }
            if let Some(ns) = &filter.namespace {
                clauses.push("s.namespace = ?");
                args.push(ns.clone());
            }
            if let Some(svc) = &filter.service {
                clauses.push("s.service = ?");
                args.push(svc.clone());
            }
            if !clauses.is_empty() {
                sql.push_str(" WHERE ");
                sql.push_str(&clauses.join(" AND "));
            }
            sql.push_str(" ORDER BY p.ts DESC, p.id DESC");
            let mut stmt = conn.prepare(&sql)?;
            let rows =
                stmt.query_map(rusqlite::params_from_iter(args.iter()), proposal_from_row)?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
        .await
    }

    async fn get_proposal(&self, id: &str) -> Result<Proposal, StoreError> {
        let id = id.to_string();
        self.run(move |conn| {
            conn.query_row(
                &format!("{PROPOSAL_SELECT} WHERE p.id = ?1"),
                params![id],
                proposal_from_row,
            )
            .optional()?
            .ok_or(StoreError::NotFound)
        })
        .await
    }

    async fn put_proposal(
        &self,
        proposal: &Proposal,
        dedup_key: Option<&str>,
    ) -> Result<ProposalPut, StoreError> {
        let key = ServiceKey::new(&proposal.namespace, &proposal.service);
        checked_key(&key)?;
        let (k, p, dedup_key) = (key.clone(), proposal.clone(), dedup_key.map(str::to_string));
        let put = self
            .run(move |conn| {
                let tx = conn.transaction()?;
                let row = ensure_service(&tx, &k)?;
                // a decided proposal carries its decision time from the start (the CHECK)
                let decided_at = (p.status != ProposalStatus::Pending).then(|| p.ts.clone());
                match dedup_key {
                    Some(dk) => {
                        let existing: Option<String> = tx
                            .query_row(
                                "SELECT id FROM proposals WHERE service_id = ?1 AND dedup_key = ?2",
                                params![row.id, dk],
                                |r| r.get(0),
                            )
                            .optional()?;
                        if let Some(existing_id) = existing {
                            return Ok(ProposalPut::Duplicate { existing_id });
                        }
                        tx.execute(
                            "INSERT INTO proposals (id, service_id, agent, note, rationale, request_id, \
                             trace_id, ts, status, auto, dedup_key, decided_at) \
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                            params![
                                p.id,
                                row.id,
                                p.agent,
                                p.note,
                                p.rationale,
                                p.request_id,
                                p.trace_id,
                                p.ts,
                                status_str(p.status),
                                i64::from(p.auto),
                                dk,
                                decided_at,
                            ],
                        )?;
                    }
                    None => {
                        let changed = tx.execute(
                            "UPDATE proposals SET agent = ?3, note = ?4, rationale = ?5, request_id = ?6, \
                             trace_id = ?7, ts = ?8, status = ?9, auto = ?10, \
                             decided_at = CASE WHEN ?9 = 'pending' THEN NULL ELSE COALESCE(decided_at, ?11) END \
                             WHERE id = ?1 AND service_id = ?2",
                            params![
                                p.id,
                                row.id,
                                p.agent,
                                p.note,
                                p.rationale,
                                p.request_id,
                                p.trace_id,
                                p.ts,
                                status_str(p.status),
                                i64::from(p.auto),
                                decided_at.clone().unwrap_or_else(now_ts),
                            ],
                        )?;
                        if changed == 0 {
                            return Err(StoreError::NotFound);
                        }
                    }
                }
                tx.commit()?;
                Ok(ProposalPut::Stored)
            })
            .await?;
        if put == ProposalPut::Stored {
            self.emit(StoreEvent::ProposalChanged {
                key,
                id: proposal.id.clone(),
            });
        }
        Ok(put)
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
        Ok(self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect())
    }

    async fn put_pending_adoption(&self, adoption: PendingAdoption) -> Result<(), StoreError> {
        checked_key(&adoption.key)?;
        let k = adoption.key.clone();
        let stored_version = self
            .run(move |conn| {
                Ok(find_service(conn, &k)?
                    .filter(ServiceRow::has_charter)
                    .map(|r| r.version.to_string()))
            })
            .await?;
        if let Some(current) = stored_version {
            return Err(StoreError::Conflict { current });
        }
        let key = adoption.key.clone();
        let sha256 = adoption.sha256.clone();
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key.clone(), adoption);
        self.emit(StoreEvent::AdoptionPending { key, sha256 });
        Ok(())
    }

    async fn take_pending_adoption(
        &self,
        key: &ServiceKey,
        sha256: &str,
    ) -> Result<PendingAdoption, StoreError> {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        match pending.get(key) {
            Some(p) if p.sha256 == sha256 => pending.remove(key).ok_or(StoreError::NotFound),
            _ => Err(StoreError::NotFound),
        }
    }

    async fn append_cp_audit(&self, record: &CpAuditRecord) -> Result<(), StoreError> {
        let record = record.clone();
        self.run(move |conn| {
            let json = serde_json::to_string(&record).map_err(|e| io_err("audit record", e))?;
            conn.execute(
                "INSERT INTO cp_audit (ts, actor, actor_kind, role, action, namespace, service, agent, \
                 from_version, to_version, sha256_before, sha256_after, result, reason, record) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    record.ts,
                    record.actor,
                    kind_str(record.actor_kind),
                    record.role.map(Role::as_str),
                    enum_text(&record.action),
                    record.namespace,
                    record.service,
                    record.agent,
                    record.from_version,
                    record.to_version,
                    record.sha256_before,
                    record.sha256_after,
                    enum_text(&record.result),
                    record.reason,
                    json,
                ],
            )?;
            Ok(())
        })
        .await
    }

    async fn cp_audit(&self, limit: usize) -> Result<Vec<CpAuditRecord>, StoreError> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        self.run(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT record FROM (SELECT seq, record FROM cp_audit ORDER BY seq DESC LIMIT ?1) \
                 ORDER BY seq",
            )?;
            let rows = stmt
                .query_map(params![limit], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            rows.iter()
                .map(|json| serde_json::from_str(json).map_err(|e| io_err("cp_audit record", e)))
                .collect()
        })
        .await
    }

    fn subscribe(&self) -> broadcast::Receiver<StoreEvent> {
        self.tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_schema_applies_and_is_versioned() {
        let conn = Connection::open_in_memory().unwrap();
        prepare(&conn).unwrap();
        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        let fk: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fk, 1);
        // applying it twice is a no-op
        prepare(&conn).unwrap();
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            tables,
            [
                "agent_aliases",
                "agents",
                "charter_versions",
                "cp_audit",
                "notes",
                "proposals",
                "services"
            ]
        );
        // a newer file is refused
        conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        let e = prepare(&conn).unwrap_err().to_string();
        assert!(e.contains("newer embassy"), "{e}");
    }

    #[test]
    fn triggers_keep_versions_honest_and_the_audit_append_only() {
        let conn = Connection::open_in_memory().unwrap();
        prepare(&conn).unwrap();
        conn.execute(
            "INSERT INTO services (namespace, service) VALUES ('shop', 'orders')",
            [],
        )
        .unwrap();
        let insert = |version: i64| {
            conn.execute(
                "INSERT INTO charter_versions (service_id, version, epoch, yaml, json, sha256, ts, actor, actor_kind, actor_role, source) \
                 VALUES (1, ?1, 'e1', 'a: 1', '{\"a\":1}', ?2, '2026-10-24T10:00:00.000Z', 'alice', 'token', 'admin', 'api')",
                params![version, "0".repeat(64)],
            )
        };
        // version 2 before 1: refused; 1 then 2: fine, and the counter follows
        assert!(insert(2).is_err());
        insert(1).unwrap();
        insert(2).unwrap();
        let (version, epoch): (i64, Option<String>) = conn
            .query_row(
                "SELECT version, epoch FROM services WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((version, epoch.as_deref()), (2, Some("e1")));
        assert!(
            conn.execute(
                "UPDATE charter_versions SET yaml = 'b: 2' WHERE version = 1",
                []
            )
            .is_err(),
            "stored versions are immutable"
        );
        assert!(
            conn.execute("UPDATE services SET version = 1 WHERE id = 1", [])
                .is_err(),
            "the counter never goes down"
        );
        // retiring the service drops the history and keeps the counter
        conn.execute("UPDATE services SET epoch = NULL WHERE id = 1", [])
            .unwrap();
        let left: i64 = conn
            .query_row("SELECT count(*) FROM charter_versions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 0);
        let version: i64 = conn
            .query_row("SELECT version FROM services WHERE id = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(version, 2);

        conn.execute(
            "INSERT INTO cp_audit (ts, actor, actor_kind, action, result, record) \
             VALUES ('t', 'alice', 'token', 'login', 'ok', '{}')",
            [],
        )
        .unwrap();
        assert!(
            conn.execute("UPDATE cp_audit SET actor = 'bob'", [])
                .is_err()
        );
        assert!(conn.execute("DELETE FROM cp_audit", []).is_err());

        // a decided proposal stays decided
        conn.execute(
            "INSERT INTO proposals (id, service_id, agent, note, rationale, request_id, trace_id, ts, status, auto, dedup_key) \
             VALUES ('p1', 1, 'ops', 'n', 'r', 'q', 't', 'ts', 'pending', 0, 'd1')",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE proposals SET status = 'approved', decided_at = 'ts2' WHERE id = 'p1'",
            [],
        )
        .unwrap();
        assert!(
            conn.execute(
                "UPDATE proposals SET status = 'rejected' WHERE id = 'p1'",
                []
            )
            .is_err()
        );
        // the same dedup key twice is refused by the unique index
        assert!(
            conn.execute(
                "INSERT INTO proposals (id, service_id, agent, note, rationale, request_id, trace_id, ts, status, auto, dedup_key) \
                 VALUES ('p2', 1, 'ops', 'n', 'r', 'q', 't', 'ts', 'pending', 0, 'd1')",
                [],
            )
            .is_err()
        );
    }

    #[test]
    fn enum_texts_round_trip() {
        for s in [NoteSource::Review, NoteSource::Auto, NoteSource::Manual] {
            assert_eq!(note_source_of(note_source_str(s)), s);
        }
        for s in [
            ProposalStatus::Pending,
            ProposalStatus::Approved,
            ProposalStatus::Rejected,
        ] {
            assert_eq!(status_of(status_str(s)), s);
        }
        assert_eq!(enum_text(&crate::api::types::CpResult::Denied), "denied");
        assert_eq!(
            enum_text(&crate::api::types::CpAction::CharterPut),
            "charter_put"
        );
    }
}
