//! The `file:<dir>` store (design §8.4).
//!
//! Layout under `<dir>`:
//!
//! | Path | What |
//! | --- | --- |
//! | `<ns>/<svc>.charter.yaml` | the current charter, exactly as written |
//! | `.meta/<ns>/<svc>.json` | `{epoch, version}`, plus the last memory version and the history entries (`{version, ts, actor, sha256}`, oldest first) |
//! | `.history/<ns>/<svc>/<version>.yaml` | every stored version |
//! | `.memory/<ns>/<svc>.json` | the memory document (`MemoryDoc`) |
//! | `.proposals/<ns>/<svc>.json` | the proposals, each with the sidecar's `dedup_key` |
//! | `.audit.jsonl` | the control-plane audit log, one JSON line per action |
//! | `.secops.sqlite3` | the AgentSecOps data (agent registry), a SQLite database `embassy serve` opens beside this store ([`crate::secops`]) |
//!
//! Every file is written atomically (a temporary file in the same directory, flushed, then
//! renamed). After a service is deleted its `.meta` file stays with `epoch: null` and the last
//! versions, so versions are never reused and a recreated service gets a new epoch.
//!
//! **External edits.** `<ns>/<svc>.charter.yaml` may be edited by hand (or created, for a new
//! service). The store looks at the files when it opens and then every [`POLL_INTERVAL`]: a
//! changed file (the same content on two polls in a row, so a file being written is never read
//! half way) is validated ([`FileStore::set_validator`]; by default the charter validator and
//! the check that it names the service of its path) and stored as a new version with source
//! `file` (audited as `cr_external_edit`, `result: ok`); an invalid one is ignored and audited as
//! `cr_external_edit` with `result: invalid`, once per content. A removed file is reported the
//! same way and the stored charter stays (`DELETE /services/{ns}/{svc}` deletes a service).
//!
//! Pending adoptions are kept in memory only: a sidecar reports its start-up charter again
//! whenever it connects.
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, Weak};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt as _;
use tokio::sync::{Mutex, broadcast};

use super::{
    Actor, ActorKind, ChangeSource, CharterWrite, HistoryEntry, LearningState, MemoryDoc, Note,
    PendingAdoption, Precondition, Proposal, ProposalFilter, ProposalPut, ProposalVerdict,
    ServiceKey, Store, StoreError, StoreEvent, StoredCharter, decide_proposal, prune_memory,
};
use crate::api::types::{CpAction, CpAuditRecord, CpResult};
use crate::names::is_dns_label;

/// How often the charter files are compared with what is stored.
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Store events a slow subscriber may fall behind before it loses some.
pub const EVENTS_CAPACITY: usize = 1024;
/// The name of the actor of external edits.
pub const FILE_ACTOR: &str = "file";

/// Decides whether an externally edited charter text may be stored for a service, given the
/// charter text it would replace (`None` for a new service): the charter as JSON (the YAML
/// converted as written), or every problem.
pub type ExternalValidator =
    dyn Fn(&ServiceKey, &str, Option<&str>) -> Result<Value, Vec<String>> + Send + Sync + 'static;

/// The YAML text as JSON, converted as written (no defaults filled in).
pub fn yaml_to_json(yaml: &str) -> Result<Value, String> {
    serde_yaml_ng::from_str::<Value>(yaml).map_err(|e| format!("not YAML: {e}"))
}

/// Lowercase hex SHA-256 of a text.
pub fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// The default external-edit check: the charter validator, and the charter names the service of
/// its path.
pub fn default_validator(
    key: &ServiceKey,
    yaml: &str,
    _previous: Option<&str>,
) -> Result<Value, Vec<String>> {
    let charter = agentsc_charter::Charter::from_yaml(yaml).map_err(|e| vec![e.to_string()])?;
    let mut errs = Vec::new();
    if charter.service.name != key.service {
        errs.push(format!(
            "service.name {:?} is not {:?} (the file's name)",
            charter.service.name, key.service
        ));
    }
    if charter.service.namespace != key.namespace {
        errs.push(format!(
            "service.namespace {:?} is not {:?} (the file's directory)",
            charter.service.namespace, key.namespace
        ));
    }
    if !errs.is_empty() {
        return Err(errs);
    }
    yaml_to_json(yaml).map_err(|e| vec![e])
}

fn now_ts() -> String {
    crate::cp_audit::now_ts()
}

fn io_err(what: impl std::fmt::Display, e: impl std::fmt::Display) -> StoreError {
    StoreError::Io(format!("{what}: {e}"))
}

fn next_version(v: &str) -> Result<String, StoreError> {
    v.parse::<u64>()
        .ok()
        .and_then(|n| n.checked_add(1))
        .map(|n| n.to_string())
        .ok_or_else(|| StoreError::Io(format!("version {v:?} is not a decimal u64 below u64::MAX")))
}

fn checked_key(key: &ServiceKey) -> Result<(), StoreError> {
    if is_dns_label(&key.namespace) && is_dns_label(&key.service) {
        Ok(())
    } else {
        Err(StoreError::NotFound)
    }
}

fn zero() -> String {
    "0".to_string()
}

/// `.meta/<ns>/<svc>.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Meta {
    /// `None` once the service was deleted.
    epoch: Option<String>,
    /// The last charter version assigned (`"0"`: none yet).
    version: String,
    /// The last memory version assigned.
    #[serde(default = "zero")]
    memory_version: String,
    /// Oldest first.
    #[serde(default)]
    history: Vec<HistoryEntry>,
}

impl Default for Meta {
    fn default() -> Self {
        Self {
            epoch: None,
            version: zero(),
            memory_version: zero(),
            history: Vec::new(),
        }
    }
}

/// One entry of `.proposals/<ns>/<svc>.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct StoredProposal {
    dedup_key: Option<String>,
    proposal: Proposal,
}

#[derive(Debug, Clone)]
struct Current {
    yaml: String,
    json: Value,
    sha256: String,
}

#[derive(Debug, Clone, Default)]
struct Service {
    meta: Meta,
    current: Option<Current>,
    memory: Option<MemoryDoc>,
    proposals: Vec<StoredProposal>,
    /// The content (SHA-256, or `"missing"`) of the charter file last refused as an external
    /// edit, so that it is audited once.
    ignored: Option<String>,
    /// A changed content seen once by the poll: it is taken in when the next poll sees it
    /// unchanged (an editor that writes in place is never read half way).
    settling: Option<String>,
}

impl Service {
    fn memory(&self) -> MemoryDoc {
        self.memory.clone().unwrap_or_else(|| MemoryDoc {
            version: self.meta.memory_version.clone(),
            agents: BTreeMap::new(),
        })
    }
}

#[derive(Debug, Default)]
struct State {
    services: BTreeMap<ServiceKey, Service>,
    pending: BTreeMap<ServiceKey, PendingAdoption>,
}

/// The `file:<dir>` store; see the module docs.
pub struct FileStore {
    dir: PathBuf,
    state: Mutex<State>,
    tx: broadcast::Sender<StoreEvent>,
    validator: RwLock<Arc<ExternalValidator>>,
    audit_lock: Mutex<()>,
    poll_task: std::sync::Mutex<Option<tokio::task::AbortHandle>>,
}

impl std::fmt::Debug for FileStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileStore").field("dir", &self.dir).finish()
    }
}

impl Drop for FileStore {
    fn drop(&mut self) {
        if let Ok(mut task) = self.poll_task.lock()
            && let Some(t) = task.take()
        {
            t.abort();
        }
    }
}

impl FileStore {
    /// Open (or create) the store in `dir` and watch the charter files every [`POLL_INTERVAL`].
    pub async fn open(dir: impl Into<PathBuf>) -> Result<Arc<Self>, StoreError> {
        Self::open_with_poll(dir, Some(POLL_INTERVAL)).await
    }

    /// [`Self::open`] with another polling interval; `None` looks at the files only when the
    /// store opens and on [`Self::scan`].
    pub async fn open_with_poll(
        dir: impl Into<PathBuf>,
        poll: Option<Duration>,
    ) -> Result<Arc<Self>, StoreError> {
        let dir = dir.into();
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| io_err(dir.display(), e))?;
        let (tx, _) = broadcast::channel(EVENTS_CAPACITY);
        let store = Arc::new(Self {
            state: Mutex::new(State::default()),
            tx,
            validator: RwLock::new(Arc::new(default_validator)),
            audit_lock: Mutex::new(()),
            poll_task: std::sync::Mutex::new(None),
            dir,
        });
        store.load().await?;
        store.scan().await;
        if let Some(every) = poll {
            let weak = Arc::downgrade(&store);
            let task = tokio::spawn(poll_files(weak, every.max(Duration::from_millis(10))));
            if let Ok(mut slot) = store.poll_task.lock() {
                *slot = Some(task.abort_handle());
            }
        }
        Ok(store)
    }

    /// The store's directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Replace the check of external edits (the serve wiring adds the write policy).
    pub fn set_validator(&self, validator: Arc<ExternalValidator>) {
        if let Ok(mut v) = self.validator.write() {
            *v = validator;
        }
    }

    fn validator(&self) -> Arc<ExternalValidator> {
        match self.validator.read() {
            Ok(v) => v.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    fn charter_path(&self, key: &ServiceKey) -> PathBuf {
        self.dir
            .join(&key.namespace)
            .join(format!("{}.charter.yaml", key.service))
    }

    fn meta_path(&self, key: &ServiceKey) -> PathBuf {
        self.dir
            .join(".meta")
            .join(&key.namespace)
            .join(format!("{}.json", key.service))
    }

    fn history_dir(&self, key: &ServiceKey) -> PathBuf {
        self.dir
            .join(".history")
            .join(&key.namespace)
            .join(&key.service)
    }

    fn history_path(&self, key: &ServiceKey, version: &str) -> PathBuf {
        self.history_dir(key).join(format!("{version}.yaml"))
    }

    fn memory_path(&self, key: &ServiceKey) -> PathBuf {
        self.dir
            .join(".memory")
            .join(&key.namespace)
            .join(format!("{}.json", key.service))
    }

    fn proposals_path(&self, key: &ServiceKey) -> PathBuf {
        self.dir
            .join(".proposals")
            .join(&key.namespace)
            .join(format!("{}.json", key.service))
    }

    fn audit_path(&self) -> PathBuf {
        self.dir.join(".audit.jsonl")
    }

    fn emit(&self, event: StoreEvent) {
        // no subscriber is not an error
        let _ = self.tx.send(event);
    }

    /// Read every `.meta` file and what it points to.
    async fn load(&self) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        for (key, path) in list_files(&self.dir.join(".meta"), ".json").await {
            let text = tokio::fs::read_to_string(&path)
                .await
                .map_err(|e| io_err(path.display(), e))?;
            let meta: Meta = serde_json::from_str(&text).map_err(|e| io_err(path.display(), e))?;
            let mut svc = Service {
                meta,
                ..Default::default()
            };
            if svc.meta.epoch.is_some() && svc.meta.version != "0" {
                let hist = self.history_path(&key, &svc.meta.version);
                let yaml = match tokio::fs::read_to_string(&hist).await {
                    Ok(y) => y,
                    // the history copy is missing: the live file is the best there is
                    Err(_) => tokio::fs::read_to_string(self.charter_path(&key))
                        .await
                        .map_err(|e| io_err(hist.display(), e))?,
                };
                let json = yaml_to_json(&yaml).map_err(|e| io_err(hist.display(), e))?;
                svc.current = Some(Current {
                    sha256: sha256_hex(&yaml),
                    yaml,
                    json,
                });
            }
            let mem_path = self.memory_path(&key);
            if let Ok(text) = tokio::fs::read_to_string(&mem_path).await {
                let doc: MemoryDoc =
                    serde_json::from_str(&text).map_err(|e| io_err(mem_path.display(), e))?;
                svc.memory = Some(doc);
            }
            let prop_path = self.proposals_path(&key);
            if let Ok(text) = tokio::fs::read_to_string(&prop_path).await {
                svc.proposals =
                    serde_json::from_str(&text).map_err(|e| io_err(prop_path.display(), e))?;
            }
            state.services.insert(key, svc);
        }
        Ok(())
    }

    /// Compare the charter files with what is stored and take in external edits (see the module
    /// docs) now. The store does this by itself every poll interval, taking in a changed file
    /// once two polls in a row saw the same content.
    pub async fn scan(&self) {
        self.scan_files(false).await;
    }

    async fn scan_files(&self, settle: bool) {
        let found: BTreeMap<ServiceKey, PathBuf> = list_charter_files(&self.dir).await;
        let mut state = self.state.lock().await;
        // a stored charter whose file is gone
        let missing: Vec<ServiceKey> = state
            .services
            .iter()
            .filter(|(k, s)| s.current.is_some() && !found.contains_key(*k))
            .map(|(k, _)| k.clone())
            .collect();
        for key in missing {
            let Some(svc) = state.services.get_mut(&key) else {
                continue;
            };
            if svc.ignored.as_deref() == Some("missing") {
                continue;
            }
            svc.ignored = Some("missing".into());
            let version = svc.meta.version.clone();
            let sha = svc.current.as_ref().map(|c| c.sha256.clone());
            let mut rec = external_record(&key, CpResult::Invalid);
            rec.from_version = Some(version);
            rec.sha256_before = sha;
            rec.reason = Some(format!(
                "{} was removed; the stored charter stays (DELETE /api/v1/services/{}/{} deletes a service)",
                self.charter_path(&key).display(),
                key.namespace,
                key.service
            ));
            self.audit_own(rec).await;
        }
        for (key, path) in found {
            let Ok(text) = tokio::fs::read_to_string(&path).await else {
                continue;
            };
            let sha = sha256_hex(&text);
            let svc = state.services.entry(key.clone()).or_default();
            if svc.current.as_ref().is_some_and(|c| c.sha256 == sha) {
                svc.ignored = None;
                svc.settling = None;
                continue;
            }
            if svc.ignored.as_deref() == Some(sha.as_str()) {
                continue;
            }
            if settle && svc.settling.as_deref() != Some(sha.as_str()) {
                svc.settling = Some(sha);
                continue;
            }
            svc.settling = None;
            let previous = svc.current.as_ref().map(|c| c.yaml.clone());
            let validator = self.validator();
            match validator(&key, &text, previous.as_deref()) {
                Ok(json) => {
                    let actor = Actor {
                        name: FILE_ACTOR.into(),
                        kind: ActorKind::System,
                        role: None,
                    };
                    let before = svc.current.as_ref().map(|c| c.sha256.clone());
                    let from = svc.current.as_ref().map(|_| svc.meta.version.clone());
                    let write = CharterWrite {
                        yaml: text,
                        charter_json: json,
                        actor,
                        source: ChangeSource::File,
                    };
                    match self.commit(&mut state, &key, write, false).await {
                        Ok(stored) => {
                            let mut rec = external_record(&key, CpResult::Ok);
                            rec.from_version = from;
                            rec.to_version = Some(stored.version.clone());
                            rec.sha256_before = before;
                            rec.sha256_after = Some(sha);
                            self.audit_own(rec).await;
                        }
                        Err(e) => {
                            tracing::error!(service = %key, error = %e, "storing an external charter edit failed");
                        }
                    }
                }
                Err(problems) => {
                    let svc = state.services.entry(key.clone()).or_default();
                    svc.ignored = Some(sha.clone());
                    let mut rec = external_record(&key, CpResult::Invalid);
                    rec.from_version = svc.current.as_ref().map(|_| svc.meta.version.clone());
                    rec.sha256_before = svc.current.as_ref().map(|c| c.sha256.clone());
                    rec.sha256_after = Some(sha);
                    rec.reason = Some(format!(
                        "{} is invalid and was ignored: {}",
                        path.display(),
                        problems.join("; ")
                    ));
                    self.audit_own(rec).await;
                }
            }
        }
    }

    /// A control-plane audit record the store produced: stdout, `.audit.jsonl`, subscribers.
    async fn audit_own(&self, rec: CpAuditRecord) {
        if let Ok(mut line) = serde_json::to_string(&rec) {
            line.push('\n');
            let mut out = std::io::stdout().lock();
            let _ = out.write_all(line.as_bytes()).and_then(|()| out.flush());
        }
        if let Err(e) = self.append_cp_audit(&rec).await {
            tracing::error!(error = %e, "persisting a control-plane audit record failed");
        }
        self.emit(StoreEvent::CpAudit(Box::new(rec)));
    }

    /// Store `write` as the next version of `key` (the precondition was checked): history file,
    /// charter file (unless the file already holds it), pruned memory, meta. Emits the events.
    async fn commit(
        &self,
        state: &mut State,
        key: &ServiceKey,
        write: CharterWrite,
        write_file: bool,
    ) -> Result<StoredCharter, StoreError> {
        let svc = state.services.entry(key.clone()).or_default();
        let version = next_version(&svc.meta.version)?;
        let epoch = match (&svc.current, &svc.meta.epoch) {
            (Some(_), Some(e)) => e.clone(),
            _ => uuid::Uuid::new_v4().to_string(),
        };
        let sha = sha256_hex(&write.yaml);
        write_atomic(&self.history_path(key, &version), write.yaml.as_bytes()).await?;
        if write_file {
            write_atomic(&self.charter_path(key), write.yaml.as_bytes()).await?;
        }
        let pruned = prune_memory(&svc.memory(), &write.charter_json);
        if let Some(m) = &pruned {
            write_json(&self.memory_path(key), m).await?;
        }
        let mut meta = svc.meta.clone();
        meta.epoch = Some(epoch.clone());
        meta.version = version.clone();
        if let Some(m) = &pruned {
            meta.memory_version = m.version.clone();
        }
        meta.history.push(HistoryEntry {
            version: version.clone(),
            ts: now_ts(),
            actor: write.actor.name.clone(),
            sha256: sha.clone(),
        });
        write_json(&self.meta_path(key), &meta).await?;
        svc.meta = meta;
        svc.current = Some(Current {
            yaml: write.yaml.clone(),
            json: write.charter_json.clone(),
            sha256: sha,
        });
        svc.ignored = None;
        if let Some(m) = pruned.clone() {
            svc.memory = Some(m);
        }
        state.pending.remove(key);
        self.emit(StoreEvent::CharterChanged {
            key: key.clone(),
            epoch: epoch.clone(),
            version: version.clone(),
            actor: write.actor,
            source: write.source,
        });
        if let Some(m) = pruned {
            self.emit(StoreEvent::MemoryChanged {
                key: key.clone(),
                version: m.version,
            });
        }
        Ok(StoredCharter {
            epoch,
            version,
            yaml: write.yaml,
            charter_json: write.charter_json,
        })
    }

    async fn write_proposals(&self, key: &ServiceKey, svc: &Service) -> Result<(), StoreError> {
        write_json(&self.proposals_path(key), &svc.proposals).await
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
        let mut state = self.state.lock().await;
        let svc = state.services.get_mut(key).ok_or(StoreError::NotFound)?;
        let idx = svc
            .proposals
            .iter()
            .position(|p| p.proposal.id == id)
            .ok_or(StoreError::NotFound)?;
        let memory = svc.memory();
        let (new_memory, decided) = decide_proposal(
            LearningState {
                charter: svc.current.as_ref().map(|c| &c.json),
                memory: &memory,
                proposal: &svc.proposals[idx].proposal,
            },
            verdict,
            if_match,
            actor,
            &now_ts(),
            uuid::Uuid::new_v4().to_string(),
        )?;
        let memory_changed = new_memory.version != memory.version;
        if memory_changed {
            write_json(&self.memory_path(key), &new_memory).await?;
            svc.meta.memory_version = new_memory.version.clone();
            write_json(&self.meta_path(key), &svc.meta).await?;
            svc.memory = Some(new_memory.clone());
        }
        svc.proposals[idx].proposal = decided.clone();
        let snapshot = svc.clone();
        self.write_proposals(key, &snapshot).await?;
        if memory_changed {
            self.emit(StoreEvent::MemoryChanged {
                key: key.clone(),
                version: new_memory.version.clone(),
            });
        }
        self.emit(StoreEvent::ProposalChanged {
            key: key.clone(),
            id: id.to_string(),
        });
        Ok((new_memory, decided))
    }
}

fn external_record(key: &ServiceKey, result: CpResult) -> CpAuditRecord {
    let actor = Actor {
        name: FILE_ACTOR.into(),
        kind: ActorKind::System,
        role: None,
    };
    let mut rec = crate::cp_audit::CpAudit::entry(CpAction::CrExternalEdit, &actor, result);
    rec.namespace = Some(key.namespace.clone());
    rec.service = Some(key.service.clone());
    rec
}

async fn poll_files(store: Weak<FileStore>, every: Duration) {
    loop {
        tokio::time::sleep(every).await;
        let Some(store) = store.upgrade() else {
            return;
        };
        store.scan_files(true).await;
    }
}

/// `<root>/<ns>/<svc><suffix>` for DNS-label namespaces and services.
async fn list_files(root: &Path, suffix: &str) -> Vec<(ServiceKey, PathBuf)> {
    let mut out = Vec::new();
    let Ok(mut namespaces) = tokio::fs::read_dir(root).await else {
        return out;
    };
    while let Ok(Some(ns)) = namespaces.next_entry().await {
        let Some(ns_name) = ns.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !is_dns_label(&ns_name) || !ns.file_type().await.is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Ok(mut files) = tokio::fs::read_dir(ns.path()).await else {
            continue;
        };
        while let Ok(Some(f)) = files.next_entry().await {
            let Some(name) = f.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let Some(svc) = name.strip_suffix(suffix) else {
                continue;
            };
            if is_dns_label(svc) && f.file_type().await.is_ok_and(|t| t.is_file()) {
                out.push((ServiceKey::new(ns_name.clone(), svc), f.path()));
            }
        }
    }
    out
}

async fn list_charter_files(dir: &Path) -> BTreeMap<ServiceKey, PathBuf> {
    list_files(dir, ".charter.yaml").await.into_iter().collect()
}

/// Write `bytes` to `path` atomically: a temporary file next to it, flushed, then renamed.
pub async fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let parent = path
        .parent()
        .ok_or_else(|| io_err(path.display(), "no parent directory"))?;
    tokio::fs::create_dir_all(parent)
        .await
        .map_err(|e| io_err(parent.display(), e))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = parent.join(format!(".{name}.tmp-{}", uuid::Uuid::new_v4().simple()));
    let result = async {
        let mut f = tokio::fs::File::create(&tmp).await?;
        f.write_all(bytes).await?;
        f.sync_all().await?;
        drop(f);
        tokio::fs::rename(&tmp, path).await
    }
    .await;
    if let Err(e) = result {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(io_err(path.display(), e));
    }
    Ok(())
}

async fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), StoreError> {
    let mut text = serde_json::to_string_pretty(value).map_err(|e| io_err(path.display(), e))?;
    text.push('\n');
    write_atomic(path, text.as_bytes()).await
}

async fn remove_if_exists(path: &Path) -> Result<(), StoreError> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_err(path.display(), e)),
    }
}

#[async_trait]
impl Store for FileStore {
    async fn list_services(&self) -> Result<Vec<ServiceKey>, StoreError> {
        let state = self.state.lock().await;
        Ok(state
            .services
            .iter()
            .filter(|(_, s)| s.current.is_some())
            .map(|(k, _)| k.clone())
            .collect())
    }

    async fn get_charter(&self, key: &ServiceKey) -> Result<StoredCharter, StoreError> {
        checked_key(key)?;
        let state = self.state.lock().await;
        let svc = state.services.get(key).ok_or(StoreError::NotFound)?;
        let cur = svc.current.as_ref().ok_or(StoreError::NotFound)?;
        Ok(StoredCharter {
            epoch: svc.meta.epoch.clone().unwrap_or_default(),
            version: svc.meta.version.clone(),
            yaml: cur.yaml.clone(),
            charter_json: cur.json.clone(),
        })
    }

    async fn put_charter(
        &self,
        key: &ServiceKey,
        precondition: &Precondition,
        write: CharterWrite,
    ) -> Result<StoredCharter, StoreError> {
        checked_key(key)?;
        let mut state = self.state.lock().await;
        let current = state
            .services
            .get(key)
            .and_then(|s| s.current.as_ref().map(|_| s.meta.version.clone()));
        match (precondition, current) {
            (Precondition::NotExists, Some(v)) => return Err(StoreError::Conflict { current: v }),
            (Precondition::Version(_), None) => return Err(StoreError::NotFound),
            (Precondition::Version(want), Some(v)) if *want != v => {
                return Err(StoreError::Conflict { current: v });
            }
            _ => {}
        }
        self.commit(&mut state, key, write, true).await
    }

    async fn history(&self, key: &ServiceKey) -> Result<Vec<HistoryEntry>, StoreError> {
        checked_key(key)?;
        let state = self.state.lock().await;
        let svc = state.services.get(key).ok_or(StoreError::NotFound)?;
        if svc.current.is_none() {
            return Err(StoreError::NotFound);
        }
        Ok(svc.meta.history.iter().rev().cloned().collect())
    }

    async fn get_revision(&self, key: &ServiceKey, version: &str) -> Result<String, StoreError> {
        checked_key(key)?;
        let state = self.state.lock().await;
        let svc = state.services.get(key).ok_or(StoreError::NotFound)?;
        if svc.current.is_none() || !svc.meta.history.iter().any(|h| h.version == version) {
            return Err(StoreError::NotFound);
        }
        let path = self.history_path(key, version);
        tokio::fs::read_to_string(&path)
            .await
            .map_err(|e| io_err(path.display(), e))
    }

    async fn delete_service(
        &self,
        key: &ServiceKey,
        if_match: &str,
        actor: &Actor,
    ) -> Result<(), StoreError> {
        checked_key(key)?;
        let mut state = self.state.lock().await;
        let svc = state.services.get_mut(key).ok_or(StoreError::NotFound)?;
        if svc.current.is_none() {
            return Err(StoreError::NotFound);
        }
        if svc.meta.version != if_match {
            return Err(StoreError::Conflict {
                current: svc.meta.version.clone(),
            });
        }
        remove_if_exists(&self.charter_path(key)).await?;
        let hist = self.history_dir(key);
        match tokio::fs::remove_dir_all(&hist).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_err(hist.display(), e)),
        }
        remove_if_exists(&self.memory_path(key)).await?;
        remove_if_exists(&self.proposals_path(key)).await?;
        let meta = Meta {
            epoch: None,
            version: svc.meta.version.clone(),
            memory_version: svc.memory().version,
            history: Vec::new(),
        };
        write_json(&self.meta_path(key), &meta).await?;
        *svc = Service {
            meta,
            ..Default::default()
        };
        self.emit(StoreEvent::ServiceDeleted {
            key: key.clone(),
            actor: actor.clone(),
        });
        Ok(())
    }

    async fn get_memory(&self, key: &ServiceKey) -> Result<MemoryDoc, StoreError> {
        checked_key(key)?;
        let state = self.state.lock().await;
        Ok(state
            .services
            .get(key)
            .map(Service::memory)
            .unwrap_or_else(|| MemoryDoc {
                version: zero(),
                agents: BTreeMap::new(),
            }))
    }

    async fn put_memory(
        &self,
        key: &ServiceKey,
        if_match: &str,
        agents: BTreeMap<String, Vec<Note>>,
        _actor: &Actor,
    ) -> Result<MemoryDoc, StoreError> {
        checked_key(key)?;
        let mut state = self.state.lock().await;
        let svc = state.services.entry(key.clone()).or_default();
        let current = svc.memory();
        if current.version != if_match {
            return Err(StoreError::Conflict {
                current: current.version,
            });
        }
        let doc = MemoryDoc {
            version: next_version(&current.version)?,
            agents: agents.into_iter().filter(|(_, n)| !n.is_empty()).collect(),
        };
        write_json(&self.memory_path(key), &doc).await?;
        svc.meta.memory_version = doc.version.clone();
        write_json(&self.meta_path(key), &svc.meta).await?;
        svc.memory = Some(doc.clone());
        self.emit(StoreEvent::MemoryChanged {
            key: key.clone(),
            version: doc.version.clone(),
        });
        Ok(doc)
    }

    async fn list_proposals(&self, filter: &ProposalFilter) -> Result<Vec<Proposal>, StoreError> {
        let state = self.state.lock().await;
        let mut out: Vec<Proposal> = state
            .services
            .values()
            .flat_map(|s| s.proposals.iter().map(|p| &p.proposal))
            .filter(|p| filter.matches(p))
            .cloned()
            .collect();
        out.sort_by(|a, b| b.ts.cmp(&a.ts).then_with(|| b.id.cmp(&a.id)));
        Ok(out)
    }

    async fn get_proposal(&self, id: &str) -> Result<Proposal, StoreError> {
        let state = self.state.lock().await;
        state
            .services
            .values()
            .flat_map(|s| s.proposals.iter())
            .find(|p| p.proposal.id == id)
            .map(|p| p.proposal.clone())
            .ok_or(StoreError::NotFound)
    }

    async fn put_proposal(
        &self,
        proposal: &Proposal,
        dedup_key: Option<&str>,
    ) -> Result<ProposalPut, StoreError> {
        let key = ServiceKey::new(&proposal.namespace, &proposal.service);
        checked_key(&key)?;
        let mut state = self.state.lock().await;
        let svc = state.services.entry(key.clone()).or_default();
        match dedup_key {
            Some(dk) => {
                if let Some(existing) = svc
                    .proposals
                    .iter()
                    .find(|p| p.dedup_key.as_deref() == Some(dk))
                {
                    return Ok(ProposalPut::Duplicate {
                        existing_id: existing.proposal.id.clone(),
                    });
                }
                svc.proposals.push(StoredProposal {
                    dedup_key: Some(dk.to_string()),
                    proposal: proposal.clone(),
                });
            }
            None => {
                let slot = svc
                    .proposals
                    .iter_mut()
                    .find(|p| p.proposal.id == proposal.id)
                    .ok_or(StoreError::NotFound)?;
                slot.proposal = proposal.clone();
            }
        }
        let snapshot = svc.clone();
        self.write_proposals(&key, &snapshot).await?;
        self.emit(StoreEvent::ProposalChanged {
            key,
            id: proposal.id.clone(),
        });
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
        let state = self.state.lock().await;
        Ok(state.pending.values().cloned().collect())
    }

    async fn put_pending_adoption(&self, adoption: PendingAdoption) -> Result<(), StoreError> {
        checked_key(&adoption.key)?;
        let mut state = self.state.lock().await;
        if state
            .services
            .get(&adoption.key)
            .is_some_and(|s| s.current.is_some())
        {
            return Err(StoreError::Conflict {
                current: state
                    .services
                    .get(&adoption.key)
                    .map(|s| s.meta.version.clone())
                    .unwrap_or_default(),
            });
        }
        let key = adoption.key.clone();
        let sha256 = adoption.sha256.clone();
        state.pending.insert(key.clone(), adoption);
        self.emit(StoreEvent::AdoptionPending { key, sha256 });
        Ok(())
    }

    async fn take_pending_adoption(
        &self,
        key: &ServiceKey,
        sha256: &str,
    ) -> Result<PendingAdoption, StoreError> {
        let mut state = self.state.lock().await;
        match state.pending.get(key) {
            Some(p) if p.sha256 == sha256 => state.pending.remove(key).ok_or(StoreError::NotFound),
            _ => Err(StoreError::NotFound),
        }
    }

    async fn append_cp_audit(&self, record: &CpAuditRecord) -> Result<(), StoreError> {
        let mut line = serde_json::to_string(record).map_err(|e| io_err("audit record", e))?;
        line.push('\n');
        let path = self.audit_path();
        let _guard = self.audit_lock.lock().await;
        let mut f = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .map_err(|e| io_err(path.display(), e))?;
        f.write_all(line.as_bytes())
            .await
            .map_err(|e| io_err(path.display(), e))?;
        f.flush().await.map_err(|e| io_err(path.display(), e))?;
        Ok(())
    }

    async fn cp_audit(&self, limit: usize) -> Result<Vec<CpAuditRecord>, StoreError> {
        let path = self.audit_path();
        let text = {
            let _guard = self.audit_lock.lock().await;
            match tokio::fs::read_to_string(&path).await {
                Ok(t) => t,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(e) => return Err(io_err(path.display(), e)),
            }
        };
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        let mut out = Vec::new();
        for (i, line) in lines
            .iter()
            .enumerate()
            .skip(lines.len().saturating_sub(limit))
        {
            match serde_json::from_str(line) {
                Ok(r) => out.push(r),
                // a line edited by hand is skipped, not the whole log
                Err(e) => {
                    tracing::warn!(path = %path.display(), line = i + 1, error = %e, "unreadable control-plane audit line")
                }
            }
        }
        Ok(out)
    }

    fn subscribe(&self) -> broadcast::Receiver<StoreEvent> {
        self.tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &str = "apiVersion: agentsc.io/v1alpha1\nkind: Charter\nservice: {name: orders, namespace: shop, app_port: 8080}\n";

    #[tokio::test]
    async fn the_poll_takes_in_a_change_once_it_settled() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::open_with_poll(dir.path(), None).await.unwrap();
        let key = ServiceKey::new("shop", "orders");
        std::fs::create_dir_all(dir.path().join("shop")).unwrap();
        std::fs::write(dir.path().join("shop/orders.charter.yaml"), YAML).unwrap();
        // first seen: waits
        store.scan_files(true).await;
        assert_eq!(store.get_charter(&key).await, Err(StoreError::NotFound));
        // changed again before the next poll: waits for that content
        let v2 = YAML.replace("8080", "8081");
        std::fs::write(dir.path().join("shop/orders.charter.yaml"), &v2).unwrap();
        store.scan_files(true).await;
        assert_eq!(store.get_charter(&key).await, Err(StoreError::NotFound));
        // the same content twice: taken in
        store.scan_files(true).await;
        assert_eq!(store.get_charter(&key).await.unwrap().yaml, v2);
        // an explicit scan takes a change in at once
        std::fs::write(dir.path().join("shop/orders.charter.yaml"), YAML).unwrap();
        store.scan().await;
        assert_eq!(store.get_charter(&key).await.unwrap().version, "2");
    }

    #[tokio::test]
    async fn atomic_writes_replace_and_clean_up() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a/b/c.json");
        write_atomic(&path, b"one").await.unwrap();
        write_atomic(&path, b"two").await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        let names: Vec<_> = std::fs::read_dir(dir.path().join("a/b"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["c.json"], "no temporary file is left");
        // a directory in the way: an error, and no temporary file either
        std::fs::create_dir_all(dir.path().join("d/e.json")).unwrap();
        assert!(
            write_atomic(&dir.path().join("d/e.json"), b"x")
                .await
                .is_err()
        );
        let names: Vec<_> = std::fs::read_dir(dir.path().join("d"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["e.json"]);
    }
}
