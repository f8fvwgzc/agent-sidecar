//! The `kubernetes` store (design §8.4): one `Charter` custom resource per service.
//!
//! | What | Where |
//! | --- | --- |
//! | the charter | the CR `spec` (the plain charter without `apiVersion`/`kind`) |
//! | its version | `status.appliedVersion` (a decimal `u64`, +1 per applied change; the CRD's `Version` column); each spec write also sets annotation [`VERSION_ANNOTATION`] and [`SPEC_SHA256_ANNOTATION`] |
//! | the epoch | `metadata.uid` (a new one when the CR is deleted and recreated) |
//! | history | one `apps/v1 ControllerRevision` per version, owned by the Charter, newest [`HISTORY_LIMIT`] kept; `data` holds the YAML exactly as written, `ts`, `actor`, `sha256`, `spec_sha256` and `source` |
//! | memory, proposals | `status.memory` ([`MemoryDoc`]), `status.proposals` ([`Proposal`] plus the sidecar's `dedup_key`), written only by embassy |
//! | progress | `status.observedGeneration`, `status.appliedVersion`, conditions `Valid` and `Synced` ([`KubeStore::set_synced`], reached through [`crate::k8s::report_synced`]) |
//! | pending adoptions | in memory (they are re-offered on every sidecar `Hello`) |
//!
//! **What is trusted.** `spec` and `metadata` (annotations included) are written by whoever may
//! edit `charters`; `status` (the chart grants `charters/status` writes to embassy only) and the
//! ControllerRevisions are embassy's. So the served version is `status.appliedVersion`; the next
//! version is one above both it and the newest revision of the epoch,
//! never below a version that was ever applied, whatever the annotations say; and an existing
//! revision is never overwritten. The annotations only help recognise embassy's own unfinished
//! write (a spec write whose revision or status write did not happen): the annotated version is
//! the newest revision and that revision has the annotated spec hash, or it is one above the
//! newest revision and embassy is the newest `managedFields` writer of the object. Anything else
//! whose `generation` differs from `observedGeneration` is an external change, including a CR
//! someone else created with copied annotations (a restore, a re-applied export: a new epoch,
//! processed as a kubectl create). The validating webhook also refuses changes of the two
//! annotations by anyone but embassy ([`crate::webhook::validate_charter`]).
//!
//! **Changes made with kubectl.** Every spec write embassy makes is followed by a `status` write
//! that sets `observedGeneration` to the `generation` that spec write returned (never one read
//! later: a kubectl edit landing between the two writes stays unobserved and is processed next),
//! so a CR whose `generation` is not its `observedGeneration` was changed by someone else. The
//! watcher (kube-rs `runtime::watcher`, list+watch with bookmarks, a fresh list every
//! [`RESYNC_INTERVAL`]) and every write path process such a CR first: a valid spec becomes the
//! next version (annotations, revision, `Valid=True`, [`StoreEvent::CharterChanged`] with source
//! `kubernetes`); an invalid one gets `Valid=False` with the validator's errors and is never
//! served or pushed (the stored charter stays the last applied revision). Both are audited as
//! `cr_external_edit` with actor `k8s:<last managedFields manager>` (one JSON line on stdout and
//! [`StoreEvent::CpAudit`]). The store runs the charter validator only; the `ControlPlaneConfig`
//! policy is enforced at admission ([`crate::webhook::policy_violations`]).
//!
//! **Size.** etcd refuses objects above its request limit (1.5 MiB by default), and a Charter
//! holds its spec, memory and proposals in one object. Status writes keep the object within
//! [`MAX_OBJECT_BYTES`]: decided proposals are dropped oldest first while it is larger (the only
//! case in which this store forgets a decided proposal; the decisions stay in the control-plane
//! audit); a memory write, a new proposal or an approval that still does not fit is refused with
//! [`StoreError::Invalid`] naming the limit, instead of failing in etcd. The control plane must
//! treat that refusal of a `LearningProposal` as a dropped proposal (log it and keep the stream),
//! as it does for one whose agent does not learn.
//!
//! **Concurrency.** Writes of one service are serialized in this process (a per-service lock);
//! every write carries the `resourceVersion` it read, so a concurrent change anywhere (kubectl,
//! another process) is a conflict, after which the write reads again and retries. Memory and
//! proposal decisions are one `status` replace with the `resourceVersion` that also covers the
//! `spec` they were decided against ([`crate::store::decide_proposal`]).
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use k8s_openapi::api::apps::v1::ControllerRevision;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
use k8s_openapi::apimachinery::pkg::runtime::RawExtension;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;

use super::client::{
    ApiError, CHARTER_GROUP, CHARTER_KIND, CHARTER_VERSION, CharterApi, FIELD_MANAGER,
};
use crate::api::types::CpAuditRecord;
use crate::cp_audit::{CpAction, CpAudit, CpResult, now_ts};
use crate::store::{
    Actor, ActorKind, AgentLearning, ChangeSource, CharterWrite, HistoryEntry, LearningState,
    MemoryDoc, Note, PendingAdoption, Precondition, Proposal, ProposalFilter, ProposalPut,
    ProposalStatus, ProposalVerdict, ServiceKey, Store, StoreError, StoreEvent, StoredCharter,
    decide_proposal,
};

/// The charter version embassy's last spec write stored (written only by embassy; the webhook
/// refuses changes by anyone else).
pub const VERSION_ANNOTATION: &str = "agentsc.io/version";
/// SHA-256 of the canonical JSON of the spec that [`VERSION_ANNOTATION`] names.
pub const SPEC_SHA256_ANNOTATION: &str = "agentsc.io/spec-sha256";
/// The annotations only embassy writes.
pub const PROTECTED_ANNOTATIONS: [&str; 2] = [VERSION_ANNOTATION, SPEC_SHA256_ANNOTATION];
/// ControllerRevision labels: the service, the epoch (Charter uid) and the version.
pub const REVISION_CHARTER_LABEL: &str = "agentsc.io/charter";
pub const REVISION_EPOCH_LABEL: &str = "agentsc.io/epoch";
pub const REVISION_VERSION_LABEL: &str = "agentsc.io/version";
/// Revisions kept per service (design §8.4).
pub const HISTORY_LIMIT: usize = 20;
/// The watcher lists everything again this often (design §8.4).
pub const RESYNC_INTERVAL: Duration = Duration::from_secs(600);
/// Reads and retries of one write after `resourceVersion` conflicts.
pub const MAX_ATTEMPTS: usize = 8;
/// Largest Charter this store writes (its JSON, `metadata` and `status` included): below etcd's
/// default 1.5 MiB request limit, with room for what the API server adds. See the module docs.
pub const MAX_OBJECT_BYTES: usize = 1_400_000;
/// Longest condition message (the validator's errors, `Synced` failures).
pub const MAX_CONDITION_MESSAGE: usize = 4096;

const CONDITION_VALID: &str = "Valid";
const CONDITION_SYNCED: &str = "Synced";

fn api_version() -> String {
    format!("{CHARTER_GROUP}/{CHARTER_VERSION}")
}

fn io(e: impl fmt::Display) -> StoreError {
    StoreError::Io(e.to_string())
}

fn api_err(e: ApiError) -> StoreError {
    match e {
        ApiError::NotFound => StoreError::NotFound,
        ApiError::Refused(m) => StoreError::Invalid(vec![m]),
        other => StoreError::Io(format!("kubernetes: {other}")),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

// ---- reading CR JSON ---------------------------------------------------------------------------

fn str_at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter().try_fold(v, |v, k| v.get(*k))?.as_str()
}

fn i64_at(v: &Value, path: &[&str]) -> i64 {
    path.iter()
        .try_fold(v, |v, k| v.get(*k))
        .and_then(Value::as_i64)
        .unwrap_or(0)
}

/// `(metadata.namespace, metadata.name)`.
pub fn key_of(obj: &Value) -> Option<ServiceKey> {
    Some(ServiceKey::new(
        str_at(obj, &["metadata", "namespace"])?,
        str_at(obj, &["metadata", "name"])?,
    ))
}

fn uid_of(obj: &Value) -> Result<String, StoreError> {
    str_at(obj, &["metadata", "uid"])
        .map(str::to_string)
        .ok_or_else(|| io("the Charter has no metadata.uid"))
}

fn annotation<'a>(obj: &'a Value, name: &str) -> Option<&'a str> {
    obj.get("metadata")?.get("annotations")?.get(name)?.as_str()
}

/// The served version (`status.appliedVersion`, written by embassy only), `None` when the CR
/// never had a valid spec.
pub fn applied_version(obj: &Value) -> Result<Option<u64>, StoreError> {
    match str_at(obj, &["status", "appliedVersion"]) {
        None => Ok(None),
        Some(v) => v.parse::<u64>().map(Some).map_err(|_| {
            io(format!(
                "status.appliedVersion {v:?} is not a decimal version"
            ))
        }),
    }
}

/// The version annotation; anything that is not a decimal `u64` counts as absent (it is only a
/// hint, see the module docs).
pub fn annotated_version(obj: &Value) -> Option<u64> {
    annotation(obj, VERSION_ANNOTATION).and_then(|v| v.parse::<u64>().ok())
}

/// `metadata.generation` is not `status.observedGeneration`: someone other than this store
/// changed the spec (or embassy stopped between its two writes). Unequal rather than ahead: a
/// recreated CR carrying a restored `status` can have an `observedGeneration` above its fresh
/// `generation`.
pub fn needs_processing(obj: &Value) -> bool {
    i64_at(obj, &["metadata", "generation"]) != i64_at(obj, &["status", "observedGeneration"])
}

/// Is embassy the newest writer of the object's `metadata`/`spec` (the newest `managedFields`
/// entry outside `status`, strictly newer than every other manager's)? Times have one-second
/// resolution: a tie is "no", so a lost status write of embassy's is at worst processed as an
/// external change (a new version), never the other way round.
fn embassy_wrote_last(obj: &Value) -> bool {
    let mut embassy: Option<&str> = None;
    let mut others: Option<&str> = None;
    for entry in obj
        .get("metadata")
        .and_then(|m| m.get("managedFields"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if entry.get("subresource").and_then(Value::as_str) == Some("status") {
            continue;
        }
        let time = entry.get("time").and_then(Value::as_str).unwrap_or("");
        let slot = if entry.get("manager").and_then(Value::as_str) == Some(FIELD_MANAGER) {
            &mut embassy
        } else {
            &mut others
        };
        if slot.is_none_or(|t| time > t) {
            *slot = Some(time);
        }
    }
    match (embassy, others) {
        (Some(_), None) => true,
        (Some(e), Some(o)) => e > o,
        (None, _) => false,
    }
}

/// The newest `managedFields` manager that is not embassy and did not write `status` (design
/// §8.4: kubectl edits are audited as `k8s:<last managedFields manager>`).
pub fn last_manager(obj: &Value) -> String {
    let mut best: Option<(&str, &str)> = None;
    for entry in obj
        .get("metadata")
        .and_then(|m| m.get("managedFields"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(manager) = entry.get("manager").and_then(Value::as_str) else {
            continue;
        };
        if manager == FIELD_MANAGER
            || entry.get("subresource").and_then(Value::as_str) == Some("status")
        {
            continue;
        }
        let time = entry.get("time").and_then(Value::as_str).unwrap_or("");
        if best.is_none_or(|(_, t)| time >= t) {
            best = Some((manager, time));
        }
    }
    let manager: String = best
        .map_or("unknown", |(m, _)| m)
        .chars()
        .take(128)
        .collect();
    manager
}

/// Canonical JSON: object keys sorted, members whose value is `null` left out (the API server
/// prunes them), numbers by value (`10.0` and `10` are the same), so the hash of a spec does not
/// change when it makes a round trip through the API server.
fn canonical(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                let f = n.as_f64().unwrap_or(0.0);
                if f.is_finite() && f.fract() == 0.0 && f.abs() < 9.0e15 {
                    out.push_str(&format!("{}", f as i64));
                } else {
                    out.push_str(&format!("{f:?}"));
                }
            }
        }
        Value::String(s) => out.push_str(&Value::String(s.clone()).to_string()),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            let mut first = true;
            let sorted: BTreeMap<&String, &Value> =
                m.iter().filter(|(_, v)| !v.is_null()).collect();
            for (k, x) in sorted {
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                canonical(x, out);
            }
            out.push('}');
        }
    }
}

/// SHA-256 of the canonical JSON of a spec ([`SPEC_SHA256_ANNOTATION`]).
pub fn spec_sha256(spec: &Value) -> String {
    let mut s = String::new();
    canonical(spec, &mut s);
    sha256_hex(s.as_bytes())
}

/// The plain charter document a CR describes, as written (no defaults): `apiVersion`, `kind`,
/// then the spec, with `service.namespace` from `metadata.namespace` when the spec leaves it out.
pub fn plain_charter(obj: &Value) -> Result<Value, StoreError> {
    let spec = obj
        .get("spec")
        .and_then(Value::as_object)
        .ok_or_else(|| StoreError::Invalid(vec!["the Charter has no spec".into()]))?;
    let mut out = Map::new();
    out.insert(
        "apiVersion".into(),
        obj.get("apiVersion")
            .cloned()
            .unwrap_or_else(|| Value::String(api_version())),
    );
    out.insert("kind".into(), Value::String(CHARTER_KIND.into()));
    for (k, v) in spec {
        if k == "service"
            && let Value::Object(svc) = v
            && !svc.contains_key("namespace")
            && let Some(ns) = str_at(obj, &["metadata", "namespace"])
        {
            let mut with_ns = Map::new();
            for (sk, sv) in svc {
                with_ns.insert(sk.clone(), sv.clone());
                if sk == "name" {
                    with_ns.insert("namespace".into(), Value::String(ns.into()));
                }
            }
            if !with_ns.contains_key("namespace") {
                with_ns.insert("namespace".into(), Value::String(ns.into()));
            }
            out.insert(k.clone(), Value::Object(with_ns));
        } else {
            out.insert(k.clone(), v.clone());
        }
    }
    Ok(Value::Object(out))
}

/// The custom-resource document the charter validator reads: `apiVersion`, `kind`,
/// `metadata: {name, namespace}` and `spec` (no `status`, no server-set metadata).
pub fn resource_doc(obj: &Value) -> Value {
    let mut doc = Map::new();
    for k in ["apiVersion", "kind"] {
        if let Some(v) = obj.get(k) {
            doc.insert(k.into(), v.clone());
        }
    }
    let mut meta = Map::new();
    for k in ["name", "namespace"] {
        if let Some(v) = obj.get("metadata").and_then(|m| m.get(k)) {
            meta.insert(k.into(), v.clone());
        }
    }
    doc.insert("metadata".into(), Value::Object(meta));
    if let Some(spec) = obj.get("spec") {
        doc.insert("spec".into(), spec.clone());
    }
    Value::Object(doc)
}

/// The CR `spec` for a charter written through the API (plain or custom-resource form), checked
/// against the service it is written to.
pub fn spec_from_write(key: &ServiceKey, charter_json: &Value) -> Result<Value, StoreError> {
    let invalid = |m: String| StoreError::Invalid(vec![m]);
    let map = charter_json
        .as_object()
        .ok_or_else(|| invalid("the charter is not a mapping".into()))?;
    if agentsc_charter::resource::is_resource(charter_json) {
        for (field, want) in [("name", &key.service), ("namespace", &key.namespace)] {
            if let Some(got) = str_at(charter_json, &["metadata", field])
                && got != want
            {
                return Err(invalid(format!(
                    "metadata.{field} {got:?} is not {want:?} (the service written to)"
                )));
            }
        }
        return map
            .get("spec")
            .cloned()
            .ok_or_else(|| invalid("spec is missing".into()));
    }
    let mut spec = map.clone();
    spec.remove("apiVersion");
    spec.remove("kind");
    let spec = Value::Object(spec);
    if let Some(got) = str_at(&spec, &["service", "name"])
        && got != key.service
    {
        return Err(invalid(format!(
            "service.name {got:?} is not {:?} (the service written to)",
            key.service
        )));
    }
    if let Some(got) = str_at(&spec, &["service", "namespace"])
        && got != key.namespace
    {
        return Err(invalid(format!(
            "service.namespace {got:?} is not {:?} (the service written to)",
            key.namespace
        )));
    }
    Ok(spec)
}

/// Agents whose `learning.enabled` is true in a charter (plain or resource form).
fn learning_agents(charter_json: &Value) -> BTreeSet<String> {
    let doc = match charter_json.get("spec") {
        Some(spec) if charter_json.get("metadata").is_some() => spec,
        _ => charter_json,
    };
    doc.get("agents")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|a| a.get("name").and_then(Value::as_str))
        .filter(|name| AgentLearning::from_charter(charter_json, name).is_some_and(|l| l.enabled))
        .map(str::to_string)
        .collect()
}

// ---- status ---------------------------------------------------------------------------------------

/// One `status.conditions[]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    #[serde(rename = "type")]
    pub type_: String,
    /// `True`, `False` or `Unknown`.
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_transition_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// A proposal as `status.proposals[]` keeps it: the [`Proposal`] and the sidecar's dedup key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StatusProposal {
    id: String,
    namespace: String,
    service: String,
    agent: String,
    note: String,
    rationale: String,
    request_id: String,
    trace_id: String,
    ts: String,
    status: ProposalStatus,
    auto: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dedup_key: Option<String>,
}

impl StatusProposal {
    fn new(p: &Proposal, dedup_key: Option<String>) -> Self {
        Self {
            id: p.id.clone(),
            namespace: p.namespace.clone(),
            service: p.service.clone(),
            agent: p.agent.clone(),
            note: p.note.clone(),
            rationale: p.rationale.clone(),
            request_id: p.request_id.clone(),
            trace_id: p.trace_id.clone(),
            ts: p.ts.clone(),
            status: p.status,
            auto: p.auto,
            dedup_key,
        }
    }

    fn proposal(&self) -> Proposal {
        Proposal {
            id: self.id.clone(),
            namespace: self.namespace.clone(),
            service: self.service.clone(),
            agent: self.agent.clone(),
            note: self.note.clone(),
            rationale: self.rationale.clone(),
            request_id: self.request_id.clone(),
            trace_id: self.trace_id.clone(),
            ts: self.ts.clone(),
            status: self.status,
            auto: self.auto,
        }
    }
}

/// `status` of a Charter (fields this store does not know are kept).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CharterStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    observed_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    applied_version: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    conditions: Vec<Condition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    memory: Option<MemoryDoc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    proposals: Vec<StatusProposal>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl CharterStatus {
    fn of(obj: &Value) -> Result<Self, StoreError> {
        match obj.get("status") {
            None | Some(Value::Null) => Ok(Self::default()),
            Some(s) => Self::deserialize(s).map_err(|e| io(format!("Charter status: {e}"))),
        }
    }

    fn memory(&self) -> MemoryDoc {
        self.memory.clone().unwrap_or_else(|| MemoryDoc {
            version: "0".into(),
            agents: BTreeMap::new(),
        })
    }

    /// Set (or replace) a condition; `lastTransitionTime` moves only when `status` changes.
    fn set_condition(
        &mut self,
        type_: &str,
        status: &str,
        generation: i64,
        reason: &str,
        message: &str,
    ) {
        let message: String = message.chars().take(MAX_CONDITION_MESSAGE).collect();
        let now = now_ts();
        match self.conditions.iter_mut().find(|c| c.type_ == type_) {
            Some(c) => {
                if c.status != status {
                    c.last_transition_time = Some(now);
                }
                c.status = status.into();
                c.observed_generation = Some(generation);
                c.reason = Some(reason.into());
                c.message = Some(message);
            }
            None => self.conditions.push(Condition {
                type_: type_.into(),
                status: status.into(),
                observed_generation: Some(generation),
                last_transition_time: Some(now),
                reason: Some(reason.into()),
                message: Some(message),
            }),
        }
    }

    /// Drop the notes of agents that do not learn in `charter_json` (memory exists only for
    /// agents with learning enabled, design §3); bumps the memory version when it drops any.
    /// Returns the new memory version if it changed.
    fn drop_notes_without_learning(
        &mut self,
        charter_json: &Value,
    ) -> Result<Option<String>, StoreError> {
        let Some(memory) = &mut self.memory else {
            return Ok(None);
        };
        let learning = learning_agents(charter_json);
        let before = memory.agents.len();
        memory.agents.retain(|agent, _| learning.contains(agent));
        if memory.agents.len() == before {
            return Ok(None);
        }
        let next = bump(&memory.version)?;
        memory.version = next.clone();
        Ok(Some(next))
    }

    /// `obj` with this status, within [`MAX_OBJECT_BYTES`] (module docs, **Size**): decided
    /// proposals are dropped oldest first while the object is larger; with
    /// [`Budget::Enforce`] a write that still does not fit is refused.
    fn fit_into(
        &mut self,
        key: &ServiceKey,
        obj: &Value,
        budget: Budget,
    ) -> Result<Value, StoreError> {
        let build = |st: &CharterStatus| -> Result<(Value, usize), StoreError> {
            let mut next = obj.clone();
            if let Some(m) = next.as_object_mut() {
                m.insert("status".into(), serde_json::to_value(st).map_err(io)?);
            }
            let size = serde_json::to_vec(&next).map_err(io)?.len();
            Ok((next, size))
        };
        let (next, size) = build(self)?;
        if size <= MAX_OBJECT_BYTES {
            return Ok(next);
        }
        // oldest decided first; each one frees about its own JSON and a comma
        let mut decided: Vec<usize> = (0..self.proposals.len())
            .filter(|i| self.proposals[*i].status != ProposalStatus::Pending)
            .collect();
        decided.sort_by(|a, b| {
            let (a, b) = (&self.proposals[*a], &self.proposals[*b]);
            a.ts.cmp(&b.ts).then_with(|| a.id.cmp(&b.id))
        });
        let mut drop = vec![false; self.proposals.len()];
        let mut excess = size - MAX_OBJECT_BYTES;
        for i in decided {
            if excess == 0 {
                break;
            }
            let bytes = serde_json::to_vec(&self.proposals[i]).map_or(0, |b| b.len()) + 1;
            excess = excess.saturating_sub(bytes);
            drop[i] = true;
        }
        let mut i = 0;
        self.proposals.retain(|_| {
            let d = drop[i];
            i += 1;
            !d
        });
        let (next, size) = build(self)?;
        if size > MAX_OBJECT_BYTES && budget == Budget::Enforce {
            let pending = self
                .proposals
                .iter()
                .filter(|p| p.status == ProposalStatus::Pending)
                .count();
            return Err(StoreError::Invalid(vec![format!(
                "{key}: the Charter would be {size} bytes, more than the {MAX_OBJECT_BYTES} \
                 this store writes (its spec, memory and {pending} pending proposals); decide \
                 pending proposals or shorten the memory"
            )]));
        }
        Ok(next)
    }
}

/// Whether a status write that does not fit in [`MAX_OBJECT_BYTES`] is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Budget {
    /// Writes that add data (memory, proposals, approvals): refused.
    Enforce,
    /// Bookkeeping (`observedGeneration`, conditions) that must never get stuck: decided
    /// proposals are dropped and the write is made anyway.
    TrimOnly,
}

/// `version + 1` as a decimal string.
fn bump(version: &str) -> Result<String, StoreError> {
    version
        .parse::<u64>()
        .ok()
        .and_then(|v| v.checked_add(1))
        .map(|v| v.to_string())
        .ok_or_else(|| {
            io(format!(
                "version {version:?} is not a decimal u64 below u64::MAX"
            ))
        })
}

// ---- revisions -----------------------------------------------------------------------------------

/// What a revision's `data` holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RevisionData {
    yaml: String,
    ts: String,
    actor: String,
    sha256: String,
    source: ChangeSource,
    /// [`spec_sha256`] of the CR spec this version was written as (what the annotation names).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    spec_sha256: Option<String>,
}

/// `<service>-<first 8 of the uid>-<version>`: unique per epoch, so a recreated service never
/// meets the revisions of its previous life (garbage-collected through their owner reference).
pub fn revision_name(service: &str, uid: &str, version: u64) -> String {
    let short: String = uid
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(8)
        .collect::<String>()
        .to_ascii_lowercase();
    format!("{service}-{short}-{version}")
}

fn revision_selector(service: &str, uid: &str) -> String {
    format!("{REVISION_CHARTER_LABEL}={service},{REVISION_EPOCH_LABEL}={uid}")
}

fn revision_data(rev: &ControllerRevision) -> Option<RevisionData> {
    rev.data
        .as_ref()
        .and_then(|d| RevisionData::deserialize(&d.0).ok())
}

// ---- the store ---------------------------------------------------------------------------------

/// The last applied version this process knows of a service, for telling changes from repeats.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    uid: String,
    version: u64,
}

struct Inner {
    api: Arc<dyn CharterApi>,
    tx: broadcast::Sender<StoreEvent>,
    locks: Mutex<HashMap<ServiceKey, Arc<tokio::sync::Mutex<()>>>>,
    seen: Mutex<HashMap<ServiceKey, Seen>>,
    pending: Mutex<BTreeMap<ServiceKey, PendingAdoption>>,
    out: Mutex<Box<dyn Write + Send>>,
}

/// The `kubernetes` implementation of [`Store`]; see the module docs.
pub struct KubeStore {
    inner: Arc<Inner>,
    watcher: Option<tokio::task::AbortHandle>,
}

impl fmt::Debug for KubeStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KubeStore")
            .field("watching", &self.watcher.is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for KubeStore {
    fn drop(&mut self) {
        if let Some(w) = &self.watcher {
            w.abort();
        }
    }
}

/// What a charter write stores, besides the spec.
struct Applied {
    yaml: String,
    actor: Actor,
    source: ChangeSource,
    /// [`spec_sha256`] of the spec written.
    spec_sha256: String,
}

impl KubeStore {
    /// A store over `api`; `cr_external_edit` lines go to stdout. No watcher runs until
    /// [`Self::spawn_watcher`].
    pub fn new(api: Arc<dyn CharterApi>) -> Self {
        Self::with_writer(api, Box::new(std::io::stdout()))
    }

    /// [`Self::new`] with the control-plane audit lines written to `out`.
    pub fn with_writer(api: Arc<dyn CharterApi>, out: Box<dyn Write + Send>) -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self {
            inner: Arc::new(Inner {
                api,
                tx,
                locks: Mutex::new(HashMap::new()),
                seen: Mutex::new(HashMap::new()),
                pending: Mutex::new(BTreeMap::new()),
                out: Mutex::new(out),
            }),
            watcher: None,
        }
    }

    /// Watch every Charter (list+watch with bookmarks, a fresh list every
    /// [`RESYNC_INTERVAL`]) and process kubectl changes; stops when the store is dropped.
    pub fn spawn_watcher(&mut self, client: kube::Client) {
        let inner = self.inner.clone();
        let task = tokio::spawn(watch_loop(inner, client));
        self.watcher = Some(task.abort_handle());
    }

    /// Process one Charter as the watcher does on an `Apply` event: a spec changed outside this
    /// store becomes the next version (or `Valid=False`), audited as `cr_external_edit`.
    pub async fn observe(&self, obj: &Value) {
        self.inner.on_apply(obj).await;
    }

    /// Process a deleted Charter as the watcher does on a `Delete` event.
    pub fn observe_deleted(&self, obj: &Value) {
        self.inner.on_delete(obj);
    }

    /// The watcher's full list after a (re)start: services this store knew that are not in
    /// `listed` were deleted while it was not watching.
    pub fn observe_listed(&self, listed: &BTreeSet<ServiceKey>) {
        self.inner.on_listed(listed);
    }

    /// Condition `Synced` (design §8.4): `True` when `failures` is empty, else `False` listing
    /// each pod and its `ConfigAck.error` (`(pod, error)` pairs). Nothing is written when the
    /// condition already says exactly that, so the control plane may call it on every ack.
    ///
    /// The control plane holds the store as `Arc<dyn Store>`, whose trait has no ack hook: it
    /// calls [`crate::k8s::report_synced`], which reaches this method for a store opened by
    /// [`crate::k8s::open_store`] and does nothing for other stores.
    pub async fn set_synced(
        &self,
        key: &ServiceKey,
        failures: &[(String, String)],
    ) -> Result<(), StoreError> {
        let (status, reason, message) = if failures.is_empty() {
            (
                "True",
                "Applied",
                "every connected instance applied the charter".to_string(),
            )
        } else {
            let list: Vec<String> = failures.iter().map(|(p, e)| format!("{p}: {e}")).collect();
            ("False", "AckErrors", list.join("; "))
        };
        let message: String = message.chars().take(MAX_CONDITION_MESSAGE).collect();
        let obj = self.inner.get(key).await?.ok_or(StoreError::NotFound)?;
        let unchanged = CharterStatus::of(&obj)?.conditions.iter().any(|c| {
            c.type_ == CONDITION_SYNCED
                && c.status == status
                && c.reason.as_deref() == Some(reason)
                && c.message.as_deref() == Some(message.as_str())
        });
        if unchanged {
            return Ok(());
        }
        self.inner
            .update_status(key, Budget::TrimOnly, |obj, st| {
                st.set_condition(
                    CONDITION_SYNCED,
                    status,
                    i64_at(obj, &["metadata", "generation"]),
                    reason,
                    &message,
                );
                Ok(())
            })
            .await
            .map(|_| ())
    }
}

impl Inner {
    fn lock_for(&self, key: &ServiceKey) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.locks.lock().unwrap_or_else(|p| p.into_inner());
        locks.entry(key.clone()).or_default().clone()
    }

    fn emit(&self, event: StoreEvent) {
        let _ = self.tx.send(event);
    }

    fn remember(&self, key: &ServiceKey, uid: &str, version: u64) {
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        seen.insert(
            key.clone(),
            Seen {
                uid: uid.to_string(),
                version,
            },
        );
    }

    fn forget(&self, key: &ServiceKey) -> Option<Seen> {
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        seen.remove(key)
    }

    /// One `cr_external_edit` line on stdout and [`StoreEvent::CpAudit`].
    fn audit(&self, record: CpAuditRecord) {
        match serde_json::to_string(&record) {
            Ok(mut line) => {
                line.push('\n');
                let mut out = self.out.lock().unwrap_or_else(|p| p.into_inner());
                if let Err(e) = out.write_all(line.as_bytes()).and_then(|()| out.flush()) {
                    tracing::warn!(error = %e, "writing a control-plane audit line failed");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "serializing a control-plane audit record failed")
            }
        }
        self.emit(StoreEvent::CpAudit(Box::new(record)));
    }

    async fn get(&self, key: &ServiceKey) -> Result<Option<Value>, StoreError> {
        self.api
            .get(&key.namespace, &key.service)
            .await
            .map_err(api_err)
    }

    /// Revision `version` of the CR's epoch, if it exists.
    async fn revision(
        &self,
        obj: &Value,
        key: &ServiceKey,
        version: u64,
    ) -> Result<Option<ControllerRevision>, StoreError> {
        let name = revision_name(&key.service, &uid_of(obj)?, version);
        self.api
            .get_revision(&key.namespace, &name)
            .await
            .map_err(api_err)
    }

    /// The YAML of version `version` of the CR's epoch (its revision; for the applied version
    /// of a CR whose revision is missing, the spec rendered as YAML when the annotations name
    /// that version and spec).
    async fn revision_yaml(
        &self,
        obj: &Value,
        key: &ServiceKey,
        version: u64,
    ) -> Result<Option<String>, StoreError> {
        match self.revision(obj, key, version).await? {
            Some(rev) => Ok(revision_data(&rev).map(|d| d.yaml)),
            None => {
                let current = applied_version(obj)? == Some(version)
                    && annotated_version(obj) == Some(version)
                    && obj.get("spec").map(spec_sha256).as_deref()
                        == annotation(obj, SPEC_SHA256_ANNOTATION);
                if current {
                    let plain = plain_charter(obj)?;
                    Ok(Some(serde_yaml_ng::to_string(&plain).map_err(io)?))
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// The applied charter of a CR (`None` when it never had a valid spec).
    async fn applied(
        &self,
        obj: &Value,
        key: &ServiceKey,
    ) -> Result<Option<StoredCharter>, StoreError> {
        let Some(version) = applied_version(obj)? else {
            return Ok(None);
        };
        let yaml = self
            .revision_yaml(obj, key, version)
            .await?
            .ok_or_else(|| {
                io(format!(
                    "{key}: the revision of version {version} is missing"
                ))
            })?;
        let charter_json: Value = serde_yaml_ng::from_str(&yaml).map_err(io)?;
        Ok(Some(StoredCharter {
            epoch: uid_of(obj)?,
            version: version.to_string(),
            yaml,
            charter_json,
        }))
    }

    /// Record version `version` of `obj` (already written) as a ControllerRevision and drop
    /// revisions beyond [`HISTORY_LIMIT`]. A revision of that version that exists already is
    /// never replaced: if it records another spec the write fails (versions are never reused;
    /// the CR is then processed again as a change and gets the next free version).
    async fn record_revision(
        &self,
        obj: &Value,
        key: &ServiceKey,
        version: u64,
        applied: &Applied,
    ) -> Result<(), StoreError> {
        let uid = uid_of(obj)?;
        let name = revision_name(&key.service, &uid, version);
        let data = RevisionData {
            yaml: applied.yaml.clone(),
            ts: now_ts(),
            actor: applied.actor.name.clone(),
            sha256: sha256_hex(applied.yaml.as_bytes()),
            source: applied.source,
            spec_sha256: Some(applied.spec_sha256.clone()),
        };
        let rev = ControllerRevision {
            metadata: ObjectMeta {
                name: Some(name.clone()),
                namespace: Some(key.namespace.clone()),
                labels: Some(BTreeMap::from([
                    (REVISION_CHARTER_LABEL.to_string(), key.service.clone()),
                    (REVISION_EPOCH_LABEL.to_string(), uid.clone()),
                    (REVISION_VERSION_LABEL.to_string(), version.to_string()),
                    (
                        "app.kubernetes.io/managed-by".to_string(),
                        FIELD_MANAGER.to_string(),
                    ),
                ])),
                owner_references: Some(vec![OwnerReference {
                    api_version: api_version(),
                    kind: CHARTER_KIND.into(),
                    name: key.service.clone(),
                    uid: uid.clone(),
                    controller: Some(true),
                    block_owner_deletion: None,
                }]),
                ..Default::default()
            },
            revision: i64::try_from(version).map_err(io)?,
            data: Some(RawExtension(serde_json::to_value(&data).map_err(io)?)),
        };
        match self.api.create_revision(&key.namespace, &rev).await {
            Ok(_) => {}
            Err(ApiError::AlreadyExists(_)) => {
                // a retry of the same write is fine; anything else would reuse a version
                let same = self
                    .api
                    .get_revision(&key.namespace, &name)
                    .await
                    .map_err(api_err)?
                    .as_ref()
                    .and_then(revision_data)
                    .is_some_and(|d| d.spec_sha256.as_deref() == Some(&applied.spec_sha256));
                if !same {
                    return Err(io(format!(
                        "{key}: revision {name} exists with another spec; version {version} is \
                         taken (the Charter is processed again as a change)"
                    )));
                }
            }
            Err(e) => return Err(api_err(e)),
        }
        self.prune_history(key, &uid).await
    }

    /// The lowest version the next write may not go below: the higher of `status.appliedVersion`
    /// and the newest revision of the CR's epoch (the annotations play no part), and that
    /// newest revision.
    async fn floor_version(
        &self,
        obj: &Value,
        key: &ServiceKey,
    ) -> Result<(u64, Option<ControllerRevision>), StoreError> {
        let newest = self
            .revisions(key, &uid_of(obj)?)
            .await?
            .into_iter()
            .find(|r| r.revision > 0);
        let newest_version = newest
            .as_ref()
            .and_then(|r| u64::try_from(r.revision).ok())
            .unwrap_or(0);
        let applied = applied_version(obj)?.unwrap_or(0);
        Ok((newest_version.max(applied), newest))
    }

    async fn revisions(
        &self,
        key: &ServiceKey,
        uid: &str,
    ) -> Result<Vec<ControllerRevision>, StoreError> {
        let mut revs = self
            .api
            .list_revisions(&key.namespace, &revision_selector(&key.service, uid))
            .await
            .map_err(api_err)?;
        // only the ones this epoch owns, newest first
        revs.retain(|r| {
            r.metadata
                .owner_references
                .iter()
                .flatten()
                .any(|o| o.uid == uid)
        });
        revs.sort_by_key(|r| std::cmp::Reverse(r.revision));
        Ok(revs)
    }

    async fn prune_history(&self, key: &ServiceKey, uid: &str) -> Result<(), StoreError> {
        let revs = self.revisions(key, uid).await?;
        for old in revs.iter().skip(HISTORY_LIMIT) {
            if let Some(name) = &old.metadata.name
                && let Err(e) = self.api.delete_revision(&key.namespace, name).await
            {
                tracing::warn!(service = %key, revision = %name, error = %e, "deleting an old charter revision failed");
            }
        }
        Ok(())
    }

    /// Read-modify-write of `status` with the `resourceVersion` read, retried on conflicts.
    /// `f` sees the object as read and its status; its result is returned with the written
    /// object.
    async fn update_status<R>(
        &self,
        key: &ServiceKey,
        budget: Budget,
        mut f: impl FnMut(&Value, &mut CharterStatus) -> Result<R, StoreError>,
    ) -> Result<(Value, R), StoreError> {
        for _ in 0..MAX_ATTEMPTS {
            let obj = self.get(key).await?.ok_or(StoreError::NotFound)?;
            let mut status = CharterStatus::of(&obj)?;
            let out = f(&obj, &mut status)?;
            let next = status.fit_into(key, &obj, budget)?;
            match self
                .api
                .replace_status(&key.namespace, &key.service, &next)
                .await
            {
                Ok(written) => return Ok((written, out)),
                Err(ApiError::Conflict(_)) => continue,
                Err(e) => return Err(api_err(e)),
            }
        }
        Err(io(format!("{key}: too many concurrent changes; try again")))
    }

    /// After a spec write of version `version` that returned `generation`: `observedGeneration`
    /// = that generation (never the one read now: a kubectl edit that landed after the spec
    /// write must stay unobserved, so it is processed next), `appliedVersion`, `Valid=True`, and
    /// the notes of agents that no longer learn dropped. Nothing changes when a later generation
    /// of this object was observed already.
    async fn mark_applied(
        &self,
        key: &ServiceKey,
        version: u64,
        generation: i64,
        charter_json: &Value,
    ) -> Result<Option<String>, StoreError> {
        let (_, memory_changed) = self
            .update_status(key, Budget::TrimOnly, |obj, st| {
                if observed_later(obj, st, generation) {
                    return Ok(None);
                }
                st.observed_generation = Some(generation);
                st.applied_version = Some(version.to_string());
                st.set_condition(
                    CONDITION_VALID,
                    "True",
                    generation,
                    "Applied",
                    &format!("version {version} is valid and applied"),
                );
                st.drop_notes_without_learning(charter_json)
            })
            .await?;
        Ok(memory_changed)
    }

    /// Generation `generation` (the one validated, not one read later) is invalid:
    /// `observedGeneration` and `Valid=False` with the validator's errors.
    async fn mark_invalid(
        &self,
        key: &ServiceKey,
        generation: i64,
        errors: &str,
    ) -> Result<(), StoreError> {
        self.update_status(key, Budget::TrimOnly, |obj, st| {
            if !observed_later(obj, st, generation) {
                st.observed_generation = Some(generation);
                st.set_condition(CONDITION_VALID, "False", generation, "Invalid", errors);
            }
            Ok(())
        })
        .await
        .map(|_| ())
    }

    /// Process a CR whose spec changed outside this store ([`needs_processing`]). Called with
    /// the service's lock held, on a fresh read. `Ok(true)` when it is done, `Ok(false)` after a
    /// conflict (read again and retry).
    async fn process_external(&self, key: &ServiceKey, obj: &Value) -> Result<bool, StoreError> {
        let generation = i64_at(obj, &["metadata", "generation"]);
        let uid = uid_of(obj)?;
        let current = applied_version(obj)?;
        let spec = obj.get("spec").cloned().unwrap_or(Value::Null);
        let hash = spec_sha256(&spec);
        let (floor, newest) = self.floor_version(obj, key).await?;

        // embassy's own write whose revision or status write did not happen: finish it
        if let Some(version) = own_unfinished_write(obj, &hash, floor, newest.as_ref()) {
            let plain = plain_charter(obj)?;
            if version > floor {
                let applied = Applied {
                    yaml: serde_yaml_ng::to_string(&plain).map_err(io)?,
                    actor: system(),
                    source: ChangeSource::Kubernetes,
                    spec_sha256: hash.clone(),
                };
                self.record_revision(obj, key, version, &applied).await?;
            }
            let memory = self.mark_applied(key, version, generation, &plain).await?;
            self.remember(key, &uid, version);
            if current != Some(version) {
                // the served version moved; the write that made it did not say so
                self.emit(StoreEvent::CharterChanged {
                    key: key.clone(),
                    epoch: uid,
                    version: version.to_string(),
                    actor: system(),
                    source: ChangeSource::Kubernetes,
                });
            }
            if let Some(mv) = memory {
                self.emit(StoreEvent::MemoryChanged {
                    key: key.clone(),
                    version: mv,
                });
            }
            return Ok(true);
        }

        let actor = Actor {
            name: format!("k8s:{}", last_manager(obj)),
            kind: ActorKind::K8s,
            role: None,
        };
        let before = match current {
            Some(v) => self.revision_yaml(obj, key, v).await?,
            None => None,
        };
        let mut record = CpAudit::entry(CpAction::CrExternalEdit, &actor, CpResult::Ok);
        record.namespace = Some(key.namespace.clone());
        record.service = Some(key.service.clone());
        record.from_version = current.map(|v| v.to_string());
        record.sha256_before = before.as_ref().map(|y| sha256_hex(y.as_bytes()));

        let doc = resource_doc(obj);
        if let Err(e) = agentsc_charter::Charter::from_value(&doc) {
            let errors = match e {
                agentsc_charter::CharterError::Invalid(list) => list.join("; "),
                other => other.to_string(),
            };
            self.mark_invalid(key, generation, &errors).await?;
            record.result = CpResult::Invalid;
            record.reason = Some(format!(
                "generation {generation} is invalid and was not applied: {errors}"
            ));
            self.audit(record);
            return Ok(true);
        }

        // above everything this epoch ever applied, whatever the annotations say
        let next = floor.checked_add(1).ok_or_else(|| io("version overflow"))?;
        let plain = plain_charter(obj)?;
        let yaml = serde_yaml_ng::to_string(&plain).map_err(io)?;
        let mut updated = obj.clone();
        set_annotations(&mut updated, next, &hash);
        let written = match self
            .api
            .replace(&key.namespace, &key.service, &updated)
            .await
        {
            Ok(w) => w,
            Err(ApiError::Conflict(_)) => return Ok(false),
            Err(e) => return Err(api_err(e)),
        };
        let applied = Applied {
            yaml: yaml.clone(),
            actor: actor.clone(),
            source: ChangeSource::Kubernetes,
            spec_sha256: hash.clone(),
        };
        self.record_revision(&written, key, next, &applied).await?;
        let written_generation = i64_at(&written, &["metadata", "generation"]);
        let memory = self
            .mark_applied(key, next, written_generation, &plain)
            .await?;
        self.remember(key, &uid, next);
        record.to_version = Some(next.to_string());
        record.sha256_after = Some(sha256_hex(yaml.as_bytes()));
        record.reason = Some(format!("generation {generation} applied as version {next}"));
        self.audit(record);
        self.emit(StoreEvent::CharterChanged {
            key: key.clone(),
            epoch: uid,
            version: next.to_string(),
            actor,
            source: ChangeSource::Kubernetes,
        });
        if let Some(mv) = memory {
            self.emit(StoreEvent::MemoryChanged {
                key: key.clone(),
                version: mv,
            });
        }
        Ok(true)
    }

    /// Read `key`, processing an outside change first; with the service's lock held.
    async fn read_current(&self, key: &ServiceKey) -> Result<Option<Value>, StoreError> {
        for _ in 0..MAX_ATTEMPTS {
            let Some(obj) = self.get(key).await? else {
                return Ok(None);
            };
            if !needs_processing(&obj) {
                return Ok(Some(obj));
            }
            self.process_external(key, &obj).await?;
        }
        Err(io(format!("{key}: too many concurrent changes; try again")))
    }

    async fn on_apply(&self, obj: &Value) {
        let Some(key) = key_of(obj) else {
            return;
        };
        if needs_processing(obj) {
            let lock = self.lock_for(&key);
            let _guard = lock.lock().await;
            if let Err(e) = self.read_current(&key).await {
                tracing::warn!(service = %key, error = %e, "processing a changed Charter failed; the next event or resync retries");
            }
            return;
        }
        let (Ok(Some(version)), Some(uid)) =
            (applied_version(obj), str_at(obj, &["metadata", "uid"]))
        else {
            return;
        };
        let previous = {
            let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
            seen.insert(
                key.clone(),
                Seen {
                    uid: uid.to_string(),
                    version,
                },
            )
        };
        // a version this process did not write (another embassy, a restore): tell subscribers
        if let Some(prev) = previous
            && (prev.uid != uid || prev.version < version)
        {
            self.emit(StoreEvent::CharterChanged {
                key,
                epoch: uid.to_string(),
                version: version.to_string(),
                actor: Actor {
                    name: "k8s:unknown".into(),
                    kind: ActorKind::K8s,
                    role: None,
                },
                source: ChangeSource::Kubernetes,
            });
        }
    }

    fn on_delete(&self, obj: &Value) {
        let Some(key) = key_of(obj) else {
            return;
        };
        let uid = str_at(obj, &["metadata", "uid"]).unwrap_or_default();
        let known = {
            let seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
            seen.get(&key).is_some_and(|s| s.uid == uid)
        };
        if known {
            self.forget(&key);
            self.emit(StoreEvent::ServiceDeleted {
                key,
                actor: Actor {
                    name: "k8s:unknown".into(),
                    kind: ActorKind::K8s,
                    role: None,
                },
            });
        }
    }

    fn on_listed(&self, listed: &BTreeSet<ServiceKey>) {
        let gone: Vec<ServiceKey> = {
            let seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
            seen.keys()
                .filter(|k| !listed.contains(*k))
                .cloned()
                .collect()
        };
        for key in gone {
            self.forget(&key);
            self.emit(StoreEvent::ServiceDeleted {
                key,
                actor: Actor {
                    name: "k8s:unknown".into(),
                    kind: ActorKind::K8s,
                    role: None,
                },
            });
        }
    }

    /// All Charters (for the scans over every service).
    async fn list_all(&self) -> Result<Vec<Value>, StoreError> {
        self.api.list().await.map_err(api_err)
    }
}

fn system() -> Actor {
    Actor {
        name: "system".into(),
        kind: ActorKind::System,
        role: None,
    }
}

/// Did this object's status already observe a generation after `generation`? (A restored
/// `status` whose `observedGeneration` is above the object's own `generation` does not count.)
fn observed_later(obj: &Value, st: &CharterStatus, generation: i64) -> bool {
    let observed = st.observed_generation.unwrap_or(0);
    observed > generation && observed <= i64_at(obj, &["metadata", "generation"])
}

/// The version of embassy's own unfinished write that `obj` holds, if it is one (module docs,
/// **What is trusted**). The annotations must name the current spec (`hash`), and either
/// - the annotated version is the newest revision of the epoch, not below
///   `status.appliedVersion` (`== floor`), and that revision was written from this very spec:
///   the status write was lost; or
/// - the annotated version is one above every recorded version (`floor + 1`) and embassy wrote
///   the object last: the revision write was lost.
///
/// A CR created by someone else with copied annotations, or an old manifest re-applied over a
/// newer version, is neither: it is processed as an external change.
fn own_unfinished_write(
    obj: &Value,
    hash: &str,
    floor: u64,
    newest: Option<&ControllerRevision>,
) -> Option<u64> {
    let version = annotated_version(obj)?;
    if annotation(obj, SPEC_SHA256_ANNOTATION) != Some(hash) {
        return None;
    }
    let newest_version = newest.and_then(|r| u64::try_from(r.revision).ok());
    if version == floor && newest_version == Some(version) {
        let recorded = newest.and_then(revision_data).and_then(|d| d.spec_sha256);
        return (recorded.as_deref() == Some(hash)).then_some(version);
    }
    (Some(version) == floor.checked_add(1) && embassy_wrote_last(obj)).then_some(version)
}

fn set_annotations(obj: &mut Value, version: u64, spec_hash: &str) {
    let Some(root) = obj.as_object_mut() else {
        return;
    };
    let meta = root
        .entry("metadata")
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(meta) = meta.as_object_mut() else {
        return;
    };
    let annotations = meta
        .entry("annotations")
        .or_insert_with(|| Value::Object(Map::new()));
    if !annotations.is_object() {
        *annotations = Value::Object(Map::new());
    }
    if let Some(a) = annotations.as_object_mut() {
        a.insert(
            VERSION_ANNOTATION.into(),
            Value::String(version.to_string()),
        );
        a.insert(
            SPEC_SHA256_ANNOTATION.into(),
            Value::String(spec_hash.into()),
        );
    }
}

async fn watch_loop(inner: Arc<Inner>, client: kube::Client) {
    use futures::StreamExt;
    use kube::api::{Api, DynamicObject};
    use kube::runtime::WatchStreamExt;
    use kube::runtime::watcher::{self, Event};

    let api: Api<DynamicObject> = Api::all_with(client, &super::client::charter_resource());
    loop {
        let config = watcher::Config {
            bookmarks: true,
            ..Default::default()
        };
        let stream = watcher::watcher(api.clone(), config).default_backoff();
        let mut stream = std::pin::pin!(stream);
        let resync = tokio::time::sleep(RESYNC_INTERVAL);
        let mut resync = std::pin::pin!(resync);
        let mut listed = BTreeSet::new();
        loop {
            let event = tokio::select! {
                () = &mut resync => break,
                e = stream.next() => e,
            };
            let to_json = |o: &DynamicObject| serde_json::to_value(o).ok();
            match event {
                None => break,
                Some(Err(e)) => tracing::warn!(error = %e, "watching Charters failed; retrying"),
                Some(Ok(Event::Init)) => listed.clear(),
                Some(Ok(Event::InitApply(o))) => {
                    if let Some(v) = to_json(&o) {
                        if let Some(k) = key_of(&v) {
                            listed.insert(k);
                        }
                        inner.on_apply(&v).await;
                    }
                }
                Some(Ok(Event::InitDone)) => inner.on_listed(&listed),
                Some(Ok(Event::Apply(o))) => {
                    if let Some(v) = to_json(&o) {
                        inner.on_apply(&v).await;
                    }
                }
                Some(Ok(Event::Delete(o))) => {
                    if let Some(v) = to_json(&o) {
                        inner.on_delete(&v);
                    }
                }
            }
        }
        tracing::debug!("resyncing the Charter watch");
    }
}

#[async_trait]
impl Store for KubeStore {
    async fn list_services(&self) -> Result<Vec<ServiceKey>, StoreError> {
        let mut keys = Vec::new();
        for obj in self.inner.list_all().await? {
            if let Some(key) = key_of(&obj)
                && applied_version(&obj).ok().flatten().is_some()
            {
                keys.push(key);
            }
        }
        keys.sort();
        keys.dedup();
        Ok(keys)
    }

    async fn get_charter(&self, key: &ServiceKey) -> Result<StoredCharter, StoreError> {
        let obj = self.inner.get(key).await?.ok_or(StoreError::NotFound)?;
        self.inner
            .applied(&obj, key)
            .await?
            .ok_or(StoreError::NotFound)
    }

    async fn put_charter(
        &self,
        key: &ServiceKey,
        precondition: &Precondition,
        write: CharterWrite,
    ) -> Result<StoredCharter, StoreError> {
        let spec = spec_from_write(key, &write.charter_json)?;
        let hash = spec_sha256(&spec);
        let inner = &self.inner;
        let lock = inner.lock_for(key);
        let _guard = lock.lock().await;
        for _ in 0..MAX_ATTEMPTS {
            let existing = inner.read_current(key).await?;
            let (written, version) = match existing {
                None => {
                    if let Precondition::Version(_) = precondition {
                        return Err(StoreError::NotFound);
                    }
                    let mut obj = json!({
                        "apiVersion": api_version(),
                        "kind": CHARTER_KIND,
                        "metadata": {
                            "name": key.service,
                            "namespace": key.namespace,
                            "labels": {"app.kubernetes.io/managed-by": FIELD_MANAGER},
                        },
                        "spec": spec,
                    });
                    set_annotations(&mut obj, 1, &hash);
                    match inner.api.create(&key.namespace, &obj).await {
                        Ok(w) => (w, 1),
                        Err(ApiError::AlreadyExists(_) | ApiError::Conflict(_)) => continue,
                        Err(e) => return Err(api_err(e)),
                    }
                }
                Some(obj) => {
                    let current = applied_version(&obj)?;
                    match (precondition, current) {
                        (Precondition::NotExists, Some(v)) => {
                            return Err(StoreError::Conflict {
                                current: v.to_string(),
                            });
                        }
                        (Precondition::Version(_), None) => return Err(StoreError::NotFound),
                        (Precondition::Version(want), Some(v)) if *want != v.to_string() => {
                            return Err(StoreError::Conflict {
                                current: v.to_string(),
                            });
                        }
                        _ => {}
                    }
                    let next = inner
                        .floor_version(&obj, key)
                        .await?
                        .0
                        .checked_add(1)
                        .ok_or_else(|| io("version overflow"))?;
                    let mut updated = obj.clone();
                    if let Some(m) = updated.as_object_mut() {
                        m.insert("spec".into(), spec.clone());
                    }
                    set_annotations(&mut updated, next, &hash);
                    match inner
                        .api
                        .replace(&key.namespace, &key.service, &updated)
                        .await
                    {
                        Ok(w) => (w, next),
                        Err(ApiError::Conflict(_)) => continue,
                        Err(e) => return Err(api_err(e)),
                    }
                }
            };
            let uid = uid_of(&written)?;
            let applied = Applied {
                yaml: write.yaml.clone(),
                actor: write.actor.clone(),
                source: write.source,
                spec_sha256: hash.clone(),
            };
            inner
                .record_revision(&written, key, version, &applied)
                .await?;
            let generation = i64_at(&written, &["metadata", "generation"]);
            let memory = inner
                .mark_applied(key, version, generation, &write.charter_json)
                .await?;
            inner.remember(key, &uid, version);
            inner.emit(StoreEvent::CharterChanged {
                key: key.clone(),
                epoch: uid.clone(),
                version: version.to_string(),
                actor: write.actor.clone(),
                source: write.source,
            });
            if let Some(mv) = memory {
                inner.emit(StoreEvent::MemoryChanged {
                    key: key.clone(),
                    version: mv,
                });
            }
            return Ok(StoredCharter {
                epoch: uid,
                version: version.to_string(),
                yaml: write.yaml,
                charter_json: write.charter_json,
            });
        }
        Err(io(format!("{key}: too many concurrent changes; try again")))
    }

    async fn history(&self, key: &ServiceKey) -> Result<Vec<HistoryEntry>, StoreError> {
        let obj = self.inner.get(key).await?.ok_or(StoreError::NotFound)?;
        if applied_version(&obj)?.is_none() {
            return Err(StoreError::NotFound);
        }
        let uid = uid_of(&obj)?;
        Ok(self
            .inner
            .revisions(key, &uid)
            .await?
            .iter()
            .filter_map(|r| {
                let d = revision_data(r)?;
                Some(HistoryEntry {
                    version: r.revision.to_string(),
                    ts: d.ts,
                    actor: d.actor,
                    sha256: d.sha256,
                })
            })
            .collect())
    }

    async fn get_revision(&self, key: &ServiceKey, version: &str) -> Result<String, StoreError> {
        let version: u64 = version.parse().map_err(|_| StoreError::NotFound)?;
        let obj = self.inner.get(key).await?.ok_or(StoreError::NotFound)?;
        self.inner
            .revision_yaml(&obj, key, version)
            .await?
            .ok_or(StoreError::NotFound)
    }

    async fn delete_service(
        &self,
        key: &ServiceKey,
        if_match: &str,
        actor: &Actor,
    ) -> Result<(), StoreError> {
        let inner = &self.inner;
        let lock = inner.lock_for(key);
        let _guard = lock.lock().await;
        for _ in 0..MAX_ATTEMPTS {
            let obj = inner.read_current(key).await?.ok_or(StoreError::NotFound)?;
            let current = applied_version(&obj)?.ok_or(StoreError::NotFound)?;
            if current.to_string() != if_match {
                return Err(StoreError::Conflict {
                    current: current.to_string(),
                });
            }
            let uid = uid_of(&obj)?;
            let rv = str_at(&obj, &["metadata", "resourceVersion"]).unwrap_or_default();
            match inner.api.delete(&key.namespace, &key.service, rv).await {
                Ok(()) => {}
                Err(ApiError::Conflict(_)) => continue,
                Err(e) => return Err(api_err(e)),
            }
            // the revisions go with their owner; delete them now rather than at GC time
            if let Ok(revs) = inner.revisions(key, &uid).await {
                for r in revs {
                    if let Some(name) = &r.metadata.name {
                        let _ = inner.api.delete_revision(&key.namespace, name).await;
                    }
                }
            }
            inner.forget(key);
            inner.emit(StoreEvent::ServiceDeleted {
                key: key.clone(),
                actor: actor.clone(),
            });
            return Ok(());
        }
        Err(io(format!("{key}: too many concurrent changes; try again")))
    }

    async fn get_memory(&self, key: &ServiceKey) -> Result<MemoryDoc, StoreError> {
        match self.inner.get(key).await? {
            None => Ok(MemoryDoc {
                version: "0".into(),
                agents: BTreeMap::new(),
            }),
            Some(obj) => Ok(CharterStatus::of(&obj)?.memory()),
        }
    }

    async fn put_memory(
        &self,
        key: &ServiceKey,
        if_match: &str,
        agents: BTreeMap<String, Vec<Note>>,
        _actor: &Actor,
    ) -> Result<MemoryDoc, StoreError> {
        let lock = self.inner.lock_for(key);
        let _guard = lock.lock().await;
        let (_, memory) = self
            .inner
            .update_status(key, Budget::Enforce, |_, st| {
                let current = st.memory();
                if current.version != if_match {
                    return Err(StoreError::Conflict {
                        current: current.version,
                    });
                }
                let next = MemoryDoc {
                    version: bump(&current.version)?,
                    agents: agents.clone(),
                };
                st.memory = Some(next.clone());
                Ok(next)
            })
            .await?;
        self.inner.emit(StoreEvent::MemoryChanged {
            key: key.clone(),
            version: memory.version.clone(),
        });
        Ok(memory)
    }

    async fn list_proposals(&self, filter: &ProposalFilter) -> Result<Vec<Proposal>, StoreError> {
        let objects = match (&filter.namespace, &filter.service) {
            (Some(ns), Some(svc)) => self
                .inner
                .get(&ServiceKey::new(ns.clone(), svc.clone()))
                .await?
                .into_iter()
                .collect(),
            _ => self.inner.list_all().await?,
        };
        let mut out = Vec::new();
        for obj in &objects {
            let Some(key) = key_of(obj) else { continue };
            for p in CharterStatus::of(obj)?.proposals {
                let p = p.proposal();
                // a proposal belongs to the Charter that holds it
                if p.namespace == key.namespace && p.service == key.service && filter.matches(&p) {
                    out.push(p);
                }
            }
        }
        out.sort_by(|a, b| b.ts.cmp(&a.ts).then_with(|| b.id.cmp(&a.id)));
        Ok(out)
    }

    async fn get_proposal(&self, id: &str) -> Result<Proposal, StoreError> {
        let all = self.list_proposals(&ProposalFilter::default()).await?;
        all.into_iter()
            .find(|p| p.id == id)
            .ok_or(StoreError::NotFound)
    }

    async fn put_proposal(
        &self,
        proposal: &Proposal,
        dedup_key: Option<&str>,
    ) -> Result<ProposalPut, StoreError> {
        let key = ServiceKey::new(proposal.namespace.clone(), proposal.service.clone());
        let lock = self.inner.lock_for(&key);
        let _guard = lock.lock().await;
        let (_, put) = self
            .inner
            .update_status(&key, Budget::Enforce, |_, st| {
                match dedup_key {
                    Some(dk) => {
                        if let Some(existing) = st
                            .proposals
                            .iter()
                            .find(|p| p.dedup_key.as_deref() == Some(dk))
                        {
                            return Ok(ProposalPut::Duplicate {
                                existing_id: existing.id.clone(),
                            });
                        }
                        if st.proposals.iter().any(|p| p.id == proposal.id) {
                            return Err(StoreError::Invalid(vec![format!(
                                "a proposal with id {} exists",
                                proposal.id
                            )]));
                        }
                        st.proposals
                            .push(StatusProposal::new(proposal, Some(dk.to_string())));
                    }
                    None => {
                        let slot = st
                            .proposals
                            .iter_mut()
                            .find(|p| p.id == proposal.id)
                            .ok_or(StoreError::NotFound)?;
                        let dk = slot.dedup_key.clone();
                        *slot = StatusProposal::new(proposal, dk);
                    }
                }
                Ok(ProposalPut::Stored)
            })
            .await?;
        if put == ProposalPut::Stored {
            self.inner.emit(StoreEvent::ProposalChanged {
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
        let pending = self.inner.pending.lock().unwrap_or_else(|p| p.into_inner());
        Ok(pending.values().cloned().collect())
    }

    async fn put_pending_adoption(&self, adoption: PendingAdoption) -> Result<(), StoreError> {
        let event = StoreEvent::AdoptionPending {
            key: adoption.key.clone(),
            sha256: adoption.sha256.clone(),
        };
        {
            let mut pending = self.inner.pending.lock().unwrap_or_else(|p| p.into_inner());
            pending.insert(adoption.key.clone(), adoption);
        }
        self.inner.emit(event);
        Ok(())
    }

    async fn take_pending_adoption(
        &self,
        key: &ServiceKey,
        sha256: &str,
    ) -> Result<PendingAdoption, StoreError> {
        let mut pending = self.inner.pending.lock().unwrap_or_else(|p| p.into_inner());
        match pending.get(key) {
            Some(a) if a.sha256 == sha256 => pending.remove(key).ok_or(StoreError::NotFound),
            _ => Err(StoreError::NotFound),
        }
    }

    fn subscribe(&self) -> broadcast::Receiver<StoreEvent> {
        self.inner.tx.subscribe()
    }
}

impl KubeStore {
    async fn decide(
        &self,
        key: &ServiceKey,
        id: &str,
        verdict: ProposalVerdict,
        if_match_memory: &str,
        actor: &Actor,
    ) -> Result<(MemoryDoc, Proposal), StoreError> {
        let inner = &self.inner;
        let lock = inner.lock_for(key);
        let _guard = lock.lock().await;
        let note_id = uuid_v4();
        let ts = now_ts();
        for _ in 0..MAX_ATTEMPTS {
            let obj = inner.read_current(key).await?.ok_or(StoreError::NotFound)?;
            let applied = inner.applied(&obj, key).await?;
            let mut status = CharterStatus::of(&obj)?;
            let memory = status.memory();
            let slot = status
                .proposals
                .iter()
                .position(|p| {
                    p.id == id && p.namespace == key.namespace && p.service == key.service
                })
                .ok_or(StoreError::NotFound)?;
            let proposal = status.proposals[slot].proposal();
            let (new_memory, decided) = decide_proposal(
                LearningState {
                    charter: applied.as_ref().map(|c| &c.charter_json),
                    memory: &memory,
                    proposal: &proposal,
                },
                verdict,
                if_match_memory,
                actor,
                &ts,
                note_id.clone(),
            )?;
            let memory_changed = new_memory.version != memory.version;
            let dk = status.proposals[slot].dedup_key.clone();
            status.proposals[slot] = StatusProposal::new(&decided, dk);
            if memory_changed {
                status.memory = Some(new_memory.clone());
            }
            let next = status.fit_into(key, &obj, Budget::Enforce)?;
            // one replace with the resourceVersion read: a concurrent spec change (learning
            // turned off) or decision makes it fail, and the next attempt decides again
            match inner
                .api
                .replace_status(&key.namespace, &key.service, &next)
                .await
            {
                Ok(_) => {}
                Err(ApiError::Conflict(_)) => continue,
                Err(e) => return Err(api_err(e)),
            }
            if memory_changed {
                inner.emit(StoreEvent::MemoryChanged {
                    key: key.clone(),
                    version: new_memory.version.clone(),
                });
            }
            inner.emit(StoreEvent::ProposalChanged {
                key: key.clone(),
                id: id.to_string(),
            });
            return Ok((new_memory, decided));
        }
        Err(io(format!("{key}: too many concurrent changes; try again")))
    }
}

/// A random UUIDv4 string (note ids).
fn uuid_v4() -> String {
    let mut b: [u8; 16] = rand::random();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
