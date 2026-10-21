//! An in-memory Kubernetes API for the tests of this crate: Charters with the API server's
//! `resourceVersion`, `generation`, `uid` and `managedFields` behaviour and a `status`
//! subresource, ControllerRevisions with owner-reference garbage collection, pods, TokenReviews,
//! Secrets and webhook configurations. Failures can be injected.
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Mutex;

use async_trait::async_trait;
use k8s_openapi::ByteString;
use k8s_openapi::api::apps::v1::ControllerRevision;
use k8s_openapi::api::authentication::v1::TokenReviewStatus;
use k8s_openapi::api::core::v1::{Pod, Secret};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use serde_json::{Value, json};

use super::client::{ApiError, CharterApi, FIELD_MANAGER, KubeApi, WebhookKind};

type Key = (String, String);

/// A kubectl change: the Charter's namespace and name, the field manager, the edit.
type KubectlEdit = (String, String, String, Box<dyn FnOnce(&mut Value) + Send>);

fn key(ns: &str, name: &str) -> Key {
    (ns.to_string(), name.to_string())
}

#[derive(Default)]
struct State {
    rv: u64,
    uids: u64,
    clock: u64,
    charters: BTreeMap<Key, Value>,
    revisions: BTreeMap<Key, ControllerRevision>,
    pods: BTreeMap<Key, Pod>,
    reviews: HashMap<String, TokenReviewStatus>,
    review_requests: Vec<(String, Vec<String>)>,
    secrets: BTreeMap<Key, Secret>,
    webhooks: HashMap<(WebhookKind, String), Value>,
    webhook_patches: Vec<(WebhookKind, String, Value)>,
    /// The next N charter `replace` calls fail with a conflict.
    replace_conflicts: usize,
    /// The next N `replace_status` calls fail with a conflict.
    status_conflicts: usize,
    /// The next charter `replace` is refused (an admission webhook said no).
    refuse_next_replace: Option<String>,
    /// A kubectl change that lands just before the next `replace_status` (a race).
    before_next_status_write: Option<KubectlEdit>,
    refuse_secret_creates: bool,
    /// A Secret that appears when the next create is attempted (a lost race).
    secret_on_next_create: Option<(Key, Secret)>,
    calls: VecDeque<String>,
}

impl State {
    fn next_rv(&mut self) -> String {
        self.rv += 1;
        self.rv.to_string()
    }

    fn tick(&mut self) -> String {
        self.clock += 1;
        format!(
            "2026-10-21T10:{:02}:{:02}Z",
            (self.clock / 60) % 60,
            self.clock % 60
        )
    }

    fn log(&mut self, call: String) {
        self.calls.push_back(call);
    }
}

/// See the module docs.
#[derive(Default)]
pub struct FakeCluster {
    state: Mutex<State>,
}

fn rv_of(v: &Value) -> Option<String> {
    v.get("metadata")?
        .get("resourceVersion")?
        .as_str()
        .map(str::to_string)
}

fn add_managed(obj: &mut Value, manager: &str, time: &str, subresource: Option<&str>) {
    let Some(meta) = obj.get_mut("metadata").and_then(Value::as_object_mut) else {
        return;
    };
    let fields = meta
        .entry("managedFields")
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Some(list) = fields.as_array_mut() {
        // like the API server: one entry per (manager, subresource), its time moves
        list.retain(|e| {
            !(e.get("manager").and_then(Value::as_str) == Some(manager)
                && e.get("subresource").and_then(Value::as_str) == subresource)
        });
        let mut entry = json!({"manager": manager, "operation": "Update", "apiVersion": "agentsc.io/v1alpha1", "time": time});
        if let Some(s) = subresource {
            entry["subresource"] = Value::String(s.into());
        }
        list.push(entry);
    }
}

impl FakeCluster {
    pub fn new() -> Self {
        Self::default()
    }

    fn st(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }

    // ---- inspection and setup -------------------------------------------------------------

    pub fn charter(&self, ns: &str, name: &str) -> Option<Value> {
        self.st().charters.get(&key(ns, name)).cloned()
    }

    pub fn revision_names(&self, ns: &str) -> Vec<String> {
        self.st()
            .revisions
            .keys()
            .filter(|(n, _)| n == ns)
            .map(|(_, name)| name.clone())
            .collect()
    }

    pub fn calls(&self) -> Vec<String> {
        self.st().calls.iter().cloned().collect()
    }

    pub fn fail_replaces_with_conflict(&self, n: usize) {
        self.st().replace_conflicts = n;
    }

    pub fn fail_status_writes_with_conflict(&self, n: usize) {
        self.st().status_conflicts = n;
    }

    pub fn refuse_next_replace(&self, message: &str) {
        self.st().refuse_next_replace = Some(message.to_string());
    }

    /// What `kubectl apply`/`edit` does: create or change a Charter as `manager` (the spec
    /// changes, so `generation` moves; annotations are kept unless `f` changes them). It goes
    /// around the validating webhook (as if it were not installed).
    pub fn kubectl(&self, ns: &str, name: &str, manager: &str, f: impl FnOnce(&mut Value)) {
        Self::kubectl_in(&mut self.st(), ns, name, manager, f);
    }

    /// [`Self::kubectl`] just before embassy's next status write reaches the API server (the
    /// write then conflicts and is retried on a fresh read).
    pub fn kubectl_before_next_status_write(
        &self,
        ns: &str,
        name: &str,
        manager: &str,
        f: impl FnOnce(&mut Value) + Send + 'static,
    ) {
        self.st().before_next_status_write =
            Some((ns.into(), name.into(), manager.into(), Box::new(f)));
    }

    fn kubectl_in(st: &mut State, ns: &str, name: &str, manager: &str, f: impl FnOnce(&mut Value)) {
        let time = st.tick();
        let rv = st.next_rv();
        let k = key(ns, name);
        let existing = st.charters.get(&k).cloned();
        let mut obj = match existing {
            Some(o) => o,
            None => {
                st.uids += 1;
                json!({
                    "apiVersion": "agentsc.io/v1alpha1", "kind": "Charter",
                    "metadata": {"name": name, "namespace": ns,
                                 "uid": format!("00000000-0000-4000-8000-{:012}", st.uids),
                                 "generation": 0, "creationTimestamp": time},
                    "spec": {}
                })
            }
        };
        let before = obj.get("spec").cloned();
        f(&mut obj);
        if obj.get("spec").cloned() != before {
            let g = obj["metadata"]["generation"].as_i64().unwrap_or(0) + 1;
            obj["metadata"]["generation"] = json!(g);
        }
        obj["metadata"]["resourceVersion"] = Value::String(rv);
        add_managed(&mut obj, manager, &time, None);
        st.charters.insert(k, obj);
    }

    /// `kubectl delete` (revisions are garbage-collected with their owner).
    pub fn kubectl_delete(&self, ns: &str, name: &str) -> Option<Value> {
        let mut st = self.st();
        let obj = st.charters.remove(&key(ns, name))?;
        let uid = obj["metadata"]["uid"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        st.revisions.retain(|_, r| {
            !r.metadata
                .owner_references
                .iter()
                .flatten()
                .any(|o| o.uid == uid)
        });
        Some(obj)
    }

    pub fn put_pod(&self, pod: Pod) {
        let ns = pod.metadata.namespace.clone().unwrap_or_default();
        let name = pod.metadata.name.clone().unwrap_or_default();
        self.st().pods.insert(key(&ns, &name), pod);
    }

    pub fn put_token(&self, token: &str, status: TokenReviewStatus) {
        self.st().reviews.insert(token.to_string(), status);
    }

    pub fn review_requests(&self) -> Vec<(String, Vec<String>)> {
        self.st().review_requests.clone()
    }

    pub fn secret(&self, ns: &str, name: &str) -> Option<Secret> {
        self.st().secrets.get(&key(ns, name)).cloned()
    }

    pub fn put_secret(&self, ns: &str, name: &str, data: &[(&str, &str)]) {
        let secret = Self::make_secret(ns, name, data);
        let mut st = self.st();
        let rv = st.next_rv();
        let mut secret = secret;
        secret.metadata.resource_version = Some(rv);
        st.secrets.insert(key(ns, name), secret);
    }

    fn make_secret(ns: &str, name: &str, data: &[(&str, &str)]) -> Secret {
        Secret {
            metadata: ObjectMeta {
                name: Some(name.into()),
                namespace: Some(ns.into()),
                ..Default::default()
            },
            data: Some(
                data.iter()
                    .map(|(k, v)| (k.to_string(), ByteString(v.as_bytes().to_vec())))
                    .collect(),
            ),
            ..Default::default()
        }
    }

    pub fn refuse_secret_creates(&self) {
        self.st().refuse_secret_creates = true;
    }

    pub fn create_secret_on_next_create(&self, ns: &str, name: &str, data: &[(&str, &str)]) {
        self.st().secret_on_next_create = Some((key(ns, name), Self::make_secret(ns, name, data)));
    }

    pub fn put_webhook_config(&self, kind: WebhookKind, name: &str, config: Value) {
        self.st().webhooks.insert((kind, name.to_string()), config);
    }

    pub fn webhook_config(&self, kind: WebhookKind, name: &str) -> Option<Value> {
        self.st().webhooks.get(&(kind, name.to_string())).cloned()
    }

    pub fn webhook_patches(&self) -> Vec<(WebhookKind, String, Value)> {
        self.st().webhook_patches.clone()
    }
}

#[async_trait]
impl KubeApi for FakeCluster {
    async fn token_review(
        &self,
        token: &str,
        audiences: &[String],
    ) -> Result<TokenReviewStatus, ApiError> {
        let mut st = self.st();
        st.review_requests
            .push((token.to_string(), audiences.to_vec()));
        Ok(st.reviews.get(token).cloned().unwrap_or(TokenReviewStatus {
            authenticated: Some(false),
            error: Some("invalid bearer token".into()),
            ..Default::default()
        }))
    }

    async fn get_pod(&self, namespace: &str, name: &str) -> Result<Option<Pod>, ApiError> {
        Ok(self.st().pods.get(&key(namespace, name)).cloned())
    }

    async fn get_secret(&self, namespace: &str, name: &str) -> Result<Option<Secret>, ApiError> {
        Ok(self.st().secrets.get(&key(namespace, name)).cloned())
    }

    async fn create_secret(&self, namespace: &str, secret: &Secret) -> Result<Secret, ApiError> {
        let mut st = self.st();
        let name = secret.metadata.name.clone().unwrap_or_default();
        if let Some((k, s)) = st.secret_on_next_create.take() {
            st.secrets.insert(k, s);
        }
        if st.refuse_secret_creates {
            return Err(ApiError::Refused("secrets is forbidden".into()));
        }
        let k = key(namespace, &name);
        if st.secrets.contains_key(&k) {
            return Err(ApiError::AlreadyExists(format!(
                "secrets {name:?} already exists"
            )));
        }
        let rv = st.next_rv();
        let mut s = secret.clone();
        s.metadata.resource_version = Some(rv);
        st.secrets.insert(k, s.clone());
        st.log(format!("create secret {namespace}/{name}"));
        Ok(s)
    }

    async fn replace_secret(&self, namespace: &str, secret: &Secret) -> Result<Secret, ApiError> {
        let mut st = self.st();
        let name = secret.metadata.name.clone().unwrap_or_default();
        let k = key(namespace, &name);
        let current = st.secrets.get(&k).ok_or(ApiError::NotFound)?;
        if current.metadata.resource_version != secret.metadata.resource_version {
            return Err(ApiError::Conflict("the object has been modified".into()));
        }
        let rv = st.next_rv();
        let mut s = secret.clone();
        s.metadata.resource_version = Some(rv);
        st.secrets.insert(k, s.clone());
        st.log(format!("replace secret {namespace}/{name}"));
        Ok(s)
    }

    async fn get_webhook_config(
        &self,
        kind: WebhookKind,
        name: &str,
    ) -> Result<Option<Value>, ApiError> {
        Ok(self.st().webhooks.get(&(kind, name.to_string())).cloned())
    }

    async fn patch_webhook_config(
        &self,
        kind: WebhookKind,
        name: &str,
        patch: &Value,
    ) -> Result<(), ApiError> {
        let mut st = self.st();
        st.webhook_patches
            .push((kind, name.to_string(), patch.clone()));
        let config = st
            .webhooks
            .get_mut(&(kind, name.to_string()))
            .ok_or(ApiError::NotFound)?;
        // strategic merge of `webhooks` by `name`
        for p in patch["webhooks"].as_array().cloned().unwrap_or_default() {
            let Some(entry) = config["webhooks"]
                .as_array_mut()
                .and_then(|l| l.iter_mut().find(|e| e["name"] == p["name"]))
            else {
                return Err(ApiError::Refused(format!(
                    "webhooks[{}]: the patch adds an entry",
                    p["name"]
                )));
            };
            if let Some(bundle) = p["clientConfig"].get("caBundle") {
                entry["clientConfig"]["caBundle"] = bundle.clone();
            }
        }
        Ok(())
    }
}

#[async_trait]
impl CharterApi for FakeCluster {
    async fn get(&self, namespace: &str, name: &str) -> Result<Option<Value>, ApiError> {
        Ok(self.st().charters.get(&key(namespace, name)).cloned())
    }

    async fn list(&self) -> Result<Vec<Value>, ApiError> {
        Ok(self.st().charters.values().cloned().collect())
    }

    async fn create(&self, namespace: &str, object: &Value) -> Result<Value, ApiError> {
        let mut st = self.st();
        let name = object["metadata"]["name"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let k = key(namespace, &name);
        if st.charters.contains_key(&k) {
            return Err(ApiError::AlreadyExists(format!(
                "charters {name:?} already exists"
            )));
        }
        st.uids += 1;
        let uid = format!("00000000-0000-4000-8000-{:012}", st.uids);
        let time = st.tick();
        let rv = st.next_rv();
        let mut obj = object.clone();
        if let Some(m) = obj.as_object_mut() {
            m.remove("status");
        }
        obj["metadata"]["uid"] = Value::String(uid);
        obj["metadata"]["generation"] = json!(1);
        obj["metadata"]["resourceVersion"] = Value::String(rv);
        obj["metadata"]["creationTimestamp"] = Value::String(time.clone());
        add_managed(&mut obj, FIELD_MANAGER, &time, None);
        st.charters.insert(k, obj.clone());
        st.log(format!("create charter {namespace}/{name}"));
        Ok(obj)
    }

    async fn replace(
        &self,
        namespace: &str,
        name: &str,
        object: &Value,
    ) -> Result<Value, ApiError> {
        let mut st = self.st();
        if let Some(m) = st.refuse_next_replace.take() {
            return Err(ApiError::Refused(m));
        }
        if st.replace_conflicts > 0 {
            st.replace_conflicts -= 1;
            // somebody else wrote in between
            st.next_rv();
            return Err(ApiError::Conflict("the object has been modified".into()));
        }
        let k = key(namespace, name);
        let current = st.charters.get(&k).cloned().ok_or(ApiError::NotFound)?;
        if rv_of(&current) != rv_of(object) {
            return Err(ApiError::Conflict("the object has been modified".into()));
        }
        let time = st.tick();
        let rv = st.next_rv();
        let mut obj = object.clone();
        obj["metadata"]["uid"] = current["metadata"]["uid"].clone();
        obj["metadata"]["creationTimestamp"] = current["metadata"]["creationTimestamp"].clone();
        obj["metadata"]["managedFields"] = current["metadata"]["managedFields"].clone();
        let mut generation = current["metadata"]["generation"].as_i64().unwrap_or(1);
        if obj.get("spec") != current.get("spec") {
            generation += 1;
        }
        obj["metadata"]["generation"] = json!(generation);
        obj["metadata"]["resourceVersion"] = Value::String(rv);
        match current.get("status") {
            Some(s) => obj["status"] = s.clone(),
            None => {
                if let Some(m) = obj.as_object_mut() {
                    m.remove("status");
                }
            }
        }
        add_managed(&mut obj, FIELD_MANAGER, &time, None);
        st.charters.insert(k, obj.clone());
        st.log(format!("replace charter {namespace}/{name}"));
        Ok(obj)
    }

    async fn replace_status(
        &self,
        namespace: &str,
        name: &str,
        object: &Value,
    ) -> Result<Value, ApiError> {
        let mut st = self.st();
        if let Some((ns, name, manager, f)) = st.before_next_status_write.take() {
            Self::kubectl_in(&mut st, &ns, &name, &manager, f);
        }
        if st.status_conflicts > 0 {
            st.status_conflicts -= 1;
            st.next_rv();
            return Err(ApiError::Conflict("the object has been modified".into()));
        }
        let k = key(namespace, name);
        let current = st.charters.get(&k).cloned().ok_or(ApiError::NotFound)?;
        if rv_of(&current) != rv_of(object) {
            return Err(ApiError::Conflict("the object has been modified".into()));
        }
        let time = st.tick();
        let rv = st.next_rv();
        let mut obj = current;
        obj["status"] = object.get("status").cloned().unwrap_or(Value::Null);
        obj["metadata"]["resourceVersion"] = Value::String(rv);
        add_managed(&mut obj, FIELD_MANAGER, &time, Some("status"));
        st.charters.insert(k, obj.clone());
        st.log(format!("replace status {namespace}/{name}"));
        Ok(obj)
    }

    async fn delete(
        &self,
        namespace: &str,
        name: &str,
        resource_version: &str,
    ) -> Result<(), ApiError> {
        let mut st = self.st();
        let k = key(namespace, name);
        let current = st.charters.get(&k).ok_or(ApiError::NotFound)?;
        if rv_of(current).as_deref() != Some(resource_version) {
            return Err(ApiError::Conflict("precondition failed".into()));
        }
        st.charters.remove(&k);
        st.log(format!("delete charter {namespace}/{name}"));
        Ok(())
    }

    async fn list_revisions(
        &self,
        namespace: &str,
        label_selector: &str,
    ) -> Result<Vec<ControllerRevision>, ApiError> {
        let wanted: Vec<(&str, &str)> = label_selector
            .split(',')
            .filter_map(|kv| kv.split_once('='))
            .collect();
        Ok(self
            .st()
            .revisions
            .iter()
            .filter(|((ns, _), _)| ns == namespace)
            .filter(|(_, r)| {
                let labels = r.metadata.labels.clone().unwrap_or_default();
                wanted
                    .iter()
                    .all(|(k, v)| labels.get(*k).map(String::as_str) == Some(*v))
            })
            .map(|(_, r)| r.clone())
            .collect())
    }

    async fn get_revision(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<ControllerRevision>, ApiError> {
        Ok(self.st().revisions.get(&key(namespace, name)).cloned())
    }

    async fn create_revision(
        &self,
        namespace: &str,
        revision: &ControllerRevision,
    ) -> Result<ControllerRevision, ApiError> {
        let mut st = self.st();
        let name = revision.metadata.name.clone().unwrap_or_default();
        let k = key(namespace, &name);
        if st.revisions.contains_key(&k) {
            return Err(ApiError::AlreadyExists(name));
        }
        st.revisions.insert(k, revision.clone());
        st.log(format!("create revision {namespace}/{name}"));
        Ok(revision.clone())
    }

    async fn delete_revision(&self, namespace: &str, name: &str) -> Result<(), ApiError> {
        let mut st = self.st();
        st.revisions.remove(&key(namespace, name));
        st.log(format!("delete revision {namespace}/{name}"));
        Ok(())
    }
}
