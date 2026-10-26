//! Admission webhooks (design §13, component `webhook`), served on `--webhook-addr` with the
//! serving certificate by [`crate::ca_components`]. `AdmissionReview` `admission.k8s.io/v1` in
//! and out.
//!
//! **`/mutate`** (`agentsc-sidecar-injector`, pods labelled `agentsc.io/inject: "true"`): adds
//! two native sidecars (init containers with `restartPolicy: Always`) with a JSONPatch, first
//! `agentsc-runtime` (the agent runtime), then `agentscd` with a `startupProbe` and a
//! `readinessProbe` on its `/readyz` (after start-up a failing `/readyz` takes the pod out of its
//! Service's endpoints: no charter, an expired certificate, the runtime down, or, with
//! `AGENTSC_AUDIT_FAIL_CLOSED`, a failing audit sink).
//! The runtime has a container of its own so that it cannot read what `agentscd` holds (the
//! provider API key in its environment, the workload key in its state directory): containers
//! do not share a process namespace (`/proc/<pid>/environ`), and the runtime mounts only the
//! socket directory. It must come first: the kubelet starts the next init container only when
//! the previous native sidecar has started (and passed its startup probe), and `agentscd`'s
//! `/readyz` waits for the runtime's `Health`. `/readyz` is served by the app API, which listens
//! on `127.0.0.1:3500` only (the app shares the pod's loopback; the kubelet's `httpGet` probes
//! connect to the pod IP and cannot reach it), so the probe is an `exec` of [`READY_COMMAND`]
//! inside the sidecar container. **Image contract:** whatever image is injected (the official
//! `agentscd` image, `--injector-image`, or annotation `agentsc.io/sidecar-image`) runs both
//! containers: its entrypoint is `agentscd`, it has [`RUNTIME_COMMAND`] and [`READY_COMMAND`] on
//! its `PATH`, and [`READY_COMMAND`] exits 0 exactly when `GET http://127.0.0.1:3500/readyz`
//! answers 200; the official image ships them (`docker/agentsc-ready`, which needs `python3`). An
//! image without it never passes the probe: the pod waits [`STARTUP_PROBE_SECONDS`] and the
//! sidecar is restarted. The patch:
//!
//! - `agentscd`, env for managed mode: `AGENTSC_CONTROL_PLANE=embassy.<cp-ns>.svc:15012`,
//!   `AGENTSC_CA_ADDRESS=embassy-ca.<cp-ns>.svc:15012`, `AGENTSC_SERVICE`, `AGENTSC_NAMESPACE`,
//!   `AGENTSC_APP_PORT`, `POD_NAME` and `POD_NAMESPACE` (fieldRef), `AGENTSC_CA_PEM` (the CA
//!   bundle), `AGENTSC_K8S_TOKEN_FILE`, `AGENTSC_TRUST_DOMAIN` (embassy's `--trust-domain`),
//!   `AGENTSC_STATE_DIR` ([`STATE_DIR`]),
//!   `AGENTSC_NO_RUNTIME=true` (the runtime is the other container), and `ANTHROPIC_API_KEY` from
//!   key `ANTHROPIC_API_KEY` of the Secret named by annotation `agentsc.io/anthropic-secret` when
//!   present (on `agentscd` only);
//! - `agentscd` mounts an `emptyDir` at `/run/agentsc` (the Unix sockets), an `emptyDir` at
//!   [`STATE_DIR`] (key, certificate, last charter) and a projected service-account token
//!   (audience `agentsc`, `expirationSeconds: 3600`) at `/var/run/secrets/agentsc/token`, and has
//!   containerPort 50002 `mesh`;
//! - `agentsc-runtime`: the same image, command [`RUNTIME_COMMAND`] with [`RUNTIME_ARGS`] only,
//!   no env but the template's [`RUNTIME_TEMPLATE_ENV`] (no secret, no `ANTHROPIC_API_KEY`), and
//!   only the `/run/agentsc` mount;
//! - image from annotation `agentsc.io/sidecar-image`, else `--injector-image`; with
//!   `sidecar_images.allowed_digests` set it must be pinned to an allowed digest
//!   ([`crate::sidecar_images`]), else the pod is denied with a message naming the image;
//! - `imagePullPolicy`, `resources` and `securityContext` (both containers) and the env
//!   `OTEL_EXPORTER_OTLP_ENDPOINT`, `AGENTSC_OTLP_ENDPOINT_ALLOW`, `AGENTSC_CLUSTER_DOMAIN` and
//!   `AGENTSC_AUDIT_FAIL_CLOSED` (`agentscd`) and `AGENTSC_MOCK_FALLBACK` (both containers: the
//!   runtime reads it) from env
//!   `AGENTSC_INJECT_TEMPLATE` (the chart → injector contract, [`InjectTemplate`]); without it,
//!   the chart's defaults;
//! - annotation `agentsc.io/injected: "true"`.
//!
//! Annotations `agentsc.io/service` (a DNS label) and `agentsc.io/app-port` are required; without
//! them the pod is denied with a message naming what is missing. A labelled pod is also denied,
//! with every problem named, when it brings a container named `agentscd` or `agentsc-runtime` of
//! its own (it would be its own "sidecar"), defines a volume of the sidecar's names, mounts one
//! in another container, projects another service-account token for audience `agentsc` (the
//! `IssueCertificate` credential), or sets `shareProcessNamespace` or `hostPID` (another
//! container could read the sidecar's memory and environment). So the injector never injects
//! twice: a pod that already carries the sidecars (an exported, injected pod applied again) is
//! denied too; create pods from their controller's template. The chart's
//! ValidatingAdmissionPolicy `agentsc-sidecar-integrity` applies the same rules after every
//! mutation, which covers a webhook that was bypassed (`failurePolicy: Ignore`).
//!
//! **`/validate-charter`** (`agentsc-charter-validator`, CREATE/UPDATE of `charters`): the
//! charter validator ([`agentsc_charter::Charter::from_value`] on the whole resource, so unknown
//! fields are refused) and the `ControlPlaneConfig` policy ([`policy_violations`]). An UPDATE by
//! anyone but embassy that changes annotation `agentsc.io/version` or `agentsc.io/spec-sha256`
//! ([`crate::k8s::store::PROTECTED_ANNOTATIONS`]) is refused: they are embassy's record of its
//! own writes, and an old exported manifest re-applied with them would otherwise look like one
//! (a CREATE may carry them: a new Charter is a new epoch, and the store ignores annotations it
//! did not write there). Each decision is a control-plane audit record `cr_external_edit` with
//! actor `k8s:<userInfo.username>` (embassy's own writes, by its service accounts in the
//! control-plane namespace, are validated but not audited here: the store audits what it
//! applies).
//!
//! [`policy_violations`] is the one implementation of the policy check (design §8.2, §8.4: every
//! write passes validator → policy → role-on-diff → skew → store). The REST API's write path
//! must call it too, after the validator, so that admission and the API never disagree (for
//! example on how an `http` tool's origin is normalised).
use std::collections::BTreeMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use k8s_openapi::api::core::v1::{
    Capabilities, Container, ContainerPort, EnvVar, EnvVarSource, ExecAction, ObjectFieldSelector,
    Probe, ProjectedVolumeSource, ResourceRequirements, SeccompProfile, SecretKeySelector,
    SecurityContext, ServiceAccountTokenProjection, Volume, VolumeMount, VolumeProjection,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::ca::CaMaterial;
use crate::config::{ControlPlaneConfig, PolicyConfig, SidecarImagesConfig};
use crate::context::ServeContext;
use crate::cp_audit::{CpAction, CpAudit, CpResult};
use crate::names::{RESERVED_SERVICE, is_dns_label, is_dns_subdomain};
use crate::servingcert::ServingCertSource;
use crate::store::{Actor, ActorKind};

/// Largest admission request body (a Charter and its old object, up to 3 MiB each).
pub const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
pub const INJECT_LABEL: &str = "agentsc.io/inject";
pub const SERVICE_ANNOTATION: &str = "agentsc.io/service";
pub const APP_PORT_ANNOTATION: &str = "agentsc.io/app-port";
pub const ANTHROPIC_SECRET_ANNOTATION: &str = "agentsc.io/anthropic-secret";
pub const SIDECAR_IMAGE_ANNOTATION: &str = "agentsc.io/sidecar-image";
pub const INJECTED_ANNOTATION: &str = "agentsc.io/injected";
/// The injected sidecar container's name (a pod that brings one of its own is denied).
pub const SIDECAR_CONTAINER: &str = "agentscd";
/// The injected agent runtime container's name (a pod that brings one of its own is denied).
pub const RUNTIME_CONTAINER: &str = "agentsc-runtime";
/// The runtime container's command and its only arguments (the sockets in [`RUN_DIR`]).
pub const RUNTIME_COMMAND: &str = "agentsc-runtime";
pub const RUNTIME_ARGS: [&str; 4] = [
    "--listen",
    "unix:/run/agentsc/runtime.sock",
    "--sidecar",
    "unix:/run/agentsc/sidecar.sock",
];
/// The Unix sockets (`sidecar.sock`, `runtime.sock`): the only volume both containers mount.
pub const RUN_VOLUME: &str = "agentsc-run";
pub const RUN_DIR: &str = "/run/agentsc";
/// `agentscd`'s state directory (workload key, certificate, last charter): its own volume, so
/// the runtime, which mounts only [`RUN_VOLUME`], cannot read the key.
pub const STATE_VOLUME: &str = "agentsc-state";
pub const STATE_DIR: &str = "/var/lib/agentsc/state";
pub const TOKEN_VOLUME: &str = "agentsc-token";
pub const TOKEN_DIR: &str = "/var/run/secrets/agentsc";
pub const TOKEN_FILE: &str = "/var/run/secrets/agentsc/token";
pub const TOKEN_AUDIENCE: &str = "agentsc";
pub const TOKEN_EXPIRATION_SECONDS: i64 = 3600;
/// The volumes the injector adds: no other container may mount them.
pub const SIDECAR_VOLUMES: [&str; 3] = [RUN_VOLUME, STATE_VOLUME, TOKEN_VOLUME];
pub const MESH_PORT: i32 = 50002;
/// The startup and readiness probes' command (see the module docs for the image contract).
pub const READY_COMMAND: &str = "agentsc-ready";
/// The readiness probe after start-up: unready after 3 × 10 s of a failing `/readyz`.
const READY_PROBE_PERIOD: i32 = 10;
const READY_PROBE_FAILURES: i32 = 3;
/// Probe period and failures before the sidecar is restarted: 2 s × 150 = 300 s for the first
/// certificate, the charter and the agent runtime.
const STARTUP_PROBE_PERIOD: i32 = 2;
const STARTUP_PROBE_FAILURES: i32 = 150;
pub const STARTUP_PROBE_SECONDS: i32 = STARTUP_PROBE_PERIOD * STARTUP_PROBE_FAILURES;
/// The control-plane Services' gRPC port (design §13).
pub const CONTROL_PLANE_PORT: u16 = 15012;
/// The env var with the chart → injector template.
pub const TEMPLATE_ENV: &str = "AGENTSC_INJECT_TEMPLATE";
/// The only env names the template may set (the sidecar's own telemetry and audit settings, the
/// cluster DNS domain of its peer addresses, and the agent runtime's opt-in to the mock model
/// without `ANTHROPIC_API_KEY`).
pub const TEMPLATE_ENV_ALLOWED: [&str; 5] = [
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "AGENTSC_OTLP_ENDPOINT_ALLOW",
    "AGENTSC_CLUSTER_DOMAIN",
    "AGENTSC_MOCK_FALLBACK",
    "AGENTSC_AUDIT_FAIL_CLOSED",
];
/// The template env the `agentsc-runtime` container gets too: the runtime's own opt-in to the
/// mock model (not a secret). Every other template env is `agentscd`'s only.
pub const RUNTIME_TEMPLATE_ENV: [&str; 1] = ["AGENTSC_MOCK_FALLBACK"];

// ---- the chart → injector template -----------------------------------------------------------------

/// `AGENTSC_INJECT_TEMPLATE`: Kubernetes `Container` fields applied to the generated `agentscd`
/// container (and, except `env` outside [`RUNTIME_TEMPLATE_ENV`], to `agentsc-runtime`). Any other field, or an env name outside
/// [`TEMPLATE_ENV_ALLOWED`], is an error at start-up. A field left out keeps the built-in
/// default (the chart's default values).
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InjectTemplate {
    #[serde(default)]
    pub image_pull_policy: Option<String>,
    #[serde(default)]
    pub resources: Option<ResourceRequirements>,
    #[serde(default)]
    pub security_context: Option<SecurityContext>,
    #[serde(default)]
    pub env: Option<Vec<EnvVar>>,
}

impl InjectTemplate {
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let t: Self =
            serde_json::from_str(text).map_err(|e| anyhow::anyhow!("{TEMPLATE_ENV}: {e}"))?;
        for e in t.env.iter().flatten() {
            if !TEMPLATE_ENV_ALLOWED.contains(&e.name.as_str()) {
                anyhow::bail!(
                    "{TEMPLATE_ENV}: env {:?} may not come from the template (allowed: {})",
                    e.name,
                    TEMPLATE_ENV_ALLOWED.join(", ")
                );
            }
        }
        if let Some(p) = &t.image_pull_policy
            && !matches!(p.as_str(), "Always" | "IfNotPresent" | "Never")
        {
            anyhow::bail!(
                "{TEMPLATE_ENV}: imagePullPolicy {p:?} is not Always, IfNotPresent or Never"
            );
        }
        Ok(t)
    }

    /// From the process env; absent or empty = no template (built-in defaults).
    pub fn from_env() -> anyhow::Result<Self> {
        match std::env::var(TEMPLATE_ENV) {
            Ok(v) if !v.trim().is_empty() => Self::parse(&v),
            _ => Ok(Self::default()),
        }
    }

    fn pull_policy(&self) -> String {
        self.image_pull_policy
            .clone()
            .unwrap_or_else(|| "IfNotPresent".into())
    }

    fn resources(&self) -> ResourceRequirements {
        self.resources.clone().unwrap_or_else(default_resources)
    }

    fn security_context(&self) -> SecurityContext {
        self.security_context
            .clone()
            .unwrap_or_else(default_security_context)
    }
}

/// The chart's `injection.resources` default.
pub fn default_resources() -> ResourceRequirements {
    let q = |s: &str| Quantity(s.to_string());
    ResourceRequirements {
        requests: Some(BTreeMap::from([
            ("cpu".to_string(), q("50m")),
            ("memory".to_string(), q("128Mi")),
        ])),
        limits: Some(BTreeMap::from([("memory".to_string(), q("512Mi"))])),
        ..Default::default()
    }
}

/// The chart's `injection.securityContext` default.
pub fn default_security_context() -> SecurityContext {
    SecurityContext {
        run_as_non_root: Some(true),
        run_as_user: Some(10001),
        run_as_group: Some(10001),
        read_only_root_filesystem: Some(true),
        allow_privilege_escalation: Some(false),
        capabilities: Some(Capabilities {
            drop: Some(vec!["ALL".into()]),
            add: None,
        }),
        seccomp_profile: Some(SeccompProfile {
            type_: "RuntimeDefault".into(),
            localhost_profile: None,
        }),
        ..Default::default()
    }
}

// ---- state ---------------------------------------------------------------------------------------

/// Where `AGENTSC_CA_PEM` comes from: the CA's roots, or the serving certificate's bundle.
#[derive(Clone)]
pub enum CaBundle {
    Ca(Arc<CaMaterial>),
    Serving(Arc<ServingCertSource>),
    Fixed(String),
}

impl CaBundle {
    pub fn pem(&self) -> String {
        match self {
            CaBundle::Ca(ca) => ca.roots_pem().to_string(),
            CaBundle::Serving(s) => s.current().ca_pem.clone(),
            CaBundle::Fixed(p) => p.clone(),
        }
    }
}

/// What the injector needs (the image allow-list comes from the live config, see [`mutate`]).
#[derive(Clone)]
pub struct Injector {
    /// `--injector-image` (a pod may name another with `agentsc.io/sidecar-image`).
    pub image: Option<String>,
    pub template: InjectTemplate,
    pub cp_namespace: String,
    pub ca_bundle: CaBundle,
    /// `--trust-domain`, handed to the sidecar as `AGENTSC_TRUST_DOMAIN`.
    pub trust_domain: String,
}

/// The webhook handlers' state.
pub struct WebhookState {
    pub injector: Injector,
    pub config: Arc<ArcSwap<ControlPlaneConfig>>,
    pub cp_audit: Arc<CpAudit>,
}

impl WebhookState {
    /// From the serve context and env `AGENTSC_INJECT_TEMPLATE`.
    pub fn from_context(ctx: &ServeContext) -> anyhow::Result<Self> {
        let ca_bundle = match (&ctx.ca, &ctx.serving) {
            (Some(ca), _) => CaBundle::Ca(ca.clone()),
            (None, Some(s)) => CaBundle::Serving(s.clone()),
            (None, None) => {
                anyhow::bail!("the webhook component needs the CA or the serving certificate")
            }
        };
        Ok(Self {
            injector: Injector {
                image: ctx.args.injector_image.clone(),
                template: InjectTemplate::from_env()?,
                cp_namespace: ctx.args.cp_namespace.clone(),
                ca_bundle,
                trust_domain: ctx.args.trust_domain.clone(),
            },
            config: ctx.config.clone(),
            cp_audit: ctx.cp_audit.clone(),
        })
    }
}

/// `/mutate`, `/validate-charter` and `/healthz`.
pub fn router(state: Arc<WebhookState>) -> Router {
    Router::new()
        .route("/mutate", post(mutate_handler))
        .route("/validate-charter", post(validate_handler))
        .route("/healthz", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

// ---- AdmissionReview v1 ------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserInfo {
    #[serde(default)]
    pub username: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionRequest {
    pub uid: String,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub operation: String,
    #[serde(default)]
    pub user_info: UserInfo,
    #[serde(default)]
    pub object: Option<Value>,
    #[serde(default)]
    pub old_object: Option<Value>,
    #[serde(default)]
    pub dry_run: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdmissionReview {
    #[serde(default)]
    api_version: Option<String>,
    #[serde(default)]
    request: Option<AdmissionRequest>,
}

/// One webhook decision.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub allowed: bool,
    /// HTTP-like code and message when denied.
    pub status: Option<(u16, String)>,
    /// JSONPatch operations (mutate only).
    pub patch: Vec<Value>,
}

impl Decision {
    fn allow() -> Self {
        Self {
            allowed: true,
            status: None,
            patch: Vec::new(),
        }
    }

    fn patch(ops: Vec<Value>) -> Self {
        Self {
            allowed: true,
            status: None,
            patch: ops,
        }
    }

    fn deny(code: u16, message: impl Into<String>) -> Self {
        Self {
            allowed: false,
            status: Some((code, message.into())),
            patch: Vec::new(),
        }
    }

    /// The `AdmissionReview` response for request `uid`.
    pub fn into_review(self, uid: &str) -> Value {
        let mut response = Map::new();
        response.insert("uid".into(), Value::String(uid.to_string()));
        response.insert("allowed".into(), Value::Bool(self.allowed));
        if let Some((code, message)) = self.status {
            response.insert("status".into(), json!({"code": code, "message": message}));
        }
        if !self.patch.is_empty() {
            let bytes = serde_json::to_vec(&Value::Array(self.patch)).unwrap_or_default();
            response.insert("patchType".into(), Value::String("JSONPatch".into()));
            response.insert(
                "patch".into(),
                Value::String(base64::engine::general_purpose::STANDARD.encode(bytes)),
            );
        }
        json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": Value::Object(response),
        })
    }
}

/// The request of an `admission.k8s.io/v1` review, or why the body is not one (a 400).
fn parse_review(body: &[u8]) -> Result<AdmissionRequest, String> {
    let review: AdmissionReview =
        serde_json::from_slice(body).map_err(|e| format!("not an AdmissionReview: {e}"))?;
    if review
        .api_version
        .as_deref()
        .is_some_and(|v| v != "admission.k8s.io/v1")
    {
        return Err("only admission.k8s.io/v1 AdmissionReviews are served".into());
    }
    review
        .request
        .ok_or_else(|| "the AdmissionReview has no request".into())
}

async fn mutate_handler(State(state): State<Arc<WebhookState>>, body: Bytes) -> Response {
    let req = match parse_review(&body) {
        Ok(r) => r,
        Err(why) => return (StatusCode::BAD_REQUEST, why).into_response(),
    };
    let decision = mutate(&state.injector, &state.config.load().sidecar_images, &req);
    if !decision.allowed {
        tracing::info!(
            namespace = req.namespace.as_deref().unwrap_or(""),
            reason = decision.status.as_ref().map_or("", |s| s.1.as_str()),
            "sidecar injection denied a pod"
        );
    }
    axum::Json(decision.into_review(&req.uid)).into_response()
}

async fn validate_handler(State(state): State<Arc<WebhookState>>, body: Bytes) -> Response {
    let req = match parse_review(&body) {
        Ok(r) => r,
        Err(why) => return (StatusCode::BAD_REQUEST, why).into_response(),
    };
    let decision = validate_charter(&state, &req).await;
    axum::Json(decision.into_review(&req.uid)).into_response()
}

// ---- /mutate ---------------------------------------------------------------------------------------

/// A JSON pointer token (`/` → `~1`, `~` → `~0`).
fn escape(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

/// Every container of the pod (`containers`, `initContainers`, `ephemeralContainers`).
fn all_containers(pod: &Value) -> impl Iterator<Item = &Value> {
    ["containers", "initContainers", "ephemeralContainers"]
        .into_iter()
        .filter_map(|list| pod.get("spec")?.get(list)?.as_array())
        .flatten()
}

fn name_of(v: &Value) -> &str {
    v.get("name").and_then(Value::as_str).unwrap_or_default()
}

/// What the pod itself does that would weaken the sidecar (module docs), one message each.
fn sidecar_conflicts(pod: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    let spec = pod.get("spec");
    for c in all_containers(pod) {
        let name = name_of(c);
        if crate::sidecar_images::SIDECAR_CONTAINERS.contains(&name) {
            problems.push(format!(
                "the pod already has a container named {name:?}: the injector adds the sidecar \
                 containers, a pod may not bring its own"
            ));
            continue;
        }
        for m in c
            .get("volumeMounts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let volume = name_of(m);
            if SIDECAR_VOLUMES.contains(&volume) {
                problems.push(format!(
                    "container {name:?} mounts volume {volume:?}, which only the sidecar may mount"
                ));
            }
        }
    }
    for v in spec
        .and_then(|s| s.get("volumes"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let volume = name_of(v);
        if SIDECAR_VOLUMES.contains(&volume) {
            problems.push(format!(
                "the pod already has a volume named {volume:?}, which the sidecar needs"
            ));
        }
        let agentsc_token = v
            .get("projected")
            .and_then(|p| p.get("sources"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|s| {
                s.get("serviceAccountToken")
                    .and_then(|t| t.get("audience"))
                    .and_then(Value::as_str)
                    == Some(TOKEN_AUDIENCE)
            });
        if agentsc_token && !SIDECAR_VOLUMES.contains(&volume) {
            problems.push(format!(
                "volume {volume:?} projects a service-account token for audience \
                 {TOKEN_AUDIENCE:?}, the IssueCertificate credential, which only the sidecar may \
                 hold"
            ));
        }
    }
    for field in ["shareProcessNamespace", "hostPID"] {
        if spec.and_then(|s| s.get(field)).and_then(Value::as_bool) == Some(true) {
            problems.push(format!(
                "spec.{field} is true: other containers could read the sidecar's memory and \
                 environment"
            ));
        }
    }
    problems
}

fn annotation<'a>(pod: &'a Value, key: &str) -> Option<&'a str> {
    pod.get("metadata")?.get("annotations")?.get(key)?.as_str()
}

/// The op that sets annotation `key` (creating `metadata.annotations` when there is none).
fn set_annotation_op(pod: &Value, key: &str, value: &str) -> Value {
    if pod
        .get("metadata")
        .and_then(|m| m.get("annotations"))
        .is_some_and(Value::is_object)
    {
        json!({"op": "add", "path": format!("/metadata/annotations/{}", escape(key)), "value": value})
    } else {
        json!({"op": "add", "path": "/metadata/annotations", "value": {key: value}})
    }
}

fn env(name: &str, value: impl Into<String>) -> EnvVar {
    EnvVar {
        name: name.into(),
        value: Some(value.into()),
        value_from: None,
    }
}

fn field_env(name: &str, path: &str) -> EnvVar {
    EnvVar {
        name: name.into(),
        value: None,
        value_from: Some(EnvVarSource {
            field_ref: Some(ObjectFieldSelector {
                api_version: Some("v1".into()),
                field_path: path.into(),
            }),
            ..Default::default()
        }),
    }
}

/// What the pod asks for, checked.
struct PodRequest {
    service: String,
    app_port: u16,
    namespace: String,
    image: String,
    anthropic_secret: Option<String>,
}

fn read_pod_request(
    inj: &Injector,
    images: &SidecarImagesConfig,
    req: &AdmissionRequest,
    pod: &Value,
) -> Result<PodRequest, String> {
    let mut problems = sidecar_conflicts(pod);
    let service = match annotation(pod, SERVICE_ANNOTATION) {
        None => {
            problems.push(format!(
                "annotation {SERVICE_ANNOTATION} is required (the service name, a DNS-1123 label)"
            ));
            String::new()
        }
        Some(s) if !is_dns_label(s) => {
            problems.push(format!(
                "annotation {SERVICE_ANNOTATION} {s:?} is not a DNS-1123 label"
            ));
            String::new()
        }
        Some(s) if s == RESERVED_SERVICE => {
            problems.push(format!(
                "annotation {SERVICE_ANNOTATION}: {s:?} is reserved for the control plane"
            ));
            String::new()
        }
        Some(s) => s.to_string(),
    };
    let app_port = match annotation(pod, APP_PORT_ANNOTATION) {
        None => {
            problems.push(format!(
                "annotation {APP_PORT_ANNOTATION} is required (the port the app listens on)"
            ));
            0
        }
        Some(p) => match p.parse::<u16>() {
            Ok(n) if n > 0 => n,
            _ => {
                problems.push(format!(
                    "annotation {APP_PORT_ANNOTATION} {p:?} is not a port (1-65535)"
                ));
                0
            }
        },
    };
    let namespace = req
        .namespace
        .clone()
        .or_else(|| {
            pod.get("metadata")
                .and_then(|m| m.get("namespace"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default();
    if !is_dns_label(&namespace) {
        problems.push(format!(
            "the pod's namespace {namespace:?} is not a DNS-1123 label"
        ));
    }
    let image = match annotation(pod, SIDECAR_IMAGE_ANNOTATION) {
        Some(i)
            if i.is_empty()
                || i.len() > 512
                || i.chars().any(|c| c.is_whitespace() || c.is_control()) =>
        {
            problems.push(format!(
                "annotation {SIDECAR_IMAGE_ANNOTATION} is not an image reference"
            ));
            String::new()
        }
        Some(i) => {
            if let Err(e) = crate::sidecar_images::check_reference(
                images,
                i,
                &format!("annotation {SIDECAR_IMAGE_ANNOTATION}"),
            ) {
                problems.push(e);
            }
            i.to_string()
        }
        None => match &inj.image {
            Some(i) => {
                if let Err(e) =
                    crate::sidecar_images::check_reference(images, i, "embassy's --injector-image")
                {
                    problems.push(e);
                }
                i.clone()
            }
            None => {
                problems.push(format!(
                    "no sidecar image: embassy has no --injector-image and the pod has no \
                     annotation {SIDECAR_IMAGE_ANNOTATION}"
                ));
                String::new()
            }
        },
    };
    let anthropic_secret = match annotation(pod, ANTHROPIC_SECRET_ANNOTATION) {
        Some(s) if !is_dns_subdomain(s) => {
            problems.push(format!(
                "annotation {ANTHROPIC_SECRET_ANNOTATION} {s:?} is not a Secret name"
            ));
            None
        }
        other => other.map(str::to_string),
    };
    if problems.is_empty() {
        Ok(PodRequest {
            service,
            app_port,
            namespace,
            image,
            anthropic_secret,
        })
    } else {
        Err(format!(
            "agentsc sidecar injection ({INJECT_LABEL}=true): {}",
            problems.join("; ")
        ))
    }
}

/// The `agentscd` container for `p`.
fn sidecar_container(inj: &Injector, p: &PodRequest) -> Container {
    let cp = &inj.cp_namespace;
    let mut env_list = vec![
        env(
            "AGENTSC_CONTROL_PLANE",
            format!("embassy.{cp}.svc:{CONTROL_PLANE_PORT}"),
        ),
        env(
            "AGENTSC_CA_ADDRESS",
            format!("embassy-ca.{cp}.svc:{CONTROL_PLANE_PORT}"),
        ),
        env("AGENTSC_SERVICE", p.service.clone()),
        env("AGENTSC_NAMESPACE", p.namespace.clone()),
        env("AGENTSC_APP_PORT", p.app_port.to_string()),
        field_env("POD_NAME", "metadata.name"),
        field_env("POD_NAMESPACE", "metadata.namespace"),
        env("AGENTSC_CA_PEM", inj.ca_bundle.pem()),
        env("AGENTSC_K8S_TOKEN_FILE", TOKEN_FILE),
        env("AGENTSC_STATE_DIR", STATE_DIR),
        // the runtime is the agentsc-runtime container (runtime_container)
        env("AGENTSC_NO_RUNTIME", "true"),
        env("AGENTSC_TRUST_DOMAIN", inj.trust_domain.clone()),
    ];
    // agentscd only: the runtime container never gets the key
    if let Some(secret) = &p.anthropic_secret {
        env_list.push(EnvVar {
            name: "ANTHROPIC_API_KEY".into(),
            value: None,
            value_from: Some(EnvVarSource {
                secret_key_ref: Some(SecretKeySelector {
                    name: secret.clone(),
                    key: "ANTHROPIC_API_KEY".into(),
                    optional: Some(true),
                }),
                ..Default::default()
            }),
        });
    }
    env_list.extend(inj.template.env.iter().flatten().cloned());
    Container {
        name: SIDECAR_CONTAINER.into(),
        image: Some(p.image.clone()),
        image_pull_policy: Some(inj.template.pull_policy()),
        restart_policy: Some("Always".into()),
        ports: Some(vec![ContainerPort {
            name: Some("mesh".into()),
            container_port: MESH_PORT,
            protocol: Some("TCP".into()),
            ..Default::default()
        }]),
        env: Some(env_list),
        volume_mounts: Some(vec![
            run_mount(),
            VolumeMount {
                name: STATE_VOLUME.into(),
                mount_path: STATE_DIR.into(),
                ..Default::default()
            },
            VolumeMount {
                name: TOKEN_VOLUME.into(),
                mount_path: TOKEN_DIR.into(),
                read_only: Some(true),
                ..Default::default()
            },
        ]),
        // /readyz listens on loopback only: exec probes (module docs, image contract)
        startup_probe: Some(ready_probe(STARTUP_PROBE_PERIOD, STARTUP_PROBE_FAILURES)),
        readiness_probe: Some(ready_probe(READY_PROBE_PERIOD, READY_PROBE_FAILURES)),
        resources: Some(inj.template.resources()),
        security_context: Some(inj.template.security_context()),
        ..Default::default()
    }
}

/// An exec probe of [`READY_COMMAND`].
fn ready_probe(period: i32, failures: i32) -> Probe {
    Probe {
        exec: Some(ExecAction {
            command: Some(vec![READY_COMMAND.into()]),
        }),
        period_seconds: Some(period),
        timeout_seconds: Some(3),
        failure_threshold: Some(failures),
        ..Default::default()
    }
}

fn run_mount() -> VolumeMount {
    VolumeMount {
        name: RUN_VOLUME.into(),
        mount_path: RUN_DIR.into(),
        ..Default::default()
    }
}

/// The `agentsc-runtime` container for `p`: `agentscd`'s image, pull policy, resources and
/// securityContext; its command line, the socket directory and the template's
/// [`RUNTIME_TEMPLATE_ENV`] only (no secret).
fn runtime_container(inj: &Injector, p: &PodRequest) -> Container {
    let env: Vec<EnvVar> = inj
        .template
        .env
        .iter()
        .flatten()
        .filter(|e| RUNTIME_TEMPLATE_ENV.contains(&e.name.as_str()))
        .cloned()
        .collect();
    Container {
        name: RUNTIME_CONTAINER.into(),
        image: Some(p.image.clone()),
        image_pull_policy: Some(inj.template.pull_policy()),
        restart_policy: Some("Always".into()),
        command: Some(vec![RUNTIME_COMMAND.into()]),
        args: Some(RUNTIME_ARGS.iter().map(|a| a.to_string()).collect()),
        env: (!env.is_empty()).then_some(env),
        volume_mounts: Some(vec![run_mount()]),
        resources: Some(inj.template.resources()),
        security_context: Some(inj.template.security_context()),
        ..Default::default()
    }
}

/// A pod as the injector leaves it (service account and `agentsc.io/service` = `service`, the
/// Anthropic Secret named), for the shape checks' tests in [`crate::sidecar_images`] and
/// [`crate::issuance`].
#[cfg(test)]
pub(crate) fn injected_pod(
    namespace: &str,
    name: &str,
    service: &str,
    image: &str,
    template: InjectTemplate,
) -> k8s_openapi::api::core::v1::Pod {
    use k8s_openapi::api::core::v1::{Pod, PodSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    let inj = Injector {
        image: Some(image.into()),
        template,
        cp_namespace: "agentsc-system".into(),
        trust_domain: "agentsc".into(),
        ca_bundle: CaBundle::Fixed("CA PEM".into()),
    };
    let p = PodRequest {
        service: service.into(),
        app_port: 8080,
        namespace: namespace.into(),
        image: image.into(),
        anthropic_secret: Some("agentsc-anthropic".into()),
    };
    Pod {
        metadata: ObjectMeta {
            name: Some(name.into()),
            namespace: Some(namespace.into()),
            labels: Some([(INJECT_LABEL.to_string(), "true".to_string())].into()),
            ..Default::default()
        },
        spec: Some(PodSpec {
            service_account_name: Some(service.into()),
            init_containers: Some(vec![
                runtime_container(&inj, &p),
                sidecar_container(&inj, &p),
            ]),
            containers: vec![Container {
                name: "app".into(),
                image: Some("orders:1".into()),
                ..Default::default()
            }],
            volumes: Some(sidecar_volumes()),
            ..Default::default()
        }),
        status: None,
    }
}

fn sidecar_volumes() -> Vec<Volume> {
    let empty_dir = |name: &str| Volume {
        name: name.into(),
        empty_dir: Some(Default::default()),
        ..Default::default()
    };
    vec![
        empty_dir(RUN_VOLUME),
        empty_dir(STATE_VOLUME),
        Volume {
            name: TOKEN_VOLUME.into(),
            projected: Some(ProjectedVolumeSource {
                sources: Some(vec![VolumeProjection {
                    service_account_token: Some(ServiceAccountTokenProjection {
                        audience: Some(TOKEN_AUDIENCE.into()),
                        expiration_seconds: Some(TOKEN_EXPIRATION_SECONDS),
                        path: "token".into(),
                    }),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        },
    ]
}

/// The `/mutate` decision for one request; `images` is the live config's allow-list.
pub fn mutate(inj: &Injector, images: &SidecarImagesConfig, req: &AdmissionRequest) -> Decision {
    if req.operation != "CREATE" {
        return Decision::allow();
    }
    let Some(pod) = &req.object else {
        return Decision::deny(400, "the AdmissionReview request has no object");
    };
    // never the control plane's own pods, never pods that did not ask
    if req.namespace.as_deref() == Some(inj.cp_namespace.as_str()) {
        return Decision::allow();
    }
    let labelled = pod
        .get("metadata")
        .and_then(|m| m.get("labels"))
        .and_then(|l| l.get(INJECT_LABEL))
        .and_then(Value::as_str)
        == Some("true");
    if !labelled {
        return Decision::allow();
    }
    // a pod's own agentscd (or one injected before) is denied, never skipped: the annotation
    // agentsc.io/injected is the pod owner's to write, so it proves nothing
    let p = match read_pod_request(inj, images, req, pod) {
        Ok(p) => p,
        Err(message) => return Decision::deny(400, message),
    };
    let containers = match (
        serde_json::to_value(runtime_container(inj, &p)),
        serde_json::to_value(sidecar_container(inj, &p)),
    ) {
        (Ok(runtime), Ok(sidecar)) => [runtime, sidecar],
        (Err(e), _) | (_, Err(e)) => {
            return Decision::deny(500, format!("building the sidecar containers failed: {e}"));
        }
    };
    let spec = pod.get("spec");
    let mut ops = vec![set_annotation_op(pod, INJECTED_ANNOTATION, "true")];
    if spec
        .and_then(|s| s.get("initContainers"))
        .is_some_and(Value::is_array)
    {
        // first, so the sidecars are up before the other init containers and the app; the
        // runtime before agentscd, whose startup probe waits for the runtime's Health
        let [runtime, sidecar] = containers;
        ops.push(json!({"op": "add", "path": "/spec/initContainers/0", "value": runtime}));
        ops.push(json!({"op": "add", "path": "/spec/initContainers/1", "value": sidecar}));
    } else {
        ops.push(json!({"op": "add", "path": "/spec/initContainers", "value": containers}));
    }
    let volumes: Vec<Value> = sidecar_volumes()
        .iter()
        .filter_map(|v| serde_json::to_value(v).ok())
        .collect();
    if spec
        .and_then(|s| s.get("volumes"))
        .is_some_and(Value::is_array)
    {
        for v in volumes {
            ops.push(json!({"op": "add", "path": "/spec/volumes/-", "value": v}));
        }
    } else {
        ops.push(json!({"op": "add", "path": "/spec/volumes", "value": volumes}));
    }
    Decision::patch(ops)
}

// ---- /validate-charter ------------------------------------------------------------------------------

/// The `ControlPlaneConfig` `policy` rules a charter breaks (design §8.2), each naming its rule.
///
/// The one implementation of the policy check: admission ([`validate_charter`]) and the REST
/// API's write path (after the validator, before role-on-diff, design §8.4) both call it, so
/// they cannot disagree. An `http` tool's origin is compared after `url::Url` normalisation
/// (scheme and host lower-cased, default port dropped), the canonical form the config
/// validation requires of every `http_origin_allowlist` entry.
pub fn policy_violations(
    charter: &agentsc_charter::Charter,
    policy: Option<&PolicyConfig>,
) -> Vec<String> {
    let Some(policy) = policy else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if policy.require_authz_default_deny && charter.authz.default != agentsc_charter::Decision::Deny
    {
        out.push("policy.require_authz_default_deny: authz.default must be deny".to_string());
    }
    if let Some(allowed) = &policy.http_origin_allowlist {
        for agent in &charter.agents {
            for tool in &agent.tools {
                if tool.tool_type != agentsc_charter::ToolType::Http {
                    continue;
                }
                let origin = tool
                    .url
                    .as_deref()
                    .and_then(agentsc_charter::http_origin)
                    .and_then(|o| url::Url::parse(&o).ok())
                    .map(|u| u.origin().ascii_serialization());
                match origin {
                    Some(o) if allowed.contains(&o) => {}
                    Some(o) => out.push(format!(
                        "policy.http_origin_allowlist: agent {} tool {} calls {o}, which is not allowed",
                        agent.name, tool.name
                    )),
                    None => out.push(format!(
                        "policy.http_origin_allowlist: agent {} tool {} has no origin to check",
                        agent.name, tool.name
                    )),
                }
            }
        }
    }
    if policy.forbid_learning_auto {
        for agent in &charter.agents {
            if agent
                .learning
                .as_ref()
                .is_some_and(|l| l.mode == agentsc_charter::LearningMode::Auto)
            {
                out.push(format!(
                    "policy.forbid_learning_auto: agent {} uses learning.mode auto",
                    agent.name
                ));
            }
        }
    }
    out
}

/// Is `username` one of embassy's own service accounts (whose writes the store audits)?
fn is_embassy(username: &str, cp_namespace: &str) -> bool {
    ["embassy", "embassy-ca"]
        .iter()
        .any(|sa| username == format!("system:serviceaccount:{cp_namespace}:{sa}"))
}

/// Changes an UPDATE makes to the annotations only embassy writes, one message each.
fn protected_annotation_changes(req: &AdmissionRequest, object: &Value) -> Vec<String> {
    if req.operation != "UPDATE" {
        return Vec::new();
    }
    let read = |obj: Option<&Value>, name: &str| -> Option<Value> {
        obj?.get("metadata")?.get("annotations")?.get(name).cloned()
    };
    let show = |v: &Option<Value>| v.as_ref().map_or("absent".to_string(), Value::to_string);
    crate::k8s::store::PROTECTED_ANNOTATIONS
        .iter()
        .filter_map(|name| {
            let old = read(req.old_object.as_ref(), name);
            let new = read(Some(object), name);
            (old != new).then(|| {
                format!(
                    "annotation {name} is written by embassy only ({} → {}); keep its current \
                     value",
                    show(&old),
                    show(&new)
                )
            })
        })
        .collect()
}

/// The `/validate-charter` decision for one request, audited.
pub async fn validate_charter(state: &WebhookState, req: &AdmissionRequest) -> Decision {
    if !matches!(req.operation.as_str(), "CREATE" | "UPDATE") {
        return Decision::allow();
    }
    let Some(object) = &req.object else {
        return Decision::deny(400, "the AdmissionReview request has no object");
    };
    let mut object = object.clone();
    // the namespace of a CREATE may only be in the request
    if let (Some(ns), Some(meta)) = (
        &req.namespace,
        object.get_mut("metadata").and_then(Value::as_object_mut),
    ) && !meta.contains_key("namespace")
    {
        meta.insert("namespace".into(), Value::String(ns.clone()));
    }
    let username = req.user_info.username.clone().unwrap_or_default();
    let embassy = is_embassy(&username, &state.injector.cp_namespace);
    let protected = if embassy {
        Vec::new()
    } else {
        protected_annotation_changes(req, &object)
    };
    let checked = if protected.is_empty() {
        agentsc_charter::Charter::from_value(&object).map_err(Some)
    } else {
        Err(None)
    };
    let (decision, result, reason) = match checked {
        Err(None) => {
            let p = protected.join("; ");
            (
                Decision::deny(403, format!("the Charter update is refused: {p}")),
                CpResult::Denied,
                p,
            )
        }
        Err(Some(e)) => {
            let errors = match e {
                agentsc_charter::CharterError::Invalid(list) => list.join("; "),
                other => other.to_string(),
            };
            (
                Decision::deny(400, format!("the Charter is invalid: {errors}")),
                CpResult::Invalid,
                errors,
            )
        }
        Ok(charter) => {
            let config = state.config.load();
            let violations = policy_violations(&charter, config.policy.as_ref());
            if violations.is_empty() {
                (
                    Decision::allow(),
                    CpResult::Ok,
                    format!("{} admitted", req.operation),
                )
            } else {
                let v = violations.join("; ");
                (
                    Decision::deny(
                        403,
                        format!("the Charter breaks the control-plane policy: {v}"),
                    ),
                    CpResult::Denied,
                    v,
                )
            }
        }
    };
    if !embassy {
        let actor = Actor {
            name: format!(
                "k8s:{}",
                if username.is_empty() {
                    "unknown"
                } else {
                    &username
                }
            ),
            kind: ActorKind::K8s,
            role: None,
        };
        let mut rec = CpAudit::entry(CpAction::CrExternalEdit, &actor, result);
        rec.namespace = object
            .get("metadata")
            .and_then(|m| m.get("namespace"))
            .and_then(Value::as_str)
            .map(str::to_string);
        rec.service = object
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .or(req.name.as_deref())
            .map(str::to_string);
        // the version served before the change (embassy's status, not a user-written annotation)
        rec.from_version = req
            .old_object
            .as_ref()
            .and_then(|o| crate::k8s::store::applied_version(o).ok().flatten())
            .map(|v| v.to_string());
        rec.sha256_after = object.get("spec").map(crate::k8s::store::spec_sha256);
        let dry = if req.dry_run == Some(true) {
            " (dry run)"
        } else {
            ""
        };
        let reason: String = reason.chars().take(4096).collect();
        rec.reason = Some(format!("admission{dry}: {reason}"));
        state.cp_audit.record(rec).await;
    }
    decision
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PolicyConfig;
    use crate::cp_audit::CpAuditRecord;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const IMAGE: &str = "ghcr.io/f8fvwgzc/agent-sidecar/agentscd:0.2.0";

    fn injector(template: InjectTemplate) -> Injector {
        Injector {
            image: Some(IMAGE.into()),
            template,
            cp_namespace: "agentsc-system".into(),
            ca_bundle: CaBundle::Fixed("CA PEM".into()),
            trust_domain: "agentsc".into(),
        }
    }

    fn pod(annotations: Value) -> Value {
        json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"generateName": "orders-", "labels": {"app": "orders", INJECT_LABEL: "true"}, "annotations": annotations},
            "spec": {"serviceAccountName": "orders", "containers": [{"name": "app", "image": "orders:1"}]}
        })
    }

    fn create(object: Value) -> AdmissionRequest {
        AdmissionRequest {
            uid: "req-1".into(),
            namespace: Some("shop".into()),
            name: None,
            operation: "CREATE".into(),
            user_info: UserInfo {
                username: Some("system:serviceaccount:kube-system:replicaset-controller".into()),
            },
            object: Some(object),
            old_object: None,
            dry_run: None,
        }
    }

    fn annotated() -> Value {
        json!({SERVICE_ANNOTATION: "orders", APP_PORT_ANNOTATION: "8080"})
    }

    /// RFC 6902 `add` (the only op the injector emits), for checking patches.
    fn apply(doc: &mut Value, ops: &[Value]) {
        for op in ops {
            assert_eq!(op["op"], "add", "{op}");
            let path = op["path"].as_str().unwrap();
            let tokens: Vec<String> = path
                .split('/')
                .skip(1)
                .map(|t| t.replace("~1", "/").replace("~0", "~"))
                .collect();
            let (last, parents) = tokens.split_last().unwrap();
            let mut at = &mut *doc;
            for t in parents {
                at = match at {
                    Value::Array(a) => &mut a[t.parse::<usize>().unwrap()],
                    other => other.get_mut(t.as_str()).unwrap(),
                };
            }
            match at {
                Value::Array(a) if last == "-" => a.push(op["value"].clone()),
                Value::Array(a) => a.insert(last.parse().unwrap(), op["value"].clone()),
                Value::Object(m) => {
                    m.insert(last.clone(), op["value"].clone());
                }
                other => panic!("cannot add under {other}"),
            }
        }
    }

    /// The allow-list off (development builds), as in the default config.
    const OFF: SidecarImagesConfig = SidecarImagesConfig {
        allowed_digests: Vec::new(),
    };

    fn digest(c: char) -> String {
        format!("sha256:{}", std::iter::repeat_n(c, 64).collect::<String>())
    }

    fn security_context() -> Value {
        json!({
            "runAsNonRoot": true, "runAsUser": 10001, "runAsGroup": 10001,
            "readOnlyRootFilesystem": true, "allowPrivilegeEscalation": false,
            "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}
        })
    }

    fn resources() -> Value {
        json!({"requests": {"cpu": "50m", "memory": "128Mi"}, "limits": {"memory": "512Mi"}})
    }

    fn expected_container(extra_env: &[Value]) -> Value {
        let mut env = vec![
            json!({"name": "AGENTSC_CONTROL_PLANE", "value": "embassy.agentsc-system.svc:15012"}),
            json!({"name": "AGENTSC_CA_ADDRESS", "value": "embassy-ca.agentsc-system.svc:15012"}),
            json!({"name": "AGENTSC_SERVICE", "value": "orders"}),
            json!({"name": "AGENTSC_NAMESPACE", "value": "shop"}),
            json!({"name": "AGENTSC_APP_PORT", "value": "8080"}),
            json!({"name": "POD_NAME", "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.name"}}}),
            json!({"name": "POD_NAMESPACE", "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.namespace"}}}),
            json!({"name": "AGENTSC_CA_PEM", "value": "CA PEM"}),
            json!({"name": "AGENTSC_K8S_TOKEN_FILE", "value": "/var/run/secrets/agentsc/token"}),
            json!({"name": "AGENTSC_STATE_DIR", "value": "/var/lib/agentsc/state"}),
            json!({"name": "AGENTSC_NO_RUNTIME", "value": "true"}),
            json!({"name": "AGENTSC_TRUST_DOMAIN", "value": "agentsc"}),
        ];
        env.extend(extra_env.iter().cloned());
        json!({
            "name": "agentscd",
            "image": IMAGE,
            "imagePullPolicy": "IfNotPresent",
            "restartPolicy": "Always",
            "ports": [{"name": "mesh", "containerPort": 50002, "protocol": "TCP"}],
            "env": env,
            "volumeMounts": [
                {"name": "agentsc-run", "mountPath": "/run/agentsc"},
                {"name": "agentsc-state", "mountPath": "/var/lib/agentsc/state"},
                {"name": "agentsc-token", "mountPath": "/var/run/secrets/agentsc", "readOnly": true}
            ],
            "startupProbe": {"exec": {"command": ["agentsc-ready"]}, "periodSeconds": 2, "timeoutSeconds": 3, "failureThreshold": 150},
            "readinessProbe": {"exec": {"command": ["agentsc-ready"]}, "periodSeconds": 10, "timeoutSeconds": 3, "failureThreshold": 3},
            "resources": resources(),
            "securityContext": security_context()
        })
    }

    /// The runtime: agentscd's image and template, its command line, the sockets, nothing else.
    fn expected_runtime() -> Value {
        json!({
            "name": "agentsc-runtime",
            "image": IMAGE,
            "imagePullPolicy": "IfNotPresent",
            "restartPolicy": "Always",
            "command": ["agentsc-runtime"],
            "args": ["--listen", "unix:/run/agentsc/runtime.sock", "--sidecar", "unix:/run/agentsc/sidecar.sock"],
            "volumeMounts": [{"name": "agentsc-run", "mountPath": "/run/agentsc"}],
            "resources": resources(),
            "securityContext": security_context()
        })
    }

    fn expected_volumes() -> Value {
        json!([
            {"name": "agentsc-run", "emptyDir": {}},
            {"name": "agentsc-state", "emptyDir": {}},
            {"name": "agentsc-token", "projected": {"sources": [
                {"serviceAccountToken": {"audience": "agentsc", "expirationSeconds": 3600, "path": "token"}}
            ]}}
        ])
    }

    #[test]
    fn inject_golden_patch() {
        let d = mutate(
            &injector(InjectTemplate::default()),
            &OFF,
            &create(pod(annotated())),
        );
        assert!(d.allowed && d.status.is_none());
        assert_eq!(
            Value::Array(d.patch.clone()),
            json!([
                {"op": "add", "path": "/metadata/annotations/agentsc.io~1injected", "value": "true"},
                {"op": "add", "path": "/spec/initContainers", "value": [expected_runtime(), expected_container(&[])]},
                {"op": "add", "path": "/spec/volumes", "value": expected_volumes()}
            ])
        );
    }

    #[test]
    fn the_runtime_shares_only_the_sockets_with_agentscd() {
        let mut ann = annotated();
        ann[ANTHROPIC_SECRET_ANNOTATION] = json!("agentsc-anthropic");
        let d = mutate(
            &injector(InjectTemplate::default()),
            &OFF,
            &create(pod(ann)),
        );
        let [runtime, sidecar] = [&d.patch[1]["value"][0], &d.patch[1]["value"][1]];
        assert_eq!(
            (runtime["name"].as_str(), sidecar["name"].as_str()),
            (Some(RUNTIME_CONTAINER), Some(SIDECAR_CONTAINER)),
            "the runtime starts first: agentscd's startup probe waits for its Health"
        );
        // agentscd does not spawn a runtime of its own and holds the key; the runtime has no env
        let env = |c: &Value, name: &str| {
            c["env"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|e| e["name"] == name)
                .cloned()
        };
        assert_eq!(
            env(sidecar, "AGENTSC_NO_RUNTIME"),
            Some(json!({"name": "AGENTSC_NO_RUNTIME", "value": "true"}))
        );
        assert!(env(sidecar, "ANTHROPIC_API_KEY").is_some());
        assert!(runtime.get("env").is_none() && runtime.get("envFrom").is_none());
        // the state directory (the workload key) is agentscd's own volume
        let mounts = |c: &Value| -> Vec<String> {
            c["volumeMounts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m["name"].as_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(mounts(runtime), [RUN_VOLUME]);
        assert_eq!(mounts(sidecar), [RUN_VOLUME, STATE_VOLUME, TOKEN_VOLUME]);
        assert_eq!(
            env(sidecar, "AGENTSC_STATE_DIR").unwrap()["value"],
            STATE_DIR
        );
        // the runtime's flags name the sockets in the shared directory
        for a in RUNTIME_ARGS.iter().filter(|a| a.starts_with("unix:")) {
            assert!(a.starts_with(&format!("unix:{RUN_DIR}/")), "{a}");
        }
    }

    /// The review finding: with the runtime in its own container, Helm's
    /// `injection.mockFallback` reached agentscd only, so the demo's agents were refused.
    #[test]
    fn the_runtime_gets_the_mock_fallback_and_no_other_template_env() {
        let template = InjectTemplate::parse(
            r#"{"env": [{"name": "OTEL_EXPORTER_OTLP_ENDPOINT", "value": "http://otel:4317"},
                        {"name": "AGENTSC_MOCK_FALLBACK", "value": "1"}]}"#,
        )
        .unwrap();
        let d = mutate(&injector(template), &OFF, &create(pod(annotated())));
        let [runtime, sidecar] = [&d.patch[1]["value"][0], &d.patch[1]["value"][1]];
        assert_eq!(
            runtime["env"],
            json!([{"name": "AGENTSC_MOCK_FALLBACK", "value": "1"}])
        );
        let names: Vec<&str> = sidecar["env"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"OTEL_EXPORTER_OTLP_ENDPOINT"));
        assert!(names.contains(&"AGENTSC_MOCK_FALLBACK"));
    }

    /// The review finding: `--audit-fail-closed` could not reach an injected sidecar (the
    /// template refused the name), and the pod's readiness would not have followed `/readyz`.
    #[test]
    fn fail_closed_audit_reaches_the_injected_sidecar_and_readiness_follows_it() {
        let template = InjectTemplate::parse(
            r#"{"env": [{"name": "AGENTSC_AUDIT_FAIL_CLOSED", "value": "true"}]}"#,
        )
        .unwrap();
        let d = mutate(&injector(template), &OFF, &create(pod(annotated())));
        let [runtime, sidecar] = [&d.patch[1]["value"][0], &d.patch[1]["value"][1]];
        assert!(
            sidecar["env"]
                .as_array()
                .unwrap()
                .contains(&json!({"name": "AGENTSC_AUDIT_FAIL_CLOSED", "value": "true"}))
        );
        assert!(runtime.get("env").is_none(), "agentscd's setting only");
        assert_eq!(
            sidecar["readinessProbe"]["exec"]["command"],
            json!([READY_COMMAND])
        );
        assert!(runtime.get("readinessProbe").is_none());
    }

    #[test]
    fn existing_init_containers_and_volumes_are_kept() {
        let mut p = pod(annotated());
        p["spec"]["initContainers"] = json!([{"name": "migrate", "image": "m:1"}]);
        p["spec"]["volumes"] = json!([{"name": "data", "emptyDir": {}}]);
        let d = mutate(
            &injector(InjectTemplate::default()),
            &OFF,
            &create(p.clone()),
        );
        let paths: Vec<&str> = d
            .patch
            .iter()
            .map(|o| o["path"].as_str().unwrap())
            .collect();
        assert_eq!(
            paths,
            [
                "/metadata/annotations/agentsc.io~1injected",
                "/spec/initContainers/0",
                "/spec/initContainers/1",
                "/spec/volumes/-",
                "/spec/volumes/-",
                "/spec/volumes/-"
            ]
        );
        apply(&mut p, &d.patch);
        let init: Vec<&str> = p["spec"]["initContainers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            init,
            ["agentsc-runtime", "agentscd", "migrate"],
            "the sidecars start first, the runtime before agentscd"
        );
        assert_eq!(p["spec"]["volumes"].as_array().unwrap().len(), 4);
        assert_eq!(p["spec"]["containers"][0]["name"], "app");
    }

    #[test]
    fn the_template_and_the_secret_are_applied() {
        let template = InjectTemplate::parse(
            r#"{"imagePullPolicy":"Always",
                "resources":{"requests":{"cpu":"10m"}},
                "securityContext":{"runAsNonRoot":true},
                "env":[{"name":"OTEL_EXPORTER_OTLP_ENDPOINT","value":"http://otel:4318"},
                       {"name":"AGENTSC_OTLP_ENDPOINT_ALLOW","value":"http://otel:4318"}]}"#,
        )
        .unwrap();
        let mut ann = annotated();
        ann[ANTHROPIC_SECRET_ANNOTATION] = json!("agentsc-anthropic");
        ann[SIDECAR_IMAGE_ANNOTATION] = json!("registry.local/agentscd:dev");
        let d = mutate(&injector(template), &OFF, &create(pod(ann)));
        let c = &d.patch[1]["value"][1];
        let mut want = expected_container(&[
            json!({"name": "ANTHROPIC_API_KEY", "valueFrom": {"secretKeyRef": {"name": "agentsc-anthropic", "key": "ANTHROPIC_API_KEY", "optional": true}}}),
            json!({"name": "OTEL_EXPORTER_OTLP_ENDPOINT", "value": "http://otel:4318"}),
            json!({"name": "AGENTSC_OTLP_ENDPOINT_ALLOW", "value": "http://otel:4318"}),
        ]);
        want["image"] = json!("registry.local/agentscd:dev");
        want["imagePullPolicy"] = json!("Always");
        want["resources"] = json!({"requests": {"cpu": "10m"}});
        want["securityContext"] = json!({"runAsNonRoot": true});
        assert_eq!(c, &want);
        // the runtime gets the same image, pull policy, resources and securityContext, no env
        let mut want = expected_runtime();
        want["image"] = json!("registry.local/agentscd:dev");
        want["imagePullPolicy"] = json!("Always");
        want["resources"] = json!({"requests": {"cpu": "10m"}});
        want["securityContext"] = json!({"runAsNonRoot": true});
        assert_eq!(&d.patch[1]["value"][0], &want);
    }

    #[test]
    fn the_sidecar_gets_embassys_trust_domain() {
        let mut inj = injector(InjectTemplate::default());
        inj.trust_domain = "prod.example".into();
        let d = mutate(&inj, &OFF, &create(pod(annotated())));
        // the init containers are agentsc-runtime, then agentscd (which alone has env)
        let env = d.patch[1]["value"][1]["env"].as_array().unwrap().clone();
        assert_eq!(d.patch[1]["value"][1]["name"], SIDECAR_CONTAINER);
        let td: Vec<&Value> = env
            .iter()
            .filter(|e| e["name"] == "AGENTSC_TRUST_DOMAIN")
            .collect();
        assert_eq!(
            td,
            [&json!({"name": "AGENTSC_TRUST_DOMAIN", "value": "prod.example"})]
        );
    }

    #[test]
    fn templates_may_not_reach_the_injectors_own_settings() {
        for bad in [
            r#"{"env":[{"name":"AGENTSC_CONTROL_PLANE","value":"evil:15012"}]}"#,
            r#"{"env":[{"name":"AGENTSC_SERVICE","value":"x"}]}"#,
            r#"{"env":[{"name":"AGENTSC_NO_RUNTIME","value":"false"}]}"#,
            r#"{"env":[{"name":"AGENTSC_TRUST_DOMAIN","value":"evil"}]}"#,
            r#"{"command":["sh"]}"#,
            r#"{"imagePullPolicy":"Sometimes"}"#,
            r#"not json"#,
        ] {
            assert!(InjectTemplate::parse(bad).is_err(), "{bad}");
        }
        let empty = InjectTemplate::parse("{}").unwrap();
        assert_eq!(empty, InjectTemplate::default());
        // the built-in defaults are the chart's
        assert_eq!(
            serde_json::to_value(default_resources()).unwrap(),
            json!({"requests": {"cpu": "50m", "memory": "128Mi"}, "limits": {"memory": "512Mi"}})
        );
    }

    /// The audit finding: a pod could run its own "sidecar" by naming a container agentscd.
    #[test]
    fn pods_that_bring_their_own_sidecar_are_denied() {
        let inj = injector(InjectTemplate::default());
        for (list, name) in [
            ("containers", SIDECAR_CONTAINER),
            ("initContainers", SIDECAR_CONTAINER),
            ("initContainers", RUNTIME_CONTAINER),
            ("containers", RUNTIME_CONTAINER),
        ] {
            let mut p = pod(annotated());
            let entry = json!({"name": name, "image": "evil.example/agentscd:1", "restartPolicy": "Always"});
            match p["spec"][list].as_array_mut() {
                Some(l) => l.push(entry),
                None => p["spec"][list] = json!([entry]),
            }
            // the annotation is the pod owner's to write: it skips nothing
            p["metadata"]["annotations"][INJECTED_ANNOTATION] = json!("true");
            let d = mutate(&inj, &OFF, &create(p));
            assert!(!d.allowed && d.patch.is_empty(), "{list} {name}");
            let (code, msg) = d.status.unwrap();
            assert_eq!(code, 400);
            assert!(
                msg.contains(&format!("the pod already has a container named {name:?}"))
                    && msg.contains("may not bring its own"),
                "{msg}"
            );
        }
        // without the required annotations every problem is named
        let mut bare = pod(json!(null));
        bare["metadata"]
            .as_object_mut()
            .unwrap()
            .remove("annotations");
        bare["spec"]["initContainers"] = json!([{"name": "agentscd"}]);
        let msg = mutate(&inj, &OFF, &create(bare)).status.unwrap().1;
        assert!(
            msg.contains("\"agentscd\"") && msg.contains("agentsc.io/service is required"),
            "{msg}"
        );
    }

    #[test]
    fn an_injected_pod_is_never_injected_twice() {
        let inj = injector(InjectTemplate::default());
        let mut p = pod(annotated());
        let first = mutate(&inj, &OFF, &create(p.clone()));
        apply(&mut p, &first.patch);
        assert_eq!(p["metadata"]["annotations"][INJECTED_ANNOTATION], "true");
        assert_eq!(p["spec"]["initContainers"][0], expected_runtime());
        assert_eq!(p["spec"]["initContainers"][1], expected_container(&[]));
        // the same pod again (an exported pod applied as it is): its sidecars are not ours to trust
        let second = mutate(&inj, &OFF, &create(p.clone()));
        assert!(!second.allowed && second.patch.is_empty());
        let msg = second.status.unwrap().1;
        for name in [RUNTIME_CONTAINER, SIDECAR_CONTAINER] {
            assert!(msg.contains(&format!("container named {name:?}")), "{msg}");
        }
    }

    /// A change to a test pod.
    type PodChange = fn(&mut Value);

    /// A projected service-account token volume for `audience`.
    fn token_volume(audience: &str) -> Value {
        json!({"name": "my-token", "projected": {"sources": [{"serviceAccountToken": {"audience": audience, "path": "t"}}]}})
    }

    #[test]
    fn pods_may_not_weaken_the_sidecar() {
        let inj = injector(InjectTemplate::default());
        let cases: [(PodChange, &str); 7] = [
            (
                |p| p["spec"]["shareProcessNamespace"] = json!(true),
                "spec.shareProcessNamespace is true",
            ),
            (
                |p| p["spec"]["hostPID"] = json!(true),
                "spec.hostPID is true",
            ),
            (
                |p| {
                    p["spec"]["containers"][0]["volumeMounts"] =
                        json!([{"name": "agentsc-run", "mountPath": "/run/agentsc"}])
                },
                "container \"app\" mounts volume \"agentsc-run\"",
            ),
            (
                |p| {
                    p["spec"]["initContainers"] = json!([{"name": "steal", "image": "x",
                        "volumeMounts": [{"name": "agentsc-token", "mountPath": "/t"}]}])
                },
                "container \"steal\" mounts volume \"agentsc-token\"",
            ),
            (
                |p| {
                    p["spec"]["containers"][0]["volumeMounts"] =
                        json!([{"name": "agentsc-state", "mountPath": "/s"}])
                },
                "mounts volume \"agentsc-state\"",
            ),
            (
                |p| p["spec"]["volumes"] = json!([token_volume("agentsc")]),
                "volume \"my-token\" projects a service-account token for audience \"agentsc\"",
            ),
            (
                |p| p["spec"]["volumes"] = json!([{"name": "agentsc-state", "emptyDir": {}}]),
                "the pod already has a volume named \"agentsc-state\"",
            ),
        ];
        for (change, want) in cases {
            let mut p = pod(annotated());
            change(&mut p);
            let d = mutate(&inj, &OFF, &create(p));
            let msg = d.status.map(|s| s.1).unwrap_or_default();
            assert!(!d.allowed && msg.contains(want), "{want}: {msg}");
        }
        // false flags and tokens for other audiences are fine
        let mut p = pod(annotated());
        p["spec"]["shareProcessNamespace"] = json!(false);
        p["spec"]["hostPID"] = json!(false);
        p["spec"]["volumes"] = json!([token_volume("vault")]);
        assert!(mutate(&inj, &OFF, &create(p)).allowed);
    }

    #[test]
    fn missing_or_bad_annotations_are_denied_with_a_clear_message() {
        let inj = injector(InjectTemplate::default());
        let d = mutate(&inj, &OFF, &create(pod(json!({}))));
        assert!(!d.allowed);
        let (code, msg) = d.status.unwrap();
        assert_eq!(code, 400);
        assert!(
            msg.contains("annotation agentsc.io/service is required"),
            "{msg}"
        );
        assert!(
            msg.contains("annotation agentsc.io/app-port is required"),
            "{msg}"
        );
        assert!(d.patch.is_empty());

        for (ann, want) in [
            (
                json!({SERVICE_ANNOTATION: "Orders", APP_PORT_ANNOTATION: "8080"}),
                "not a DNS-1123 label",
            ),
            (
                json!({SERVICE_ANNOTATION: "embassy", APP_PORT_ANNOTATION: "8080"}),
                "reserved",
            ),
            (
                json!({SERVICE_ANNOTATION: "orders", APP_PORT_ANNOTATION: "0"}),
                "is not a port",
            ),
            (
                json!({SERVICE_ANNOTATION: "orders", APP_PORT_ANNOTATION: "http"}),
                "is not a port",
            ),
            (
                json!({SERVICE_ANNOTATION: "orders", APP_PORT_ANNOTATION: "8080", ANTHROPIC_SECRET_ANNOTATION: "Bad Secret"}),
                "is not a Secret name",
            ),
            (
                json!({SERVICE_ANNOTATION: "orders", APP_PORT_ANNOTATION: "8080", SIDECAR_IMAGE_ANNOTATION: "a b"}),
                "not an image reference",
            ),
        ] {
            let d = mutate(&inj, &OFF, &create(pod(ann.clone())));
            let msg = d.status.map(|s| s.1).unwrap_or_default();
            assert!(!d.allowed && msg.contains(want), "{ann}: {msg}");
        }
        // no image anywhere
        let mut no_image = injector(InjectTemplate::default());
        no_image.image = None;
        let d = mutate(&no_image, &OFF, &create(pod(annotated())));
        assert!(d.status.unwrap().1.contains("--injector-image"));
        // a volume name the sidecar needs is taken
        let mut p = pod(annotated());
        p["spec"]["volumes"] = json!([{"name": "agentsc-run", "emptyDir": {}}]);
        let d = mutate(&inj, &OFF, &create(p));
        assert!(d.status.unwrap().1.contains("\"agentsc-run\""));
    }

    /// The audit finding: annotation agentsc.io/sidecar-image could name any image.
    #[test]
    fn the_allow_list_decides_which_image_is_injected() {
        let (a, b) = (digest('a'), digest('b'));
        let on = SidecarImagesConfig {
            allowed_digests: vec![a.clone()],
        };
        let pinned = |d: &str| format!("ghcr.io/f8fvwgzc/agent-sidecar/agentscd@{d}");
        let mut inj = injector(InjectTemplate::default());
        inj.image = Some(pinned(&a));
        let image_of = |d: &Decision| d.patch[1]["value"][1]["image"].clone();
        // the pinned --injector-image
        let d = mutate(&inj, &on, &create(pod(annotated())));
        assert!(d.allowed);
        assert_eq!(image_of(&d), json!(pinned(&a)));
        assert_eq!(d.patch[1]["value"][0]["image"], json!(pinned(&a)));
        // an annotation pinned to an allowed digest (any registry: the digest names the content)
        let mut ann = annotated();
        ann[SIDECAR_IMAGE_ANNOTATION] = json!(format!("mirror.example/agentscd:0.2.0@{a}"));
        let d = mutate(&inj, &on, &create(pod(ann)));
        assert!(d.allowed, "{:?}", d.status);
        assert_eq!(
            image_of(&d),
            json!(format!("mirror.example/agentscd:0.2.0@{a}"))
        );
        // another digest, or a tag only: refused, naming the image
        for (image, want) in [
            (
                format!("evil.example/agentscd@{b}"),
                format!("annotation agentsc.io/sidecar-image \"evil.example/agentscd@{b}\" is pinned to {b}, which is not in sidecar_images.allowed_digests"),
            ),
            (
                "evil.example/agentscd:0.2.0".to_string(),
                "annotation agentsc.io/sidecar-image \"evil.example/agentscd:0.2.0\" is not pinned to a digest".to_string(),
            ),
        ] {
            let mut ann = annotated();
            ann[SIDECAR_IMAGE_ANNOTATION] = json!(image);
            let d = mutate(&inj, &on, &create(pod(ann)));
            let msg = d.status.map(|s| s.1).unwrap_or_default();
            assert!(!d.allowed && d.patch.is_empty() && msg.contains(&want), "{msg}");
        }
        // embassy's own image must be pinned too once the list is on
        inj.image = Some(IMAGE.into());
        let msg = mutate(&inj, &on, &create(pod(annotated())))
            .status
            .unwrap()
            .1;
        assert!(
            msg.contains(&format!(
                "embassy's --injector-image {IMAGE:?} is not pinned to a digest"
            )),
            "{msg}"
        );
        // off: as before, any image
        assert!(mutate(&inj, &OFF, &create(pod(annotated()))).allowed);
    }

    #[test]
    fn only_labelled_pod_creations_outside_the_control_plane_are_injected() {
        let inj = injector(InjectTemplate::default());
        let mut unlabelled = pod(annotated());
        unlabelled["metadata"]["labels"][INJECT_LABEL] = json!("false");
        assert_eq!(mutate(&inj, &OFF, &create(unlabelled)), Decision::allow());
        let mut in_cp = create(pod(annotated()));
        in_cp.namespace = Some("agentsc-system".into());
        assert_eq!(mutate(&inj, &OFF, &in_cp), Decision::allow());
        let mut update = create(pod(annotated()));
        update.operation = "UPDATE".into();
        assert_eq!(mutate(&inj, &OFF, &update), Decision::allow());
        let mut empty = create(pod(annotated()));
        empty.object = None;
        assert!(!mutate(&inj, &OFF, &empty).allowed);
    }

    fn state(
        policy: Option<PolicyConfig>,
    ) -> (
        Arc<WebhookState>,
        tokio::sync::broadcast::Receiver<Arc<CpAuditRecord>>,
    ) {
        let config = ControlPlaneConfig {
            policy,
            ..Default::default()
        };
        let cp_audit = Arc::new(CpAudit::with_writer(None, Box::new(std::io::sink())));
        let rx = cp_audit.subscribe();
        (
            Arc::new(WebhookState {
                injector: injector(InjectTemplate::default()),
                config: Arc::new(ArcSwap::from_pointee(config)),
                cp_audit,
            }),
            rx,
        )
    }

    fn charter_cr(extra_spec: Value) -> Value {
        let mut spec = json!({
            "service": {"name": "orders", "app_port": 8080},
            "agents": [{"name": "ops", "model": "claude-opus-5-5",
                        "tools": [{"name": "partner", "description": "d", "type": "http", "method": "GET", "url": "https://api.partner.example/v1/x"}]}],
            "authz": {"default": "deny", "callers": [{"identity": "local", "agents": ["*"]}]}
        });
        if let (Some(s), Some(e)) = (spec.as_object_mut(), extra_spec.as_object()) {
            for (k, v) in e {
                s.insert(k.clone(), v.clone());
            }
        }
        json!({
            "apiVersion": "agentsc.io/v1alpha1", "kind": "Charter",
            "metadata": {"name": "orders", "uid": "u", "resourceVersion": "5", "managedFields": []},
            "spec": spec
        })
    }

    fn charter_request(object: Value, user: &str) -> AdmissionRequest {
        AdmissionRequest {
            uid: "req-2".into(),
            namespace: Some("shop".into()),
            name: Some("orders".into()),
            operation: "CREATE".into(),
            user_info: UserInfo {
                username: Some(user.into()),
            },
            object: Some(object),
            old_object: None,
            dry_run: None,
        }
    }

    #[tokio::test]
    async fn a_valid_charter_is_admitted_and_audited() {
        let (st, mut rx) = state(None);
        let annotations = json!({"agentsc.io/version": "4", "agentsc.io/spec-sha256": "ab"});
        let mut new = charter_cr(json!({}));
        new["metadata"]["annotations"] = annotations.clone();
        let mut req = charter_request(new, "alice@example.com");
        req.operation = "UPDATE".into();
        let mut old = charter_cr(json!({}));
        old["metadata"]["annotations"] = annotations;
        // the version served before: embassy's status, not the annotation
        old["status"] = json!({"appliedVersion": "4"});
        req.old_object = Some(old);
        let d = validate_charter(&st, &req).await;
        assert_eq!(d, Decision::allow());
        let rec = rx.recv().await.unwrap();
        assert_eq!(
            (rec.action, rec.result),
            (CpAction::CrExternalEdit, CpResult::Ok)
        );
        assert_eq!(
            (rec.actor.as_str(), rec.actor_kind),
            ("k8s:alice@example.com", ActorKind::K8s)
        );
        assert_eq!(
            (rec.namespace.as_deref(), rec.service.as_deref()),
            (Some("shop"), Some("orders"))
        );
        assert_eq!(rec.from_version.as_deref(), Some("4"));
        assert_eq!(rec.sha256_after.as_ref().map(String::len), Some(64));
        assert!(rec.reason.as_deref().unwrap().contains("UPDATE admitted"));
    }

    #[tokio::test]
    async fn unknown_fields_are_refused() {
        let (st, mut rx) = state(None);
        let mut obj = charter_cr(json!({}));
        obj["spec"]["agents"][0]["modle"] = json!("typo");
        let d = validate_charter(&st, &charter_request(obj, "alice")).await;
        assert!(!d.allowed);
        let (code, msg) = d.status.unwrap();
        assert_eq!(code, 400);
        assert!(msg.contains("modle"), "{msg}");
        let rec = rx.recv().await.unwrap();
        assert_eq!(rec.result, CpResult::Invalid);
        // unknown top-level fields too (the CRD preserves them, the validator does not)
        let mut obj = charter_cr(json!({}));
        obj["extra"] = json!(1);
        assert!(
            !validate_charter(&st, &charter_request(obj, "alice"))
                .await
                .allowed
        );
        // and a name that is not the service's
        let mut obj = charter_cr(json!({}));
        obj["metadata"]["name"] = json!("inventory");
        assert!(
            !validate_charter(&st, &charter_request(obj, "alice"))
                .await
                .allowed
        );
    }

    #[tokio::test]
    async fn policy_violations_are_refused() {
        let policy = PolicyConfig {
            require_authz_default_deny: true,
            http_origin_allowlist: Some(vec!["https://other.example".into()]),
            forbid_learning_auto: true,
        };
        let (st, mut rx) = state(Some(policy));
        let obj = charter_cr(json!({"authz": {"default": "allow"}}));
        let mut obj = obj;
        obj["spec"]["agents"][0]["learning"] = json!({"enabled": true, "mode": "auto"});
        let d = validate_charter(&st, &charter_request(obj, "bob")).await;
        let (code, msg) = d.status.clone().unwrap();
        assert!(!d.allowed);
        assert_eq!(code, 403);
        assert!(msg.contains("policy.require_authz_default_deny"), "{msg}");
        assert!(msg.contains("policy.http_origin_allowlist: agent ops tool partner calls https://api.partner.example"), "{msg}");
        assert!(
            msg.contains("policy.forbid_learning_auto: agent ops"),
            "{msg}"
        );
        let rec = rx.recv().await.unwrap();
        assert_eq!(
            (rec.result, rec.actor.as_str()),
            (CpResult::Denied, "k8s:bob")
        );

        // the allowed origin passes (default ports normalized)
        let policy = PolicyConfig {
            require_authz_default_deny: true,
            http_origin_allowlist: Some(vec!["https://api.partner.example".into()]),
            forbid_learning_auto: true,
        };
        let (st, _rx) = state(Some(policy));
        let mut obj = charter_cr(json!({}));
        obj["spec"]["agents"][0]["tools"][0]["url"] = json!("https://API.partner.example:443/v1/x");
        assert!(
            validate_charter(&st, &charter_request(obj, "bob"))
                .await
                .allowed
        );
    }

    #[tokio::test]
    async fn embassys_own_writes_are_validated_but_not_audited() {
        let (st, mut rx) = state(None);
        let d = validate_charter(
            &st,
            &charter_request(
                charter_cr(json!({})),
                "system:serviceaccount:agentsc-system:embassy",
            ),
        )
        .await;
        assert!(d.allowed);
        assert!(rx.try_recv().is_err());
        let mut bad = charter_cr(json!({}));
        bad["spec"]["bogus"] = json!(1);
        let d = validate_charter(
            &st,
            &charter_request(bad, "system:serviceaccount:agentsc-system:embassy"),
        )
        .await;
        assert!(!d.allowed);
        // deletes are not this webhook's business
        let mut del = charter_request(charter_cr(json!({})), "alice");
        del.operation = "DELETE".into();
        assert!(validate_charter(&st, &del).await.allowed);
    }

    #[tokio::test]
    async fn only_embassy_may_change_the_version_annotations() {
        let (st, mut rx) = state(None);
        let with = |version: Option<&str>, hash: Option<&str>| {
            let mut o = charter_cr(json!({}));
            let mut a = Map::new();
            if let Some(v) = version {
                a.insert("agentsc.io/version".into(), json!(v));
            }
            if let Some(h) = hash {
                a.insert("agentsc.io/spec-sha256".into(), json!(h));
            }
            o["metadata"]["annotations"] = Value::Object(a);
            o
        };
        let update = |old: Value, new: Value, user: &str| {
            let mut r = charter_request(new, user);
            r.operation = "UPDATE".into();
            r.old_object = Some(old);
            r
        };
        let current = with(Some("3"), Some("h3"));
        // an old export re-applied: the version goes back
        let d = validate_charter(
            &st,
            &update(current.clone(), with(Some("1"), Some("h1")), "alice"),
        )
        .await;
        assert!(!d.allowed);
        let (code, msg) = d.status.unwrap();
        assert_eq!(code, 403);
        assert!(
            msg.contains(
                "annotation agentsc.io/version is written by embassy only (\"3\" → \"1\")"
            ),
            "{msg}"
        );
        assert!(msg.contains("agentsc.io/spec-sha256"), "{msg}");
        let rec = rx.recv().await.unwrap();
        assert_eq!(
            (rec.action, rec.result, rec.actor.as_str()),
            (CpAction::CrExternalEdit, CpResult::Denied, "k8s:alice")
        );
        // removing them (kubectl replace of a manifest without them) is a change too
        let d = validate_charter(&st, &update(current.clone(), with(None, None), "alice")).await;
        assert!(d.status.unwrap().1.contains("(\"3\" → absent)"));
        // a spec change that keeps them is fine
        let mut edited = current.clone();
        edited["spec"]["agents"][0]["model"] = json!("claude-sonnet-5-5");
        assert!(
            validate_charter(&st, &update(current.clone(), edited, "alice"))
                .await
                .allowed
        );
        // embassy writes them
        assert!(
            validate_charter(
                &st,
                &update(
                    current.clone(),
                    with(Some("4"), Some("h4")),
                    "system:serviceaccount:agentsc-system:embassy"
                )
            )
            .await
            .allowed
        );
        // a create may carry them (a restore; the store treats it as a new epoch)
        assert!(
            validate_charter(&st, &charter_request(with(Some("7"), Some("h7")), "velero"))
                .await
                .allowed
        );
    }

    async fn post(app: Router, path: &str, body: Value) -> (StatusCode, Value) {
        let resp = app
            .oneshot(
                Request::post(path)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    fn review(request: Value) -> Value {
        json!({"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "request": request})
    }

    #[tokio::test]
    async fn the_router_speaks_admission_review_v1() {
        let (st, _rx) = state(None);
        let app = router(st.clone());
        let (status, out) = post(
            app.clone(),
            "/mutate",
            review(json!({
                "uid": "abc", "kind": {"group": "", "version": "v1", "kind": "Pod"},
                "resource": {"group": "", "version": "v1", "resource": "pods"},
                "namespace": "shop", "operation": "CREATE",
                "userInfo": {"username": "system:serviceaccount:kube-system:replicaset-controller"},
                "object": pod(annotated()), "oldObject": null, "dryRun": false
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(out["apiVersion"], "admission.k8s.io/v1");
        assert_eq!(out["kind"], "AdmissionReview");
        let r = &out["response"];
        assert_eq!(
            (r["uid"].as_str(), r["allowed"].as_bool()),
            (Some("abc"), Some(true))
        );
        assert_eq!(r["patchType"], "JSONPatch");
        let patch: Value = serde_json::from_slice(
            &base64::engine::general_purpose::STANDARD
                .decode(r["patch"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(patch[1]["value"][0]["name"], "agentsc-runtime");
        assert_eq!(patch[1]["value"][1]["name"], "agentscd");

        // the allow-list comes from the live config: a reload that sets it applies at once
        // (the test injector's image is pinned by tag only, so it is refused now)
        let mut cfg = ControlPlaneConfig::clone(&st.config.load());
        cfg.sidecar_images.allowed_digests = vec![digest('a')];
        st.config.store(Arc::new(cfg));
        let (_, out) = post(
            app.clone(),
            "/mutate",
            review(json!({
                "uid": "abd", "namespace": "shop", "operation": "CREATE",
                "object": pod(annotated())
            })),
        )
        .await;
        assert_eq!(out["response"]["allowed"], false);
        assert!(
            out["response"]["status"]["message"]
                .as_str()
                .unwrap()
                .contains("--injector-image")
        );

        let (_, out) = post(
            app.clone(),
            "/validate-charter",
            review(json!({
                "uid": "def", "namespace": "shop", "name": "orders", "operation": "CREATE",
                "userInfo": {"username": "alice"}, "object": {"apiVersion": "agentsc.io/v1alpha1", "kind": "Charter", "metadata": {"name": "orders"}, "spec": {"service": {"name": "orders"}}}
            })),
        )
        .await;
        let r = &out["response"];
        assert_eq!(
            (r["uid"].as_str(), r["allowed"].as_bool()),
            (Some("def"), Some(false))
        );
        assert_eq!(r["status"]["code"], 400);
        assert!(r["status"]["message"].as_str().unwrap().contains("invalid"));
        assert!(r.get("patch").is_none());

        // not an AdmissionReview, or another version
        let (status, _) = post(app.clone(), "/mutate", json!({"hello": 1})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = post(
            app.clone(),
            "/mutate",
            json!({"apiVersion": "admission.k8s.io/v1beta1", "kind": "AdmissionReview", "request": {"uid": "x"}}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let resp = app
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
