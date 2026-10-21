//! Admission webhooks (design §13, component `webhook`), served on `--webhook-addr` with the
//! serving certificate by [`crate::ca_components`]. `AdmissionReview` `admission.k8s.io/v1` in
//! and out.
//!
//! **`/mutate`** (`attache-sidecar-injector`, pods labelled `attache.io/inject: "true"`): adds
//! the `attached` native sidecar (an init container with `restartPolicy: Always` and a
//! `startupProbe` on the sidecar's `/readyz`) with a JSONPatch. `/readyz` is served by the app
//! API, which listens on `127.0.0.1:3500` only (the app shares the pod's loopback; the kubelet's
//! `httpGet` probes connect to the pod IP and cannot reach it), so the probe is an `exec` of
//! [`READY_COMMAND`] inside the sidecar container. **Image contract:** whatever image is
//! injected (the official `attached` image, `--injector-image`, or annotation
//! `attache.io/sidecar-image`) must have [`READY_COMMAND`] on its `PATH`, exiting 0 exactly when
//! `GET http://127.0.0.1:3500/readyz` answers 200; the official image ships it
//! (`docker/attache-ready`, which needs `python3`). An image without it never passes the probe:
//! the pod waits [`STARTUP_PROBE_SECONDS`] and the sidecar is restarted. The patch:
//!
//! - env for managed mode: `ATTACHE_CONTROL_PLANE=embassy.<cp-ns>.svc:15012`,
//!   `ATTACHE_CA_ADDRESS=embassy-ca.<cp-ns>.svc:15012`, `ATTACHE_SERVICE`, `ATTACHE_NAMESPACE`,
//!   `ATTACHE_APP_PORT`, `POD_NAME` and `POD_NAMESPACE` (fieldRef), `ATTACHE_CA_PEM` (the CA
//!   bundle), `ATTACHE_K8S_TOKEN_FILE`, and `ANTHROPIC_API_KEY` from key `ANTHROPIC_API_KEY` of
//!   the Secret named by annotation `attache.io/anthropic-secret` when present;
//! - an `emptyDir` at `/run/attache`, a projected service-account token (audience `attache`,
//!   `expirationSeconds: 3600`) at `/var/run/secrets/attache/token`, containerPort 50002 `mesh`;
//! - image from annotation `attache.io/sidecar-image`, else `--injector-image`;
//! - `imagePullPolicy`, `resources`, `securityContext` and the env `OTEL_EXPORTER_OTLP_ENDPOINT` /
//!   `ATTACHE_OTLP_ENDPOINT_ALLOW` from env `ATTACHE_INJECT_TEMPLATE` (the chart → injector
//!   contract, [`InjectTemplate`]); without it, the chart's defaults;
//! - annotation `attache.io/injected: "true"`.
//!
//! Annotations `attache.io/service` (a DNS label) and `attache.io/app-port` are required; without
//! them the pod is denied with a message naming what is missing. A pod that already has a
//! container named `attached` is left alone and annotated `attache.io/injected:
//! skipped-existing`. Mutating an already mutated pod changes nothing (idempotent).
//!
//! **`/validate-charter`** (`attache-charter-validator`, CREATE/UPDATE of `charters`): the
//! charter validator ([`attache_charter::Charter::from_value`] on the whole resource, so unknown
//! fields are refused) and the `ControlPlaneConfig` policy ([`policy_violations`]). An UPDATE by
//! anyone but embassy that changes annotation `attache.io/version` or `attache.io/spec-sha256`
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
use crate::config::{ControlPlaneConfig, PolicyConfig};
use crate::context::ServeContext;
use crate::cp_audit::{CpAction, CpAudit, CpResult};
use crate::names::{RESERVED_SERVICE, is_dns_label, is_dns_subdomain};
use crate::servingcert::ServingCertSource;
use crate::store::{Actor, ActorKind};

/// Largest admission request body (a Charter and its old object, up to 3 MiB each).
pub const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
pub const INJECT_LABEL: &str = "attache.io/inject";
pub const SERVICE_ANNOTATION: &str = "attache.io/service";
pub const APP_PORT_ANNOTATION: &str = "attache.io/app-port";
pub const ANTHROPIC_SECRET_ANNOTATION: &str = "attache.io/anthropic-secret";
pub const SIDECAR_IMAGE_ANNOTATION: &str = "attache.io/sidecar-image";
pub const INJECTED_ANNOTATION: &str = "attache.io/injected";
pub const SKIPPED_EXISTING: &str = "skipped-existing";
/// The injected container's name (and the one whose presence skips injection).
pub const SIDECAR_CONTAINER: &str = "attached";
pub const RUN_VOLUME: &str = "attache-run";
pub const RUN_DIR: &str = "/run/attache";
pub const TOKEN_VOLUME: &str = "attache-token";
pub const TOKEN_DIR: &str = "/var/run/secrets/attache";
pub const TOKEN_FILE: &str = "/var/run/secrets/attache/token";
pub const TOKEN_AUDIENCE: &str = "attache";
pub const TOKEN_EXPIRATION_SECONDS: i64 = 3600;
pub const MESH_PORT: i32 = 50002;
/// The startup probe's command (see the module docs for the image contract).
pub const READY_COMMAND: &str = "attache-ready";
/// Probe period and failures before the sidecar is restarted: 2 s × 150 = 300 s for the first
/// certificate, the charter and the agent runtime.
const STARTUP_PROBE_PERIOD: i32 = 2;
const STARTUP_PROBE_FAILURES: i32 = 150;
pub const STARTUP_PROBE_SECONDS: i32 = STARTUP_PROBE_PERIOD * STARTUP_PROBE_FAILURES;
/// The control-plane Services' gRPC port (design §13).
pub const CONTROL_PLANE_PORT: u16 = 15012;
/// The env var with the chart → injector template.
pub const TEMPLATE_ENV: &str = "ATTACHE_INJECT_TEMPLATE";
/// The only env names the template may set (the sidecar's own telemetry settings).
pub const TEMPLATE_ENV_ALLOWED: [&str; 2] =
    ["OTEL_EXPORTER_OTLP_ENDPOINT", "ATTACHE_OTLP_ENDPOINT_ALLOW"];

// ---- the chart → injector template -----------------------------------------------------------------

/// `ATTACHE_INJECT_TEMPLATE`: Kubernetes `Container` fields applied to the generated `attached`
/// container. Any other field, or an env name outside [`TEMPLATE_ENV_ALLOWED`], is an error at
/// start-up. A field left out keeps the built-in default (the chart's default values).
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

/// Where `ATTACHE_CA_PEM` comes from: the CA's roots, or the serving certificate's bundle.
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

/// What the injector needs.
#[derive(Clone)]
pub struct Injector {
    /// `--injector-image` (a pod may name another with `attache.io/sidecar-image`).
    pub image: Option<String>,
    pub template: InjectTemplate,
    pub cp_namespace: String,
    pub ca_bundle: CaBundle,
}

/// The webhook handlers' state.
pub struct WebhookState {
    pub injector: Injector,
    pub config: Arc<ArcSwap<ControlPlaneConfig>>,
    pub cp_audit: Arc<CpAudit>,
}

impl WebhookState {
    /// From the serve context and env `ATTACHE_INJECT_TEMPLATE`.
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
    let decision = mutate(&state.injector, &req);
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

fn has_container(pod: &Value, name: &str) -> bool {
    ["containers", "initContainers"].iter().any(|list| {
        pod.get("spec")
            .and_then(|s| s.get(*list))
            .and_then(Value::as_array)
            .is_some_and(|l| {
                l.iter()
                    .any(|c| c.get("name").and_then(Value::as_str) == Some(name))
            })
    })
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
    req: &AdmissionRequest,
    pod: &Value,
) -> Result<PodRequest, String> {
    let mut problems = Vec::new();
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
        Some(i) => i.to_string(),
        None => match &inj.image {
            Some(i) => i.clone(),
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
    for (list, volume) in [("volumes", RUN_VOLUME), ("volumes", TOKEN_VOLUME)] {
        let taken = pod
            .get("spec")
            .and_then(|s| s.get(list))
            .and_then(Value::as_array)
            .is_some_and(|l| {
                l.iter()
                    .any(|v| v.get("name").and_then(Value::as_str) == Some(volume))
            });
        if taken {
            problems.push(format!(
                "the pod already has a volume named {volume:?}, which the sidecar needs"
            ));
        }
    }
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
            "attache sidecar injection ({INJECT_LABEL}=true): {}",
            problems.join("; ")
        ))
    }
}

/// The `attached` container for `p`.
fn sidecar_container(inj: &Injector, p: &PodRequest) -> Container {
    let cp = &inj.cp_namespace;
    let mut env_list = vec![
        env(
            "ATTACHE_CONTROL_PLANE",
            format!("embassy.{cp}.svc:{CONTROL_PLANE_PORT}"),
        ),
        env(
            "ATTACHE_CA_ADDRESS",
            format!("embassy-ca.{cp}.svc:{CONTROL_PLANE_PORT}"),
        ),
        env("ATTACHE_SERVICE", p.service.clone()),
        env("ATTACHE_NAMESPACE", p.namespace.clone()),
        env("ATTACHE_APP_PORT", p.app_port.to_string()),
        field_env("POD_NAME", "metadata.name"),
        field_env("POD_NAMESPACE", "metadata.namespace"),
        env("ATTACHE_CA_PEM", inj.ca_bundle.pem()),
        env("ATTACHE_K8S_TOKEN_FILE", TOKEN_FILE),
    ];
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
            VolumeMount {
                name: RUN_VOLUME.into(),
                mount_path: RUN_DIR.into(),
                ..Default::default()
            },
            VolumeMount {
                name: TOKEN_VOLUME.into(),
                mount_path: TOKEN_DIR.into(),
                read_only: Some(true),
                ..Default::default()
            },
        ]),
        // /readyz listens on loopback only: an exec probe (module docs, image contract)
        startup_probe: Some(Probe {
            exec: Some(ExecAction {
                command: Some(vec![READY_COMMAND.into()]),
            }),
            period_seconds: Some(STARTUP_PROBE_PERIOD),
            timeout_seconds: Some(3),
            failure_threshold: Some(STARTUP_PROBE_FAILURES),
            ..Default::default()
        }),
        resources: Some(inj.template.resources()),
        security_context: Some(inj.template.security_context()),
        ..Default::default()
    }
}

fn sidecar_volumes() -> Vec<Volume> {
    vec![
        Volume {
            name: RUN_VOLUME.into(),
            empty_dir: Some(Default::default()),
            ..Default::default()
        },
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

/// The `/mutate` decision for one request.
pub fn mutate(inj: &Injector, req: &AdmissionRequest) -> Decision {
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
    if has_container(pod, SIDECAR_CONTAINER) {
        // ours (already injected) or the pod's own: leave the containers alone
        if annotation(pod, INJECTED_ANNOTATION).is_some() {
            return Decision::allow();
        }
        return Decision::patch(vec![set_annotation_op(
            pod,
            INJECTED_ANNOTATION,
            SKIPPED_EXISTING,
        )]);
    }
    let p = match read_pod_request(inj, req, pod) {
        Ok(p) => p,
        Err(message) => return Decision::deny(400, message),
    };
    let container = match serde_json::to_value(sidecar_container(inj, &p)) {
        Ok(c) => c,
        Err(e) => {
            return Decision::deny(500, format!("building the sidecar container failed: {e}"));
        }
    };
    let spec = pod.get("spec");
    let mut ops = vec![set_annotation_op(pod, INJECTED_ANNOTATION, "true")];
    if spec
        .and_then(|s| s.get("initContainers"))
        .is_some_and(Value::is_array)
    {
        // first, so the sidecar is up before the other init containers and the app
        ops.push(json!({"op": "add", "path": "/spec/initContainers/0", "value": container}));
    } else {
        ops.push(json!({"op": "add", "path": "/spec/initContainers", "value": [container]}));
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
    charter: &attache_charter::Charter,
    policy: Option<&PolicyConfig>,
) -> Vec<String> {
    let Some(policy) = policy else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if policy.require_authz_default_deny && charter.authz.default != attache_charter::Decision::Deny
    {
        out.push("policy.require_authz_default_deny: authz.default must be deny".to_string());
    }
    if let Some(allowed) = &policy.http_origin_allowlist {
        for agent in &charter.agents {
            for tool in &agent.tools {
                if tool.tool_type != attache_charter::ToolType::Http {
                    continue;
                }
                let origin = tool
                    .url
                    .as_deref()
                    .and_then(attache_charter::http_origin)
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
                .is_some_and(|l| l.mode == attache_charter::LearningMode::Auto)
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
        attache_charter::Charter::from_value(&object).map_err(Some)
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
                attache_charter::CharterError::Invalid(list) => list.join("; "),
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

    const IMAGE: &str = "ghcr.io/f8fvwgzc/agent-sidecar/attached:0.2.0";

    fn injector(template: InjectTemplate) -> Injector {
        Injector {
            image: Some(IMAGE.into()),
            template,
            cp_namespace: "attache-system".into(),
            ca_bundle: CaBundle::Fixed("CA PEM".into()),
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

    fn expected_container(extra_env: &[Value]) -> Value {
        let mut env = vec![
            json!({"name": "ATTACHE_CONTROL_PLANE", "value": "embassy.attache-system.svc:15012"}),
            json!({"name": "ATTACHE_CA_ADDRESS", "value": "embassy-ca.attache-system.svc:15012"}),
            json!({"name": "ATTACHE_SERVICE", "value": "orders"}),
            json!({"name": "ATTACHE_NAMESPACE", "value": "shop"}),
            json!({"name": "ATTACHE_APP_PORT", "value": "8080"}),
            json!({"name": "POD_NAME", "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.name"}}}),
            json!({"name": "POD_NAMESPACE", "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.namespace"}}}),
            json!({"name": "ATTACHE_CA_PEM", "value": "CA PEM"}),
            json!({"name": "ATTACHE_K8S_TOKEN_FILE", "value": "/var/run/secrets/attache/token"}),
        ];
        env.extend(extra_env.iter().cloned());
        json!({
            "name": "attached",
            "image": IMAGE,
            "imagePullPolicy": "IfNotPresent",
            "restartPolicy": "Always",
            "ports": [{"name": "mesh", "containerPort": 50002, "protocol": "TCP"}],
            "env": env,
            "volumeMounts": [
                {"name": "attache-run", "mountPath": "/run/attache"},
                {"name": "attache-token", "mountPath": "/var/run/secrets/attache", "readOnly": true}
            ],
            "startupProbe": {"exec": {"command": ["attache-ready"]}, "periodSeconds": 2, "timeoutSeconds": 3, "failureThreshold": 150},
            "resources": {"requests": {"cpu": "50m", "memory": "128Mi"}, "limits": {"memory": "512Mi"}},
            "securityContext": {
                "runAsNonRoot": true, "runAsUser": 10001, "runAsGroup": 10001,
                "readOnlyRootFilesystem": true, "allowPrivilegeEscalation": false,
                "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}
            }
        })
    }

    fn expected_volumes() -> Value {
        json!([
            {"name": "attache-run", "emptyDir": {}},
            {"name": "attache-token", "projected": {"sources": [
                {"serviceAccountToken": {"audience": "attache", "expirationSeconds": 3600, "path": "token"}}
            ]}}
        ])
    }

    #[test]
    fn inject_golden_patch() {
        let d = mutate(
            &injector(InjectTemplate::default()),
            &create(pod(annotated())),
        );
        assert!(d.allowed && d.status.is_none());
        assert_eq!(
            Value::Array(d.patch.clone()),
            json!([
                {"op": "add", "path": "/metadata/annotations/attache.io~1injected", "value": "true"},
                {"op": "add", "path": "/spec/initContainers", "value": [expected_container(&[])]},
                {"op": "add", "path": "/spec/volumes", "value": expected_volumes()}
            ])
        );
    }

    #[test]
    fn existing_init_containers_and_volumes_are_kept() {
        let mut p = pod(annotated());
        p["spec"]["initContainers"] = json!([{"name": "migrate", "image": "m:1"}]);
        p["spec"]["volumes"] = json!([{"name": "data", "emptyDir": {}}]);
        let d = mutate(&injector(InjectTemplate::default()), &create(p.clone()));
        let paths: Vec<&str> = d
            .patch
            .iter()
            .map(|o| o["path"].as_str().unwrap())
            .collect();
        assert_eq!(
            paths,
            [
                "/metadata/annotations/attache.io~1injected",
                "/spec/initContainers/0",
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
        assert_eq!(init, ["attached", "migrate"], "the sidecar starts first");
        assert_eq!(p["spec"]["volumes"].as_array().unwrap().len(), 3);
        assert_eq!(p["spec"]["containers"][0]["name"], "app");
    }

    #[test]
    fn the_template_and_the_secret_are_applied() {
        let template = InjectTemplate::parse(
            r#"{"imagePullPolicy":"Always",
                "resources":{"requests":{"cpu":"10m"}},
                "securityContext":{"runAsNonRoot":true},
                "env":[{"name":"OTEL_EXPORTER_OTLP_ENDPOINT","value":"http://otel:4318"},
                       {"name":"ATTACHE_OTLP_ENDPOINT_ALLOW","value":"http://otel:4318"}]}"#,
        )
        .unwrap();
        let mut ann = annotated();
        ann[ANTHROPIC_SECRET_ANNOTATION] = json!("attache-anthropic");
        ann[SIDECAR_IMAGE_ANNOTATION] = json!("registry.local/attached:dev");
        let d = mutate(&injector(template), &create(pod(ann)));
        let c = &d.patch[1]["value"][0];
        let mut want = expected_container(&[
            json!({"name": "ANTHROPIC_API_KEY", "valueFrom": {"secretKeyRef": {"name": "attache-anthropic", "key": "ANTHROPIC_API_KEY", "optional": true}}}),
            json!({"name": "OTEL_EXPORTER_OTLP_ENDPOINT", "value": "http://otel:4318"}),
            json!({"name": "ATTACHE_OTLP_ENDPOINT_ALLOW", "value": "http://otel:4318"}),
        ]);
        want["image"] = json!("registry.local/attached:dev");
        want["imagePullPolicy"] = json!("Always");
        want["resources"] = json!({"requests": {"cpu": "10m"}});
        want["securityContext"] = json!({"runAsNonRoot": true});
        assert_eq!(c, &want);
    }

    #[test]
    fn templates_may_not_reach_the_injectors_own_settings() {
        for bad in [
            r#"{"env":[{"name":"ATTACHE_CONTROL_PLANE","value":"evil:15012"}]}"#,
            r#"{"env":[{"name":"ATTACHE_SERVICE","value":"x"}]}"#,
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

    #[test]
    fn pods_with_an_attached_container_are_left_alone() {
        let mut p = pod(annotated());
        p["spec"]["containers"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name": "attached", "image": "attache/attached:0.1"}));
        let d = mutate(&injector(InjectTemplate::default()), &create(p.clone()));
        assert_eq!(
            d.patch,
            [
                json!({"op": "add", "path": "/metadata/annotations/attache.io~1injected", "value": "skipped-existing"})
            ]
        );
        apply(&mut p, &d.patch);
        assert_eq!(
            mutate(&injector(InjectTemplate::default()), &create(p)),
            Decision::allow()
        );
        // without annotations at all (and without the required ones: they are not needed then)
        let mut bare = pod(json!(null));
        bare["metadata"]
            .as_object_mut()
            .unwrap()
            .remove("annotations");
        bare["spec"]["initContainers"] = json!([{"name": "attached"}]);
        let d = mutate(&injector(InjectTemplate::default()), &create(bare));
        assert_eq!(
            d.patch,
            [
                json!({"op": "add", "path": "/metadata/annotations", "value": {"attache.io/injected": "skipped-existing"}})
            ]
        );
    }

    #[test]
    fn missing_or_bad_annotations_are_denied_with_a_clear_message() {
        let inj = injector(InjectTemplate::default());
        let d = mutate(&inj, &create(pod(json!({}))));
        assert!(!d.allowed);
        let (code, msg) = d.status.unwrap();
        assert_eq!(code, 400);
        assert!(
            msg.contains("annotation attache.io/service is required"),
            "{msg}"
        );
        assert!(
            msg.contains("annotation attache.io/app-port is required"),
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
            let d = mutate(&inj, &create(pod(ann.clone())));
            let msg = d.status.map(|s| s.1).unwrap_or_default();
            assert!(!d.allowed && msg.contains(want), "{ann}: {msg}");
        }
        // no image anywhere
        let mut no_image = injector(InjectTemplate::default());
        no_image.image = None;
        let d = mutate(&no_image, &create(pod(annotated())));
        assert!(d.status.unwrap().1.contains("--injector-image"));
        // a volume name the sidecar needs is taken
        let mut p = pod(annotated());
        p["spec"]["volumes"] = json!([{"name": "attache-run", "emptyDir": {}}]);
        let d = mutate(&inj, &create(p));
        assert!(d.status.unwrap().1.contains("\"attache-run\""));
    }

    #[test]
    fn injection_is_idempotent() {
        let inj = injector(InjectTemplate::default());
        let mut p = pod(annotated());
        let first = mutate(&inj, &create(p.clone()));
        apply(&mut p, &first.patch);
        assert_eq!(p["metadata"]["annotations"][INJECTED_ANNOTATION], "true");
        assert_eq!(p["spec"]["initContainers"][0], expected_container(&[]));
        let second = mutate(&inj, &create(p.clone()));
        assert_eq!(second, Decision::allow());
    }

    #[test]
    fn only_labelled_pod_creations_outside_the_control_plane_are_injected() {
        let inj = injector(InjectTemplate::default());
        let mut unlabelled = pod(annotated());
        unlabelled["metadata"]["labels"][INJECT_LABEL] = json!("false");
        assert_eq!(mutate(&inj, &create(unlabelled)), Decision::allow());
        let mut in_cp = create(pod(annotated()));
        in_cp.namespace = Some("attache-system".into());
        assert_eq!(mutate(&inj, &in_cp), Decision::allow());
        let mut update = create(pod(annotated()));
        update.operation = "UPDATE".into();
        assert_eq!(mutate(&inj, &update), Decision::allow());
        let mut empty = create(pod(annotated()));
        empty.object = None;
        assert!(!mutate(&inj, &empty).allowed);
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
            "apiVersion": "attache.io/v1alpha1", "kind": "Charter",
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
        let annotations = json!({"attache.io/version": "4", "attache.io/spec-sha256": "ab"});
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
                "system:serviceaccount:attache-system:embassy",
            ),
        )
        .await;
        assert!(d.allowed);
        assert!(rx.try_recv().is_err());
        let mut bad = charter_cr(json!({}));
        bad["spec"]["bogus"] = json!(1);
        let d = validate_charter(
            &st,
            &charter_request(bad, "system:serviceaccount:attache-system:embassy"),
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
                a.insert("attache.io/version".into(), json!(v));
            }
            if let Some(h) = hash {
                a.insert("attache.io/spec-sha256".into(), json!(h));
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
                "annotation attache.io/version is written by embassy only (\"3\" → \"1\")"
            ),
            "{msg}"
        );
        assert!(msg.contains("attache.io/spec-sha256"), "{msg}");
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
                    "system:serviceaccount:attache-system:embassy"
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
        let app = router(st);
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
        assert_eq!(patch[1]["value"][0]["name"], "attached");

        let (_, out) = post(
            app.clone(),
            "/validate-charter",
            review(json!({
                "uid": "def", "namespace": "shop", "name": "orders", "operation": "CREATE",
                "userInfo": {"username": "alice"}, "object": {"apiVersion": "attache.io/v1alpha1", "kind": "Charter", "metadata": {"name": "orders"}, "spec": {"service": {"name": "orders"}}}
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
