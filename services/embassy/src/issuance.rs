//! `CertificateAuthority.IssueCertificate` (design §7, component `ca`).
//!
//! A sidecar sends a CSR and one credential; it gets a fresh workload leaf for
//! `spiffe://<trust domain>/ns/<ns>/svc/<svc>` (`--trust-domain`) only if, in this order:
//!
//! 1. `namespace` and `service` are DNS-1123 labels and not reserved (the control-plane
//!    namespace, the service `embassy`) — else `INVALID_ARGUMENT`;
//! 2. the CSR is one ECDSA P-256 request whose self-signature verifies (only its public key is
//!    used; subject, SANs and extensions are ignored) — else `INVALID_ARGUMENT`;
//! 3. exactly one credential is given and it grants that identity — else `UNAUTHENTICATED` or
//!    `PERMISSION_DENIED` (`UNAVAILABLE` when the Kubernetes API cannot be asked):
//!    - a **join token** (`issuance.join_tokens`): its SHA-256 matches an unexpired entry whose
//!      `namespace` is the request's and whose `services` lists the request's service;
//!    - a **Kubernetes token** (`issuance.kubernetes`): a TokenReview with audience `agentsc`
//!      authenticates it (and says so in `status.audiences`) as a service account bound to a
//!      pod (`authentication.kubernetes.io/pod-name` / `pod-uid` extras); the pod exists, has
//!      that uid and is not terminating; pod, token and request namespaces are equal; the
//!      service is the `AGENTSC_SERVICE` env of the pod's `agentscd` container (init or
//!      regular; container env is immutable) and equals the request's; the pod's
//!      `serviceAccountName` is the token's; with `sidecar_images.allowed_digests` set, the pod's
//!      sidecar containers (`agentscd`, and `agentsc-runtime` when there is one) run allowed
//!      images with their own program ([`crate::sidecar_images::check_running_pod`]: the digest
//!      of the `imageID` the kubelet reports in `status.initContainerStatuses[]` or
//!      `status.containerStatuses[]`, `UNAVAILABLE` while it has reported none yet); and the
//!      service account is the service's name or listed in the stored charter's
//!      `service.service_accounts`.
//!
//! A renewal is a new `IssueCertificate` with a fresh token and CSR, so it passes every check
//! again: a sidecar whose image was swapped after its first certificate gets no second one.
//!
//! The leaf has the URI SAN, the four DNS SANs, EKU serverAuth + clientAuth and the lifetime
//! `issuance.workload_cert_ttl` ([`crate::ca::CaMaterial::sign_workload`]). Every issuance and
//! refusal is a control-plane audit record (`cert_issue` / `cert_denied`) naming the identity
//! (`namespace`, `service`), the pod or join token, and the public key's SHA-256
//! (`sha256_after`). The actor of an issuance follows the `sidecar:<spiffe id>/<pod>` convention
//! of design §7 (`sidecar:spiffe://<td>/ns/<ns>/svc/<svc>/<pod>`, or `.../join:<token name>`
//! for a join token); a refusal never names the identity that was asked for but only what the
//! credential showed: `sidecar:pod:<ns>/<pod>`, `sidecar:join:<token name>` or `sidecar:unknown`.
//!
//! **Serving it.** In split mode (`embassy-ca`, no `controlplane` component) [`crate::ca_components`]
//! serves [`issuance_service`] alone on `--grpc-addr`. When the `controlplane` component runs in
//! the same process, `--grpc-addr` is the control plane's tonic server: it must add
//! [`issuance_service`] next to `ControlPlaneServer` (TLS with optional client certificates);
//! `ca_components` then starts no gRPC listener of its own.
use std::sync::Arc;

use agentsc_proto::certificate_authority_server::{
    CertificateAuthority, CertificateAuthorityServer,
};
use agentsc_proto::{CertificateRequest, CertificateResponse};
use arc_swap::ArcSwap;
use chrono::{DateTime, SecondsFormat, Utc};
use k8s_openapi::api::core::v1::{Container, Pod};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tonic::{Code, Request, Response, Status};

use crate::ca::CaMaterial;
use crate::config::ControlPlaneConfig;
use crate::context::ServeContext;
use crate::cp_audit::{CpAction, CpAudit, CpResult};
use crate::k8s::client::{KubeApi, KubeClient};
use crate::names::{RESERVED_SERVICE, is_dns_label};
use crate::store::{Actor, ActorKind, ServiceKey, Store, StoreError};

/// gRPC max decode of `IssueCertificate` (design §3).
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// The TokenReview audience (and the projected token's audience, design §13).
pub const AUDIENCE: &str = "agentsc";
pub const POD_NAME_EXTRA: &str = "authentication.kubernetes.io/pod-name";
pub const POD_UID_EXTRA: &str = "authentication.kubernetes.io/pod-uid";
/// The container the service is read from, and the env var.
pub const SIDECAR_CONTAINER: &str = "agentscd";
pub const SERVICE_ENV: &str = "AGENTSC_SERVICE";

/// Where the Kubernetes calls go.
enum KubeSource {
    /// Given (tests, or a client the caller already has).
    Fixed(Arc<dyn KubeApi>),
    /// The in-cluster client, created on the first Kubernetes token (a failure is retried on
    /// the next one).
    Lazy(tokio::sync::OnceCell<Arc<dyn KubeApi>>),
}

/// The `CertificateAuthority` service.
pub struct Issuer {
    ca: Arc<CaMaterial>,
    config: Arc<ArcSwap<ControlPlaneConfig>>,
    store: Option<Arc<dyn Store>>,
    cp_audit: Arc<CpAudit>,
    cp_namespace: String,
    kube: KubeSource,
}

impl std::fmt::Debug for Issuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issuer")
            .field("cp_namespace", &self.cp_namespace)
            .finish_non_exhaustive()
    }
}

/// `IssueCertificate` for `ctx`, ready to add to a tonic server (`max_decoding_message_size`
/// [`MAX_REQUEST_BYTES`]). Needs the `ca` component's material (`ctx.ca`).
pub fn issuance_service(ctx: &ServeContext) -> anyhow::Result<CertificateAuthorityServer<Issuer>> {
    let ca = ctx.ca.clone().ok_or_else(|| {
        anyhow::anyhow!("IssueCertificate needs the CA (--ca-dir or --ca-secret)")
    })?;
    let issuer = Issuer::new(
        ca,
        ctx.config.clone(),
        ctx.store.clone(),
        ctx.cp_audit.clone(),
        ctx.args.cp_namespace.clone(),
        None,
    );
    Ok(issuer.into_server())
}

/// What a credential showed about its holder (the audit actor).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Caller {
    /// A pod-bound Kubernetes token: the pod.
    Pod { namespace: String, name: String },
    /// A join token, by its `issuance.join_tokens` name.
    Join { name: String },
}

/// A refusal: the gRPC status and what the audit record says.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Denial {
    code: Code,
    message: String,
    /// Who the credential showed the caller to be, when it showed anything.
    who: Option<Caller>,
}

fn deny(code: Code, message: impl Into<String>) -> Denial {
    Denial {
        code,
        message: message.into(),
        who: None,
    }
}

/// What granted an identity.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Grant {
    caller: Caller,
    /// The pod's service account (Kubernetes tokens).
    service_account: Option<String>,
}

impl Grant {
    fn describe(&self) -> String {
        match (&self.caller, &self.service_account) {
            (Caller::Pod { namespace, name }, sa) => format!(
                "kubernetes pod {namespace}/{name}, service account {}",
                sa.as_deref().unwrap_or("default")
            ),
            (Caller::Join { name }, _) => format!("join token {name}"),
        }
    }
}

/// `a == b` without an early exit.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A request field quoted for an error message, at most 64 characters.
fn quote(s: &str) -> String {
    let short: String = s.chars().take(64).collect();
    format!("{short:?}")
}

/// `service.service_accounts` of a stored charter (plain or custom-resource form).
fn charter_service_accounts(charter_json: &Value) -> Vec<String> {
    let doc = match charter_json.get("spec") {
        Some(spec) if charter_json.get("metadata").is_some() => spec,
        _ => charter_json,
    };
    doc.get("service")
        .and_then(|s| s.get("service_accounts"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

/// The value of `AGENTSC_SERVICE` on the pod's `agentscd` container (init containers first;
/// the last entry of a repeated name wins, as in Kubernetes). Only a literal `value` counts.
pub fn pod_service(pod: &Pod) -> Option<String> {
    let spec = pod.spec.as_ref()?;
    let find = |list: &[Container]| -> Option<Option<String>> {
        let c = list.iter().find(|c| c.name == SIDECAR_CONTAINER)?;
        Some(
            c.env
                .iter()
                .flatten()
                .rev()
                .find(|e| e.name == SERVICE_ENV)
                .and_then(|e| {
                    if e.value_from.is_some() {
                        None
                    } else {
                        e.value.clone()
                    }
                }),
        )
    };
    let init = spec.init_containers.as_deref().unwrap_or_default();
    find(init).or_else(|| find(&spec.containers)).flatten()
}

impl Issuer {
    /// `kube`: the Kubernetes API to use; `None` = the in-cluster client, created when the
    /// first Kubernetes token arrives.
    pub fn new(
        ca: Arc<CaMaterial>,
        config: Arc<ArcSwap<ControlPlaneConfig>>,
        store: Option<Arc<dyn Store>>,
        cp_audit: Arc<CpAudit>,
        cp_namespace: String,
        kube: Option<Arc<dyn KubeApi>>,
    ) -> Self {
        Self {
            ca,
            config,
            store,
            cp_audit,
            cp_namespace,
            kube: match kube {
                Some(k) => KubeSource::Fixed(k),
                None => KubeSource::Lazy(tokio::sync::OnceCell::new()),
            },
        }
    }

    /// The tonic service, with the 64 KiB decode limit.
    pub fn into_server(self) -> CertificateAuthorityServer<Issuer> {
        CertificateAuthorityServer::new(self).max_decoding_message_size(MAX_REQUEST_BYTES)
    }

    async fn kube_api(&self) -> Result<Arc<dyn KubeApi>, Denial> {
        match &self.kube {
            KubeSource::Fixed(k) => Ok(k.clone()),
            KubeSource::Lazy(cell) => cell
                .get_or_try_init(|| async {
                    KubeClient::try_default()
                        .await
                        .map(|c| Arc::new(c) as Arc<dyn KubeApi>)
                })
                .await
                .cloned()
                .map_err(|e| {
                    deny(
                        Code::Unavailable,
                        format!("the Kubernetes API is not reachable: {e:#}"),
                    )
                }),
        }
    }

    fn check_names(&self, namespace: &str, service: &str) -> Result<(), Denial> {
        let mut problems = Vec::new();
        if !is_dns_label(namespace) {
            problems.push(format!(
                "namespace {} is not a DNS-1123 label",
                quote(namespace)
            ));
        } else if namespace == self.cp_namespace {
            problems.push(format!(
                "namespace {namespace:?} is the control plane's and is never issued certificates"
            ));
        }
        if !is_dns_label(service) {
            problems.push(format!(
                "service {} is not a DNS-1123 label",
                quote(service)
            ));
        } else if service == RESERVED_SERVICE {
            problems.push(format!(
                "service {service:?} is reserved for the control plane"
            ));
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(deny(Code::InvalidArgument, problems.join("; ")))
        }
    }

    fn check_join(&self, token: &str, namespace: &str, service: &str) -> Result<Grant, Denial> {
        let hash = hex::encode(Sha256::digest(token.as_bytes()));
        let config = self.config.load();
        let mut found = None;
        for entry in &config.issuance.join_tokens {
            if ct_eq(entry.sha256.as_bytes(), hash.as_bytes()) {
                found = Some(entry);
            }
        }
        let Some(entry) = found else {
            return Err(deny(Code::Unauthenticated, "unknown join token"));
        };
        let who = Some(Caller::Join {
            name: entry.name.clone(),
        });
        let refuse = |message: String| Denial {
            code: Code::PermissionDenied,
            message,
            who: who.clone(),
        };
        if entry.is_expired(Utc::now()) {
            return Err(refuse(format!(
                "join token {} expired at {}",
                entry.name,
                entry.expires_at.to_rfc3339_opts(SecondsFormat::Secs, true)
            )));
        }
        if entry.namespace != namespace {
            return Err(refuse(format!(
                "join token {} is for namespace {:?}, not {namespace:?}",
                entry.name, entry.namespace
            )));
        }
        if !entry.services.iter().any(|s| s == service) {
            return Err(refuse(format!(
                "join token {} does not list service {service:?}",
                entry.name
            )));
        }
        Ok(Grant {
            caller: Caller::Join {
                name: entry.name.clone(),
            },
            service_account: None,
        })
    }

    async fn check_kubernetes(
        &self,
        token: &str,
        namespace: &str,
        service: &str,
    ) -> Result<Grant, Denial> {
        if !self.config.load().issuance.kubernetes {
            return Err(deny(
                Code::PermissionDenied,
                "Kubernetes tokens are not accepted (issuance.kubernetes is false)",
            ));
        }
        let api = self.kube_api().await?;
        let review = api
            .token_review(token, &[AUDIENCE.to_string()])
            .await
            .map_err(|e| deny(Code::Unavailable, format!("TokenReview failed: {e}")))?;
        if review.authenticated != Some(true) {
            let why = review.error.unwrap_or_else(|| "not authenticated".into());
            let why: String = why.chars().take(256).collect();
            return Err(deny(
                Code::Unauthenticated,
                format!("the Kubernetes token was not accepted: {why}"),
            ));
        }
        if !review.audiences.iter().flatten().any(|a| a == AUDIENCE) {
            return Err(deny(
                Code::Unauthenticated,
                format!("the Kubernetes token is not for audience {AUDIENCE:?}"),
            ));
        }
        let user = review.user.unwrap_or_default();
        let username = user.username.unwrap_or_default();
        let Some((token_ns, token_sa)) = username
            .strip_prefix("system:serviceaccount:")
            .and_then(|rest| rest.split_once(':'))
        else {
            return Err(deny(
                Code::PermissionDenied,
                "the Kubernetes token is not a service-account token",
            ));
        };
        let extra = user.extra.unwrap_or_default();
        let first = |k: &str| extra.get(k).and_then(|v| v.first()).cloned();
        let (Some(pod_name), Some(pod_uid)) = (first(POD_NAME_EXTRA), first(POD_UID_EXTRA)) else {
            return Err(deny(
                Code::PermissionDenied,
                "the Kubernetes token is not bound to a pod (mount a projected service-account \
                 token with audience agentsc)",
            ));
        };
        let who = Some(Caller::Pod {
            namespace: token_ns.to_string(),
            name: pod_name.clone(),
        });
        let refuse = |message: String| Denial {
            code: Code::PermissionDenied,
            message,
            who: who.clone(),
        };
        if token_ns != namespace {
            return Err(refuse(format!(
                "the token's namespace {token_ns:?} is not the requested namespace {namespace:?}"
            )));
        }
        let pod = api
            .get_pod(token_ns, &pod_name)
            .await
            .map_err(|e| Denial {
                code: Code::Unavailable,
                message: format!("reading pod {token_ns}/{pod_name} failed: {e}"),
                who: who.clone(),
            })?
            .ok_or_else(|| refuse(format!("pod {token_ns}/{pod_name} does not exist")))?;
        if pod.metadata.uid.as_deref() != Some(pod_uid.as_str()) {
            return Err(refuse(format!(
                "pod {token_ns}/{pod_name} has another uid than the token's (it was replaced)"
            )));
        }
        if pod.metadata.deletion_timestamp.is_some() {
            return Err(refuse(format!("pod {token_ns}/{pod_name} is terminating")));
        }
        if pod.metadata.namespace.as_deref() != Some(token_ns) {
            return Err(refuse(format!(
                "pod {pod_name} is not in namespace {token_ns:?}"
            )));
        }
        let Some(derived) = pod_service(&pod) else {
            return Err(refuse(format!(
                "pod {token_ns}/{pod_name} has no {SIDECAR_CONTAINER:?} container with a \
                 {SERVICE_ENV} value"
            )));
        };
        if derived != service {
            return Err(refuse(format!(
                "pod {token_ns}/{pod_name} runs the sidecar of service {}, not {service:?}",
                quote(&derived)
            )));
        }
        let pod_sa = pod
            .spec
            .as_ref()
            .and_then(|s| s.service_account_name.clone())
            .unwrap_or_else(|| "default".into());
        if pod_sa != token_sa {
            return Err(refuse(format!(
                "the token's service account {token_sa:?} is not the pod's {pod_sa:?}"
            )));
        }
        // the image that runs, not the one the spec names (design §13, the allow-list)
        let images =
            crate::sidecar_images::check_running_pod(&self.config.load().sidecar_images, &pod);
        match images {
            Ok(()) => {}
            Err(crate::sidecar_images::Refusal::Refused(why)) => return Err(refuse(why)),
            Err(crate::sidecar_images::Refusal::NotReported(why)) => {
                return Err(Denial {
                    code: Code::Unavailable,
                    message: format!("{why}; retry"),
                    who: who.clone(),
                });
            }
        }
        let mut allowed = vec![service.to_string()];
        if let Some(store) = &self.store {
            match store
                .get_charter(&ServiceKey::new(namespace, service))
                .await
            {
                Ok(c) => allowed.extend(charter_service_accounts(&c.charter_json)),
                Err(StoreError::NotFound) => {}
                Err(e) => {
                    return Err(Denial {
                        code: Code::Unavailable,
                        message: format!(
                            "reading the charter of {namespace}/{service} failed: {e}"
                        ),
                        who: who.clone(),
                    });
                }
            }
        }
        if !allowed.contains(&pod_sa) {
            return Err(refuse(format!(
                "service account {pod_sa:?} may not obtain the identity of {namespace}/{service} \
                 (allowed: {}; add it to the charter's service.service_accounts)",
                allowed.join(", ")
            )));
        }
        Ok(Grant {
            caller: Caller::Pod {
                namespace: token_ns.to_string(),
                name: pod_name,
            },
            service_account: Some(pod_sa),
        })
    }

    /// The audit actor (module docs): the identity and pod (or join token) for an issuance;
    /// for a refusal only what the credential showed, never the identity asked for.
    fn actor(
        trust_domain: &str,
        namespace: &str,
        service: &str,
        who: Option<&Caller>,
        issued: bool,
    ) -> Actor {
        let name = match (who, issued) {
            (Some(caller), true) if is_dns_label(namespace) && is_dns_label(service) => {
                let slot = match caller {
                    Caller::Pod { name, .. } => name.clone(),
                    Caller::Join { name } => format!("join:{name}"),
                };
                let id = agentsc_charter::spiffe_id_in(trust_domain, namespace, service);
                format!("sidecar:{id}/{slot}")
            }
            (Some(Caller::Pod { namespace, name }), false) => {
                format!("sidecar:pod:{namespace}/{name}")
            }
            (Some(Caller::Join { name }), false) => format!("sidecar:join:{name}"),
            _ => "sidecar:unknown".into(),
        };
        Actor {
            name,
            kind: ActorKind::Sidecar,
            role: None,
        }
    }

    async fn audit(
        &self,
        req: &CertificateRequest,
        who: Option<&Caller>,
        key_sha256: Option<String>,
        result: Result<String, &Denial>,
    ) {
        let (action, outcome, reason) = match result {
            Ok(reason) => (CpAction::CertIssue, CpResult::Ok, reason),
            Err(d) => (CpAction::CertDenied, CpResult::Denied, d.message.clone()),
        };
        let issued = outcome == CpResult::Ok;
        let td = self.ca.trust_domain();
        let actor = Self::actor(td, &req.namespace, &req.service, who, issued);
        let mut rec = CpAudit::entry(action, &actor, outcome);
        if is_dns_label(&req.namespace) {
            rec.namespace = Some(req.namespace.clone());
        }
        if is_dns_label(&req.service) {
            rec.service = Some(req.service.clone());
        }
        rec.sha256_after = key_sha256;
        rec.reason = Some(reason);
        self.cp_audit.record(rec).await;
    }

    /// Decide and sign; every outcome is audited.
    pub async fn issue(&self, req: CertificateRequest) -> Result<CertificateResponse, Status> {
        if let Err(d) = self.check_names(&req.namespace, &req.service) {
            self.audit(&req, None, None, Err(&d)).await;
            return Err(Status::new(d.code, d.message));
        }
        let key = match agentsc_pki::verify_csr_p256(&req.csr_pem) {
            Ok(k) => k,
            Err(e) => {
                let d = deny(Code::InvalidArgument, e.to_string());
                self.audit(&req, None, None, Err(&d)).await;
                return Err(Status::new(d.code, d.message));
            }
        };
        let key_sha = key.sha256_hex();
        let granted = match (req.kubernetes_token.is_empty(), req.join_token.is_empty()) {
            (false, false) => Err(deny(
                Code::InvalidArgument,
                "give either kubernetes_token or join_token, not both",
            )),
            (true, true) => Err(deny(
                Code::Unauthenticated,
                "a kubernetes_token or a join_token is required",
            )),
            (false, true) => {
                self.check_kubernetes(&req.kubernetes_token, &req.namespace, &req.service)
                    .await
            }
            (true, false) => self.check_join(&req.join_token, &req.namespace, &req.service),
        };
        let grant = match granted {
            Ok(g) => g,
            Err(d) => {
                self.audit(&req, d.who.as_ref(), Some(key_sha), Err(&d))
                    .await;
                return Err(Status::new(d.code, d.message));
            }
        };
        let ttl = self.config.load().issuance.workload_cert_ttl.as_duration();
        let leaf = match self
            .ca
            .sign_workload(&key, &req.namespace, &req.service, ttl)
        {
            Ok(l) => l,
            Err(e) => {
                let d = Denial {
                    code: Code::Internal,
                    message: format!("signing failed: {e:#}"),
                    who: Some(grant.caller.clone()),
                };
                self.audit(&req, d.who.as_ref(), Some(key_sha), Err(&d))
                    .await;
                return Err(Status::new(d.code, d.message));
            }
        };
        let expires_at =
            DateTime::<Utc>::from(leaf.not_after).to_rfc3339_opts(SecondsFormat::Secs, true);
        self.audit(
            &req,
            Some(&grant.caller),
            Some(key_sha),
            Ok(format!("{}; expires {expires_at}", grant.describe())),
        )
        .await;
        Ok(CertificateResponse {
            cert_pem: leaf.cert_pem,
            ca_pem: self.ca.roots_pem().to_string(),
            expires_at,
        })
    }
}

#[tonic::async_trait]
impl CertificateAuthority for Issuer {
    async fn issue_certificate(
        &self,
        request: Request<CertificateRequest>,
    ) -> Result<Response<CertificateResponse>, Status> {
        self.issue(request.into_inner()).await.map(Response::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HumanDuration, JoinTokenEntry};
    use crate::cp_audit::CpAuditRecord;
    use crate::k8s::fake::FakeCluster;
    use crate::k8s::store::KubeStore;
    use crate::store::{ChangeSource, CharterWrite, Precondition};
    use k8s_openapi::api::authentication::v1::{TokenReviewStatus, UserInfo};
    use k8s_openapi::api::core::v1::{EnvVar, EnvVarSource, ObjectFieldSelector, PodSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, Time};
    use std::collections::BTreeMap;
    use std::time::Duration;

    const POD_UID: &str = "7d3c2a1e-0000-4000-8000-000000000001";

    fn csr() -> String {
        let key = rcgen::KeyPair::generate().unwrap();
        rcgen::CertificateParams::default()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap()
    }

    fn pod(ns: &str, name: &str, sa: &str, service: &str) -> Pod {
        Pod {
            metadata: ObjectMeta {
                name: Some(name.into()),
                namespace: Some(ns.into()),
                uid: Some(POD_UID.into()),
                ..Default::default()
            },
            spec: Some(PodSpec {
                service_account_name: Some(sa.into()),
                init_containers: Some(vec![Container {
                    name: SIDECAR_CONTAINER.into(),
                    restart_policy: Some("Always".into()),
                    env: Some(vec![EnvVar {
                        name: SERVICE_ENV.into(),
                        value: Some(service.into()),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }]),
                containers: vec![Container {
                    name: "app".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn review(ns: &str, sa: &str, pod: &str, uid: &str, audiences: &[&str]) -> TokenReviewStatus {
        TokenReviewStatus {
            authenticated: Some(true),
            audiences: Some(audiences.iter().map(|a| a.to_string()).collect()),
            user: Some(UserInfo {
                username: Some(format!("system:serviceaccount:{ns}:{sa}")),
                extra: Some(BTreeMap::from([
                    (POD_NAME_EXTRA.to_string(), vec![pod.to_string()]),
                    (POD_UID_EXTRA.to_string(), vec![uid.to_string()]),
                ])),
                ..Default::default()
            }),
            error: None,
        }
    }

    struct Rig {
        issuer: Issuer,
        cluster: Arc<FakeCluster>,
        audit: tokio::sync::broadcast::Receiver<Arc<CpAuditRecord>>,
        ca: Arc<CaMaterial>,
        store: Arc<KubeStore>,
    }

    fn config(join: Vec<JoinTokenEntry>) -> ControlPlaneConfig {
        let mut c = ControlPlaneConfig::default();
        c.issuance.join_tokens = join;
        c.issuance.workload_cert_ttl = HumanDuration(Duration::from_secs(2 * 3600));
        c
    }

    fn join_entry(
        name: &str,
        token: &str,
        ns: &str,
        services: &[&str],
        expires_in: i64,
    ) -> JoinTokenEntry {
        JoinTokenEntry {
            name: name.into(),
            sha256: hex::encode(Sha256::digest(token.as_bytes())),
            namespace: ns.into(),
            services: services.iter().map(|s| s.to_string()).collect(),
            expires_at: Utc::now() + chrono::Duration::seconds(expires_in),
        }
    }

    fn rig(join: Vec<JoinTokenEntry>) -> Rig {
        let ca = agentsc_pki::ca_init().unwrap();
        let ca = Arc::new(CaMaterial::from_pems(&ca.cert_pem, &ca.key_pem).unwrap());
        let cluster = Arc::new(FakeCluster::new());
        let store = Arc::new(KubeStore::with_writer(
            cluster.clone(),
            Box::new(std::io::sink()),
        ));
        let cp_audit = Arc::new(CpAudit::with_writer(None, Box::new(std::io::sink())));
        let audit = cp_audit.subscribe();
        let issuer = Issuer::new(
            ca.clone(),
            Arc::new(ArcSwap::from_pointee(config(join))),
            Some(store.clone()),
            cp_audit,
            "agentsc-system".into(),
            Some(cluster.clone()),
        );
        Rig {
            issuer,
            cluster,
            audit,
            ca,
            store,
        }
    }

    fn request(ns: &str, svc: &str) -> CertificateRequest {
        CertificateRequest {
            csr_pem: csr(),
            kubernetes_token: String::new(),
            join_token: String::new(),
            namespace: ns.into(),
            service: svc.into(),
        }
    }

    fn k8s_request(ns: &str, svc: &str, token: &str) -> CertificateRequest {
        CertificateRequest {
            kubernetes_token: token.into(),
            ..request(ns, svc)
        }
    }

    async fn put_charter(store: &KubeStore, ns: &str, svc: &str, service_accounts: &[&str]) {
        let json = serde_json::json!({
            "apiVersion": "agentsc.io/v1alpha1", "kind": "Charter",
            "service": {"name": svc, "namespace": ns, "app_port": 8080, "service_accounts": service_accounts},
            "agents": []
        });
        store
            .put_charter(
                &ServiceKey::new(ns, svc),
                &Precondition::NotExists,
                CharterWrite {
                    yaml: serde_yaml_ng::to_string(&json).unwrap(),
                    charter_json: json,
                    actor: Actor {
                        name: "alice".into(),
                        kind: ActorKind::Token,
                        role: None,
                    },
                    source: ChangeSource::Api,
                },
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_kubernetes_token_gets_a_fresh_leaf_from_the_csr_key_only() {
        let mut r = rig(vec![]);
        r.cluster
            .put_pod(pod("shop", "orders-0", "orders", "orders"));
        r.cluster.put_token(
            "tok",
            review("shop", "orders", "orders-0", POD_UID, &["agentsc"]),
        );
        // the CSR asks for another identity: ignored
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["evil.example".to_string()]).unwrap();
        params.subject_alt_names.push(rcgen::SanType::URI(
            "spiffe://agentsc/ns/kube-system/svc/admin"
                .try_into()
                .unwrap(),
        ));
        let mut req = k8s_request("shop", "orders", "tok");
        req.csr_pem = params.serialize_request(&key).unwrap().pem().unwrap();

        let resp = r.issuer.issue(req).await.unwrap();
        let der = agentsc_pki::certs_from_pem(&resp.cert_pem)
            .unwrap()
            .remove(0);
        assert_eq!(
            agentsc_pki::uri_sans_of(&der).unwrap(),
            ["spiffe://agentsc/ns/shop/svc/orders"]
        );
        let dns = agentsc_pki::dns_names_of(&der).unwrap();
        assert_eq!(
            dns,
            [
                "orders",
                "orders.shop",
                "orders.shop.svc",
                "orders.shop.svc.cluster.local"
            ]
        );
        assert_eq!(resp.ca_pem, r.ca.roots_pem());
        // lifetime: issuance.workload_cert_ttl (2 h here)
        let not_after = agentsc_pki::not_after_of(&der).unwrap();
        let left = not_after
            .duration_since(std::time::SystemTime::now())
            .unwrap();
        assert!(
            left <= Duration::from_secs(2 * 3600) && left > Duration::from_secs(3600),
            "{left:?}"
        );
        assert_eq!(
            chrono::DateTime::parse_from_rfc3339(&resp.expires_at)
                .unwrap()
                .timestamp(),
            DateTime::<Utc>::from(not_after).timestamp()
        );
        // the token was reviewed for audience agentsc
        assert_eq!(
            r.cluster.review_requests(),
            [("tok".to_string(), vec!["agentsc".to_string()])]
        );

        let rec = r.audit.recv().await.unwrap();
        assert_eq!(rec.action, CpAction::CertIssue);
        assert_eq!(rec.result, CpResult::Ok);
        // design §7: sidecar:<spiffe id>/<pod>
        assert_eq!(
            rec.actor,
            "sidecar:spiffe://agentsc/ns/shop/svc/orders/orders-0"
        );
        assert_eq!(rec.actor_kind, ActorKind::Sidecar);
        assert_eq!(
            (rec.namespace.as_deref(), rec.service.as_deref()),
            (Some("shop"), Some("orders"))
        );
        let spki = agentsc_pki::verify_csr_p256(&k8s_request_csr_of(&key))
            .unwrap()
            .sha256_hex();
        assert_eq!(rec.sha256_after.as_deref(), Some(spki.as_str()));
        assert!(
            rec.reason
                .as_deref()
                .unwrap()
                .contains("service account orders"),
            "{rec:?}"
        );
    }

    /// A CSR of `key` (same public key as any other CSR of it).
    fn k8s_request_csr_of(key: &rcgen::KeyPair) -> String {
        rcgen::CertificateParams::default()
            .serialize_request(key)
            .unwrap()
            .pem()
            .unwrap()
    }

    /// The TokenReview decision table: each row is refused with its code and reason.
    #[tokio::test]
    async fn token_review_decision_table() {
        struct Row {
            name: &'static str,
            review: TokenReviewStatus,
            pod: Option<Pod>,
            request_service: &'static str,
            code: Code,
            reason: &'static str,
        }
        let good_pod = || pod("shop", "orders-0", "orders", "orders");
        let good = || review("shop", "orders", "orders-0", POD_UID, &["agentsc"]);
        let mut terminating = good_pod();
        terminating.metadata.deletion_timestamp = Some(Time(k8s_openapi::jiff::Timestamp::now()));
        let mut from_field = good_pod();
        from_field
            .spec
            .as_mut()
            .unwrap()
            .init_containers
            .as_mut()
            .unwrap()[0]
            .env = Some(vec![EnvVar {
            name: SERVICE_ENV.into(),
            value_from: Some(EnvVarSource {
                field_ref: Some(ObjectFieldSelector {
                    field_path: "metadata.name".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }]);
        let mut no_extras = good();
        no_extras.user.as_mut().unwrap().extra = None;
        let mut unauthenticated = good();
        unauthenticated.authenticated = Some(false);
        unauthenticated.error = Some("token has expired".into());
        let mut not_sa = good();
        not_sa.user.as_mut().unwrap().username = Some("alice@example.com".into());
        let rows = vec![
            Row {
                name: "audience missing",
                review: review("shop", "orders", "orders-0", POD_UID, &[]),
                pod: Some(good_pod()),
                request_service: "orders",
                code: Code::Unauthenticated,
                reason: "audience",
            },
            Row {
                name: "other audience",
                review: review(
                    "shop",
                    "orders",
                    "orders-0",
                    POD_UID,
                    &["https://kubernetes.default.svc"],
                ),
                pod: Some(good_pod()),
                request_service: "orders",
                code: Code::Unauthenticated,
                reason: "audience",
            },
            Row {
                name: "not authenticated",
                review: unauthenticated,
                pod: Some(good_pod()),
                request_service: "orders",
                code: Code::Unauthenticated,
                reason: "token has expired",
            },
            Row {
                name: "not a service account",
                review: not_sa,
                pod: Some(good_pod()),
                request_service: "orders",
                code: Code::PermissionDenied,
                reason: "not a service-account token",
            },
            Row {
                name: "not bound to a pod",
                review: no_extras,
                pod: Some(good_pod()),
                request_service: "orders",
                code: Code::PermissionDenied,
                reason: "not bound to a pod",
            },
            Row {
                name: "uid mismatch",
                review: review("shop", "orders", "orders-0", "another-uid", &["agentsc"]),
                pod: Some(good_pod()),
                request_service: "orders",
                code: Code::PermissionDenied,
                reason: "another uid",
            },
            Row {
                name: "pod gone",
                review: good(),
                pod: None,
                request_service: "orders",
                code: Code::PermissionDenied,
                reason: "does not exist",
            },
            Row {
                name: "terminating pod",
                review: good(),
                pod: Some(terminating),
                request_service: "orders",
                code: Code::PermissionDenied,
                reason: "terminating",
            },
            Row {
                name: "token namespace",
                review: review("other", "orders", "orders-0", POD_UID, &["agentsc"]),
                pod: Some(good_pod()),
                request_service: "orders",
                code: Code::PermissionDenied,
                reason: "is not the requested namespace",
            },
            Row {
                name: "SA mismatch",
                review: review("shop", "inventory", "orders-0", POD_UID, &["agentsc"]),
                pod: Some(pod("shop", "orders-0", "inventory", "orders")),
                request_service: "orders",
                code: Code::PermissionDenied,
                reason: "may not obtain the identity",
            },
            Row {
                name: "token SA is not the pod's",
                review: review("shop", "default", "orders-0", POD_UID, &["agentsc"]),
                pod: Some(good_pod()),
                request_service: "orders",
                code: Code::PermissionDenied,
                reason: "is not the pod's",
            },
            Row {
                name: "service mismatch",
                review: good(),
                pod: Some(good_pod()),
                request_service: "inventory",
                code: Code::PermissionDenied,
                reason: "runs the sidecar of service \"orders\"",
            },
            Row {
                name: "no agentscd container",
                review: good(),
                pod: Some({
                    let mut p = good_pod();
                    p.spec.as_mut().unwrap().init_containers = None;
                    p
                }),
                request_service: "orders",
                code: Code::PermissionDenied,
                reason: "has no \"agentscd\" container",
            },
            Row {
                name: "service from valueFrom",
                review: good(),
                pod: Some(from_field),
                request_service: "orders",
                code: Code::PermissionDenied,
                reason: "has no \"agentscd\" container",
            },
        ];
        for row in rows {
            let mut r = rig(vec![]);
            if let Some(p) = row.pod {
                r.cluster.put_pod(p);
            }
            r.cluster.put_token("tok", row.review);
            let err = r
                .issuer
                .issue(k8s_request("shop", row.request_service, "tok"))
                .await
                .unwrap_err();
            assert_eq!(err.code(), row.code, "{}: {err:?}", row.name);
            assert!(
                err.message().contains(row.reason),
                "{}: {}",
                row.name,
                err.message()
            );
            let rec = r.audit.recv().await.unwrap();
            assert_eq!(rec.action, CpAction::CertDenied, "{}", row.name);
            assert_eq!(rec.result, CpResult::Denied);
            // a refusal is attributed to what the token showed, never to the identity asked for
            let want_actor = match row.name {
                "audience missing"
                | "other audience"
                | "not authenticated"
                | "not a service account"
                | "not bound to a pod" => "sidecar:unknown",
                "token namespace" => "sidecar:pod:other/orders-0",
                _ => "sidecar:pod:shop/orders-0",
            };
            assert_eq!(rec.actor, want_actor, "{}", row.name);
            assert_eq!(
                (rec.namespace.as_deref(), rec.service.as_deref()),
                (Some("shop"), Some(row.request_service)),
                "{}",
                row.name
            );
            assert_eq!(rec.reason.as_deref(), Some(err.message()), "{}", row.name);
            assert!(
                rec.sha256_after.as_ref().is_some_and(|h| h.len() == 64),
                "{}",
                row.name
            );
        }
    }

    #[tokio::test]
    async fn service_accounts_come_from_the_stored_charter() {
        let mut r = rig(vec![]);
        r.cluster
            .put_pod(pod("shop", "orders-0", "orders-runner", "orders"));
        r.cluster.put_token(
            "tok",
            review("shop", "orders-runner", "orders-0", POD_UID, &["agentsc"]),
        );
        // no charter: only the service's own name is allowed
        let err = r
            .issuer
            .issue(k8s_request("shop", "orders", "tok"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
        assert!(
            err.message().contains("allowed: orders;"),
            "{}",
            err.message()
        );
        // listed in service.service_accounts: allowed
        put_charter(&r.store, "shop", "orders", &["orders-runner"]).await;
        r.issuer
            .issue(k8s_request("shop", "orders", "tok"))
            .await
            .unwrap();
        let denied = r.audit.recv().await.unwrap();
        assert_eq!(denied.action, CpAction::CertDenied);
        let issued = r.audit.recv().await.unwrap();
        assert_eq!(issued.action, CpAction::CertIssue);
        assert!(issued.reason.as_ref().unwrap().contains("orders-runner"));
    }

    fn digest(c: char) -> String {
        format!("sha256:{}", std::iter::repeat_n(c, 64).collect::<String>())
    }

    /// `pod` as the kubelet reports it: the injected runtime container next to agentscd, and
    /// the `imageID` of each (`None`: not reported yet).
    fn running_pod(agentscd_image_id: Option<&str>, runtime_image_id: Option<&str>) -> Pod {
        use crate::webhook::{RUNTIME_ARGS, RUNTIME_COMMAND, RUNTIME_CONTAINER};
        use k8s_openapi::api::core::v1::{ContainerStatus, PodStatus};
        let mut p = pod("shop", "orders-0", "orders", "orders");
        let spec = p.spec.as_mut().unwrap();
        spec.init_containers.as_mut().unwrap().insert(
            0,
            Container {
                name: RUNTIME_CONTAINER.into(),
                restart_policy: Some("Always".into()),
                command: Some(vec![RUNTIME_COMMAND.into()]),
                args: Some(RUNTIME_ARGS.iter().map(|a| a.to_string()).collect()),
                ..Default::default()
            },
        );
        let status = |name: &str, id: Option<&str>| ContainerStatus {
            name: name.into(),
            image_id: id.unwrap_or_default().into(),
            ..Default::default()
        };
        p.status = Some(PodStatus {
            init_container_statuses: Some(vec![
                status(RUNTIME_CONTAINER, runtime_image_id),
                status(SIDECAR_CONTAINER, agentscd_image_id),
            ]),
            container_statuses: Some(vec![status("app", Some("docker.io/app@sha256:1"))]),
            ..Default::default()
        });
        p
    }

    /// The audit finding: issuance looked at the container name and env, never at the image
    /// that runs. With the allow-list on, the first certificate and every renewal (a new
    /// IssueCertificate) need allowed running images; each refusal is audited like the others.
    #[tokio::test]
    async fn the_running_sidecar_images_must_be_allowed_at_issuance_and_renewal() {
        let mut r = rig(vec![]);
        let mut c = ControlPlaneConfig::clone(&r.issuer.config.load());
        c.sidecar_images.allowed_digests = vec![digest('a'), digest('c')];
        r.issuer.config.store(Arc::new(c));
        let (a, b) = (digest('a'), digest('b'));
        let pulled =
            |d: &str| format!("docker-pullable://ghcr.io/f8fvwgzc/agent-sidecar/agentscd@{d}");
        r.cluster.put_token(
            "tok",
            review("shop", "orders", "orders-0", POD_UID, &["agentsc"]),
        );

        // allowed images (containerd's and cri-dockerd's imageID forms): issued
        r.cluster.put_pod(running_pod(
            Some(&pulled(&a)),
            Some(&format!("ghcr.io/f8fvwgzc/agent-sidecar/agentscd@{a}")),
        ));
        r.issuer
            .issue(k8s_request("shop", "orders", "tok"))
            .await
            .unwrap();
        assert_eq!(r.audit.recv().await.unwrap().action, CpAction::CertIssue);

        // the image is swapped under the running pod: the renewal is refused
        let cases: Vec<(Pod, Code, String)> = vec![
            (
                running_pod(Some(&pulled(&b)), Some(&pulled(&a))),
                Code::PermissionDenied,
                format!(
                    "container \"agentscd\" of pod shop/orders-0 runs image {b}, which is not in \
                     sidecar_images.allowed_digests"
                ),
            ),
            (
                running_pod(Some(&pulled(&a)), Some(&pulled(&b))),
                Code::PermissionDenied,
                "container \"agentsc-runtime\" of pod shop/orders-0 runs image".into(),
            ),
            (
                running_pod(
                    Some("docker-pullable://agentsc/agentscd:dev"),
                    Some(&pulled(&a)),
                ),
                Code::PermissionDenied,
                "names no sha256 digest".into(),
            ),
            (
                // an allowed image started with another program
                {
                    let mut p = running_pod(Some(&pulled(&a)), Some(&pulled(&a)));
                    p.spec.as_mut().unwrap().init_containers.as_mut().unwrap()[1].command =
                        Some(vec!["python3".into(), "/tmp/evil.py".into()]);
                    p
                },
                Code::PermissionDenied,
                "container \"agentscd\" must run its image's entrypoint".into(),
            ),
            (
                running_pod(None, Some(&pulled(&a))),
                Code::Unavailable,
                "the kubelet has not reported the image of container \"agentscd\"".into(),
            ),
        ];
        for (p, code, reason) in cases {
            r.cluster.put_pod(p);
            let err = r
                .issuer
                .issue(k8s_request("shop", "orders", "tok"))
                .await
                .unwrap_err();
            assert_eq!(err.code(), code, "{reason}: {err:?}");
            assert!(
                err.message().contains(&reason),
                "{reason}: {}",
                err.message()
            );
            let rec = r.audit.recv().await.unwrap();
            assert_eq!(
                (rec.action, rec.result),
                (CpAction::CertDenied, CpResult::Denied)
            );
            assert_eq!(rec.actor, "sidecar:pod:shop/orders-0");
            assert_eq!(rec.reason.as_deref(), Some(err.message()));
            assert_eq!(rec.sha256_after.as_ref().map(String::len), Some(64));
        }

        // a pod without the runtime container (agentscd spawns its own) needs agentscd only
        let mut p = pod("shop", "orders-0", "orders", "orders");
        p.status = running_pod(Some(&pulled(&digest('c'))), None).status;
        r.cluster.put_pod(p);
        r.issuer
            .issue(k8s_request("shop", "orders", "tok"))
            .await
            .unwrap();
        assert_eq!(r.audit.recv().await.unwrap().action, CpAction::CertIssue);

        // allow-list off (the default): images are not looked at
        let mut c = ControlPlaneConfig::clone(&r.issuer.config.load());
        c.sidecar_images.allowed_digests.clear();
        r.issuer.config.store(Arc::new(c));
        r.cluster
            .put_pod(running_pod(Some(&pulled(&b)), Some(&pulled(&b))));
        r.issuer
            .issue(k8s_request("shop", "orders", "tok"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn kubernetes_tokens_can_be_turned_off() {
        let r = rig(vec![]);
        let mut c = ControlPlaneConfig::clone(&r.issuer.config.load());
        c.issuance.kubernetes = false;
        r.issuer.config.store(Arc::new(c));
        let err = r
            .issuer
            .issue(k8s_request("shop", "orders", "tok"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
        assert!(err.message().contains("issuance.kubernetes is false"));
        assert!(r.cluster.review_requests().is_empty());
    }

    #[tokio::test]
    async fn join_tokens_are_scoped_and_expire() {
        let mut r = rig(vec![
            join_entry(
                "compose-orders",
                "att_join_orders",
                "demo",
                &["orders"],
                3600,
            ),
            join_entry("old", "att_join_old", "demo", &["orders"], -60),
        ]);
        let join = |ns: &str, svc: &str, token: &str| CertificateRequest {
            join_token: token.into(),
            ..request(ns, svc)
        };
        let resp = r
            .issuer
            .issue(join("demo", "orders", "att_join_orders"))
            .await
            .unwrap();
        let der = agentsc_pki::certs_from_pem(&resp.cert_pem)
            .unwrap()
            .remove(0);
        assert_eq!(
            agentsc_pki::uri_sans_of(&der).unwrap(),
            ["spiffe://agentsc/ns/demo/svc/orders"]
        );
        let rec = r.audit.recv().await.unwrap();
        assert_eq!(rec.action, CpAction::CertIssue);
        assert_eq!(
            rec.actor,
            "sidecar:spiffe://agentsc/ns/demo/svc/orders/join:compose-orders"
        );
        assert!(
            rec.reason
                .as_ref()
                .unwrap()
                .contains("join token compose-orders")
        );

        for (ns, svc, token, code, reason, actor) in [
            (
                "demo",
                "inventory",
                "att_join_orders",
                Code::PermissionDenied,
                "does not list service \"inventory\"",
                "sidecar:join:compose-orders",
            ),
            (
                "shop",
                "orders",
                "att_join_orders",
                Code::PermissionDenied,
                "is for namespace \"demo\"",
                "sidecar:join:compose-orders",
            ),
            (
                "demo",
                "orders",
                "att_join_old",
                Code::PermissionDenied,
                "expired",
                "sidecar:join:old",
            ),
            (
                "demo",
                "orders",
                "att_join_unknown",
                Code::Unauthenticated,
                "unknown join token",
                "sidecar:unknown",
            ),
        ] {
            let err = r.issuer.issue(join(ns, svc, token)).await.unwrap_err();
            assert_eq!(err.code(), code, "{ns}/{svc} {token}: {err:?}");
            assert!(err.message().contains(reason), "{}", err.message());
            let rec = r.audit.recv().await.unwrap();
            assert_eq!(rec.action, CpAction::CertDenied);
            assert_eq!(rec.actor, actor, "{ns}/{svc} {token}");
        }
    }

    #[tokio::test]
    async fn names_are_checked_first_and_reserved_names_refused() {
        let mut r = rig(vec![join_entry("t", "att_t", "demo", &["orders"], 3600)]);
        for (ns, svc, reason) in [
            (
                "Demo",
                "orders",
                "namespace \"Demo\" is not a DNS-1123 label",
            ),
            (
                "demo",
                "orders_v2",
                "service \"orders_v2\" is not a DNS-1123 label",
            ),
            ("agentsc-system", "orders", "is the control plane's"),
            ("demo", "embassy", "reserved for the control plane"),
            ("", "", "is not a DNS-1123 label"),
        ] {
            let req = CertificateRequest {
                join_token: "att_t".into(),
                ..request(ns, svc)
            };
            let err = r.issuer.issue(req).await.unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument, "{ns}/{svc}");
            assert!(err.message().contains(reason), "{}", err.message());
            let rec = r.audit.recv().await.unwrap();
            assert_eq!(rec.action, CpAction::CertDenied);
            assert!(rec.sha256_after.is_none());
        }
        // a garbage name never reaches the audit record verbatim as an identity
        let pod = Caller::Pod {
            namespace: "shop".into(),
            name: "p".into(),
        };
        assert_eq!(
            Issuer::actor("agentsc", "Bad NS", "x", Some(&pod), true).name,
            "sidecar:unknown"
        );
        assert_eq!(
            Issuer::actor("agentsc", "shop", "orders", None, true).name,
            "sidecar:unknown"
        );
    }

    #[tokio::test]
    async fn csrs_are_verified_wrong_curve_and_bad_signature_refused() {
        let mut r = rig(vec![join_entry("t", "att_t", "demo", &["orders"], 3600)]);
        let with_csr = |csr: String| CertificateRequest {
            join_token: "att_t".into(),
            csr_pem: csr,
            ..request("demo", "orders")
        };
        // P-384: wrong curve
        let p384 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let csr384 = rcgen::CertificateParams::default()
            .serialize_request(&p384)
            .unwrap()
            .pem()
            .unwrap();
        // Ed25519: not EC at all
        let ed = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let csr_ed = rcgen::CertificateParams::default()
            .serialize_request(&ed)
            .unwrap()
            .pem()
            .unwrap();
        // a P-256 CSR whose signature was tampered with
        let good = csr();
        let der = rustls_pki_types::pem::PemObject::from_pem_slice(good.as_bytes())
            .map(|d: rustls_pki_types::CertificateSigningRequestDer<'static>| d.as_ref().to_vec())
            .unwrap();
        let mut bad = der.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        let tampered = agentsc_pki::pem_block("CERTIFICATE REQUEST", &bad);
        for (csr, reason) in [
            (csr384, "P-256"),
            (csr_ed, "only ECDSA P-256"),
            (tampered, "request refused"),
            ("not a csr".to_string(), "request refused"),
        ] {
            let err = r.issuer.issue(with_csr(csr)).await.unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message().contains(reason),
                "{reason}: {}",
                err.message()
            );
            let rec = r.audit.recv().await.unwrap();
            assert_eq!(rec.action, CpAction::CertDenied);
            assert!(rec.sha256_after.is_none());
        }
    }

    #[tokio::test]
    async fn exactly_one_credential() {
        let r = rig(vec![]);
        let none = r.issuer.issue(request("demo", "orders")).await.unwrap_err();
        assert_eq!(none.code(), Code::Unauthenticated);
        let both = CertificateRequest {
            join_token: "a".into(),
            kubernetes_token: "b".into(),
            ..request("demo", "orders")
        };
        let both = r.issuer.issue(both).await.unwrap_err();
        assert_eq!(both.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn requests_over_64_kib_are_refused_by_the_server() {
        use agentsc_proto::certificate_authority_client::CertificateAuthorityClient;
        let r = rig(vec![join_entry("t", "att_t", "demo", &["orders"], 3600)]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = r.issuer.into_server();
        let task = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(server)
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
        );
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client = CertificateAuthorityClient::new(channel);
        let ok = client
            .issue_certificate(CertificateRequest {
                join_token: "att_t".into(),
                ..request("demo", "orders")
            })
            .await
            .unwrap()
            .into_inner();
        assert!(ok.cert_pem.contains("BEGIN CERTIFICATE"));
        let big = CertificateRequest {
            join_token: "att_t".into(),
            csr_pem: "x".repeat(MAX_REQUEST_BYTES + 1),
            ..request("demo", "orders")
        };
        let err = client.issue_certificate(big).await.unwrap_err();
        assert_eq!(err.code(), Code::OutOfRange, "{err:?}");
        task.abort();
    }

    #[test]
    fn the_service_comes_from_the_agentscd_container_only() {
        let mut p = pod("shop", "orders-0", "orders", "orders");
        assert_eq!(pod_service(&p).as_deref(), Some("orders"));
        // a regular container named agentscd (v0.1 explicit sidecar)
        let sidecar = p
            .spec
            .as_mut()
            .unwrap()
            .init_containers
            .take()
            .unwrap()
            .remove(0);
        p.spec.as_mut().unwrap().containers.push(sidecar);
        assert_eq!(pod_service(&p).as_deref(), Some("orders"));
        // the app container's env does not count
        let mut q = pod("shop", "orders-0", "orders", "orders");
        q.spec.as_mut().unwrap().init_containers = None;
        q.spec.as_mut().unwrap().containers[0].env = Some(vec![EnvVar {
            name: SERVICE_ENV.into(),
            value: Some("orders".into()),
            ..Default::default()
        }]);
        assert_eq!(pod_service(&q), None);
    }

    #[test]
    fn charter_service_accounts_in_both_forms() {
        let plain = serde_json::json!({"service": {"name": "a", "service_accounts": ["x", "y"]}});
        assert_eq!(charter_service_accounts(&plain), ["x", "y"]);
        let cr = serde_json::json!({"metadata": {"name": "a"}, "spec": {"service": {"name": "a", "service_accounts": ["z"]}}});
        assert_eq!(charter_service_accounts(&cr), ["z"]);
        assert!(charter_service_accounts(&serde_json::json!({})).is_empty());
        assert!(ct_eq(b"abc", b"abc") && !ct_eq(b"abc", b"abd") && !ct_eq(b"ab", b"abc"));
    }

    /// The Kubernetes path against a real cluster (the current kubeconfig context), read-only:
    /// one TokenReview and one pod GET. Run by hand with a token bound to a pod:
    ///
    /// ```text
    /// AGENTSC_K8S_SMOKE_TOKEN=$(kubectl create token <sa> -n <ns> --audience agentsc \
    ///     --bound-object-kind Pod --bound-object-name <pod> --duration 10m) \
    /// AGENTSC_K8S_SMOKE_NAMESPACE=<ns> AGENTSC_K8S_SMOKE_SERVICE=<svc> \
    /// AGENTSC_K8S_SMOKE_EXPECT='issued' (or a part of the expected refusal) \
    ///     cargo test -p embassy -- --ignored kubernetes_smoke --nocapture
    /// ```
    #[tokio::test]
    #[ignore = "needs a cluster and a pod-bound token (see the doc comment)"]
    async fn kubernetes_smoke() {
        let var = |k: &str| std::env::var(k).unwrap_or_default();
        let token = match var("AGENTSC_K8S_SMOKE_TOKEN_FILE") {
            f if !f.is_empty() => std::fs::read_to_string(f).unwrap().trim().to_string(),
            _ => var("AGENTSC_K8S_SMOKE_TOKEN"),
        };
        let (token, ns, svc, expect) = (
            token,
            var("AGENTSC_K8S_SMOKE_NAMESPACE"),
            var("AGENTSC_K8S_SMOKE_SERVICE"),
            var("AGENTSC_K8S_SMOKE_EXPECT"),
        );
        if token.is_empty() || ns.is_empty() || svc.is_empty() {
            eprintln!("AGENTSC_K8S_SMOKE_* not set; nothing to do");
            return;
        }
        let ca = agentsc_pki::ca_init().unwrap();
        let ca = Arc::new(CaMaterial::from_pems(&ca.cert_pem, &ca.key_pem).unwrap());
        let issuer = Issuer::new(
            ca,
            Arc::new(ArcSwap::from_pointee(ControlPlaneConfig::default())),
            None,
            Arc::new(CpAudit::with_writer(None, Box::new(std::io::sink()))),
            "agentsc-system".into(),
            None,
        );
        let outcome = issuer.issue(k8s_request(&ns, &svc, &token)).await;
        eprintln!("IssueCertificate against the cluster: {outcome:?}");
        match outcome {
            Ok(resp) => {
                assert_eq!(expect, "issued");
                let der = agentsc_pki::certs_from_pem(&resp.cert_pem)
                    .unwrap()
                    .remove(0);
                assert_eq!(
                    agentsc_pki::uri_sans_of(&der).unwrap(),
                    [format!("spiffe://agentsc/ns/{ns}/svc/{svc}")]
                );
            }
            Err(status) => assert!(
                status.message().contains(&expect),
                "expected {expect:?}: {status:?}"
            ),
        }
        // the read-only calls of the other components
        let client = KubeClient::try_default().await.unwrap();
        let missing = client
            .get_webhook_config(
                crate::k8s::client::WebhookKind::Mutating,
                "agentsc-smoke-does-not-exist",
            )
            .await
            .unwrap();
        assert!(missing.is_none());
        let charters = crate::k8s::client::CharterApi::list(&client).await;
        eprintln!("listing Charters: {:?}", charters.map(|l| l.len()));
    }
}
