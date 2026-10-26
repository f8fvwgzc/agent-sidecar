//! The sidecar image allow-list (design §13, `ControlPlaneConfig` `sidecar_images`): which
//! images may run as the sidecar containers of an agent pod, `agentscd` and the agent runtime
//! `agentsc-runtime` that the injector adds next to it ([`crate::webhook`]).
//!
//! **What is allowed.** `sidecar_images.allowed_digests` holds `sha256:<64 hex>` digests: the
//! ones the release workflow publishes for `ghcr.io/f8fvwgzc/agent-sidecar/agentscd` (the
//! multi-arch index digest, in the release asset `IMAGE_DIGESTS` and printed by
//! `docker buildx imagetools inspect <image>:<version>`, which the chart pins with
//! `images.agentscd.digest`, allowing it automatically), or your own build's. A digest names content, so the registry an image is pulled from does not matter.
//!
//! **Empty means not enforced.** A development build loaded into minikube
//! (`agentsc/agentscd:dev`) has no registry digest, so there would be nothing to allow. With an
//! empty list embassy injects and issues as before and warns loudly at start-up and whenever a
//! config reload empties the list ([`unenforced_warning`]). Production sets it (chart: pin
//! `images.agentscd.digest`, and keep the previous release's digest in
//! `injection.allowedImageDigests` until every pod has been replaced).
//!
//! **Enforced** (non-empty):
//!
//! - the injector injects only an image reference pinned to an allowed digest
//!   ([`check_reference`]: `<repo>@sha256:<hex>` or `<repo>:<tag>@sha256:<hex>`); a tag alone
//!   names no content and is refused;
//! - `IssueCertificate`, and so every renewal (a renewal is a new `IssueCertificate`), refuses a
//!   pod whose running sidecar containers are not allowed ([`check_running_pod`]): the digest of
//!   the `imageID` the kubelet reports for each of them in `status.initContainerStatuses[]`
//!   (native sidecars) or `status.containerStatuses[]` ([`image_id_digest`]) must be allowed,
//!   `agentscd` must run its image's entrypoint (no `command`, no `args`) and `agentsc-runtime`
//!   exactly the injected command line ([`crate::webhook::RUNTIME_COMMAND`]): an allowed image
//!   started with another command runs any program (the image has `python3`) as the sidecar;
//!   and the pod must have the injected shape ([`shape_problem`]: the sidecars' env, mounts,
//!   probes and volumes), since a pod without the injection label brings its own `agentscd`
//!   past the injector, and every `agentscd` flag has an env form;
//! - the chart's ValidatingAdmissionPolicy `agentsc-sidecar-integrity` applies the same image and
//!   command rules to the pod spec (`deploy/helm/agent-sidecar/templates/sidecar-policy.yaml`),
//!   and refuses the sidecar containers in a pod without the label `agentsc.io/inject: "true"`,
//!   so the injector checks every pod that has them.
use k8s_openapi::api::core::v1::{Container, ContainerStatus, EnvVar, Pod, Probe, VolumeMount};
use serde_json::Value;

use crate::config::SidecarImagesConfig;
use crate::names::is_sha256_hex;
use crate::webhook::{
    CONTROL_PLANE_PORT, READY_COMMAND, RUN_DIR, RUN_VOLUME, RUNTIME_ARGS, RUNTIME_COMMAND,
    RUNTIME_CONTAINER, RUNTIME_TEMPLATE_ENV, SIDECAR_CONTAINER, SIDECAR_VOLUMES, STATE_DIR,
    STATE_VOLUME, TEMPLATE_ENV_ALLOWED, TOKEN_AUDIENCE, TOKEN_DIR, TOKEN_FILE, TOKEN_VOLUME,
};

/// The container names the injector owns: a pod may not bring its own.
pub const SIDECAR_CONTAINERS: [&str; 2] = [SIDECAR_CONTAINER, RUNTIME_CONTAINER];

/// `sha256:` and 64 lowercase hex characters.
pub fn is_digest(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(is_sha256_hex)
}

/// The digest an image reference is pinned to (`<repo>[:<tag>]@sha256:<hex>`), if any.
pub fn reference_digest(image: &str) -> Option<&str> {
    let (_, digest) = image.rsplit_once('@')?;
    is_digest(digest).then_some(digest)
}

/// The digest in a container status `imageID`: `docker-pullable://<repo>@sha256:<hex>`
/// (cri-dockerd), `<repo>@sha256:<hex>` (containerd, CRI-O) or a bare `sha256:<hex>` (an image
/// that was never pulled by digest: that is the image's config digest, which matches an
/// allow-list entry only if someone listed it).
pub fn image_id_digest(image_id: &str) -> Option<&str> {
    let rest = image_id.split_once("://").map_or(image_id, |(_, r)| r);
    let digest = rest.rsplit_once('@').map_or(rest, |(_, d)| d);
    is_digest(digest).then_some(digest)
}

/// The injector's check of the image it is about to inject; `what` says where the reference
/// came from (the annotation or `--injector-image`).
pub fn check_reference(cfg: &SidecarImagesConfig, image: &str, what: &str) -> Result<(), String> {
    if !cfg.enforced() {
        return Ok(());
    }
    match reference_digest(image) {
        Some(d) if cfg.allows(d) => Ok(()),
        Some(d) => Err(format!(
            "{what} {image:?} is pinned to {d}, which is not in sidecar_images.allowed_digests"
        )),
        None => Err(format!(
            "{what} {image:?} is not pinned to a digest (<repository>@sha256:<hex>): with \
             sidecar_images.allowed_digests set, only an allowed digest is injected"
        )),
    }
}

/// Why a pod's sidecar containers get no certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The kubelet has not reported a sidecar container's image yet (it was just started): the
    /// sidecar retries.
    NotReported(String),
    /// Not allowed.
    Refused(String),
}

/// Does `c` run the program the injector gives it?
fn program_problem(c: &Container) -> Option<String> {
    let command = c.command.as_deref().unwrap_or_default();
    let args = c.args.as_deref().unwrap_or_default();
    if c.name == RUNTIME_CONTAINER {
        let ok = command == [RUNTIME_COMMAND]
            && args
                .iter()
                .map(String::as_str)
                .eq(RUNTIME_ARGS.iter().copied());
        (!ok).then(|| {
            format!(
                "container {RUNTIME_CONTAINER:?} must run {:?} (it runs command {command:?}, \
                 args {args:?})",
                [RUNTIME_COMMAND]
                    .iter()
                    .chain(RUNTIME_ARGS.iter())
                    .collect::<Vec<_>>()
            )
        })
    } else {
        (!command.is_empty() || !args.is_empty()).then(|| {
            format!(
                "container {:?} must run its image's entrypoint (it sets command {command:?}, \
                 args {args:?})",
                c.name
            )
        })
    }
}

/// Is `p` the injected probe (exec [`READY_COMMAND`], nothing else)?
fn is_ready_probe(p: &Probe) -> bool {
    p.exec.as_ref().and_then(|e| e.command.as_deref()) == Some(&[READY_COMMAND.to_string()])
        && p.http_get.is_none()
        && p.tcp_socket.is_none()
        && p.grpc.is_none()
}

/// Does `c` have exactly the mounts `want` (name, path), with no subPath and no propagation?
fn mounts_are(c: &Container, want: &[(&str, &str)]) -> bool {
    let got: Vec<&VolumeMount> = c.volume_mounts.iter().flatten().collect();
    got.len() == want.len()
        && want
            .iter()
            .all(|(n, path)| got.iter().any(|m| m.name == *n && m.mount_path == *path))
        && got.iter().all(|m| {
            m.sub_path.as_deref().unwrap_or_default().is_empty()
                && m.sub_path_expr.as_deref().unwrap_or_default().is_empty()
                && m.mount_propagation.as_deref().is_none_or(|p| p == "None")
        })
        && c.volume_devices.as_ref().is_none_or(Vec::is_empty)
}

/// The JSON object `v` has exactly the keys `keys`.
fn keys_are(v: &Value, keys: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|o| o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k)))
}

/// Is `e` one of the env entries the injector gives `agentscd` (module docs)? `fixed`: the
/// names with one possible value.
fn sidecar_env_ok(e: &EnvVar, fixed: &[(&str, String)]) -> bool {
    let literal = e
        .value_from
        .is_none()
        .then(|| e.value.as_deref().unwrap_or_default());
    let from = || serde_json::to_value(e.value_from.as_ref()?).ok();
    let name = e.name.as_str();
    if let Some((_, want)) = fixed.iter().find(|(n, _)| *n == name) {
        literal == Some(want.as_str())
    } else if INJECTED_LITERAL_ENV.contains(&name) {
        literal.is_some()
    } else if let Some((_, path)) = INJECTED_FIELD_ENV.iter().find(|(n, _)| *n == name) {
        e.value.is_none()
            && from()
                .is_some_and(|f| keys_are(&f, &["fieldRef"]) && f["fieldRef"]["fieldPath"] == *path)
    } else if name == "ANTHROPIC_API_KEY" {
        e.value.is_none()
            && from().is_some_and(|f| {
                keys_are(&f, &["secretKeyRef"]) && f["secretKeyRef"]["key"] == "ANTHROPIC_API_KEY"
            })
    } else {
        TEMPLATE_ENV_ALLOWED.contains(&name)
    }
}

/// `agentscd` env the injector sets to a literal that depends on the pod.
const INJECTED_LITERAL_ENV: [&str; 4] = [
    "AGENTSC_SERVICE",
    "AGENTSC_NAMESPACE",
    "AGENTSC_APP_PORT",
    "AGENTSC_CA_PEM",
];
/// `agentscd` env the injector takes from the pod's own fields.
const INJECTED_FIELD_ENV: [(&str, &str); 2] = [
    ("POD_NAME", "metadata.name"),
    ("POD_NAMESPACE", "metadata.namespace"),
];

/// How `pod` differs from what the injector makes ([`crate::webhook`] module docs), in what
/// matters for the workload key and the program that runs; `cp_namespace`: the control plane's
/// namespace, which the injected addresses name; `trust_domain`: embassy's `--trust-domain`,
/// which the injector hands the sidecar. A pod can bring its own `agentscd`: without
/// the label `agentsc.io/inject` the injector never sees it, and while the injector is bypassed
/// (`failurePolicy: Ignore`) nothing at admission may check it. Every `agentscd` flag has an env
/// form, so the allowed image with no `command` can still keep its key in a volume the app
/// mounts (`AGENTSC_STATE_DIR`) or start another program (`AGENTSC_RUNTIME_CMD`), and probes
/// and lifecycle hooks run programs inside the container. So, besides the image and command line:
///
/// - `agentscd` has exactly the injector's env: `AGENTSC_CONTROL_PLANE`,
///   `AGENTSC_CA_ADDRESS`, `AGENTSC_K8S_TOKEN_FILE`, `AGENTSC_TRUST_DOMAIN`,
///   `AGENTSC_STATE_DIR` and `AGENTSC_NO_RUNTIME=true` with the injected values, the pod-specific literals
///   ([`INJECTED_LITERAL_ENV`]) and fields ([`INJECTED_FIELD_ENV`]), `ANTHROPIC_API_KEY` from
///   a Secret's key `ANTHROPIC_API_KEY`, and the template's [`TEMPLATE_ENV_ALLOWED`];
///   `agentsc-runtime` only the template's [`RUNTIME_TEMPLATE_ENV`]; neither has `envFrom` or
///   lifecycle hooks, and no probe but exec [`READY_COMMAND`] (`agentscd`'s; the runtime has
///   none);
/// - both are present, and mount exactly the injected volumes at the injected paths
///   (`agentscd`: [`RUN_VOLUME`], [`STATE_VOLUME`], [`TOKEN_VOLUME`]; the runtime:
///   [`RUN_VOLUME`]), which no other container mounts;
/// - [`RUN_VOLUME`] and [`STATE_VOLUME`] are `emptyDir`s and [`TOKEN_VOLUME`] projects only
///   the service-account token for audience [`TOKEN_AUDIENCE`]; no other volume projects one;
/// - no ephemeral containers, `shareProcessNamespace` or `hostPID`.
pub fn shape_problem(pod: &Pod, cp_namespace: &str, trust_domain: &str) -> Option<String> {
    let Some(spec) = pod.spec.as_ref() else {
        return Some("the pod has no spec".into());
    };
    if spec.share_process_namespace == Some(true) || spec.host_pid == Some(true) {
        return Some(
            "shareProcessNamespace or hostPID is set: another container could read the sidecar's \
             memory and environment"
                .into(),
        );
    }
    if spec
        .ephemeral_containers
        .as_ref()
        .is_some_and(|e| !e.is_empty())
    {
        return Some("the pod has ephemeral containers".into());
    }
    let all: Vec<&Container> = spec
        .init_containers
        .iter()
        .flatten()
        .chain(&spec.containers)
        .collect();
    let find = |name: &str| all.iter().copied().find(|c| c.name == name);
    let (Some(sidecar), Some(runtime)) = (find(SIDECAR_CONTAINER), find(RUNTIME_CONTAINER)) else {
        return Some(format!(
            "the pod lacks the {SIDECAR_CONTAINER:?} or {RUNTIME_CONTAINER:?} container the \
             injector adds"
        ));
    };
    let fixed = [
        (
            "AGENTSC_CONTROL_PLANE",
            format!("embassy.{cp_namespace}.svc:{CONTROL_PLANE_PORT}"),
        ),
        (
            "AGENTSC_CA_ADDRESS",
            format!("embassy-ca.{cp_namespace}.svc:{CONTROL_PLANE_PORT}"),
        ),
        ("AGENTSC_K8S_TOKEN_FILE", TOKEN_FILE.to_string()),
        ("AGENTSC_TRUST_DOMAIN", trust_domain.to_string()),
        ("AGENTSC_STATE_DIR", STATE_DIR.to_string()),
        ("AGENTSC_NO_RUNTIME", "true".to_string()),
    ];
    let env: Vec<&EnvVar> = sidecar.env.iter().flatten().collect();
    if let Some(e) = env.iter().find(|e| !sidecar_env_ok(e, &fixed)) {
        return Some(format!(
            "container {SIDECAR_CONTAINER:?} sets env {:?}, which the injector does not set so",
            e.name
        ));
    }
    if let Some((name, want)) = fixed
        .iter()
        .find(|(n, _)| !env.iter().any(|e| e.name == *n))
    {
        return Some(format!(
            "container {SIDECAR_CONTAINER:?} lacks env {name}={want:?}"
        ));
    }
    if let Some(e) = runtime
        .env
        .iter()
        .flatten()
        .find(|e| !RUNTIME_TEMPLATE_ENV.contains(&e.name.as_str()))
    {
        return Some(format!(
            "container {RUNTIME_CONTAINER:?} sets env {:?}, which the injector does not set",
            e.name
        ));
    }
    for (c, probes) in [(sidecar, true), (runtime, false)] {
        if c.env_from.as_ref().is_some_and(|e| !e.is_empty()) {
            return Some(format!("container {:?} sets envFrom", c.name));
        }
        if c.lifecycle.is_some() {
            return Some(format!("container {:?} has lifecycle hooks", c.name));
        }
        let probe_ok = |p: &Option<Probe>| p.as_ref().is_none_or(|p| probes && is_ready_probe(p));
        if !(probe_ok(&c.startup_probe)
            && probe_ok(&c.readiness_probe)
            && probe_ok(&c.liveness_probe))
        {
            return Some(format!(
                "container {:?} has a probe other than the injected exec {READY_COMMAND:?}",
                c.name
            ));
        }
    }
    if !mounts_are(
        sidecar,
        &[
            (RUN_VOLUME, RUN_DIR),
            (STATE_VOLUME, STATE_DIR),
            (TOKEN_VOLUME, TOKEN_DIR),
        ],
    ) {
        return Some(format!(
            "container {SIDECAR_CONTAINER:?} must mount exactly {RUN_VOLUME} at {RUN_DIR}, \
             {STATE_VOLUME} at {STATE_DIR} and {TOKEN_VOLUME} at {TOKEN_DIR}"
        ));
    }
    if !mounts_are(runtime, &[(RUN_VOLUME, RUN_DIR)]) {
        return Some(format!(
            "container {RUNTIME_CONTAINER:?} must mount exactly {RUN_VOLUME} at {RUN_DIR}"
        ));
    }
    let ephemeral_mounts = spec
        .ephemeral_containers
        .iter()
        .flatten()
        .flat_map(|c| c.volume_mounts.iter().flatten());
    if let Some(m) = all
        .iter()
        .filter(|c| !SIDECAR_CONTAINERS.contains(&c.name.as_str()))
        .flat_map(|c| c.volume_mounts.iter().flatten())
        .chain(ephemeral_mounts)
        .find(|m| SIDECAR_VOLUMES.contains(&m.name.as_str()))
    {
        return Some(format!(
            "another container mounts the sidecar volume {:?}",
            m.name
        ));
    }
    let volumes: Vec<Value> = spec
        .volumes
        .iter()
        .flatten()
        .filter_map(|v| serde_json::to_value(v).ok())
        .collect();
    let volume = |name: &str| volumes.iter().find(|v| v["name"] == name);
    for name in [RUN_VOLUME, STATE_VOLUME] {
        if !volume(name).is_some_and(|v| keys_are(v, &["name", "emptyDir"])) {
            return Some(format!("volume {name:?} must be an emptyDir"));
        }
    }
    let projects_token = |v: &Value| {
        v["projected"]["sources"].as_array().is_some_and(|s| {
            s.iter()
                .any(|s| s["serviceAccountToken"]["audience"] == TOKEN_AUDIENCE)
        })
    };
    let token_ok = volume(TOKEN_VOLUME).is_some_and(|v| {
        keys_are(v, &["name", "projected"])
            && v["projected"]["sources"].as_array().is_some_and(|s| {
                s.len() == 1
                    && keys_are(&s[0], &["serviceAccountToken"])
                    && s[0]["serviceAccountToken"]["audience"] == TOKEN_AUDIENCE
                    && s[0]["serviceAccountToken"]["path"] == "token"
            })
    });
    if !token_ok {
        return Some(format!(
            "volume {TOKEN_VOLUME:?} must project only the service-account token for audience \
             {TOKEN_AUDIENCE:?}"
        ));
    }
    if let Some(v) = volumes
        .iter()
        .find(|v| v["name"] != TOKEN_VOLUME && projects_token(v))
    {
        return Some(format!(
            "volume {} projects a service-account token for audience {TOKEN_AUDIENCE:?}",
            v["name"]
        ));
    }
    None
}

/// `IssueCertificate`'s check of a pod's running sidecar containers (module docs); `Ok` when
/// the allow-list is not enforced. `cp_namespace` and `trust_domain`: embassy's
/// ([`shape_problem`]).
pub fn check_running_pod(
    cfg: &SidecarImagesConfig,
    pod: &Pod,
    cp_namespace: &str,
    trust_domain: &str,
) -> Result<(), Refusal> {
    if !cfg.enforced() {
        return Ok(());
    }
    let name = format!(
        "{}/{}",
        pod.metadata.namespace.as_deref().unwrap_or_default(),
        pod.metadata.name.as_deref().unwrap_or_default()
    );
    let spec = pod.spec.as_ref();
    let sidecars: Vec<&Container> = spec
        .into_iter()
        .flat_map(|s| s.init_containers.iter().flatten().chain(&s.containers))
        .filter(|c| SIDECAR_CONTAINERS.contains(&c.name.as_str()))
        .collect();
    if let Some(problem) = sidecars
        .iter()
        .find_map(|c| program_problem(c))
        .or_else(|| shape_problem(pod, cp_namespace, trust_domain))
    {
        return Err(Refusal::Refused(format!("pod {name}: {problem}")));
    }
    let status = pod.status.as_ref();
    let statuses: Vec<&ContainerStatus> = status
        .into_iter()
        .flat_map(|s| {
            s.init_container_statuses
                .iter()
                .flatten()
                .chain(s.container_statuses.iter().flatten())
        })
        .collect();
    let mut not_reported = None;
    for c in sidecars {
        let image_id = statuses
            .iter()
            .find(|s| s.name == c.name)
            .map(|s| s.image_id.as_str())
            .filter(|id| !id.is_empty());
        let Some(image_id) = image_id else {
            not_reported.get_or_insert_with(|| {
                format!(
                    "the kubelet has not reported the image of container {:?} of pod {name} yet",
                    c.name
                )
            });
            continue;
        };
        match image_id_digest(image_id) {
            Some(d) if cfg.allows(d) => {}
            Some(d) => {
                return Err(Refusal::Refused(format!(
                    "container {:?} of pod {name} runs image {d}, which is not in \
                     sidecar_images.allowed_digests",
                    c.name
                )));
            }
            None => {
                return Err(Refusal::Refused(format!(
                    "container {:?} of pod {name} runs image {:?}, which names no sha256 digest",
                    c.name,
                    image_id.chars().take(256).collect::<String>()
                )));
            }
        }
    }
    match not_reported {
        Some(why) => Err(Refusal::NotReported(why)),
        None => Ok(()),
    }
}

/// The warning the `ca` and `webhook` components log at start-up, and on a config reload that
/// empties the list, while the allow-list is off.
pub fn unenforced_warning(cfg: &SidecarImagesConfig) -> Option<&'static str> {
    (!cfg.enforced()).then_some(
        "SIDECAR IMAGE ALLOW-LIST IS OFF: sidecar_images.allowed_digests is empty, so the \
         injector injects any image (a pod's agentsc.io/sidecar-image too) and IssueCertificate \
         issues certificates to any agentscd image. This is meant for development builds \
         without a registry digest. In production list the digests of the signed sidecar images \
         (Helm: images.agentscd.digest and injection.allowedImageDigests).",
    )
}

/// With the allow-list on, the problem with `--injector-image` (every pod without annotation
/// `agentsc.io/sidecar-image` would be refused).
pub fn injector_image_problem(cfg: &SidecarImagesConfig, image: Option<&str>) -> Option<String> {
    let image = image?;
    check_reference(cfg, image, "--injector-image").err()
}

/// What `embassy serve` logs about the allow-list, at start-up and when a config reload changes
/// it: only in processes that apply it (the `ca` and `webhook` components).
#[derive(Debug, Clone)]
pub struct StateLog {
    webhook: bool,
    injector_image: Option<String>,
}

impl StateLog {
    /// `None` when the process runs neither `ca` nor `webhook`.
    pub fn for_args(args: &crate::serve::ServeArgs) -> Option<Self> {
        use crate::serve::Component;
        (args.has(Component::Ca) || args.has(Component::Webhook)).then(|| Self {
            webhook: args.has(Component::Webhook),
            injector_image: args.injector_image.clone(),
        })
    }

    pub fn log(&self, cfg: &SidecarImagesConfig) {
        if let Some(warning) = unenforced_warning(cfg) {
            tracing::warn!("{warning}");
            return;
        }
        tracing::info!(
            digests = cfg.allowed_digests.len(),
            "the sidecar image allow-list is enforced"
        );
        if self.webhook
            && let Some(problem) = injector_image_problem(cfg, self.injector_image.as_deref())
        {
            tracing::error!(
                "{problem}; every pod without annotation agentsc.io/sidecar-image is refused"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::PodStatus;

    fn d(c: char) -> String {
        format!("sha256:{}", std::iter::repeat_n(c, 64).collect::<String>())
    }

    fn allow(digests: &[String]) -> SidecarImagesConfig {
        SidecarImagesConfig {
            allowed_digests: digests.to_vec(),
        }
    }

    #[test]
    fn digests_in_references_and_image_ids() {
        let a = d('a');
        assert!(is_digest(&a));
        for bad in [
            "sha256:",
            "sha512:aa",
            &a.to_uppercase(),
            &format!("{a}0"),
            "aaaa",
        ] {
            assert!(!is_digest(bad), "{bad}");
        }
        for (image, want) in [
            (format!("ghcr.io/x/agentscd@{a}"), Some(a.as_str())),
            (format!("ghcr.io/x/agentscd:0.2.0@{a}"), Some(a.as_str())),
            (format!("registry:5000/agentscd@{a}"), Some(a.as_str())),
            ("ghcr.io/x/agentscd:0.2.0".to_string(), None),
            ("agentsc/agentscd:dev".to_string(), None),
            ("ghcr.io/x/agentscd@sha256:short".to_string(), None),
        ] {
            assert_eq!(reference_digest(&image), want, "{image}");
        }
        for (id, want) in [
            (
                format!("docker-pullable://ghcr.io/x/agentscd@{a}"),
                Some(a.as_str()),
            ),
            (format!("ghcr.io/x/agentscd@{a}"), Some(a.as_str())),
            (format!("registry:5000/x/agentscd@{a}"), Some(a.as_str())),
            (a.clone(), Some(a.as_str())),
            (format!("docker://{a}"), Some(a.as_str())),
            (String::new(), None),
            ("docker-pullable://agentsc/agentscd:dev".to_string(), None),
            ("sha256:nothex".to_string(), None),
        ] {
            assert_eq!(image_id_digest(&id), want, "{id}");
        }
    }

    #[test]
    fn references_are_checked_only_when_enforced() {
        let off = allow(&[]);
        assert!(check_reference(&off, "agentsc/agentscd:dev", "x").is_ok());
        assert!(
            unenforced_warning(&off)
                .unwrap()
                .contains("ALLOW-LIST IS OFF")
        );
        let on = allow(&[d('a')]);
        assert!(unenforced_warning(&on).is_none());
        assert!(check_reference(&on, &format!("r/agentscd@{}", d('a')), "x").is_ok());
        let e =
            check_reference(&on, &format!("r/agentscd@{}", d('b')), "annotation x").unwrap_err();
        assert!(
            e.contains("annotation x") && e.contains("is not in sidecar_images.allowed_digests"),
            "{e}"
        );
        let e = check_reference(&on, "r/agentscd:0.2.0", "x").unwrap_err();
        assert!(e.contains("is not pinned to a digest"), "{e}");
        assert!(injector_image_problem(&on, Some("r/agentscd:0.2.0")).is_some());
        assert!(injector_image_problem(&on, None).is_none());
        assert!(injector_image_problem(&off, Some("r/agentscd:0.2.0")).is_none());
    }

    /// The control plane's namespace and trust domain in [`crate::webhook::injected_pod`].
    const CP: &str = "agentsc-system";
    const TD: &str = "agentsc";

    fn status(name: &str, image_id: &str) -> ContainerStatus {
        ContainerStatus {
            name: name.into(),
            image_id: image_id.into(),
            ..Default::default()
        }
    }

    /// The injector's pod with images reported for `statuses`.
    fn running(image: &str, statuses: Vec<ContainerStatus>) -> Pod {
        let mut p =
            crate::webhook::injected_pod("shop", "orders-0", "orders", image, Default::default());
        p.status = Some(PodStatus {
            init_container_statuses: Some(statuses),
            container_statuses: Some(vec![status("app", "docker.io/app@sha256:x")]),
            ..Default::default()
        });
        p
    }

    #[test]
    fn running_sidecars_must_be_allowed_images_running_their_own_program() {
        let a = d('a');
        let on = allow(std::slice::from_ref(&a));
        let good = || {
            running(
                &format!("ghcr.io/x/agentscd@{a}"),
                vec![
                    status(RUNTIME_CONTAINER, &format!("ghcr.io/x/agentscd@{a}")),
                    status(
                        SIDECAR_CONTAINER,
                        &format!("docker-pullable://ghcr.io/x/agentscd@{a}"),
                    ),
                ],
            )
        };
        assert_eq!(check_running_pod(&on, &good(), CP, TD), Ok(()));
        // off: anything goes
        let mut evil = good();
        evil.status = None;
        assert_eq!(check_running_pod(&allow(&[]), &evil, CP, TD), Ok(()));

        // the agentscd image is another one
        let mut p = good();
        p.status
            .as_mut()
            .unwrap()
            .init_container_statuses
            .as_mut()
            .unwrap()[1]
            .image_id = format!("ghcr.io/evil/agentscd@{}", d('b'));
        let Err(Refusal::Refused(m)) = check_running_pod(&on, &p, CP, TD) else {
            panic!()
        };
        assert!(
            m.contains("container \"agentscd\" of pod shop/orders-0 runs image sha256:bbbb"),
            "{m}"
        );
        // the runtime image too
        let mut p = good();
        p.status
            .as_mut()
            .unwrap()
            .init_container_statuses
            .as_mut()
            .unwrap()[0]
            .image_id = format!("ghcr.io/evil/agentscd@{}", d('b'));
        assert!(
            matches!(check_running_pod(&on, &p, CP, TD), Err(Refusal::Refused(m)) if m.contains("agentsc-runtime"))
        );
        // agentscd as a regular container (an explicit sidecar), reported in containerStatuses
        let mut p = good();
        let spec = p.spec.as_mut().unwrap();
        let sidecar = spec.init_containers.as_mut().unwrap().remove(1);
        spec.containers.push(sidecar);
        let st = p.status.as_mut().unwrap();
        st.init_container_statuses.as_mut().unwrap().truncate(1);
        st.container_statuses
            .as_mut()
            .unwrap()
            .push(status(SIDECAR_CONTAINER, &a));
        assert_eq!(check_running_pod(&on, &p, CP, TD), Ok(()));
        // a tag-only image id names no digest
        st_set(
            &mut p,
            SIDECAR_CONTAINER,
            "docker-pullable://agentsc/agentscd:dev",
        );
        assert!(
            matches!(check_running_pod(&on, &p, CP, TD), Err(Refusal::Refused(m)) if m.contains("names no sha256 digest"))
        );
        // not reported yet: retryable
        let mut p = good();
        p.status
            .as_mut()
            .unwrap()
            .init_container_statuses
            .as_mut()
            .unwrap()[1]
            .image_id = String::new();
        assert!(
            matches!(check_running_pod(&on, &p, CP, TD), Err(Refusal::NotReported(m)) if m.contains("has not reported"))
        );
        let mut p = good();
        p.status = None;
        assert!(matches!(
            check_running_pod(&on, &p, CP, TD),
            Err(Refusal::NotReported(_))
        ));

        // an allowed image running another program
        for (name, command, args) in [
            (SIDECAR_CONTAINER, Some(vec!["python3"]), None),
            (SIDECAR_CONTAINER, None, Some(vec!["--no-runtime"])),
            (RUNTIME_CONTAINER, Some(vec!["python3", "-c", "x"]), None),
            (
                RUNTIME_CONTAINER,
                Some(vec![RUNTIME_COMMAND]),
                Some(vec!["--listen", "unix:/tmp/x"]),
            ),
            (RUNTIME_CONTAINER, None, None),
        ] {
            let mut p = good();
            let init = p.spec.as_mut().unwrap().init_containers.as_mut().unwrap();
            let c = init.iter_mut().find(|c| c.name == name).unwrap();
            c.command = command.map(|v| v.into_iter().map(String::from).collect());
            c.args = args.map(|v| v.into_iter().map(String::from).collect());
            let Err(Refusal::Refused(m)) = check_running_pod(&on, &p, CP, TD) else {
                panic!("{name}")
            };
            assert!(m.contains(name) && m.contains("must run"), "{m}");
        }
    }

    fn st_set(p: &mut Pod, name: &str, image_id: &str) {
        let st = p.status.as_mut().unwrap();
        for s in st
            .init_container_statuses
            .iter_mut()
            .flatten()
            .chain(st.container_statuses.iter_mut().flatten())
        {
            if s.name == name {
                s.image_id = image_id.into();
            }
        }
    }

    /// A weakened pod: what it does, the change, and the problem named.
    type ShapeCase = (&'static str, fn(&mut Value), &'static str);

    /// `p` changed as JSON (`initContainers[0]` is agentsc-runtime, `[1]` agentscd).
    fn edited(p: &Pod, change: fn(&mut Value)) -> Pod {
        let mut v = serde_json::to_value(p).unwrap();
        change(&mut v);
        serde_json::from_value(v).unwrap()
    }

    /// The review finding: a pod without the injection label never reaches the injector, so it
    /// can bring its own agentscd with the allowed image and no command, and change what it does
    /// through env (every flag has one), probes, hooks, mounts and volumes. Each is refused at
    /// IssueCertificate; the injector's own pods pass.
    #[test]
    fn a_pod_supplied_sidecar_must_have_the_injected_shape() {
        use serde_json::json;
        let a = d('a');
        let on = allow(std::slice::from_ref(&a));
        let image = format!("ghcr.io/x/agentscd@{a}");
        let good = running(
            &image,
            vec![
                status(RUNTIME_CONTAINER, &image),
                status(SIDECAR_CONTAINER, &image),
            ],
        );
        assert_eq!(shape_problem(&good, CP, TD), None);
        // with the template's env (Helm otlp.* and injection.mockFallback)
        let template = crate::webhook::InjectTemplate::parse(
            r#"{"env": [{"name": "OTEL_EXPORTER_OTLP_ENDPOINT", "value": "http://otel:4317"},
                        {"name": "AGENTSC_MOCK_FALLBACK", "value": "1"}]}"#,
        )
        .unwrap();
        let templated =
            crate::webhook::injected_pod("shop", "orders-0", "orders", &image, template);
        assert_eq!(shape_problem(&templated, CP, TD), None);
        assert!(
            shape_problem(&good, "elsewhere", TD)
                .unwrap()
                .contains("AGENTSC_CONTROL_PLANE"),
            "the addresses name the control plane's namespace"
        );

        let cases: [ShapeCase; 22] = [
            (
                "the key in a volume the app mounts (the review's pod)",
                |p| {
                    let s = &mut p["spec"];
                    s["volumes"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!({"name": "loot", "emptyDir": {}}));
                    s["containers"][0]["volumeMounts"] =
                        json!([{"name": "loot", "mountPath": "/loot"}]);
                    let agentscd = &mut s["initContainers"][1];
                    agentscd["volumeMounts"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!({"name": "loot", "mountPath": "/loot"}));
                    agentscd["env"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!({"name": "AGENTSC_STATE_DIR", "value": "/loot"}));
                },
                "sets env \"AGENTSC_STATE_DIR\"",
            ),
            (
                "another runtime program",
                |p| {
                    p["spec"]["initContainers"][1]["env"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!({"name": "AGENTSC_RUNTIME_CMD", "value": "python3 -c x"}))
                },
                "sets env \"AGENTSC_RUNTIME_CMD\"",
            ),
            (
                "agentscd spawns the runtime itself",
                |p| {
                    p["spec"]["initContainers"][1]["env"]
                        .as_array_mut()
                        .unwrap()
                        .retain(|e| e["name"] != "AGENTSC_NO_RUNTIME")
                },
                "lacks env AGENTSC_NO_RUNTIME=\"true\"",
            ),
            (
                "another control plane",
                |p| {
                    p["spec"]["initContainers"][1]["env"]
                        .as_array_mut()
                        .unwrap()
                        .push(
                            json!({"name": "AGENTSC_CONTROL_PLANE", "value": "evil.example:15012"}),
                        )
                },
                "sets env \"AGENTSC_CONTROL_PLANE\"",
            ),
            (
                "another trust domain",
                |p| {
                    p["spec"]["initContainers"][1]["env"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!({"name": "AGENTSC_TRUST_DOMAIN", "value": "evil"}))
                },
                "sets env \"AGENTSC_TRUST_DOMAIN\"",
            ),
            (
                "a fixed value from a ConfigMap",
                |p| {
                    p["spec"]["initContainers"][1]["env"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!({
                            "name": "AGENTSC_STATE_DIR",
                            "valueFrom": {"configMapKeyRef": {"name": "x", "key": "dir"}},
                        }))
                },
                "sets env \"AGENTSC_STATE_DIR\"",
            ),
            (
                "the pod name from another field",
                |p| {
                    p["spec"]["initContainers"][1]["env"].as_array_mut().unwrap().push(json!({
                    "name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}},
                }))
                },
                "sets env \"POD_NAME\"",
            ),
            (
                "envFrom",
                |p| {
                    p["spec"]["initContainers"][1]["envFrom"] =
                        json!([{"configMapRef": {"name": "flags"}}])
                },
                "sets envFrom",
            ),
            (
                "the runtime gets the key",
                |p| {
                    p["spec"]["initContainers"][0]["env"] = json!([{
                        "name": "ANTHROPIC_API_KEY",
                        "valueFrom": {"secretKeyRef": {"name": "agentsc-anthropic", "key": "ANTHROPIC_API_KEY"}},
                    }])
                },
                "container \"agentsc-runtime\" sets env \"ANTHROPIC_API_KEY\"",
            ),
            (
                "a liveness probe runs a program",
                |p| {
                    p["spec"]["initContainers"][1]["livenessProbe"] =
                        json!({"exec": {"command": ["python3", "-c", "x"]}})
                },
                "container \"agentscd\" has a probe other than",
            ),
            (
                "the startup probe runs another program",
                |p| {
                    p["spec"]["initContainers"][1]["startupProbe"]["exec"]["command"] =
                        json!(["sh", "-c", "x"])
                },
                "container \"agentscd\" has a probe other than",
            ),
            (
                "the runtime gets a probe",
                |p| {
                    p["spec"]["initContainers"][0]["readinessProbe"] =
                        json!({"exec": {"command": [READY_COMMAND]}})
                },
                "container \"agentsc-runtime\" has a probe other than",
            ),
            (
                "a postStart hook",
                |p| p["spec"]["initContainers"][1]["lifecycle"] = json!({"postStart": {"exec": {"command": ["cp", "-r", "/var/lib/agentsc/state", "/run/agentsc"]}}}),
                "container \"agentscd\" has lifecycle hooks",
            ),
            (
                "agentscd mounts another volume",
                |p| {
                    p["spec"]["volumes"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!({"name": "x", "emptyDir": {}}));
                    p["spec"]["initContainers"][1]["volumeMounts"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!({"name": "x", "mountPath": "/x"}));
                },
                "container \"agentscd\" must mount exactly",
            ),
            (
                "the state at another path",
                |p| {
                    p["spec"]["initContainers"][1]["volumeMounts"][1]["mountPath"] =
                        json!("/run/agentsc/state")
                },
                "container \"agentscd\" must mount exactly",
            ),
            (
                "the runtime mounts the state",
                |p| {
                    p["spec"]["initContainers"][0]["volumeMounts"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!({"name": "agentsc-state", "mountPath": "/s"}))
                },
                "container \"agentsc-runtime\" must mount exactly",
            ),
            (
                "the app mounts the state",
                |p| {
                    p["spec"]["containers"][0]["volumeMounts"] =
                        json!([{"name": "agentsc-state", "mountPath": "/s"}])
                },
                "another container mounts the sidecar volume \"agentsc-state\"",
            ),
            (
                "the state on the node",
                |p| {
                    p["spec"]["volumes"][1] =
                        json!({"name": "agentsc-state", "hostPath": {"path": "/tmp/loot"}})
                },
                "volume \"agentsc-state\" must be an emptyDir",
            ),
            (
                "the token volume carries more",
                |p| {
                    p["spec"]["volumes"][2]["projected"]["sources"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!({"configMap": {"name": "x"}}))
                },
                "volume \"agentsc-token\" must project only",
            ),
            (
                "the app gets an agentsc token of its own",
                |p| {
                    p["spec"]["volumes"].as_array_mut().unwrap().push(json!({
                    "name": "mine",
                    "projected": {"sources": [{"serviceAccountToken": {"audience": "agentsc", "path": "t"}}]},
                }))
                },
                "volume \"mine\" projects a service-account token",
            ),
            (
                "no runtime container (agentscd spawns one)",
                |p| {
                    p["spec"]["initContainers"]
                        .as_array_mut()
                        .unwrap()
                        .remove(0);
                },
                "lacks the \"agentscd\" or \"agentsc-runtime\" container",
            ),
            (
                "shareProcessNamespace",
                |p| p["spec"]["shareProcessNamespace"] = json!(true),
                "shareProcessNamespace or hostPID",
            ),
        ];
        for (case, change, want) in cases {
            let p = edited(&good, change);
            let problem = shape_problem(&p, CP, TD).unwrap_or_else(|| panic!("{case}: no problem"));
            assert!(problem.contains(want), "{case}: {problem}");
            // IssueCertificate refuses it, while the allow-list is on
            let Err(Refusal::Refused(m)) = check_running_pod(&on, &p, CP, TD) else {
                panic!("{case}")
            };
            assert!(
                m.starts_with("pod shop/orders-0: ") && m.contains(want),
                "{case}: {m}"
            );
            assert_eq!(check_running_pod(&allow(&[]), &p, CP, TD), Ok(()), "{case}");
        }
        let debug = edited(&good, |p| {
            p["spec"]["ephemeralContainers"] = json!([{"name": "debugger", "image": "busybox"}]);
        });
        assert!(
            shape_problem(&debug, CP, TD)
                .unwrap()
                .contains("ephemeral containers")
        );
    }
}
