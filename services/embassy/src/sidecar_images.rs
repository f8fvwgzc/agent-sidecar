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
//! - the chart's ValidatingAdmissionPolicy `agentsc-sidecar-integrity` applies the same image and
//!   command rules to the pod spec (`deploy/helm/agent-sidecar/templates/sidecar-policy.yaml`).
use k8s_openapi::api::core::v1::{Container, ContainerStatus, Pod};

use crate::config::SidecarImagesConfig;
use crate::names::is_sha256_hex;
use crate::webhook::{RUNTIME_ARGS, RUNTIME_COMMAND, RUNTIME_CONTAINER, SIDECAR_CONTAINER};

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

/// `IssueCertificate`'s check of a pod's running sidecar containers (module docs); `Ok` when
/// the allow-list is not enforced.
pub fn check_running_pod(cfg: &SidecarImagesConfig, pod: &Pod) -> Result<(), Refusal> {
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
    if let Some(problem) = sidecars.iter().find_map(|c| program_problem(c)) {
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
    use k8s_openapi::api::core::v1::{PodSpec, PodStatus};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

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

    fn container(name: &str) -> Container {
        Container {
            name: name.into(),
            ..Default::default()
        }
    }

    fn runtime() -> Container {
        Container {
            command: Some(vec![RUNTIME_COMMAND.into()]),
            args: Some(RUNTIME_ARGS.iter().map(|a| a.to_string()).collect()),
            ..container(RUNTIME_CONTAINER)
        }
    }

    fn status(name: &str, image_id: &str) -> ContainerStatus {
        ContainerStatus {
            name: name.into(),
            image_id: image_id.into(),
            ..Default::default()
        }
    }

    fn running(init: Vec<Container>, statuses: Vec<ContainerStatus>) -> Pod {
        Pod {
            metadata: ObjectMeta {
                name: Some("orders-0".into()),
                namespace: Some("shop".into()),
                ..Default::default()
            },
            spec: Some(PodSpec {
                init_containers: Some(init),
                containers: vec![container("app")],
                ..Default::default()
            }),
            status: Some(PodStatus {
                init_container_statuses: Some(statuses),
                container_statuses: Some(vec![status("app", "docker.io/app@sha256:x")]),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn running_sidecars_must_be_allowed_images_running_their_own_program() {
        let a = d('a');
        let on = allow(std::slice::from_ref(&a));
        let good = || {
            running(
                vec![runtime(), container(SIDECAR_CONTAINER)],
                vec![
                    status(RUNTIME_CONTAINER, &format!("ghcr.io/x/agentscd@{a}")),
                    status(
                        SIDECAR_CONTAINER,
                        &format!("docker-pullable://ghcr.io/x/agentscd@{a}"),
                    ),
                ],
            )
        };
        assert_eq!(check_running_pod(&on, &good()), Ok(()));
        // off: anything goes
        let mut evil = good();
        evil.status = None;
        assert_eq!(check_running_pod(&allow(&[]), &evil), Ok(()));

        // the agentscd image is another one
        let mut p = good();
        p.status
            .as_mut()
            .unwrap()
            .init_container_statuses
            .as_mut()
            .unwrap()[1]
            .image_id = format!("ghcr.io/evil/agentscd@{}", d('b'));
        let Err(Refusal::Refused(m)) = check_running_pod(&on, &p) else {
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
            matches!(check_running_pod(&on, &p), Err(Refusal::Refused(m)) if m.contains("agentsc-runtime"))
        );
        // agentscd as a regular container (an explicit sidecar), reported in containerStatuses
        let mut p = good();
        let spec = p.spec.as_mut().unwrap();
        spec.init_containers = Some(vec![]);
        spec.containers.push(container(SIDECAR_CONTAINER));
        let st = p.status.as_mut().unwrap();
        st.init_container_statuses = None;
        st.container_statuses
            .as_mut()
            .unwrap()
            .push(status(SIDECAR_CONTAINER, &a));
        assert_eq!(check_running_pod(&on, &p), Ok(()));
        // a tag-only image id names no digest
        st_set(
            &mut p,
            SIDECAR_CONTAINER,
            "docker-pullable://agentsc/agentscd:dev",
        );
        assert!(
            matches!(check_running_pod(&on, &p), Err(Refusal::Refused(m)) if m.contains("names no sha256 digest"))
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
            matches!(check_running_pod(&on, &p), Err(Refusal::NotReported(m)) if m.contains("has not reported"))
        );
        let mut p = good();
        p.status = None;
        assert!(matches!(
            check_running_pod(&on, &p),
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
            let Err(Refusal::Refused(m)) = check_running_pod(&on, &p) else {
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
}
