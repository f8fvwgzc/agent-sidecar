//! Kubernetes integration (design §8.4 `kubernetes` store, §7 split-mode serving certificate,
//! §13 caBundle reconcile).
//!
//! | Module | What |
//! | --- | --- |
//! | [`client`] | the [`client::KubeApi`] and [`client::CharterApi`] traits and their kube-rs implementation |
//! | [`store`] | [`store::KubeStore`], the `--store kubernetes` implementation of [`crate::store::Store`] |
//! | [`tls_secret`] | Secret `embassy-tls` (`--tls-secret`) written and renewed from the `ca` component's serving certificate |
//! | [`ca_bundle`] | `clientConfig.caBundle` of both webhook configurations, reconciled every 30 s |
//!
//! [`load_ca_secret`] reads `--ca-secret` (and creates the CA there on first start).
use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context, anyhow, bail};
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

use crate::ca::CaMaterial;
use crate::serve::{Component, ServeArgs};
use crate::store::Store;

pub mod ca_bundle;
pub mod client;
pub mod store;
pub mod tls_secret;

#[cfg(test)]
pub(crate) mod fake;

use client::{ApiError, CharterApi, KubeApi, KubeClient};
use store::KubeStore;

/// Is this process running in a Kubernetes pod (the API server's address is in its env)?
pub fn in_cluster() -> bool {
    std::env::var_os("KUBERNETES_SERVICE_HOST").is_some()
}

/// The `--store kubernetes` store. The watcher that processes kubectl changes runs only in the
/// process with the `controlplane` component (the one writer); other components (the `ca`
/// reading `service.service_accounts`) only read.
pub async fn open_store(args: &ServeArgs) -> anyhow::Result<Arc<dyn Store>> {
    let store: Arc<dyn Store> = open_kube_store(args).await?;
    Ok(store)
}

/// [`open_store`] with the concrete type (for [`KubeStore::set_synced`]).
pub async fn open_kube_store(args: &ServeArgs) -> anyhow::Result<Arc<KubeStore>> {
    let client = KubeClient::try_default()
        .await
        .context("--store kubernetes")?;
    match CharterApi::list(&client).await {
        Ok(_) => {}
        Err(ApiError::NotFound) => bail!(
            "--store kubernetes: the CustomResourceDefinition charters.attache.io is not \
             installed (helm install the agent-sidecar chart with crds.install=true, or kubectl \
             apply -f deploy/crds/charters.attache.io.yaml)"
        ),
        Err(e) => bail!("--store kubernetes: listing Charters failed: {e}"),
    }
    let mut store = KubeStore::new(Arc::new(client.clone()));
    if args.has(Component::Controlplane) {
        store.spawn_watcher(client.client().clone());
    }
    Ok(Arc::new(store))
}

/// The CA material in Secret `<namespace>/<name>` (`--ca-secret`, keys `ca.crt` and `ca.key`,
/// the layout of `embassy ca-init` and of the v0.1 `attache-ca` Secret). When the Secret does not
/// exist a new CA is created in it (the chart's default `attache-ca`); with `ca.existingSecret`
/// the Secret exists and is only read.
pub async fn load_ca_secret(namespace: &str, name: &str) -> anyhow::Result<CaMaterial> {
    let api = KubeClient::try_default()
        .await
        .with_context(|| format!("--ca-secret {namespace}/{name}"))?;
    load_or_create_ca(&api, namespace, name).await
}

fn secret_text<'a>(secret: &'a Secret, key: &str) -> Option<&'a str> {
    secret
        .data
        .as_ref()?
        .get(key)
        .and_then(|b| std::str::from_utf8(&b.0).ok())
}

/// [`load_ca_secret`] over any [`KubeApi`]. Two replicas starting at once both try to create
/// the Secret; the one that loses the race reads the winner's CA.
pub async fn load_or_create_ca(
    api: &dyn KubeApi,
    namespace: &str,
    name: &str,
) -> anyhow::Result<CaMaterial> {
    let what = format!("--ca-secret {namespace}/{name}");
    for _ in 0..3 {
        match api.get_secret(namespace, name).await {
            Ok(Some(secret)) => {
                let (Some(crt), Some(key)) = (
                    secret_text(&secret, "ca.crt"),
                    secret_text(&secret, "ca.key"),
                ) else {
                    bail!("{what}: the Secret has no ca.crt and ca.key");
                };
                return CaMaterial::from_pems(crt, key).with_context(|| what.clone());
            }
            Ok(None) => {
                let ca = attache_pki::ca_init().map_err(|e| anyhow!("{what}: {e}"))?;
                let secret = Secret {
                    metadata: ObjectMeta {
                        name: Some(name.to_string()),
                        namespace: Some(namespace.to_string()),
                        labels: Some(BTreeMap::from([(
                            "app.kubernetes.io/managed-by".to_string(),
                            client::FIELD_MANAGER.to_string(),
                        )])),
                        ..Default::default()
                    },
                    type_: Some("Opaque".into()),
                    data: Some(BTreeMap::from([
                        (
                            "ca.crt".to_string(),
                            ByteString(ca.cert_pem.clone().into_bytes()),
                        ),
                        (
                            "ca.key".to_string(),
                            ByteString(ca.key_pem.clone().into_bytes()),
                        ),
                    ])),
                    ..Default::default()
                };
                match api.create_secret(namespace, &secret).await {
                    Ok(_) => {
                        tracing::info!(secret = %format!("{namespace}/{name}"), "created a new CA");
                        return CaMaterial::from_pems(&ca.cert_pem, &ca.key_pem)
                            .with_context(|| what.clone());
                    }
                    // another replica created it first: use that one
                    Err(ApiError::AlreadyExists(_)) => continue,
                    Err(e) => {
                        bail!("{what}: the Secret does not exist and creating it failed: {e}")
                    }
                }
            }
            Err(e) => bail!("{what}: reading the Secret failed: {e}"),
        }
    }
    bail!("{what}: the Secret keeps appearing and disappearing")
}

#[cfg(test)]
mod tests {
    use super::*;
    use fake::FakeCluster;

    #[tokio::test]
    async fn the_ca_secret_is_read_or_created_once() {
        let cluster = FakeCluster::new();
        // first start: created, with both keys
        let first = load_or_create_ca(&cluster, "attache-system", "attache-ca")
            .await
            .unwrap();
        let stored = cluster.secret("attache-system", "attache-ca").unwrap();
        assert_eq!(stored.type_.as_deref(), Some("Opaque"));
        assert_eq!(
            secret_text(&stored, "ca.crt").unwrap().trim(),
            first.roots_pem().trim()
        );
        assert!(
            secret_text(&stored, "ca.key")
                .unwrap()
                .contains("PRIVATE KEY")
        );
        // later starts: the same CA
        let again = load_or_create_ca(&cluster, "attache-system", "attache-ca")
            .await
            .unwrap();
        assert_eq!(again.roots_pem(), first.roots_pem());
    }

    #[tokio::test]
    async fn an_existing_v01_ca_is_reused_and_bad_ones_are_named() {
        let cluster = FakeCluster::new();
        let ca = attache_pki::ca_init().unwrap();
        cluster.put_secret(
            "attache-demo",
            "attache-ca",
            &[("ca.crt", &ca.cert_pem), ("ca.key", &ca.key_pem)],
        );
        let m = load_or_create_ca(&cluster, "attache-demo", "attache-ca")
            .await
            .unwrap();
        assert_eq!(
            attache_pki::certs_from_pem(m.roots_pem()).unwrap(),
            attache_pki::certs_from_pem(&ca.cert_pem).unwrap()
        );

        cluster.put_secret("attache-demo", "broken", &[("ca.crt", &ca.cert_pem)]);
        let e = format!(
            "{:#}",
            load_or_create_ca(&cluster, "attache-demo", "broken")
                .await
                .err()
                .unwrap()
        );
        assert!(
            e.contains("attache-demo/broken") && e.contains("ca.key"),
            "{e}"
        );

        // creation refused (ca.existingSecret in another namespace: get only)
        cluster.refuse_secret_creates();
        let e = format!(
            "{:#}",
            load_or_create_ca(&cluster, "elsewhere", "attache-ca")
                .await
                .err()
                .unwrap()
        );
        assert!(e.contains("creating it failed"), "{e}");
    }

    #[tokio::test]
    async fn a_lost_creation_race_uses_the_winners_ca() {
        let cluster = FakeCluster::new();
        let winner = attache_pki::ca_init().unwrap();
        // the Secret appears between our read and our create
        cluster.create_secret_on_next_create(
            "attache-system",
            "attache-ca",
            &[("ca.crt", &winner.cert_pem), ("ca.key", &winner.key_pem)],
        );
        let m = load_or_create_ca(&cluster, "attache-system", "attache-ca")
            .await
            .unwrap();
        assert_eq!(
            attache_pki::certs_from_pem(m.roots_pem()).unwrap(),
            attache_pki::certs_from_pem(&winner.cert_pem).unwrap()
        );
    }

    #[test]
    fn in_cluster_reads_the_service_host_env() {
        // whatever the environment, the answer matches the variable
        assert_eq!(
            in_cluster(),
            std::env::var_os("KUBERNETES_SERVICE_HOST").is_some()
        );
    }
}
