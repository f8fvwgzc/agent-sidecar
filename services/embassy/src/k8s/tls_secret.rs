//! Secret `embassy-tls` (`--tls-secret`, design §7): in split mode the `ca` component's serving
//! certificate (issued in memory from the CA and renewed at two thirds of its lifetime) is
//! written to a `kubernetes.io/tls` Secret with keys `tls.crt`, `tls.key` and `ca.crt`, which the
//! `controlplane` component mounts as `--tls-dir`.
//!
//! Several `embassy-ca` replicas converge on one certificate: each pass ([`sync_once`]) reads
//! the Secret; when it holds a usable certificate (it loads, its CA bundle is this CA's, it has
//! the control-plane URI SAN and exactly the `--dns-name` SANs, and more than a third of
//! [`crate::servingcert::SERVING_CERT_TTL`] is left) that is newer than this replica's, the
//! replica serves it too; otherwise the replica writes its own (create, or replace with the
//! `resourceVersion` read, so of two writers one wins and the other adopts at its next pass).
//! Passes run every [`SYNC_INTERVAL`] and whenever the serving certificate changes.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, anyhow};
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use tokio_util::sync::CancellationToken;

use super::client::{ApiError, FIELD_MANAGER, KubeApi};
use crate::names::ObjectRef;
use crate::servingcert::{CONTROL_PLANE_SPIFFE_ID, SERVING_CERT_TTL, ServingCertSource};

pub const SYNC_INTERVAL: Duration = Duration::from_secs(60);

/// What one pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOutcome {
    /// The Secret holds this replica's certificate (or lost a creation race just now).
    Unchanged,
    /// The Secret held a newer usable certificate; this replica serves it now.
    Adopted,
    /// This replica's certificate was written to the Secret.
    Written,
}

/// The certificate in a Secret, if it is usable as described in the module docs.
struct Theirs {
    cert: String,
    key: String,
    ca: String,
    not_after: SystemTime,
}

fn text(secret: &Secret, key: &str) -> Option<String> {
    let b = secret.data.as_ref()?.get(key)?;
    String::from_utf8(b.0.clone()).ok()
}

/// The URI SANs of the leaf of a PEM chain.
fn leaf_uri_sans(cert_pem: &str) -> Option<Vec<String>> {
    let chain = agentsc_pki::certs_from_pem(cert_pem).ok()?;
    agentsc_pki::uri_sans_of(chain.first()?).ok()
}

/// `control_plane_uri`: the URI SAN this replica's own certificate carries
/// (`spiffe://<trust domain>/control-plane`).
fn usable(
    secret: &Secret,
    ca_pem: &str,
    control_plane_uri: &str,
    dns_names: &[String],
    min_remaining: Duration,
) -> Option<Theirs> {
    let (cert, key, ca) = (
        text(secret, "tls.crt")?,
        text(secret, "tls.key")?,
        text(secret, "ca.crt")?,
    );
    let their_ca = agentsc_pki::certs_from_pem(&ca).ok()?;
    let our_ca = agentsc_pki::certs_from_pem(ca_pem).ok()?;
    if their_ca != our_ca {
        return None;
    }
    let chain = agentsc_pki::certs_from_pem(&cert).ok()?;
    let leaf = chain.first()?;
    if !agentsc_pki::uri_sans_of(leaf)
        .ok()?
        .iter()
        .any(|u| u == control_plane_uri)
    {
        return None;
    }
    let theirs: BTreeSet<String> = agentsc_pki::dns_names_of(leaf).ok()?.into_iter().collect();
    let ours: BTreeSet<String> = dns_names.iter().cloned().collect();
    if theirs != ours {
        return None;
    }
    let not_after = agentsc_pki::not_after_of(leaf).ok()?;
    if not_after.duration_since(SystemTime::now()).ok()? <= min_remaining {
        return None;
    }
    Some(Theirs {
        cert,
        key,
        ca,
        not_after,
    })
}

fn build(
    secret: &ObjectRef,
    cert: &str,
    key: &str,
    ca: &str,
    resource_version: Option<String>,
) -> Secret {
    Secret {
        metadata: ObjectMeta {
            name: Some(secret.name.clone()),
            namespace: Some(secret.namespace.clone()),
            resource_version,
            labels: Some(BTreeMap::from([(
                "app.kubernetes.io/managed-by".to_string(),
                FIELD_MANAGER.to_string(),
            )])),
            ..Default::default()
        },
        type_: Some("kubernetes.io/tls".into()),
        data: Some(BTreeMap::from([
            ("tls.crt".to_string(), ByteString(cert.as_bytes().to_vec())),
            ("tls.key".to_string(), ByteString(key.as_bytes().to_vec())),
            ("ca.crt".to_string(), ByteString(ca.as_bytes().to_vec())),
        ])),
        ..Default::default()
    }
}

/// One pass (see the module docs). `min_remaining` is how much lifetime a certificate in the
/// Secret must have left to be served (a third of [`SERVING_CERT_TTL`] in production).
pub async fn sync_once(
    api: &dyn KubeApi,
    secret: &ObjectRef,
    serving: &ServingCertSource,
    dns_names: &[String],
    min_remaining: Duration,
) -> anyhow::Result<SyncOutcome> {
    let ours = serving.current();
    let existing = api
        .get_secret(&secret.namespace, &secret.name)
        .await
        .with_context(|| format!("read Secret {secret}"))?;
    let Some(existing) = existing else {
        let s = build(secret, &ours.cert_pem, &ours.key_pem, &ours.ca_pem, None);
        return match api.create_secret(&secret.namespace, &s).await {
            Ok(_) => Ok(SyncOutcome::Written),
            // another replica created it first; the next pass adopts or replaces it
            Err(ApiError::AlreadyExists(_)) => Ok(SyncOutcome::Unchanged),
            Err(e) => Err(anyhow!("create Secret {secret}: {e}")),
        };
    };
    let control_plane_uri = leaf_uri_sans(&ours.cert_pem)
        .and_then(|u| u.into_iter().next())
        .unwrap_or_else(|| CONTROL_PLANE_SPIFFE_ID.to_string());
    if let Some(theirs) = usable(
        &existing,
        &ours.ca_pem,
        &control_plane_uri,
        dns_names,
        min_remaining,
    ) {
        if theirs.cert.trim() == ours.cert_pem.trim() {
            return Ok(SyncOutcome::Unchanged);
        }
        if theirs.not_after >= ours.not_after {
            match serving.replace(&theirs.cert, &theirs.key, &theirs.ca) {
                Ok(()) => return Ok(SyncOutcome::Adopted),
                Err(e) => tracing::warn!(
                    secret = %secret,
                    error = format!("{e:#}"),
                    "the serving certificate in the Secret does not load; replacing it"
                ),
            }
        }
    }
    let s = build(
        secret,
        &ours.cert_pem,
        &ours.key_pem,
        &ours.ca_pem,
        existing.metadata.resource_version.clone(),
    );
    match api.replace_secret(&secret.namespace, &s).await {
        Ok(_) => Ok(SyncOutcome::Written),
        // changed since we read it: the next pass decides again
        Err(ApiError::Conflict(_)) => Ok(SyncOutcome::Unchanged),
        Err(e) => Err(anyhow!("update Secret {secret}: {e}")),
    }
}

/// Keep `secret` in step with `serving` until `shutdown`.
pub async fn run(
    api: Arc<dyn KubeApi>,
    secret: ObjectRef,
    serving: Arc<ServingCertSource>,
    dns_names: Vec<String>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let mut changes = serving.subscribe();
    let min_remaining = SERVING_CERT_TTL / 3;
    loop {
        match sync_once(api.as_ref(), &secret, &serving, &dns_names, min_remaining).await {
            Ok(SyncOutcome::Unchanged) => {}
            Ok(SyncOutcome::Adopted) => {
                tracing::info!(secret = %secret, "serving the newer certificate from the Secret")
            }
            Ok(SyncOutcome::Written) => {
                tracing::info!(secret = %secret, "wrote the serving certificate to the Secret")
            }
            Err(e) => {
                tracing::warn!(secret = %secret, error = format!("{e:#}"), "syncing the serving certificate Secret failed; retrying")
            }
        }
        tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            () = tokio::time::sleep(SYNC_INTERVAL) => {}
            r = changes.changed() => {
                if r.is_err() {
                    tokio::select! {
                        () = shutdown.cancelled() => return Ok(()),
                        () = tokio::time::sleep(SYNC_INTERVAL) => {}
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CaMaterial;
    use crate::k8s::fake::FakeCluster;

    const DAY: Duration = Duration::from_secs(24 * 3600);

    fn ca() -> Arc<CaMaterial> {
        let ca = agentsc_pki::ca_init().unwrap();
        Arc::new(CaMaterial::from_pems(&ca.cert_pem, &ca.key_pem).unwrap())
    }

    fn dns() -> Vec<String> {
        vec![
            "embassy.agentsc-system.svc".into(),
            "embassy-ca.agentsc-system.svc".into(),
        ]
    }

    fn source(ca: &CaMaterial, dns: &[String], ttl: Duration) -> ServingCertSource {
        let leaf = ca.sign_server(dns, CONTROL_PLANE_SPIFFE_ID, ttl).unwrap();
        ServingCertSource::from_pems(&leaf.cert_pem, &leaf.key_pem, ca.roots_pem()).unwrap()
    }

    fn secret_ref() -> ObjectRef {
        "agentsc-system/embassy-tls".parse().unwrap()
    }

    fn stored_cert(cluster: &FakeCluster) -> String {
        text(
            &cluster.secret("agentsc-system", "embassy-tls").unwrap(),
            "tls.crt",
        )
        .unwrap()
    }

    #[tokio::test]
    async fn the_first_replica_writes_and_the_second_adopts() {
        let cluster = FakeCluster::new();
        let ca = ca();
        let a = source(&ca, &dns(), 30 * DAY);
        // b's certificate is older (expires first)
        let b = source(&ca, &dns(), 20 * DAY);

        assert_eq!(
            sync_once(&cluster, &secret_ref(), &a, &dns(), 10 * DAY)
                .await
                .unwrap(),
            SyncOutcome::Written
        );
        let s = cluster.secret("agentsc-system", "embassy-tls").unwrap();
        assert_eq!(s.type_.as_deref(), Some("kubernetes.io/tls"));
        assert_eq!(text(&s, "tls.key").unwrap(), a.current().key_pem);
        assert_eq!(text(&s, "ca.crt").unwrap(), a.current().ca_pem);
        assert_eq!(stored_cert(&cluster).trim(), a.current().cert_pem.trim());

        assert_eq!(
            sync_once(&cluster, &secret_ref(), &b, &dns(), 10 * DAY)
                .await
                .unwrap(),
            SyncOutcome::Adopted
        );
        assert_eq!(b.current().cert_pem.trim(), a.current().cert_pem.trim());
        // both agree now
        for s in [&a, &b] {
            assert_eq!(
                sync_once(&cluster, &secret_ref(), s, &dns(), 10 * DAY)
                    .await
                    .unwrap(),
                SyncOutcome::Unchanged
            );
        }
    }

    #[tokio::test]
    async fn a_renewed_certificate_replaces_an_older_or_unusable_one() {
        let cluster = FakeCluster::new();
        let ca = ca();
        let old = source(&ca, &dns(), 20 * DAY);
        sync_once(&cluster, &secret_ref(), &old, &dns(), 10 * DAY)
            .await
            .unwrap();
        // a renewal (newer) is written over it
        let renewed = source(&ca, &dns(), 30 * DAY);
        assert_eq!(
            sync_once(&cluster, &secret_ref(), &renewed, &dns(), 10 * DAY)
                .await
                .unwrap(),
            SyncOutcome::Written
        );
        assert_eq!(
            stored_cert(&cluster).trim(),
            renewed.current().cert_pem.trim()
        );

        // less than min_remaining left in the Secret: not adopted, replaced
        let near = source(&ca, &dns(), 11 * DAY).current();
        cluster.put_secret(
            "agentsc-system",
            "embassy-tls",
            &[
                ("tls.crt", &near.cert_pem),
                ("tls.key", &near.key_pem),
                ("ca.crt", &near.ca_pem),
            ],
        );
        let ours = source(&ca, &dns(), 5 * DAY);
        assert_eq!(
            sync_once(&cluster, &secret_ref(), &ours, &dns(), 12 * DAY)
                .await
                .unwrap(),
            SyncOutcome::Written
        );

        // other DNS names (a new --dns-name) or another CA: replaced
        let more: Vec<String> = dns()
            .into_iter()
            .chain(["embassy.example".to_string()])
            .collect();
        let wider = source(&ca, &more, 30 * DAY);
        assert_eq!(
            sync_once(&cluster, &secret_ref(), &wider, &more, 10 * DAY)
                .await
                .unwrap(),
            SyncOutcome::Written
        );
        let other_ca = source(&self::ca(), &more, 40 * DAY);
        assert_eq!(
            sync_once(&cluster, &secret_ref(), &other_ca, &more, 10 * DAY)
                .await
                .unwrap(),
            SyncOutcome::Written
        );

        // garbage in the Secret: replaced
        cluster.put_secret("agentsc-system", "embassy-tls", &[("tls.crt", "nope")]);
        assert_eq!(
            sync_once(&cluster, &secret_ref(), &wider, &more, 10 * DAY)
                .await
                .unwrap(),
            SyncOutcome::Written
        );
        assert_eq!(
            stored_cert(&cluster).trim(),
            wider.current().cert_pem.trim()
        );
    }

    #[tokio::test]
    async fn a_lost_creation_race_is_not_an_error() {
        let cluster = FakeCluster::new();
        let ca = ca();
        let a = source(&ca, &dns(), 30 * DAY);
        cluster.create_secret_on_next_create("agentsc-system", "embassy-tls", &[("tls.crt", "x")]);
        assert_eq!(
            sync_once(&cluster, &secret_ref(), &a, &dns(), 10 * DAY)
                .await
                .unwrap(),
            SyncOutcome::Unchanged
        );
    }

    #[tokio::test]
    async fn the_loop_writes_and_stops() {
        let cluster = Arc::new(FakeCluster::new());
        let ca = ca();
        let serving = Arc::new(source(&ca, &dns(), 30 * DAY));
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(run(
            cluster.clone(),
            secret_ref(),
            serving.clone(),
            dns(),
            shutdown.clone(),
        ));
        for _ in 0..200 {
            if cluster.secret("agentsc-system", "embassy-tls").is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            stored_cert(&cluster).trim(),
            serving.current().cert_pem.trim()
        );
        shutdown.cancel();
        task.await.unwrap().unwrap();
    }
}
