//! The webhook `caBundle` reconcile (design §13): the chart never renders a `caBundle`;
//! `embassy-ca` sets `clientConfig.caBundle` on every entry of the live
//! `attache-sidecar-injector` (entry `sidecar-injector.attache.io`) and
//! `attache-charter-validator` (entry `charter-validator.attache.io`) whenever it differs from
//! the serving certificate's CA bundle: every [`RECONCILE_INTERVAL`] and at once when the
//! serving certificate changes.
//!
//! The patch is a strategic merge keyed on the entry names read from the live object (so it
//! never adds an entry), and only the entries that differ are in it. The RBAC is `get` and
//! `patch` on the two configurations by name; nothing is listed.
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use super::client::{ApiError, KubeApi, WebhookKind};
use crate::servingcert::ServingCertSource;

pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
/// The one entry of `attache-sidecar-injector` (chart README, "What embassy-ca reads").
pub const INJECTOR_ENTRY: &str = "sidecar-injector.attache.io";
/// The one entry of `attache-charter-validator`.
pub const VALIDATOR_ENTRY: &str = "charter-validator.attache.io";

/// What one pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// `<configuration>/<entry>` of every entry whose `caBundle` was set.
    pub patched: Vec<String>,
    /// Configurations that do not exist (yet).
    pub missing: Vec<String>,
    /// Failed reads or patches.
    pub errors: Vec<String>,
}

/// Does `entry`'s `clientConfig.caBundle` (base64 in JSON) hold exactly `ca_pem`?
fn bundle_matches(entry: &Value, ca_pem: &str) -> bool {
    entry
        .get("clientConfig")
        .and_then(|c| c.get("caBundle"))
        .and_then(Value::as_str)
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        .is_some_and(|b| b == ca_pem.as_bytes())
}

/// One reconcile pass over `targets` (`(kind, configuration name)`).
pub async fn reconcile_once(
    api: &dyn KubeApi,
    targets: &[(WebhookKind, String)],
    ca_pem: &str,
) -> Report {
    let mut report = Report::default();
    let want = base64::engine::general_purpose::STANDARD.encode(ca_pem.as_bytes());
    for (kind, name) in targets {
        let config = match api.get_webhook_config(*kind, name).await {
            Ok(Some(c)) => c,
            Ok(None) => {
                report.missing.push(name.clone());
                continue;
            }
            Err(e) => {
                report.errors.push(format!("{name}: {e}"));
                continue;
            }
        };
        let stale: Vec<String> = config
            .get("webhooks")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|e| !bundle_matches(e, ca_pem))
            .filter_map(|e| e.get("name").and_then(Value::as_str).map(str::to_string))
            .collect();
        if stale.is_empty() {
            continue;
        }
        let patch = json!({
            "webhooks": stale.iter().map(|n| json!({"name": n, "clientConfig": {"caBundle": want}})).collect::<Vec<_>>()
        });
        match api.patch_webhook_config(*kind, name, &patch).await {
            Ok(()) => report
                .patched
                .extend(stale.iter().map(|n| format!("{name}/{n}"))),
            Err(ApiError::NotFound) => report.missing.push(name.clone()),
            Err(e) => report.errors.push(format!("{name}: {e}")),
        }
    }
    report
}

/// The two configurations of `--webhook-config-name` and `--validating-webhook-name`.
pub fn targets(mutating: &str, validating: &str) -> Vec<(WebhookKind, String)> {
    vec![
        (WebhookKind::Mutating, mutating.to_string()),
        (WebhookKind::Validating, validating.to_string()),
    ]
}

/// Reconcile every [`RECONCILE_INTERVAL`] and on every serving-certificate change until
/// `shutdown`.
pub async fn run(
    api: Arc<dyn KubeApi>,
    targets: Vec<(WebhookKind, String)>,
    serving: Arc<ServingCertSource>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let mut changes = serving.subscribe();
    let mut last_missing: Vec<String> = Vec::new();
    loop {
        let ca_pem = serving.current().ca_pem.clone();
        let report = reconcile_once(api.as_ref(), &targets, &ca_pem).await;
        for p in &report.patched {
            tracing::info!(webhook = %p, "set the webhook caBundle");
        }
        for e in &report.errors {
            tracing::warn!(error = %e, "reconciling a webhook caBundle failed; retrying");
        }
        if report.missing != last_missing {
            for m in &report.missing {
                tracing::warn!(configuration = %m, "the webhook configuration does not exist; its caBundle cannot be set");
            }
            last_missing = report.missing;
        }
        tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            () = tokio::time::sleep(RECONCILE_INTERVAL) => {}
            r = changes.changed() => {
                if r.is_err() {
                    // the source is gone: keep the interval
                    tokio::select! {
                        () = shutdown.cancelled() => return Ok(()),
                        () = tokio::time::sleep(RECONCILE_INTERVAL) => {}
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::k8s::fake::FakeCluster;

    fn config(entries: &[(&str, Option<&str>)]) -> Value {
        json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "metadata": {"name": "x"},
            "webhooks": entries.iter().map(|(n, b)| {
                let mut cc = json!({"service": {"name": "embassy-ca", "namespace": "attache-system", "path": "/mutate", "port": 443}});
                if let Some(b) = b {
                    cc["caBundle"] = json!(base64::engine::general_purpose::STANDARD.encode(b));
                }
                json!({"name": n, "clientConfig": cc, "sideEffects": "None"})
            }).collect::<Vec<_>>()
        })
    }

    fn bundle(
        cluster: &FakeCluster,
        kind: WebhookKind,
        name: &str,
        entry: usize,
    ) -> Option<String> {
        let c = cluster.webhook_config(kind, name)?;
        let b = c["webhooks"][entry]["clientConfig"]["caBundle"].as_str()?;
        String::from_utf8(base64::engine::general_purpose::STANDARD.decode(b).ok()?).ok()
    }

    #[tokio::test]
    async fn every_entry_gets_the_serving_ca_and_only_stale_ones_are_patched() {
        let cluster = FakeCluster::new();
        cluster.put_webhook_config(
            WebhookKind::Mutating,
            "attache-sidecar-injector",
            config(&[(INJECTOR_ENTRY, None)]),
        );
        cluster.put_webhook_config(
            WebhookKind::Validating,
            "attache-charter-validator",
            config(&[
                (VALIDATOR_ENTRY, Some("OLD")),
                ("second.attache.io", Some("CA")),
            ]),
        );
        let targets = targets("attache-sidecar-injector", "attache-charter-validator");

        let r = reconcile_once(&cluster, &targets, "CA").await;
        assert_eq!(
            r.patched,
            [
                "attache-sidecar-injector/sidecar-injector.attache.io",
                "attache-charter-validator/charter-validator.attache.io"
            ]
        );
        assert!(r.missing.is_empty() && r.errors.is_empty(), "{r:?}");
        assert_eq!(
            bundle(
                &cluster,
                WebhookKind::Mutating,
                "attache-sidecar-injector",
                0
            )
            .as_deref(),
            Some("CA")
        );
        assert_eq!(
            bundle(
                &cluster,
                WebhookKind::Validating,
                "attache-charter-validator",
                0
            )
            .as_deref(),
            Some("CA")
        );
        // the entry that already matched was not in the patch
        let patches = cluster.webhook_patches();
        assert_eq!(patches.len(), 2);
        assert_eq!(
            patches[1].2,
            json!({"webhooks": [{"name": VALIDATOR_ENTRY, "clientConfig": {"caBundle": base64::engine::general_purpose::STANDARD.encode("CA")}}]})
        );

        // nothing to do: no patch
        let r = reconcile_once(&cluster, &targets, "CA").await;
        assert_eq!(r, Report::default());
        assert_eq!(cluster.webhook_patches().len(), 2);

        // a new CA bundle (rotation): every entry again
        let r = reconcile_once(&cluster, &targets, "CA\nNEW").await;
        assert_eq!(r.patched.len(), 3, "{r:?}");
        assert_eq!(
            bundle(
                &cluster,
                WebhookKind::Validating,
                "attache-charter-validator",
                1
            )
            .as_deref(),
            Some("CA\nNEW")
        );
    }

    #[tokio::test]
    async fn missing_configurations_are_reported_not_created() {
        let cluster = FakeCluster::new();
        let r = reconcile_once(&cluster, &targets("a", "b"), "CA").await;
        assert_eq!(r.missing, ["a", "b"]);
        assert!(cluster.webhook_patches().is_empty());
    }

    #[tokio::test]
    async fn the_loop_follows_serving_certificate_changes_and_stops() {
        let ca = attache_pki::ca_init().unwrap();
        let ca = Arc::new(crate::ca::CaMaterial::from_pems(&ca.cert_pem, &ca.key_pem).unwrap());
        let leaf = ca
            .sign_server(
                &["localhost".into()],
                crate::servingcert::CONTROL_PLANE_SPIFFE_ID,
                Duration::from_secs(3600),
            )
            .unwrap();
        let serving = Arc::new(
            ServingCertSource::from_pems(&leaf.cert_pem, &leaf.key_pem, ca.roots_pem()).unwrap(),
        );
        let cluster = Arc::new(FakeCluster::new());
        cluster.put_webhook_config(
            WebhookKind::Mutating,
            "inj",
            config(&[(INJECTOR_ENTRY, None)]),
        );
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(run(
            cluster.clone(),
            targets("inj", "val"),
            serving.clone(),
            shutdown.clone(),
        ));
        let want = serving.current().ca_pem.clone();
        for _ in 0..200 {
            if bundle(&cluster, WebhookKind::Mutating, "inj", 0).as_deref() == Some(want.as_str()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            bundle(&cluster, WebhookKind::Mutating, "inj", 0),
            Some(want)
        );

        // a new CA in the serving material is pushed without waiting for the interval
        let other = attache_pki::ca_init().unwrap();
        let bundle_pem = format!("{}{}", ca.roots_pem(), other.cert_pem);
        serving
            .replace(&leaf.cert_pem, &leaf.key_pem, &bundle_pem)
            .unwrap();
        let want = serving.current().ca_pem.clone();
        for _ in 0..200 {
            if bundle(&cluster, WebhookKind::Mutating, "inj", 0).as_deref() == Some(want.as_str()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            bundle(&cluster, WebhookKind::Mutating, "inj", 0),
            Some(want)
        );

        shutdown.cancel();
        task.await.unwrap().unwrap();
    }
}
