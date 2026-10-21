//! The `ca` and `webhook` components of `embassy serve` (docs/design/agent-platform.md §2, §7,
//! §13). [`spawn`] starts, as the components and flags ask:
//!
//! | Task | When |
//! | --- | --- |
//! | `CertificateAuthority.IssueCertificate` on `--grpc-addr` (TLS, client certificates optional) | `ca` without `controlplane` (split mode: `embassy-ca`) |
//! | the admission webhooks (`/mutate`, `/validate-charter`) on `--webhook-addr` (TLS) | `webhook` |
//! | Secret `--tls-secret` written and renewed from the serving certificate ([`crate::k8s::tls_secret`]) | `ca` with `--tls-secret` |
//! | the webhook `caBundle` reconcile every 30 s ([`crate::k8s::ca_bundle`]) | `webhook`, running in a Kubernetes pod |
//!
//! **One process with `controlplane`.** `--grpc-addr` then belongs to the control plane's tonic
//! server, and IssueCertificate must be served by it: the `controlplane` component adds
//! [`crate::issuance::issuance_service`] to the same `Server` as `ControlPlaneServer` (one TLS
//! listener whose client certificates are optional at the handshake and required by `Connect`).
//! This module starts no gRPC listener in that case.
//!
//! Every server uses the context's [`ServingCertSource`] through rustls configurations that read
//! the current certificate on each handshake, so renewals apply without a restart. Each task
//! runs until `ctx.shutdown` is cancelled and returns its error if it fails.
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;

use crate::context::ServeContext;
use crate::issuance;
use crate::k8s::client::{KubeApi, KubeClient};
use crate::k8s::{ca_bundle, in_cluster, tls_secret};
use crate::serve::Component;
use crate::servingcert::{ClientAuth, ServingCertSource};
use crate::webhook::{self, WebhookState};

/// How long a client may take to finish the TLS handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long open webhook connections may finish after shutdown.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

type Task = JoinHandle<anyhow::Result<()>>;

/// Listeners already bound (tests bind port 0 and pass them in).
#[derive(Debug, Default)]
pub struct Listeners {
    pub grpc: Option<TcpListener>,
    pub webhook: Option<TcpListener>,
}

/// Start the components of `ctx.args.components` that this module owns (see the module docs).
pub async fn spawn(ctx: Arc<ServeContext>) -> anyhow::Result<Vec<Task>> {
    let args = &ctx.args;
    let mut listeners = Listeners::default();
    if serves_grpc(&ctx) {
        listeners.grpc = Some(
            TcpListener::bind(args.grpc_addr)
                .await
                .with_context(|| format!("--grpc-addr {}", args.grpc_addr))?,
        );
    }
    if args.has(Component::Webhook) {
        listeners.webhook = Some(
            TcpListener::bind(args.webhook_addr)
                .await
                .with_context(|| format!("--webhook-addr {}", args.webhook_addr))?,
        );
    }
    spawn_with(ctx, listeners, None).await
}

/// Does this module serve IssueCertificate itself (the `ca` component without `controlplane`)?
pub fn serves_grpc(ctx: &ServeContext) -> bool {
    ctx.args.has(Component::Ca) && !ctx.args.has(Component::Controlplane)
}

fn serving(ctx: &ServeContext, who: &str) -> anyhow::Result<Arc<ServingCertSource>> {
    ctx.serving
        .clone()
        .ok_or_else(|| anyhow::anyhow!("{who} needs the serving certificate"))
}

/// [`spawn`] with bound listeners and, optionally, the Kubernetes API to use for the
/// `--tls-secret` writer and the caBundle reconcile (the in-cluster client when `None`; the
/// reconcile then runs only inside a pod).
pub async fn spawn_with(
    ctx: Arc<ServeContext>,
    listeners: Listeners,
    kube: Option<Arc<dyn KubeApi>>,
) -> anyhow::Result<Vec<Task>> {
    let args = &ctx.args;
    let mut tasks: Vec<Task> = Vec::new();
    let in_kubernetes = kube.is_some() || in_cluster();
    let mut kube = kube;

    if serves_grpc(&ctx) {
        let service = issuance::issuance_service(&ctx)?;
        let config = serving(&ctx, "the ca component")?.rustls_server_config(ClientAuth::Optional);
        let listener = listeners
            .grpc
            .ok_or_else(|| anyhow::anyhow!("the ca component needs its --grpc-addr listener"))?;
        tracing::info!(addr = %listener.local_addr()?, "IssueCertificate listening (TLS)");
        let shutdown = ctx.shutdown.clone();
        tasks.push(tokio::spawn(async move {
            let incoming = tls_incoming(listener, config, shutdown.clone());
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::ReceiverStream::new(incoming).map_ok(),
                    shutdown.cancelled_owned(),
                )
                .await
                .context("the IssueCertificate server")
        }));
    }

    if args.has(Component::Webhook) {
        let serving = serving(&ctx, "the webhook component")?;
        let state = Arc::new(WebhookState::from_context(&ctx)?);
        let listener = listeners.webhook.ok_or_else(|| {
            anyhow::anyhow!("the webhook component needs its --webhook-addr listener")
        })?;
        tracing::info!(addr = %listener.local_addr()?, "admission webhooks listening (TLS)");
        let config = serving.rustls_server_config(ClientAuth::None);
        tasks.push(tokio::spawn(serve_https(
            listener,
            config,
            webhook::router(state),
            ctx.shutdown.clone(),
        )));
        if in_kubernetes {
            let api = kube_api(&mut kube, "the webhook caBundle reconcile").await?;
            tasks.push(tokio::spawn(ca_bundle::run(
                api,
                ca_bundle::targets(&args.webhook_config_name, &args.validating_webhook_name),
                serving,
                ctx.shutdown.clone(),
            )));
        }
    }

    if args.has(Component::Ca)
        && let Some(secret) = &args.tls_secret
    {
        let serving = serving(&ctx, "--tls-secret")?;
        let api = kube_api(&mut kube, "--tls-secret").await?;
        tasks.push(tokio::spawn(tls_secret::run(
            api,
            secret.clone(),
            serving,
            args.dns_names.clone(),
            ctx.shutdown.clone(),
        )));
    }
    Ok(tasks)
}

/// The given Kubernetes API, or the in-cluster client (created once).
async fn kube_api(
    kube: &mut Option<Arc<dyn KubeApi>>,
    what: &str,
) -> anyhow::Result<Arc<dyn KubeApi>> {
    if let Some(k) = kube {
        return Ok(k.clone());
    }
    let client: Arc<dyn KubeApi> = Arc::new(
        KubeClient::try_default()
            .await
            .with_context(|| what.to_string())?,
    );
    *kube = Some(client.clone());
    Ok(client)
}

/// Turn a receiver of TLS streams into the `Result` stream tonic takes.
trait MapOk {
    fn map_ok(
        self,
    ) -> impl futures::Stream<Item = Result<TlsStream<TcpStream>, std::io::Error>> + Send + 'static;
}

impl MapOk for tokio_stream::wrappers::ReceiverStream<TlsStream<TcpStream>> {
    fn map_ok(
        self,
    ) -> impl futures::Stream<Item = Result<TlsStream<TcpStream>, std::io::Error>> + Send + 'static
    {
        use futures::StreamExt;
        self.map(Ok)
    }
}

/// Accept TCP connections and finish TLS handshakes concurrently (each within
/// [`HANDSHAKE_TIMEOUT`]); established streams come out of the receiver. Stops at `shutdown`.
fn tls_incoming(
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
    shutdown: CancellationToken,
) -> mpsc::Receiver<TlsStream<TcpStream>> {
    let (tx, rx) = mpsc::channel(64);
    let acceptor = TlsAcceptor::from(config);
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                () = shutdown.cancelled() => return,
                a = listener.accept() => a,
            };
            let (tcp, peer) = match accepted {
                Ok(c) => c,
                Err(e) => {
                    // EMFILE and friends: do not spin
                    tracing::warn!(error = %e, "accepting a connection failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                    Ok(Ok(tls)) => {
                        let _ = tx.send(tls).await;
                    }
                    Ok(Err(e)) => tracing::debug!(%peer, error = %e, "TLS handshake failed"),
                    Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
                }
            });
        }
    });
    rx
}

/// Serve `app` over TLS (HTTP/1.1 and h2) until `shutdown`; open connections get
/// [`SHUTDOWN_GRACE`] to finish.
async fn serve_https(
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
    app: axum::Router,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder;
    use hyper_util::service::TowerToHyperService;

    let mut incoming = tls_incoming(listener, config, shutdown.clone());
    let builder = Builder::new(TokioExecutor::new());
    let mut connections = tokio::task::JoinSet::new();
    loop {
        let tls = tokio::select! {
            () = shutdown.cancelled() => break,
            t = incoming.recv() => match t {
                Some(t) => t,
                None => break,
            },
        };
        let builder = builder.clone();
        let service = TowerToHyperService::new(app.clone());
        connections.spawn(async move {
            if let Err(e) = builder.serve_connection(TokioIo::new(tls), service).await {
                tracing::debug!(error = %e, "webhook connection ended with an error");
            }
        });
        // reap finished connections
        while connections.try_join_next().is_some() {}
    }
    let drain = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(SHUTDOWN_GRACE, drain).await.is_err() {
        connections.abort_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CaMaterial;
    use crate::config::{ControlPlaneConfig, JoinTokenEntry};
    use crate::cp_audit::CpAudit;
    use crate::k8s::client::WebhookKind;
    use crate::k8s::fake::FakeCluster;
    use agentsc_proto::CertificateRequest;
    use agentsc_proto::certificate_authority_client::CertificateAuthorityClient;
    use arc_swap::ArcSwap;
    use clap::Parser;
    use sha2::{Digest, Sha256};

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        serve: crate::serve::ServeArgs,
    }

    struct Rig {
        ctx: Arc<ServeContext>,
        ca: Arc<CaMaterial>,
    }

    fn rig(args: &[&str]) -> Rig {
        let args = Cli::try_parse_from(std::iter::once("serve").chain(args.iter().copied()))
            .unwrap()
            .serve;
        let ca = agentsc_pki::ca_init().unwrap();
        let ca = Arc::new(CaMaterial::from_pems(&ca.cert_pem, &ca.key_pem).unwrap());
        let serving = ServingCertSource::in_memory(ca.clone(), vec!["localhost".into()]).unwrap();
        let mut config = ControlPlaneConfig::default();
        config.issuance.join_tokens = vec![JoinTokenEntry {
            name: "compose-orders".into(),
            sha256: hex::encode(Sha256::digest(b"att_join")),
            namespace: "demo".into(),
            services: vec!["orders".into()],
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        }];
        let ctx = Arc::new(ServeContext {
            config: Arc::new(ArcSwap::from_pointee(config)),
            args,
            store: None,
            ca: Some(ca.clone()),
            serving: Some(Arc::new(serving)),
            cp_audit: Arc::new(CpAudit::with_writer(None, Box::new(std::io::sink()))),
            shutdown: CancellationToken::new(),
        });
        Rig { ctx, ca }
    }

    async fn local() -> TcpListener {
        TcpListener::bind("127.0.0.1:0").await.unwrap()
    }

    async fn finish(ctx: &ServeContext, tasks: Vec<Task>) {
        ctx.shutdown.cancel();
        for t in tasks {
            tokio::time::timeout(Duration::from_secs(10), t)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn split_mode_serves_issue_certificate_over_tls() {
        let r = rig(&["--components", "ca", "--ca-dir", "/ca"]);
        let grpc = local().await;
        let addr = grpc.local_addr().unwrap();
        let tasks = spawn_with(
            r.ctx.clone(),
            Listeners {
                grpc: Some(grpc),
                webhook: None,
            },
            None,
        )
        .await
        .unwrap();
        assert_eq!(tasks.len(), 1);

        let tls = tonic::transport::ClientTlsConfig::new()
            .ca_certificate(tonic::transport::Certificate::from_pem(r.ca.roots_pem()))
            .domain_name("localhost");
        let channel = tonic::transport::Endpoint::from_shared(format!("https://{addr}"))
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .connect()
            .await
            .unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::default()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap();
        let resp = CertificateAuthorityClient::new(channel)
            .issue_certificate(CertificateRequest {
                csr_pem: csr,
                kubernetes_token: String::new(),
                join_token: "att_join".into(),
                namespace: "demo".into(),
                service: "orders".into(),
            })
            .await
            .unwrap()
            .into_inner();
        let der = agentsc_pki::certs_from_pem(&resp.cert_pem)
            .unwrap()
            .remove(0);
        assert_eq!(
            agentsc_pki::uri_sans_of(&der).unwrap(),
            ["spiffe://agentsc/ns/demo/svc/orders"]
        );
        assert_eq!(resp.ca_pem, r.ca.roots_pem());
        finish(&r.ctx, tasks).await;
    }

    #[tokio::test]
    async fn with_the_controlplane_component_no_grpc_listener_is_started() {
        let r = rig(&["--components", "ca,controlplane", "--ca-dir", "/ca"]);
        assert!(!serves_grpc(&r.ctx));
        let tasks = spawn_with(r.ctx.clone(), Listeners::default(), None)
            .await
            .unwrap();
        assert!(tasks.is_empty());
        // the control plane adds the service to its own server
        let _svc = issuance::issuance_service(&r.ctx).unwrap();
    }

    #[tokio::test]
    async fn the_webhooks_are_served_over_https() {
        let r = rig(&[
            "--components",
            "webhook",
            "--tls-dir",
            "/tls",
            "--injector-image",
            "agentsc/agentscd:dev",
        ]);
        let listener = local().await;
        let addr = listener.local_addr().unwrap();
        let tasks = spawn_with(
            r.ctx.clone(),
            Listeners {
                grpc: None,
                webhook: Some(listener),
            },
            None,
        )
        .await
        .unwrap();

        let client = reqwest::Client::builder()
            .tls_certs_only([reqwest::Certificate::from_pem(r.ca.roots_pem().as_bytes()).unwrap()])
            .resolve("localhost", addr)
            .build()
            .unwrap();
        let review = serde_json::json!({
            "apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview",
            "request": {"uid": "u1", "namespace": "shop", "operation": "CREATE", "userInfo": {},
                        "object": {"metadata": {"labels": {"agentsc.io/inject": "true"}}, "spec": {"containers": []}}}
        });
        let resp: serde_json::Value = client
            .post(format!("https://localhost:{}/mutate", addr.port()))
            .json(&review)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(resp["response"]["uid"], "u1");
        assert_eq!(resp["response"]["allowed"], false);
        assert!(
            resp["response"]["status"]["message"]
                .as_str()
                .unwrap()
                .contains("agentsc.io/service")
        );
        finish(&r.ctx, tasks).await;
    }

    #[tokio::test]
    async fn embassy_ca_writes_the_tls_secret_and_reconciles_ca_bundles() {
        let r = rig(&[
            "--components",
            "ca,webhook",
            "--ca-dir",
            "/ca",
            "--tls-secret",
            "agentsc-system/embassy-tls",
            "--dns-name",
            "localhost",
        ]);
        let cluster = Arc::new(FakeCluster::new());
        cluster.put_webhook_config(
            WebhookKind::Mutating,
            "agentsc-sidecar-injector",
            serde_json::json!({"webhooks": [{"name": "sidecar-injector.agentsc.io", "clientConfig": {}}]}),
        );
        let tasks = spawn_with(
            r.ctx.clone(),
            Listeners {
                grpc: Some(local().await),
                webhook: Some(local().await),
            },
            Some(cluster.clone()),
        )
        .await
        .unwrap();
        assert_eq!(
            tasks.len(),
            4,
            "grpc, webhook, caBundle reconcile, tls secret"
        );
        let mut done = false;
        for _ in 0..300 {
            let secret = cluster.secret("agentsc-system", "embassy-tls");
            let bundle = cluster
                .webhook_config(WebhookKind::Mutating, "agentsc-sidecar-injector")
                .and_then(|c| {
                    c["webhooks"][0]["clientConfig"]["caBundle"]
                        .as_str()
                        .map(str::to_string)
                });
            if secret.is_some() && bundle.is_some() {
                done = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(done, "the Secret and the caBundle were written");
        finish(&r.ctx, tasks).await;
    }

    #[tokio::test]
    async fn missing_material_is_named() {
        let r = rig(&["--components", "webhook", "--tls-dir", "/tls"]);
        let ctx = Arc::new(ServeContext {
            config: r.ctx.config.clone(),
            args: r.ctx.args.clone(),
            store: None,
            ca: None,
            serving: None,
            cp_audit: r.ctx.cp_audit.clone(),
            shutdown: CancellationToken::new(),
        });
        let e = spawn_with(
            ctx,
            Listeners {
                grpc: None,
                webhook: Some(local().await),
            },
            None,
        )
        .await
        .err()
        .unwrap()
        .to_string();
        assert!(e.contains("serving certificate"), "{e}");
    }
}
