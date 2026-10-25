//! `embassy serve` (design §8.1): the flags, their validation, and the wiring of the components.
//!
//! [`run`] is the entry point: it validates the flags and the `ControlPlaneConfig`, builds the
//! [`ServeContext`], starts the `ca` and `webhook` components through
//! [`crate::ca_components::spawn`], and the `controlplane` (`Connect` on `--grpc-addr`), `api`
//! and `ui` (on `--http-addr`) components here, then runs until a signal or a failing component.
//!
//! - `--config` is reloaded when the file changes (polled every [`CONFIG_POLL`]); a changed file
//!   that does not validate is logged and the running config stays.
//! - `--dev` writes a one-time admin token (`dev-admin`) to a 0600 file (`<store dir>/.dev-admin-token`
//!   with the file store) and honours `auth.anonymous: viewer`.
//! - `--http-tls` serves `--http-addr` with the serving certificate; session cookies are then
//!   `Secure`.
//! - `--http3` (with `--http-tls`) also serves `--http-addr` over HTTP/3: QUIC on the same port
//!   over UDP, advertised with `Alt-Svc` on every TCP response ([`http3`],
//!   docs/adr/0001-http3-for-the-console.md).
//! - `--store sqlite:<path>` keeps everything the file store keeps in one SQLite database
//!   ([`crate::store::sqlite`], docs/adr/0003-sqlite-store-schema.md).
//! - When `ca` and `controlplane` both run they share `--grpc-addr`: `Connect` is served with
//!   optional client certificates there (it still refuses a stream without a verified one), and
//!   [`crate::controlplane::serve`] takes the `IssueCertificate` routes as `extra`.
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use arc_swap::ArcSwap;
use clap::Args;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::ControlPlaneConfig;
use crate::context::ServeContext;
use crate::cp_audit::CpAudit;
use crate::hub::{Hub, HubOptions};
use crate::names::{ObjectRef, is_dns_label, is_dns_subdomain};
use crate::servingcert::{ClientAuth, ServingCertSource};
use crate::store::Store;

#[cfg(feature = "http3")]
pub mod http3;
pub mod tls;

/// How often `--config` is looked at.
pub const CONFIG_POLL: Duration = Duration::from_secs(2);
/// How long running components get to stop.
pub const STOP_GRACE: Duration = Duration::from_secs(10);

/// One component of `embassy serve --components` (design §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Component {
    /// `IssueCertificate` on `--grpc-addr`.
    Ca,
    /// Mutating and validating admission on `--webhook-addr`.
    Webhook,
    /// `Connect` on `--grpc-addr`.
    Controlplane,
    /// REST/SSE on `--http-addr`.
    Api,
    /// Static UI files on `--http-addr`.
    Ui,
}

impl Component {
    pub const ALL: [Component; 5] = [
        Component::Ca,
        Component::Webhook,
        Component::Controlplane,
        Component::Api,
        Component::Ui,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Component::Ca => "ca",
            Component::Webhook => "webhook",
            Component::Controlplane => "controlplane",
            Component::Api => "api",
            Component::Ui => "ui",
        }
    }
}

impl std::fmt::Display for Component {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The parsed `--components` list: a non-empty set (duplicates collapse).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentSet(pub BTreeSet<Component>);

impl ComponentSet {
    pub fn all() -> Self {
        Self(Component::ALL.into_iter().collect())
    }

    pub fn has(&self, c: Component) -> bool {
        self.0.contains(&c)
    }
}

impl std::str::FromStr for ComponentSet {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut set = BTreeSet::new();
        for part in s.split(',') {
            let part = part.trim();
            let c = Component::ALL
                .into_iter()
                .find(|c| c.as_str() == part)
                .ok_or_else(|| {
                    format!(
                        "unknown component {part:?} (expected ca, webhook, controlplane, api, ui)"
                    )
                })?;
            set.insert(c);
        }
        Ok(Self(set))
    }
}

impl std::fmt::Display for ComponentSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<_> = self.0.iter().map(|c| c.as_str()).collect();
        f.write_str(&names.join(","))
    }
}

/// `--store file:<dir> | sqlite:<path> | kubernetes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreSpec {
    File(PathBuf),
    /// One SQLite database file (docs/adr/0003-sqlite-store-schema.md).
    Sqlite(PathBuf),
    Kubernetes,
}

impl StoreSpec {
    /// The stores this process owns outright (no external editor, no API server): the ones
    /// `--auto-adopt` may write to.
    pub fn is_local(&self) -> bool {
        matches!(self, Self::File(_) | Self::Sqlite(_))
    }
}

impl std::str::FromStr for StoreSpec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "kubernetes" {
            return Ok(Self::Kubernetes);
        }
        if let Some(dir) = s.strip_prefix("file:") {
            return if dir.is_empty() {
                Err("file: needs a directory, e.g. file:/var/lib/agentsc".into())
            } else {
                Ok(Self::File(PathBuf::from(dir)))
            };
        }
        if let Some(path) = s.strip_prefix("sqlite:") {
            return if path.is_empty() {
                Err("sqlite: needs a file, e.g. sqlite:/var/lib/agentsc/embassy.db".into())
            } else {
                Ok(Self::Sqlite(PathBuf::from(path)))
            };
        }
        Err(format!(
            "{s:?} is not a store (expected file:<dir>, sqlite:<path> or kubernetes)"
        ))
    }
}

fn parse_dns_name(s: &str) -> Result<String, String> {
    if is_dns_subdomain(s) {
        Ok(s.to_string())
    } else {
        Err(format!("{s:?} is not a DNS name"))
    }
}

/// Every flag of `embassy serve` (design §8.1).
#[derive(Debug, Clone, Args)]
pub struct ServeArgs {
    /// Comma-separated components to run: ca, webhook, controlplane, api, ui.
    #[arg(long, default_value = "ca,webhook,controlplane,api,ui")]
    pub components: ComponentSet,
    /// REST/SSE/UI listener.
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub http_addr: SocketAddr,
    /// ControlPlane and/or CertificateAuthority listener.
    #[arg(long, default_value = "0.0.0.0:15012")]
    pub grpc_addr: SocketAddr,
    /// Admission webhook listener.
    #[arg(long, default_value = "0.0.0.0:9443")]
    pub webhook_addr: SocketAddr,
    /// CA material in a directory (ca.crt may hold several roots; the first key-matching one signs).
    #[arg(long, conflicts_with = "ca_secret")]
    pub ca_dir: Option<PathBuf>,
    /// CA material in a Kubernetes Secret, <namespace>/<name>.
    #[arg(long)]
    pub ca_secret: Option<ObjectRef>,
    /// Where the ca component writes the serving certificate (Kubernetes Secret <namespace>/<name>).
    #[arg(long)]
    pub tls_secret: Option<ObjectRef>,
    /// Where the controlplane component reads the serving certificate (mounted Secret).
    #[arg(long)]
    pub tls_dir: Option<PathBuf>,
    /// file:<dir> or kubernetes.
    #[arg(long)]
    pub store: Option<StoreSpec>,
    /// ControlPlaneConfig file (reloaded on change).
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Serving-certificate DNS SAN and allowed Host header (repeatable).
    #[arg(long = "dns-name", value_parser = parse_dns_name)]
    pub dns_names: Vec<String>,
    /// Serve the HTTP API over TLS with the serving certificate.
    #[arg(long)]
    pub http_tls: bool,
    /// Also serve --http-addr over HTTP/3 (QUIC on the same port, UDP); needs --http-tls.
    #[arg(long)]
    pub http3: bool,
    /// Adopt sidecar start-up charters automatically (file and sqlite stores only).
    #[arg(long)]
    pub auto_adopt: bool,
    /// The MutatingWebhookConfiguration whose caBundle is kept current.
    #[arg(long, default_value = "agentsc-sidecar-injector")]
    pub webhook_config_name: String,
    /// The ValidatingWebhookConfiguration whose caBundle is kept current.
    #[arg(long, default_value = "agentsc-charter-validator")]
    pub validating_webhook_name: String,
    /// Image injected as the agentscd sidecar.
    #[arg(long)]
    pub injector_image: Option<String>,
    /// The control plane's own namespace (never issued certificates, never injected).
    #[arg(long, default_value = "agentsc-system")]
    pub cp_namespace: String,
    /// Serve UI files from this directory instead of the embedded copy (development).
    #[arg(long)]
    pub ui_dir: Option<PathBuf>,
    /// Allow the anonymous viewer and write a one-time admin token to a 0600 file.
    #[arg(long)]
    pub dev: bool,
    /// SPIFFE trust domain of issued identities, of the serving certificate and of the sidecars
    /// Connect accepts (spiffe://<trust domain>/...); injected sidecars get the same.
    #[arg(
        long,
        env = "AGENTSC_TRUST_DOMAIN",
        default_value = agentsc_common::identity::DEFAULT_TRUST_DOMAIN
    )]
    pub trust_domain: String,
    /// Kubernetes cluster DNS domain of the workload certificates' DNS SANs
    /// (<svc>.<ns>.svc.<cluster domain>).
    #[arg(
        long,
        env = "AGENTSC_CLUSTER_DOMAIN",
        default_value = agentsc_common::identity::DEFAULT_CLUSTER_DOMAIN
    )]
    pub cluster_domain: String,
    /// `IssueCertificate` requests per minute, per peer address and per credential (0 = no
    /// limit; ratelimit.rs).
    #[arg(long, env = "AGENTSC_ISSUANCE_RATE_LIMIT", default_value_t = crate::ratelimit::ISSUANCE_DEFAULT.per_minute)]
    pub issuance_rate_limit: u32,
    /// The burst of `--issuance-rate-limit`.
    #[arg(long, env = "AGENTSC_ISSUANCE_BURST", default_value_t = crate::ratelimit::ISSUANCE_DEFAULT.burst)]
    pub issuance_burst: u32,
    /// REST API requests per minute, per client identity (or remote address when anonymous;
    /// 0 = no limit; ratelimit.rs).
    #[arg(long, env = "AGENTSC_API_RATE_LIMIT", default_value_t = crate::ratelimit::API_DEFAULT.per_minute)]
    pub api_rate_limit: u32,
    /// The burst of `--api-rate-limit`.
    #[arg(long, env = "AGENTSC_API_BURST", default_value_t = crate::ratelimit::API_DEFAULT.burst)]
    pub api_burst: u32,
}

impl ServeArgs {
    /// `--issuance-rate-limit` and `--issuance-burst`.
    pub fn issuance_limit(&self) -> crate::ratelimit::RateLimit {
        crate::ratelimit::RateLimit {
            per_minute: self.issuance_rate_limit,
            burst: self.issuance_burst,
        }
    }

    /// `--api-rate-limit` and `--api-burst`.
    pub fn api_limit(&self) -> crate::ratelimit::RateLimit {
        crate::ratelimit::RateLimit {
            per_minute: self.api_rate_limit,
            burst: self.api_burst,
        }
    }

    pub fn has(&self, c: Component) -> bool {
        self.components.has(c)
    }

    /// Flag combinations that cannot work, each named. clap already refused unknown values,
    /// malformed addresses and `--ca-dir` with `--ca-secret`.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        use Component::*;
        let mut errs = Vec::new();
        if self.components.0.is_empty() {
            errs.push("--components is empty".into());
        }
        if !is_dns_label(&self.cp_namespace) {
            errs.push(format!(
                "--cp-namespace {:?} is not a DNS-1123 label",
                self.cp_namespace
            ));
        }
        for (flag, name) in [
            ("--webhook-config-name", &self.webhook_config_name),
            ("--validating-webhook-name", &self.validating_webhook_name),
        ] {
            if !is_dns_subdomain(name) {
                errs.push(format!("{flag} {name:?} is not a DNS-1123 subdomain"));
            }
        }
        if let Err(e) = agentsc_common::identity::check_trust_domain(&self.trust_domain) {
            errs.push(format!("--trust-domain: {e}"));
        }
        if let Err(e) = agentsc_common::identity::check_cluster_domain(&self.cluster_domain) {
            errs.push(format!("--cluster-domain: {e}"));
        }
        for p in [
            self.issuance_limit().problem("--issuance-burst"),
            self.api_limit().problem("--api-burst"),
        ]
        .into_iter()
        .flatten()
        {
            errs.push(p);
        }

        let ca_material = self.ca_dir.is_some() || self.ca_secret.is_some();
        if self.has(Ca) && !ca_material {
            errs.push("the ca component needs --ca-dir or --ca-secret".into());
        }
        if !self.has(Ca) && ca_material {
            errs.push("--ca-dir and --ca-secret are only used by the ca component".into());
        }
        if self.tls_secret.is_some() && !self.has(Ca) {
            errs.push("--tls-secret is written by the ca component, which is not enabled".into());
        }

        // Serving certificate: the ca component makes one (in memory or in --tls-secret);
        // without it, the components that serve TLS read it from --tls-dir.
        let needs_serving_cert = self.has(Controlplane) || self.has(Webhook) || self.http_tls;
        if needs_serving_cert && !self.has(Ca) && self.tls_dir.is_none() {
            let users: Vec<&str> = [
                (self.has(Controlplane), "controlplane"),
                (self.has(Webhook), "webhook"),
                (self.http_tls, "--http-tls"),
            ]
            .into_iter()
            .filter_map(|(on, name)| on.then_some(name))
            .collect();
            errs.push(format!(
                "{} need(s) the serving certificate: run the ca component too or give --tls-dir",
                users.join(", ")
            ));
        }
        if self.http_tls && !(self.has(Api) || self.has(Ui)) {
            errs.push("--http-tls needs the api or ui component".into());
        }
        if self.http3 && !self.http_tls {
            errs.push("--http3 needs --http-tls (QUIC is always TLS)".into());
        }

        if (self.has(Controlplane) || self.has(Api)) && self.store.is_none() {
            errs.push(
                "the controlplane and api components need --store file:<dir>, --store sqlite:<path> or --store kubernetes"
                    .into(),
            );
        }
        if self.has(Ca) && self.store.is_none() {
            // IssueCertificate admits a pod's service account only if it is the service's name
            // or listed in the stored charter's service.service_accounts (design §7).
            errs.push(
                "the ca component needs --store file:<dir>, --store sqlite:<path> or --store kubernetes \
                 (IssueCertificate checks service.service_accounts in the stored charter)"
                    .into(),
            );
        }
        if self.auto_adopt {
            if !self.store.as_ref().is_some_and(StoreSpec::is_local) {
                errs.push(
                    "--auto-adopt works only with --store file:<dir> or --store sqlite:<path>"
                        .into(),
                );
            }
            if !self.has(Controlplane) {
                errs.push("--auto-adopt needs the controlplane component".into());
            }
        }
        if self.ui_dir.is_some() && !self.has(Ui) {
            errs.push("--ui-dir needs the ui component".into());
        }
        if self.dev && !(self.has(Api) || self.has(Ui)) {
            errs.push("--dev needs the api or ui component".into());
        }

        // Enabled listeners must not share an address.
        let mut listeners: Vec<(&str, SocketAddr)> = Vec::new();
        if self.has(Api) || self.has(Ui) {
            listeners.push(("--http-addr", self.http_addr));
        }
        if self.has(Ca) || self.has(Controlplane) {
            listeners.push(("--grpc-addr", self.grpc_addr));
        }
        if self.has(Webhook) {
            listeners.push(("--webhook-addr", self.webhook_addr));
        }
        for (i, (a, x)) in listeners.iter().enumerate() {
            for (b, y) in &listeners[i + 1..] {
                if x == y && x.port() != 0 {
                    errs.push(format!("{a} and {b} are both {x}"));
                }
            }
        }

        if errs.is_empty() { Ok(()) } else { Err(errs) }
    }

    /// The config `--config` names, validated; the built-in default without `--config`.
    pub fn load_config(&self) -> anyhow::Result<ControlPlaneConfig> {
        match &self.config {
            Some(path) => ControlPlaneConfig::load(path, &self.cp_namespace)
                .with_context(|| format!("--config {}", path.display())),
            None => Ok(ControlPlaneConfig::default()),
        }
    }
}

/// Run `embassy serve` until SIGINT/SIGTERM or a component fails.
pub async fn run(args: ServeArgs) -> anyhow::Result<()> {
    if let Err(errs) = args.validate() {
        bail!("embassy serve: invalid flags:\n  {}", errs.join("\n  "));
    }
    let config = args.load_config()?;
    tracing::info!(
        components = %args.components,
        tokens = config.auth.tokens.len(),
        join_tokens = config.issuance.join_tokens.len(),
        "configuration is valid"
    );
    let shutdown = CancellationToken::new();
    tokio::spawn(on_signal(shutdown.clone()));
    start(args, config, shutdown).await?.wait().await
}

async fn on_signal(shutdown: CancellationToken) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "cannot listen for SIGTERM");
                let _ = tokio::signal::ctrl_c().await;
                shutdown.cancel();
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    tracing::info!("shutting down");
    shutdown.cancel();
}

/// What [`start`] started.
pub struct Started {
    pub ctx: Arc<ServeContext>,
    /// The shared state of `controlplane`, `api` and `ui`, when one of them runs.
    pub hub: Option<Arc<Hub>>,
    /// The bound `--http-addr` (`api`/`ui`).
    pub http_addr: Option<SocketAddr>,
    /// The bound HTTP/3 (UDP) address (`--http3`).
    pub http3_addr: Option<SocketAddr>,
    /// The bound `--grpc-addr` of `Connect` (`controlplane`).
    pub grpc_addr: Option<SocketAddr>,
    /// `--dev`: where the one-time admin token is.
    pub dev_token_file: Option<PathBuf>,
    tasks: Vec<JoinHandle<anyhow::Result<()>>>,
    background: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for Started {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Started")
            .field("http_addr", &self.http_addr)
            .field("http3_addr", &self.http3_addr)
            .field("grpc_addr", &self.grpc_addr)
            .finish_non_exhaustive()
    }
}

impl Started {
    /// Run until shutdown or until a component stops; then stop the others (at most
    /// [`STOP_GRACE`]). The first component error is returned.
    pub async fn wait(mut self) -> anyhow::Result<()> {
        let shutdown = self.ctx.shutdown.clone();
        let mut first: Option<anyhow::Error> = None;
        if !self.tasks.is_empty() {
            // the first component to stop (or the shutdown) stops the others
            let done = tokio::select! {
                (r, i, _) = futures::future::select_all(self.tasks.iter_mut()) => Some((r, i)),
                () = shutdown.cancelled() => None,
            };
            if let Some((r, i)) = done {
                self.tasks.remove(i);
                match r {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => first = Some(e),
                    Err(e) => first = Some(anyhow::anyhow!("a component panicked: {e}")),
                }
            }
        } else {
            shutdown.cancelled().await;
        }
        shutdown.cancel();
        let all = futures::future::join_all(self.tasks.iter_mut());
        match tokio::time::timeout(STOP_GRACE, all).await {
            Ok(results) => {
                for r in results {
                    match r {
                        Ok(Err(e)) if first.is_none() => first = Some(e),
                        Err(e) if first.is_none() => {
                            first = Some(anyhow::anyhow!("a component panicked: {e}"))
                        }
                        _ => {}
                    }
                }
            }
            Err(_) => {
                tracing::warn!("components did not stop within {STOP_GRACE:?}; stopping them");
                for t in &self.tasks {
                    t.abort();
                }
            }
        }
        for b in self.background.drain(..) {
            b.abort();
        }
        match first {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Stop everything (tests).
    pub async fn stop(self) -> anyhow::Result<()> {
        self.ctx.shutdown.cancel();
        self.wait().await
    }
}

/// The hub, once it exists: the file store is opened before it, and its external-edit check
/// needs the connected instances.
pub type HubCell = Arc<std::sync::OnceLock<std::sync::Weak<Hub>>>;

/// The external-edit check of the file store: the charter validator, the write policy, and,
/// with instances connected, the version-skew and restart-only checks of every API write
/// (design §8.4, §15 rule 5).
fn file_store_validator(
    config: Arc<ArcSwap<ControlPlaneConfig>>,
    hub: HubCell,
) -> Arc<crate::store::file::ExternalValidator> {
    Arc::new(
        move |key: &crate::store::ServiceKey, yaml: &str, previous: Option<&str>| {
            let json = crate::store::file::default_validator(key, yaml, previous)?;
            let charter =
                agentsc_charter::Charter::from_yaml(yaml).map_err(|e| vec![e.to_string()])?;
            let mut problems =
                crate::api::write::policy_problems(config.load().policy.as_ref(), &charter);
            if let Some(h) = hub.get().and_then(std::sync::Weak::upgrade) {
                problems.extend(crate::api::write::skew_problems(&h.registry, key, &charter));
                problems.extend(crate::api::write::restart_problems_yaml(
                    &h.registry,
                    key,
                    previous,
                    &charter,
                ));
            }
            if problems.is_empty() {
                Ok(json)
            } else {
                Err(problems)
            }
        },
    )
}

async fn open_store(
    args: &ServeArgs,
    config: &Arc<ArcSwap<ControlPlaneConfig>>,
    hub: &HubCell,
) -> anyhow::Result<Option<Arc<dyn Store>>> {
    Ok(match &args.store {
        None => None,
        Some(StoreSpec::File(dir)) => {
            let fs = crate::store::file::FileStore::open(dir.clone())
                .await
                .with_context(|| format!("--store file:{}", dir.display()))?;
            fs.set_validator(file_store_validator(config.clone(), hub.clone()));
            Some(fs)
        }
        Some(StoreSpec::Sqlite(path)) => {
            let db = crate::store::sqlite::SqliteStore::open(path.clone())
                .with_context(|| format!("--store sqlite:{}", path.display()))?;
            Some(db)
        }
        Some(StoreSpec::Kubernetes) => Some(crate::k8s::open_store(args).await?),
    })
}

/// Where `--dev` writes its admin token.
pub fn dev_token_path(args: &ServeArgs) -> PathBuf {
    match &args.store {
        Some(StoreSpec::File(dir)) => dir.join(".dev-admin-token"),
        Some(StoreSpec::Sqlite(path)) => match path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir.join(".dev-admin-token"),
            _ => PathBuf::from(".dev-admin-token"),
        },
        _ => std::env::temp_dir().join("embassy-dev-admin-token"),
    }
}

/// Reload `--config` when the file changes; a file that does not validate is logged and the
/// running config stays. A changed sidecar image allow-list is logged by `images_log`.
async fn reload_config(
    path: PathBuf,
    cp_namespace: String,
    config: Arc<ArcSwap<ControlPlaneConfig>>,
    hub: Option<Arc<Hub>>,
    images_log: Option<crate::sidecar_images::StateLog>,
    every: Duration,
    shutdown: CancellationToken,
) {
    let read = |p: &PathBuf| std::fs::read(p).ok();
    // compared with the running config, so a change made before this task started counts
    let mut seen: Option<Option<Vec<u8>>> = None;
    loop {
        tokio::select! {
            () = tokio::time::sleep(every) => {}
            () = shutdown.cancelled() => return,
        }
        let now = read(&path);
        if seen.as_ref() == Some(&now) {
            continue;
        }
        seen = Some(now);
        match ControlPlaneConfig::load(&path, &cp_namespace) {
            Ok(next) if next == **config.load() => {}
            Ok(next) => {
                if let Some(hub) = &hub
                    && let Err(e) = hub.auth.reload_key(&next)
                {
                    tracing::error!(
                        error = format!("{e:#}"),
                        "the changed --config was not applied"
                    );
                    continue;
                }
                let images_changed = config.load().sidecar_images != next.sidecar_images;
                if let Some(log) = &images_log
                    && images_changed
                {
                    log.log(&next.sidecar_images);
                }
                config.store(Arc::new(next));
                tracing::info!(path = %path.display(), "reloaded the ControlPlaneConfig");
            }
            Err(e) => {
                tracing::error!(path = %path.display(), error = %e, "the changed --config is invalid; the running config stays");
            }
        }
    }
}

/// Start every component of `args` (validated) with `config`; `shutdown` stops them.
pub async fn start(
    args: ServeArgs,
    config: ControlPlaneConfig,
    shutdown: CancellationToken,
) -> anyhow::Result<Started> {
    use Component::*;
    // loudly, when the allow-list is off (crate::sidecar_images)
    let images_log = crate::sidecar_images::StateLog::for_args(&args);
    if let Some(log) = &images_log {
        log.log(&config.sidecar_images);
    }
    let config = Arc::new(ArcSwap::from_pointee(config));
    let hub_cell: HubCell = Arc::default();
    let store = open_store(&args, &config, &hub_cell).await?;
    let ca = if args.has(Ca) {
        let material = match (&args.ca_dir, &args.ca_secret) {
            (Some(dir), _) => crate::ca::CaMaterial::load_dir(dir)?,
            (None, Some(s)) => crate::k8s::load_ca_secret(&s.namespace, &s.name).await?,
            (None, None) => bail!("the ca component needs --ca-dir or --ca-secret"),
        };
        Some(Arc::new(
            material.with_domains(&args.trust_domain, &args.cluster_domain)?,
        ))
    } else {
        None
    };
    let needs_serving =
        args.has(Ca) || args.has(Controlplane) || args.has(Webhook) || args.http_tls;
    let serving = if !needs_serving {
        None
    } else if let Some(ca) = &ca {
        Some(Arc::new(ServingCertSource::in_memory(
            ca.clone(),
            args.dns_names.clone(),
        )?))
    } else if let Some(dir) = &args.tls_dir {
        Some(Arc::new(
            ServingCertSource::from_dir(dir)
                .with_context(|| format!("--tls-dir {}", dir.display()))?,
        ))
    } else {
        bail!("the serving certificate needs the ca component or --tls-dir")
    };
    let cp_audit = Arc::new(CpAudit::new(store.clone()));
    let ctx = Arc::new(ServeContext {
        args: args.clone(),
        config: config.clone(),
        store: store.clone(),
        ca,
        serving: serving.clone(),
        cp_audit: cp_audit.clone(),
        shutdown: shutdown.clone(),
    });
    let mut tasks = crate::ca_components::spawn(ctx.clone()).await?;
    let mut background = Vec::new();

    let mut hub = None;
    let mut dev_token_file = None;
    if args.has(Controlplane) || args.has(Api) || args.has(Ui) {
        let mut auth = crate::auth::Auth::new(config.clone(), args.dev, args.http_tls)?;
        if args.dev {
            let token = crate::token::generate()?;
            let path = dev_token_path(&args);
            crate::auth::write_dev_token(&path, &token)?;
            tracing::warn!(
                path = %path.display(),
                "--dev: wrote a one-time admin token (dev-admin) for this process"
            );
            auth = auth.with_dev_token(&token);
            dev_token_file = Some(path);
        }
        let h = Hub::new(
            store
                .clone()
                .unwrap_or_else(|| Arc::new(crate::hub::NoStore::default())),
            config.clone(),
            cp_audit.clone(),
            auth,
            HubOptions {
                dns_names: args.dns_names.clone(),
                auto_adopt: args.auto_adopt,
                trust_domain: args.trust_domain.clone(),
                api_rate_limit: args.api_limit(),
                ..Default::default()
            },
            shutdown.clone(),
        );
        if store.is_some() {
            h.ready.set("store", true);
        }
        for c in [Ca, Webhook] {
            if args.has(c) {
                h.ready.set(c.as_str(), true);
            }
        }
        background.extend(h.start(shutdown.clone()));
        let _ = hub_cell.set(Arc::downgrade(&h));
        hub = Some(h);
    }

    let mut grpc_addr = None;
    if args.has(Controlplane)
        && let (Some(h), Some(serving)) = (&hub, &serving)
    {
        // sharing --grpc-addr with IssueCertificate: client certificates are optional on the
        // listener, and Connect refuses a stream without a verified one
        let auth = if args.has(Ca) {
            ClientAuth::Optional
        } else {
            ClientAuth::Required
        };
        // one process (`ca` and `controlplane` together, the Compose default): IssueCertificate
        // shares the Connect listener, since `ca_components` binds --grpc-addr only without
        // `controlplane` (see `ca_components::serves_grpc`)
        let extra = if args.has(Ca) {
            Some(tonic::service::Routes::new(
                crate::issuance::issuance_service(&ctx)?,
            ))
        } else {
            None
        };
        let (bound, task) = crate::controlplane::bind_and_serve(
            h.clone(),
            args.grpc_addr,
            serving,
            auth,
            extra,
            shutdown.clone(),
        )
        .await?;
        tracing::info!(addr = %bound, "Connect is listening");
        grpc_addr = Some(bound);
        tasks.push(task);
    }

    let mut http_addr = None;
    #[allow(unused_mut, unused_assignments)]
    let mut http3_addr = None;
    if (args.has(Api) || args.has(Ui))
        && let Some(h) = &hub
    {
        let ui = args.has(Ui).then(|| match &args.ui_dir {
            Some(d) => crate::ui_assets::UiFiles::Dir(d.clone()),
            None => crate::ui_assets::UiFiles::Embedded,
        });
        #[allow(unused_mut)]
        let mut app = crate::api::router(h.clone(), args.has(Api), ui);
        let listener = tokio::net::TcpListener::bind(args.http_addr)
            .await
            .with_context(|| format!("bind --http-addr {}", args.http_addr))?;
        let bound = listener.local_addr()?;
        if args.http3 {
            #[cfg(not(feature = "http3"))]
            bail!("--http3: this embassy was built without the http3 feature");
            #[cfg(feature = "http3")]
            {
                let Some(serving) = &serving else {
                    bail!("--http3 needs the serving certificate");
                };
                // QUIC on the port the TCP listener got (so `--http-addr :0` works too)
                let (bound3, endpoint) =
                    http3::bind(bound, serving.rustls_server_config(ClientAuth::None))?;
                app = app.layer(axum::middleware::from_fn_with_state(
                    http3::alt_svc_value(bound3.port()),
                    http3::alt_svc,
                ));
                let stop = shutdown.clone();
                let app3 = app.clone();
                tasks.push(tokio::spawn(async move {
                    http3::serve(endpoint, app3, stop).await
                }));
                tracing::info!(addr = %bound3, "the API/UI is listening over HTTP/3 (QUIC)");
                http3_addr = Some(bound3);
            }
        }
        let stop = shutdown.clone();
        let task = if args.http_tls {
            let Some(serving) = &serving else {
                bail!("--http-tls needs the serving certificate");
            };
            let tls = tls::TlsListener::new(
                listener,
                serving.rustls_server_config(ClientAuth::None),
                shutdown.clone(),
            )?;
            let svc = app.into_make_service_with_connect_info::<crate::api::ClientAddr>();
            tokio::spawn(async move {
                axum::serve(tls, svc)
                    .with_graceful_shutdown(stop.cancelled_owned())
                    .await
                    .map_err(|e| anyhow::anyhow!("the HTTP server failed: {e}"))
            })
        } else {
            let svc = app.into_make_service_with_connect_info::<crate::api::ClientAddr>();
            tokio::spawn(async move {
                axum::serve(listener, svc)
                    .with_graceful_shutdown(stop.cancelled_owned())
                    .await
                    .map_err(|e| anyhow::anyhow!("the HTTP server failed: {e}"))
            })
        };
        for c in [Api, Ui] {
            if args.has(c) {
                h.ready.set(c.as_str(), true);
            }
        }
        tracing::info!(addr = %bound, tls = args.http_tls, "the API/UI is listening");
        http_addr = Some(bound);
        tasks.push(task);
    }

    if let Some(path) = args.config.clone() {
        background.push(tokio::spawn(reload_config(
            path,
            args.cp_namespace.clone(),
            config.clone(),
            hub.clone(),
            images_log,
            CONFIG_POLL,
            shutdown.clone(),
        )));
    }

    Ok(Started {
        ctx,
        hub,
        http_addr,
        http3_addr,
        grpc_addr,
        dev_token_file,
        tasks,
        background,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        serve: ServeArgs,
    }

    fn parse(args: &[&str]) -> Result<ServeArgs, clap::Error> {
        Cli::try_parse_from(std::iter::once("serve").chain(args.iter().copied())).map(|c| c.serve)
    }

    fn errors(args: &[&str]) -> String {
        parse(args).unwrap().validate().unwrap_err().join("\n")
    }

    #[test]
    fn defaults_follow_the_design() {
        let a = parse(&[]).unwrap();
        assert_eq!(a.components, ComponentSet::all());
        assert_eq!(a.http_addr, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(a.grpc_addr, "0.0.0.0:15012".parse().unwrap());
        assert_eq!(a.webhook_addr, "0.0.0.0:9443".parse().unwrap());
        assert_eq!(a.webhook_config_name, "agentsc-sidecar-injector");
        assert_eq!(a.validating_webhook_name, "agentsc-charter-validator");
        assert_eq!(a.cp_namespace, "agentsc-system");
        assert!(a.store.is_none() && a.config.is_none() && a.dns_names.is_empty());
        assert!(!a.http_tls && !a.auto_adopt && !a.dev);
        // all components need CA material and a store
        let e = a.validate().unwrap_err().join("\n");
        assert!(
            e.contains("the ca component needs --ca-dir or --ca-secret"),
            "{e}"
        );
        assert!(e.contains("need --store"), "{e}");
    }

    #[test]
    fn every_flag_parses() {
        let a = parse(&[
            "--components",
            "api,ui,controlplane,api",
            "--http-addr",
            "[::1]:8081",
            "--grpc-addr",
            "127.0.0.1:15013",
            "--webhook-addr",
            "127.0.0.1:9444",
            "--ca-secret",
            "agentsc-system/agentsc-ca",
            "--tls-secret",
            "agentsc-system/embassy-tls",
            "--tls-dir",
            "/etc/agentsc/tls",
            "--store",
            "file:/var/lib/agentsc",
            "--config",
            "/etc/agentsc/config.yaml",
            "--dns-name",
            "embassy.agentsc-system.svc",
            "--dns-name",
            "localhost",
            "--http-tls",
            "--http3",
            "--auto-adopt",
            "--webhook-config-name",
            "inj",
            "--validating-webhook-name",
            "val",
            "--injector-image",
            "ghcr.io/x/agentscd:0.2.0",
            "--cp-namespace",
            "agentsc-cp",
            "--ui-dir",
            "ui",
            "--dev",
        ])
        .unwrap();
        assert_eq!(
            a.components.0.iter().copied().collect::<Vec<_>>(),
            [Component::Controlplane, Component::Api, Component::Ui]
        );
        assert_eq!(a.components.to_string(), "controlplane,api,ui");
        assert_eq!(a.http_addr, "[::1]:8081".parse().unwrap());
        assert_eq!(a.ca_secret.as_ref().unwrap().name, "agentsc-ca");
        assert_eq!(
            a.tls_secret.as_ref().unwrap().to_string(),
            "agentsc-system/embassy-tls"
        );
        assert_eq!(a.store, Some(StoreSpec::File("/var/lib/agentsc".into())));
        assert_eq!(a.dns_names, ["embassy.agentsc-system.svc", "localhost"]);
        assert_eq!(
            a.injector_image.as_deref(),
            Some("ghcr.io/x/agentscd:0.2.0")
        );
        assert_eq!(a.cp_namespace, "agentsc-cp");
        assert!(a.http_tls && a.http3 && a.auto_adopt && a.dev);
        // CA material and --tls-secret without the ca component
        let e = a.validate().unwrap_err().join("\n");
        assert!(
            e.contains("--ca-dir and --ca-secret are only used by the ca component"),
            "{e}"
        );
        assert!(
            e.contains("--tls-secret is written by the ca component"),
            "{e}"
        );
    }

    #[test]
    fn bad_values_are_refused_by_the_parser() {
        for args in [
            &["--components", "ca,api,gateway"][..],
            &["--components", ""],
            &["--components", "ca,,api"],
            &["--store", "s3://bucket"],
            &["--store", "file:"],
            &["--store", "sqlite:"],
            &["--ca-secret", "agentsc-ca"],
            &["--dns-name", "Bad_Name"],
            &["--http-addr", "localhost"],
            &["--ca-dir", "/ca", "--ca-secret", "ns/agentsc-ca"],
        ] {
            assert!(parse(args).is_err(), "{args:?} should be refused");
        }
        assert_eq!(
            parse(&["--store", "kubernetes"]).unwrap().store,
            Some(StoreSpec::Kubernetes)
        );
        assert_eq!(
            parse(&["--store", "sqlite:/var/lib/agentsc/embassy.db"])
                .unwrap()
                .store,
            Some(StoreSpec::Sqlite("/var/lib/agentsc/embassy.db".into()))
        );
    }

    #[test]
    fn http3_needs_tls_and_the_sqlite_store_is_local() {
        let e = errors(&["--components", "ui", "--http3"]);
        assert!(e.contains("--http3 needs --http-tls"), "{e}");
        // with TLS it is fine
        parse(&[
            "--components",
            "ui",
            "--tls-dir",
            "/tls",
            "--http-tls",
            "--http3",
        ])
        .unwrap()
        .validate()
        .unwrap();
        // --auto-adopt accepts the sqlite store like the file store
        parse(&[
            "--ca-dir",
            "/ca",
            "--store",
            "sqlite:/data/embassy.db",
            "--auto-adopt",
        ])
        .unwrap()
        .validate()
        .unwrap();
        assert!(StoreSpec::Sqlite("/x.db".into()).is_local());
        assert!(StoreSpec::File("/x".into()).is_local());
        assert!(!StoreSpec::Kubernetes.is_local());
        let a = parse(&["--store", "sqlite:/data/embassy.db"]).unwrap();
        assert_eq!(dev_token_path(&a), PathBuf::from("/data/.dev-admin-token"));
    }

    #[test]
    fn one_process_mode_is_valid() {
        // compose (design §14): all components, file store, auto-adopt
        let a = parse(&[
            "--ca-dir",
            "/data/ca",
            "--store",
            "file:/data/store",
            "--auto-adopt",
            "--http-addr",
            "0.0.0.0:8080",
        ])
        .unwrap();
        a.validate().unwrap();
    }

    #[test]
    fn helm_deployments_are_valid() {
        // embassy-ca: ca,webhook (design §2)
        parse(&[
            "--components",
            "ca,webhook",
            "--ca-secret",
            "agentsc-system/agentsc-ca",
            "--tls-secret",
            "agentsc-system/embassy-tls",
            "--store",
            "kubernetes",
            "--injector-image",
            "agentsc/agentscd:0.2.0",
        ])
        .unwrap()
        .validate()
        .unwrap();
        // embassy: controlplane,api,ui reading the mounted serving certificate
        parse(&[
            "--components",
            "controlplane,api,ui",
            "--tls-dir",
            "/etc/agentsc/tls",
            "--store",
            "kubernetes",
            "--http-addr",
            "0.0.0.0:8080",
        ])
        .unwrap()
        .validate()
        .unwrap();
    }

    #[test]
    fn incompatible_flags_are_named() {
        let e = errors(&["--components", "controlplane,api", "--store", "kubernetes"]);
        assert!(
            e.contains("controlplane need(s) the serving certificate"),
            "{e}"
        );

        let e = errors(&["--components", "webhook,ui", "--http-tls"]);
        assert!(
            e.contains("webhook, --http-tls need(s) the serving certificate"),
            "{e}"
        );

        let e = errors(&["--components", "ca", "--ca-dir", "/ca", "--http-tls"]);
        assert!(
            e.contains("--http-tls needs the api or ui component"),
            "{e}"
        );

        let e = errors(&[
            "--components",
            "ca,controlplane",
            "--ca-dir",
            "/ca",
            "--store",
            "kubernetes",
            "--auto-adopt",
        ]);
        assert!(
            e.contains("--auto-adopt works only with --store file:<dir>"),
            "{e}"
        );

        let e = errors(&["--components", "ca", "--ca-dir", "/ca", "--auto-adopt"]);
        assert!(
            e.contains("--auto-adopt needs the controlplane component"),
            "{e}"
        );

        let e = errors(&[
            "--components",
            "api",
            "--store",
            "kubernetes",
            "--ui-dir",
            "ui",
        ]);
        assert!(e.contains("--ui-dir needs the ui component"), "{e}");

        let e = errors(&["--components", "ca", "--ca-dir", "/ca", "--dev"]);
        assert!(e.contains("--dev needs the api or ui component"), "{e}");

        // IssueCertificate reads service.service_accounts from the stored charter
        for components in ["ca", "ca,webhook"] {
            let e = errors(&["--components", components, "--ca-dir", "/ca"]);
            assert!(
                e.contains(
                    "the ca component needs --store file:<dir>, --store sqlite:<path> or --store kubernetes"
                ),
                "{components}: {e}"
            );
            assert!(e.contains("service.service_accounts"), "{e}");
        }
        for store in ["kubernetes", "file:/data/store"] {
            parse(&["--components", "ca", "--ca-dir", "/ca", "--store", store])
                .unwrap()
                .validate()
                .unwrap();
        }
        // the webhook alone needs no store (validator and policy only)
        parse(&["--components", "webhook", "--tls-dir", "/tls"])
            .unwrap()
            .validate()
            .unwrap();

        let e = errors(&[
            "--components",
            "ca,webhook",
            "--ca-dir",
            "/ca",
            "--webhook-addr",
            "0.0.0.0:15012",
        ]);
        assert!(
            e.contains("--grpc-addr and --webhook-addr are both 0.0.0.0:15012"),
            "{e}"
        );

        let e = errors(&["--components", "ui", "--cp-namespace", "Agentsc"]);
        assert!(e.contains("--cp-namespace \"Agentsc\""), "{e}");

        let e = errors(&["--components", "ui", "--webhook-config-name", "a_b"]);
        assert!(e.contains("--webhook-config-name \"a_b\""), "{e}");
    }

    #[tokio::test]
    async fn run_validates_the_flags_and_the_config() {
        let bad = parse(&["--components", "ca"]).unwrap();
        let e = run(bad).await.unwrap_err().to_string();
        assert!(e.contains("invalid flags"), "{e}");

        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.yaml");
        std::fs::write(&cfg, "apiVersion: agentsc.io/v1alpha1\nkind: Charter\n").unwrap();
        let store = format!("file:{}", dir.path().display());
        let a = parse(&[
            "--components",
            "api",
            "--store",
            &store,
            "--config",
            cfg.to_str().unwrap(),
        ])
        .unwrap();
        let e = format!("{:#}", run(a).await.unwrap_err());
        assert!(e.contains("kind must be ControlPlaneConfig"), "{e}");
    }

    #[tokio::test]
    async fn the_api_and_ui_start_and_stop() {
        let dir = tempfile::tempdir().unwrap();
        let store = format!("file:{}", dir.path().join("store").display());
        let a = parse(&[
            "--components",
            "api,ui",
            "--store",
            &store,
            "--http-addr",
            "127.0.0.1:0",
            "--dev",
        ])
        .unwrap();
        a.validate().unwrap();
        let started = start(a, ControlPlaneConfig::default(), CancellationToken::new())
            .await
            .unwrap();
        let addr = started.http_addr.unwrap();
        assert!(started.grpc_addr.is_none());
        let token_file = started.dev_token_file.clone().unwrap();
        assert!(token_file.starts_with(dir.path()));
        let token = std::fs::read_to_string(&token_file).unwrap();
        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/api/v1/whoami"))
            .bearer_auth(token.trim())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["name"], "dev-admin");
        let ready = reqwest::get(format!("http://{addr}/readyz")).await.unwrap();
        assert_eq!(ready.status(), 200);
        started.stop().await.unwrap();
    }

    #[tokio::test]
    async fn the_ui_alone_needs_no_store_and_mounts_no_api() {
        let a = parse(&["--components", "ui", "--http-addr", "127.0.0.1:0"]).unwrap();
        a.validate().unwrap();
        let started = start(a, ControlPlaneConfig::default(), CancellationToken::new())
            .await
            .unwrap();
        let addr = started.http_addr.unwrap();
        let index = reqwest::get(format!("http://{addr}/")).await.unwrap();
        assert_eq!(index.status(), 200);
        assert_eq!(index.headers()["content-type"], "text/html; charset=utf-8");
        let api = reqwest::get(format!("http://{addr}/api/v1/whoami"))
            .await
            .unwrap();
        assert_eq!(api.status(), 404);
        let ready: serde_json::Value = reqwest::get(format!("http://{addr}/readyz"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(ready["components"], serde_json::json!({"ui": true}));
        started.stop().await.unwrap();
    }

    #[tokio::test]
    async fn the_config_is_reloaded_when_it_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        let base = "apiVersion: agentsc.io/v1alpha1\nkind: ControlPlaneConfig\n";
        std::fs::write(&path, base).unwrap();
        let config = Arc::new(ArcSwap::from_pointee(
            ControlPlaneConfig::load(&path, "agentsc-system").unwrap(),
        ));
        let stop = CancellationToken::new();
        let task = tokio::spawn(reload_config(
            path.clone(),
            "agentsc-system".into(),
            config.clone(),
            None,
            None,
            Duration::from_millis(20),
            stop.clone(),
        ));
        std::fs::write(&path, format!("{base}events:\n  retain_bytes: 2097152\n")).unwrap();
        let mut ok = false;
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if config.load().events.retain_bytes == 2_097_152 {
                ok = true;
                break;
            }
        }
        assert!(ok, "the change was not picked up");
        // an invalid file is ignored
        std::fs::write(&path, format!("{base}events:\n  retain_bytes: 1\n")).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(config.load().events.retain_bytes, 2_097_152);
        stop.cancel();
        task.await.unwrap();
    }
}
