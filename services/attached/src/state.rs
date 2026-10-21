use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use anyhow::Context;
use arc_swap::ArcSwapOption;
use attache_charter::Charter;
use attache_common::budget::Budgets;
use attache_pki::TlsMaterial;
use attache_proto::mesh_client::MeshClient;
use attache_proto::runtime_client::RuntimeClient;
use rustls::RootCertStore;
use rustls_pki_types::ServerName;
use tonic::transport::Channel;

use crate::audit::{Audit, SinkTarget};
use crate::config::Config;
use crate::deadline::{HTTP_TIMEOUT, RUN_TIMEOUT};
use crate::loaded::{Loaded, Memory};
use crate::outbox::Outbox;
use crate::persist::StateDir;
use crate::runs::Runs;
use crate::tls::{CurrentCert, TlsCell, WorkloadTls};

pub const MAX_DEPTH: u32 = 4;

/// The charter the sidecar starts with, before any reload (design §6.1, §6.3.5).
pub struct StartupCharter {
    pub charter: Charter,
    pub text: String,
    pub epoch: String,
    pub version: String,
    pub source: crate::loaded::Source,
}

pub struct AppState {
    pub config: Config,
    /// Managed mode: `--control-plane` is set.
    pub managed: bool,
    /// This workload's identity: `--service` / `--namespace` in managed mode, else the charter's.
    pub service: String,
    pub namespace: String,
    pub self_identity: String,
    pub pod: String,
    loaded: ArcSwapOption<Loaded>,
    /// Serializes reloads (file, control plane, local learning), so none is lost.
    pub(crate) apply_lock: Mutex<()>,
    /// Memory that arrived (or was persisted) before any charter was loaded.
    pub(crate) pending_memory: Mutex<Option<Memory>>,
    /// The text of the last charter loaded from the `--charter` file (`Hello.charter_yaml`).
    pub(crate) file_yaml: Mutex<Option<String>>,
    pub tls: TlsCell,
    /// `not_after` (Unix seconds) of the last workload certificate installed, kept when an
    /// expired one is dropped, so `cert_expires_in_s` turns negative instead of vanishing;
    /// `i64::MIN` before any.
    pub(crate) cert_not_after: AtomicI64,
    /// Bumped whenever a new workload certificate is installed.
    pub tls_generation: tokio::sync::watch::Sender<u64>,
    /// Trust roots for the control plane and its CA (managed mode).
    pub trust_roots: Option<Arc<RootCertStore>>,
    pub trust_pem: Option<String>,
    pub budgets: Budgets,
    pub audit: Audit,
    /// Toward this pod's app on loopback: no proxy, no redirects.
    pub http: reqwest::Client,
    /// Http tools: no redirects (the charter pins the origin), the environment's proxy if any.
    pub egress: reqwest::Client,
    pub runtime: RuntimeClient<Channel>,
    pub runtime_ready: AtomicBool,
    pub runtime_provider: Mutex<String>,
    mesh_clients: Mutex<HashMap<String, MeshClient<Channel>>>,
    pub runs: Runs,
    pub outbox: Arc<Outbox>,
    /// Accepted lesson proposals per agent in the last hour (`max_proposals_per_hour`).
    pub lessons: Mutex<HashMap<String, VecDeque<Instant>>>,
    pub otel: Mutex<Option<crate::otel::RunningExporter>>,
    /// SHA-256 of the app API token (design §6.6).
    pub app_token: Option<[u8; 32]>,
    pub state_dir: StateDir,
    /// The bound mesh port (`Hello.mesh_port`).
    pub mesh_port: AtomicU16,
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Read and validate a charter file; `Ok(None)` when it does not exist.
fn read_charter(path: &std::path::Path) -> anyhow::Result<Option<(Charter, String)>> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let charter = Charter::from_yaml(&text)
                .with_context(|| format!("load charter {}", path.display()))?;
            Ok(Some((charter, text)))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read charter {}", path.display())),
    }
}

impl AppState {
    /// Everything but the listeners and tasks. Returns the start-up charter to apply (through
    /// the reload path, so it is audited like every other) and the charter-file error, if any.
    pub async fn build(
        config: Config,
    ) -> anyhow::Result<(Self, Option<StartupCharter>, Option<String>)> {
        let managed = config.managed();
        let state_dir = StateDir::new(config.state_dir());
        let mut file_error = None;

        // The start-up charter. Standalone: the `--charter` file, required. Managed: what the
        // control plane sent last (persisted), else the `--charter` file if there is one; the
        // first control-plane charter then takes its place, restart-only fields included
        // (`reload::apply_charter`), so it serves only while the control plane is unreachable.
        let file = if managed {
            match read_charter(&config.charter) {
                Ok(f) => f,
                Err(e) => {
                    tracing::warn!(error = %format!("{e:#}"), "start-up charter refused");
                    file_error = Some(format!("{e:#}"));
                    None
                }
            }
        } else {
            Some(read_charter(&config.charter)?.ok_or_else(|| {
                anyhow::anyhow!("charter {} does not exist", config.charter.display())
            })?)
        };
        let persisted = if managed {
            state_dir.load_charter().and_then(|(text, meta)| {
                match Charter::from_yaml(&text) {
                    Ok(c) => Some(StartupCharter {
                        charter: c,
                        text,
                        epoch: meta.epoch,
                        version: meta.version,
                        source: crate::loaded::Source::State,
                    }),
                    Err(e) => {
                        tracing::warn!(error = %e, "persisted charter in the state dir is invalid; ignored");
                        None
                    }
                }
            })
        } else {
            None
        };
        // `Hello.charter_yaml` carries the file's text only when the file is this workload's.
        let file_text = file.as_ref().and_then(|(c, t)| {
            let svc = config.service_flag().unwrap_or(&c.service.name);
            let ns = config.namespace_flag().unwrap_or(&c.service.namespace);
            (c.service.name == svc && c.service.namespace == ns).then(|| t.clone())
        });
        let startup = persisted.or(file.map(|(charter, text)| StartupCharter {
            charter,
            text,
            epoch: String::new(),
            version: String::new(),
            source: crate::loaded::Source::File,
        }));

        // Identity: authoritative flags in managed mode, else the charter's service.
        let (service, namespace) = match (
            managed,
            config.service_flag(),
            config.namespace_flag(),
            &startup,
        ) {
            (true, Some(s), Some(n), _) => (s.to_string(), n.to_string()),
            (_, _, _, Some(s)) => (
                config
                    .service_flag()
                    .filter(|_| managed)
                    .unwrap_or(&s.charter.service.name)
                    .to_string(),
                config
                    .namespace_flag()
                    .filter(|_| managed)
                    .unwrap_or(&s.charter.service.namespace)
                    .to_string(),
            ),
            _ => anyhow::bail!(
                "managed mode needs --service and --namespace (or a start-up --charter)"
            ),
        };
        for (what, v) in [("service", &service), ("namespace", &namespace)] {
            anyhow::ensure!(
                attache_charter::is_dns_label(v),
                "{what} {v:?} is not a DNS-1123 label"
            );
        }
        let self_identity = attache_charter::spiffe_id(&namespace, &service);

        let (redact, pii, target) = match &startup {
            Some(s) => (
                s.charter.audit.redact.clone(),
                s.charter.guardrails.pii_redact,
                SinkTarget::of(&s.charter.audit),
            ),
            None => (Vec::new(), false, SinkTarget::Stdout),
        };
        let audit =
            Audit::new(&service, &namespace, redact, pii, target).context("open audit sink")?;

        // TLS: standalone loads `--tls-dir` (v0.1); managed finds or obtains a certificate.
        let (tls, trust_pem) = if managed {
            let trust_pem = match config.trust_roots_pem()? {
                Some(p) => Some(p),
                None => state_dir.ca_pem(),
            };
            let tls = crate::identity::initial(&config, &service, &namespace, &state_dir);
            (tls, trust_pem)
        } else {
            let tls = match TlsMaterial::load(&config.tls_dir) {
                Ok(m) => {
                    if m.identity.uri() != self_identity {
                        anyhow::bail!(
                            "tls.crt identity {} does not match charter identity {self_identity}",
                            m.identity.uri()
                        );
                    }
                    Some(WorkloadTls::from_material(m).context("load TLS material")?)
                }
                Err(attache_pki::PkiError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                    None
                }
                Err(e) => return Err(e).context("load TLS material"),
            };
            (tls, None)
        };
        let trust_roots = match &trust_pem {
            Some(pem) => Some(Arc::new(
                crate::tls::roots_from_pem(pem).context("control-plane trust roots")?,
            )),
            None if managed => anyhow::bail!(
                "managed mode needs trust roots: --ca-file, ATTACHE_CA_PEM or {}/ca.crt",
                config.tls_dir.display()
            ),
            None => None,
        };

        let app_token = config.app_token()?.map(|t| crate::app_auth::digest(&t));
        let runtime = crate::runtime::client(&config.socket_dir.join("runtime.sock"))?;
        let pending_memory = state_dir.load_memory();
        let cert_not_after = AtomicI64::new(tls.as_ref().map_or(i64::MIN, |t| t.not_after));
        let state = Self {
            managed,
            pod: config.pod(),
            service,
            namespace,
            self_identity,
            loaded: ArcSwapOption::empty(),
            apply_lock: Mutex::new(()),
            pending_memory: Mutex::new(pending_memory),
            file_yaml: Mutex::new(file_text),
            tls: Arc::new(ArcSwapOption::from(tls.map(Arc::new))),
            cert_not_after,
            tls_generation: tokio::sync::watch::channel(0).0,
            trust_roots,
            trust_pem,
            budgets: Budgets::new(),
            audit,
            // A followed redirect would reach what authz and the origin check never saw (another
            // host, the metadata IP, this sidecar's own API); a 3xx goes back to the caller as is.
            http: reqwest::Client::builder()
                .timeout(HTTP_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()?,
            egress: reqwest::Client::builder()
                .timeout(HTTP_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            runtime,
            runtime_ready: AtomicBool::new(false),
            runtime_provider: Mutex::new(String::from("unknown")),
            mesh_clients: Mutex::new(HashMap::new()),
            runs: Runs::new(config.timing.run_window),
            outbox: Arc::new(Outbox::new(managed)),
            lessons: Mutex::new(HashMap::new()),
            otel: Mutex::new(None),
            app_token,
            state_dir,
            mesh_port: AtomicU16::new(0),
            config,
        };
        Ok((state, startup, file_error))
    }

    /// The charter, guardrails and memory in force (one snapshot per request).
    pub fn loaded(&self) -> Option<Arc<Loaded>> {
        self.loaded.load_full()
    }

    pub(crate) fn store_loaded(&self, l: Arc<Loaded>) {
        self.loaded.store(Some(l));
    }

    /// The workload certificate in force.
    pub fn tls(&self) -> Option<Arc<WorkloadTls>> {
        self.tls.load_full()
    }

    /// Ready = a charter is loaded, an unexpired TLS identity is loaded and the runtime is
    /// healthy. In managed mode it never depends on the control-plane connection (design
    /// §6.3.4); an expired certificate is no certificate.
    pub fn is_ready(&self) -> bool {
        self.loaded.load().is_some()
            && self.tls.load().as_ref().is_some_and(|t| !t.expired())
            && self.runtime_ready.load(Ordering::Relaxed)
    }

    /// The app's port: `--app-port` in managed mode (authoritative), else the charter's.
    pub fn app_port(&self, l: &Loaded) -> u16 {
        match (self.managed, self.config.app_port) {
            (true, Some(p)) => p,
            _ => l.charter.service.app_port,
        }
    }

    pub fn app_base_url(&self, l: &Loaded) -> String {
        format!("http://127.0.0.1:{}", self.app_port(l))
    }

    /// A peer's mesh address: `mesh.peers`, else `--peer-address-template`.
    pub fn peer_address(&self, charter: &Charter, service: &str) -> String {
        charter.mesh.peers.get(service).cloned().unwrap_or_else(|| {
            self.config
                .peer_address_template
                .replace("{service}", service)
                .replace("{namespace}", &self.namespace)
                .replace("{port}", &charter.mesh.port.to_string())
        })
    }

    /// Forget every cached peer channel (after `mesh.peers` changed or a renewal).
    pub fn clear_mesh_clients(&self) {
        lock(&self.mesh_clients).clear();
    }

    pub fn mesh_clients_cached(&self) -> usize {
        lock(&self.mesh_clients).len()
    }

    /// A (cached, lazily connected) mTLS client for a peer service's sidecar.
    pub fn mesh_client(&self, l: &Loaded, service: &str) -> anyhow::Result<MeshClient<Channel>> {
        if let Some(c) = lock(&self.mesh_clients).get(service) {
            return Ok(c.clone());
        }
        let tls = self
            .tls()
            .ok_or_else(|| anyhow::anyhow!("mesh disabled: no TLS material loaded"))?;
        let addr = self.peer_address(&l.charter, service);
        let server_name = format!("{service}.{}.svc.cluster.local", self.namespace);
        let cfg = crate::tls::mesh_client_config(
            tls.roots.clone(),
            Arc::new(CurrentCert(self.tls.clone())),
        )?;
        let channel = crate::tls::tls_channel(
            &addr,
            ServerName::try_from(server_name)?,
            cfg,
            // A backstop only: every mesh call carries the caller's own deadline (grpc-timeout),
            // which is never longer than what the callee lets its runtime run.
            Some(RUN_TIMEOUT),
        )?;
        let client = MeshClient::new(channel);
        lock(&self.mesh_clients).insert(service.to_string(), client.clone());
        Ok(client)
    }

    /// The memory version in force (`Hello.memory_version`).
    pub fn memory_version(&self) -> String {
        match self.loaded() {
            Some(l) => l.memory.version.clone(),
            None => lock(&self.pending_memory)
                .as_ref()
                .map(|m| m.version.clone())
                .unwrap_or_default(),
        }
    }

    /// Seconds until the workload certificate expires: negative once it has (also after the
    /// expired certificate was dropped); `None` before the first one.
    pub fn cert_expires_in_s(&self) -> Option<i64> {
        if let Some(t) = self.tls.load().as_ref() {
            return Some(t.expires_in_s());
        }
        match self.cert_not_after.load(Ordering::Relaxed) {
            i64::MIN => None,
            not_after => Some(not_after - crate::tls::now_unix()),
        }
    }
}
