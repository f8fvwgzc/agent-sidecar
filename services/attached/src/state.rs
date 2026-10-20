use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use attache_charter::{AuditSink, Charter};
use attache_common::audit::AuditWriter;
use attache_common::budget::Budgets;
use attache_common::guardrails::CompiledGuardrails;
use attache_pki::TlsMaterial;
use attache_proto::mesh_client::MeshClient;
use attache_proto::runtime_client::RuntimeClient;
use tonic::transport::Channel;

use crate::config::Config;

pub const MAX_DEPTH: u32 = 4;

pub struct AppState {
    pub charter: Charter,
    pub guardrails: CompiledGuardrails,
    pub budgets: Budgets,
    pub audit: AuditWriter,
    pub tls: Option<TlsMaterial>,
    pub self_identity: String,
    pub http: reqwest::Client,
    pub runtime: RuntimeClient<Channel>,
    pub runtime_ready: AtomicBool,
    pub runtime_provider: Mutex<String>,
    mesh_clients: Mutex<HashMap<String, MeshClient<Channel>>>,
}

impl AppState {
    pub async fn load(config: &Config) -> anyhow::Result<Self> {
        let charter = Charter::load(&config.charter)
            .with_context(|| format!("load charter {}", config.charter.display()))?;
        let guardrails = CompiledGuardrails::compile(&charter.guardrails)
            .context("compile guardrail regexes")?;
        let audit = match charter.audit.sink {
            AuditSink::Stdout => AuditWriter::stdout(
                &charter.service.name,
                &charter.service.namespace,
                charter.audit.redact.clone(),
            ),
            AuditSink::File => AuditWriter::file(
                &charter.service.name,
                &charter.service.namespace,
                charter.audit.redact.clone(),
                charter
                    .audit
                    .file
                    .as_deref()
                    .unwrap_or("/var/log/attache/audit.jsonl"),
            )
            .context("open audit file")?,
        }
        .with_pii_redact(charter.guardrails.pii_redact);
        let tls = match TlsMaterial::load(&config.tls_dir) {
            Ok(m) => {
                let expected = charter.spiffe_id();
                if m.identity.uri() != expected {
                    anyhow::bail!(
                        "tls.crt identity {} does not match charter identity {expected}",
                        m.identity.uri()
                    );
                }
                Some(m)
            }
            Err(attache_pki::PkiError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e).context("load TLS material"),
        };
        let runtime = crate::runtime::client(&config.socket_dir.join("runtime.sock"))?;
        Ok(Self {
            self_identity: charter.spiffe_id(),
            charter,
            guardrails,
            budgets: Budgets::new(),
            audit,
            tls,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()?,
            runtime,
            runtime_ready: AtomicBool::new(false),
            runtime_provider: Mutex::new(String::from("unknown")),
            mesh_clients: Mutex::new(HashMap::new()),
        })
    }

    /// Ready = charter loaded (we exist), TLS identity loaded (the mesh is up) and the runtime healthy.
    pub fn is_ready(&self) -> bool {
        self.tls.is_some() && self.runtime_ready.load(Ordering::Relaxed)
    }

    pub fn app_base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.charter.service.app_port)
    }

    /// A (cached, lazily connected) mTLS client for a peer service's sidecar.
    pub fn mesh_client(self: &Arc<Self>, service: &str) -> anyhow::Result<MeshClient<Channel>> {
        if let Some(c) = self.mesh_clients.lock().unwrap().get(service) {
            return Ok(c.clone());
        }
        let tls = self
            .tls
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("mesh disabled: no TLS material loaded"))?;
        let addr = self.charter.peer_address(service);
        let server_name = format!(
            "{service}.{}.svc.cluster.local",
            self.charter.service.namespace
        );
        let channel = crate::tls::client_channel(tls, &addr, &server_name)?;
        let client = MeshClient::new(channel);
        self.mesh_clients
            .lock()
            .unwrap()
            .insert(service.to_string(), client.clone());
        Ok(client)
    }
}
