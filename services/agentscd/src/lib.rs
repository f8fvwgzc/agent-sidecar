//! `agentscd` — the sidecar. See CONTRACT.md and docs/design/agent-platform.md §6; module names
//! follow their sections.
pub mod app_auth;
pub mod audit;
pub mod config;
pub mod control;
pub mod deadline;
pub mod grpc_app;
pub mod http_api;
pub mod identity;
pub mod learning;
pub mod loaded;
pub mod mesh;
pub mod otel;
pub mod outbox;
pub mod persist;
pub mod pipeline;
pub mod profiling;
pub mod reload;
pub mod runs;
pub mod runtime;
pub mod state;
pub mod tls;
pub mod tools;

use std::sync::Arc;

use anyhow::Context;
use tokio::task::JoinHandle;

pub use config::Config;
pub use state::AppState;

/// Everything a running sidecar consists of. Dropping it does not stop the tasks; abort them.
pub struct Sidecar {
    pub state: Arc<AppState>,
    pub tasks: Vec<JoinHandle<()>>,
    pub http_addr: std::net::SocketAddr,
    pub grpc_addr: std::net::SocketAddr,
    pub mesh_addr: Option<std::net::SocketAddr>,
}

impl Sidecar {
    pub fn abort(&self) {
        for t in &self.tasks {
            t.abort();
        }
    }

    /// Abort every task and wait for them to unwind, so the supervised runtime child is killed
    /// (kill_on_drop) before the process exits; then flush the OpenTelemetry exporter.
    pub async fn shutdown(self) {
        self.abort();
        for t in self.tasks {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), t).await;
        }
        otel::shutdown(&self.state).await;
    }
}

/// Load the charter and TLS material, bind every listener, start the runtime supervisor and, in
/// managed mode, the certificate and control-plane tasks.
pub async fn start(config: Config) -> anyhow::Result<Sidecar> {
    // tonic (ring) and reqwest (aws-lc-rs) both link a rustls provider; pick one process-wide.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (state, startup, file_error) = AppState::build(config.clone()).await?;
    let state = Arc::new(state);
    let mut tasks = Vec::new();

    // Managed mode exports every record from the start, also while the stream is down (subscribed
    // before the start-up charter applies, so the export sees its `config.applied` record).
    if state.managed {
        let rx = state.audit.subscribe();
        let s = state.clone();
        tasks.push(tokio::spawn(outbox::pump_audit(
            state.outbox.clone(),
            rx,
            move || {
                s.loaded()
                    .map(|l| l.charter.telemetry_or_default().control_plane_payloads)
            },
        )));
    }

    // The start-up charter goes through the reload path, so it is audited like any other.
    if let Some(e) = file_error {
        reload::config_record(
            &state,
            "file",
            "charter",
            loaded::Source::File.as_str(),
            "",
            "",
            "",
            &[],
            &agentsc_common::authz::Verdict::deny(reload::RULE_INVALID, e),
        );
    }
    let mut last_file_hash = None;
    if let Some(s) = startup {
        if s.source == loaded::Source::File {
            last_file_hash = Some(agentsc_common::audit::sha256_hex(s.text.as_bytes()));
        }
        let applied = reload::apply_charter(
            &state,
            reload::CharterCandidate {
                text: s.text,
                epoch: s.epoch,
                version: s.version,
                source: s.source,
            },
        );
        if let Err(reason) = applied {
            if !state.managed {
                anyhow::bail!("start-up charter refused: {reason}");
            }
            tracing::warn!(%reason, "start-up charter refused; waiting for the control plane");
        }
    }
    if last_file_hash.is_none()
        && let Ok(text) = std::fs::read_to_string(&config.charter)
    {
        last_file_hash = Some(agentsc_common::audit::sha256_hex(text.as_bytes()));
    }
    tasks.push(tokio::spawn(reload::watch_file(
        state.clone(),
        last_file_hash,
    )));

    // Runtime-facing tools server on a unix socket, then the runtime process itself.
    std::fs::create_dir_all(&config.socket_dir)
        .with_context(|| format!("create {}", config.socket_dir.display()))?;
    let sidecar_sock = config.socket_dir.join("sidecar.sock");
    tasks.push(tools::serve(state.clone(), sidecar_sock.clone()).await?);
    if config.no_runtime {
        // Someone else runs the runtime on runtime.sock; readiness still follows its Health.
        tasks.push(tokio::spawn(runtime::health_loop(state.clone())));
    } else {
        tasks.push(runtime::supervise(state.clone(), config.clone()));
    }

    // App-facing HTTP + gRPC on localhost.
    let (http_addr, http_task) = http_api::serve(state.clone(), config.http_addr).await?;
    tasks.push(http_task);
    let (grpc_addr, grpc_task) = grpc_app::serve(state.clone(), config.grpc_addr).await?;
    tasks.push(grpc_task);

    // Mesh over mTLS: standalone only with an identity from --tls-dir; managed always (the
    // certificate arrives through the resolver once issued).
    let mesh_addr = if state.managed || state.tls().is_some() {
        let (addr, task) = mesh::serve(state.clone(), config.mesh_addr).await?;
        state
            .mesh_port
            .store(addr.port(), std::sync::atomic::Ordering::Relaxed);
        tasks.push(task);
        Some(addr)
    } else {
        tracing::warn!(
            "no TLS material in {}: mesh disabled, remote calls will fail",
            config.tls_dir.display()
        );
        None
    };

    if state.managed {
        tasks.push(tokio::spawn(identity::run(state.clone())));
        tasks.push(tokio::spawn(control::run(state.clone())));
    }

    tracing::info!(
        service = %state.service,
        namespace = %state.namespace,
        identity = %state.self_identity,
        managed = state.managed,
        %http_addr, %grpc_addr, ?mesh_addr,
        agents = state.loaded().map(|l| l.charter.agents.len()).unwrap_or(0),
        "agentscd is up"
    );
    Ok(Sidecar {
        state,
        tasks,
        http_addr,
        grpc_addr,
        mesh_addr,
    })
}
