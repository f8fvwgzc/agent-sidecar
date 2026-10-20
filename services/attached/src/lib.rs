//! `attached` — the sidecar. See CONTRACT.md; module names follow its sections.
pub mod config;
pub mod grpc_app;
pub mod http_api;
pub mod mesh;
pub mod pipeline;
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
}

/// Load the charter and TLS material, bind every listener, start the runtime supervisor.
pub async fn start(config: Config) -> anyhow::Result<Sidecar> {
    // tonic (ring) and reqwest (aws-lc-rs) both link a rustls provider; pick one process-wide.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let state = Arc::new(AppState::load(&config).await?);
    let mut tasks = Vec::new();

    // Runtime-facing tools server on a unix socket, then the runtime process itself.
    std::fs::create_dir_all(&config.socket_dir)
        .with_context(|| format!("create {}", config.socket_dir.display()))?;
    let sidecar_sock = config.socket_dir.join("sidecar.sock");
    tasks.push(tools::serve(state.clone(), sidecar_sock.clone()).await?);
    if !config.no_runtime {
        tasks.push(runtime::supervise(state.clone(), config.clone()));
    }

    // App-facing HTTP + gRPC on localhost.
    let (http_addr, http_task) = http_api::serve(state.clone(), config.http_addr).await?;
    tasks.push(http_task);
    let (grpc_addr, grpc_task) = grpc_app::serve(state.clone(), config.grpc_addr).await?;
    tasks.push(grpc_task);

    // Mesh over mTLS, only when we have an identity.
    let mesh_addr = if state.tls.is_some() {
        let (addr, task) = mesh::serve(state.clone(), config.mesh_addr).await?;
        tasks.push(task);
        Some(addr)
    } else {
        tracing::warn!(
            "no TLS material in {}: mesh disabled, remote calls will fail",
            config.tls_dir.display()
        );
        None
    };

    tracing::info!(
        service = %state.charter.service.name,
        namespace = %state.charter.service.namespace,
        identity = %state.self_identity,
        %http_addr, %grpc_addr, ?mesh_addr,
        agents = state.charter.agents.len(),
        "attached is up"
    );
    Ok(Sidecar {
        state,
        tasks,
        http_addr,
        grpc_addr,
        mesh_addr,
    })
}
