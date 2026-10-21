//! Spawn and supervise the agent runtime; talk to it over `runtime.sock` (CONTRACT.md §4.3).
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use agentsc_proto::Empty;
use agentsc_proto::runtime_client::RuntimeClient;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use crate::config::Config;
use crate::state::AppState;

pub fn client(socket: &Path) -> anyhow::Result<RuntimeClient<Channel>> {
    let path = socket.to_path_buf();
    let channel = Endpoint::try_from("http://runtime.agentsc.local")?
        .timeout(crate::deadline::RUN_TIMEOUT)
        .connect_with_connector_lazy(service_fn(move |_: Uri| {
            let path = path.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
        }));
    Ok(RuntimeClient::new(channel))
}

/// Spawns the runtime, restarts it with backoff, and keeps `runtime_ready` current.
pub fn supervise(state: Arc<AppState>, config: Config) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let runtime_sock = config.socket_dir.join("runtime.sock");
        let sidecar_sock = config.socket_dir.join("sidecar.sock");
        let mut backoff = Duration::from_secs(1);
        loop {
            let _ = std::fs::remove_file(&runtime_sock);
            let words = match shell_words::split(&config.runtime_cmd) {
                Ok(w) if !w.is_empty() => w,
                _ => {
                    tracing::error!(cmd = %config.runtime_cmd, "invalid --runtime-cmd");
                    return;
                }
            };
            let mut cmd = tokio::process::Command::new(&words[0]);
            cmd.args(&words[1..])
                .arg("--listen")
                .arg(format!("unix:{}", runtime_sock.display()))
                .arg("--sidecar")
                .arg(format!("unix:{}", sidecar_sock.display()))
                .env("AGENTSC_SERVICE", &state.service)
                .env("AGENTSC_NAMESPACE", &state.namespace)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            tracing::info!(cmd = %config.runtime_cmd, "starting agent runtime");
            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(error = %e, "cannot spawn runtime; retrying in {backoff:?}");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                    continue;
                }
            };
            // Runtime output goes to our stderr with a prefix; stdout stays pure audit JSONL.
            if let Some(out) = child.stdout.take() {
                tokio::spawn(forward(out, "runtime"));
            }
            if let Some(err) = child.stderr.take() {
                tokio::spawn(forward(err, "runtime"));
            }
            let health = tokio::spawn(health_loop(state.clone()));
            let ran_from = std::time::Instant::now();
            let status = child.wait().await;
            health.abort();
            state.runtime_ready.store(false, Ordering::Relaxed);
            // A runtime that stayed up for a while earned a fresh start, not the accumulated backoff.
            if ran_from.elapsed() > Duration::from_secs(60) {
                backoff = Duration::from_secs(1);
            }
            tracing::warn!(?status, "agent runtime exited; restarting in {backoff:?}");
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    })
}

async fn forward<R: tokio::io::AsyncRead + Unpin>(reader: R, prefix: &'static str) {
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        eprintln!("[{prefix}] {line}");
    }
}

pub async fn health_loop(state: Arc<AppState>) {
    let mut backoff_reset = false;
    loop {
        let mut client = state.runtime.clone();
        let ok = match tokio::time::timeout(Duration::from_secs(3), client.health(Empty {})).await {
            Ok(Ok(resp)) => {
                let h = resp.into_inner();
                *crate::state::lock(&state.runtime_provider) = h.model_provider.clone();
                if !backoff_reset {
                    tracing::info!(provider = %h.model_provider, version = %h.version, "agent runtime is ready");
                    backoff_reset = true;
                }
                h.ok
            }
            _ => false,
        };
        state.runtime_ready.store(ok, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_secs(if ok { 10 } else { 1 })).await;
    }
}
