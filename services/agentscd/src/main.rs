use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Sidecar logs go to stderr; stdout is reserved for the audit JSONL (CONTRACT.md §6).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let profiler = agentscd::profiling::Profiler::from_env();
    let config = agentscd::Config::parse();
    let sidecar = agentscd::start(config).await?;
    // Kubernetes stops containers with SIGTERM (and agentscd is PID 1, so nothing else handles it).
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    tracing::info!("shutting down");
    sidecar.shutdown().await;
    if let Some(p) = profiler {
        p.finish();
    }
    Ok(())
}
