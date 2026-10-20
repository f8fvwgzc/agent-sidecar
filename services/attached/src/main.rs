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
    let config = attached::Config::parse();
    let sidecar = attached::start(config).await?;
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    sidecar.abort();
    Ok(())
}
