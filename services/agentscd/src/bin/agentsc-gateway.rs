//! `agentsc-gateway`: the standalone model gateway (docs/LLM-CONNECTION.md). Its upstream is the
//! LLM connection contract v1 of its environment (`LLM_*`); its callers are the tenants of
//! `--tenants-file`. Logs go to stderr; stdout carries only the audit JSON lines.
use std::net::SocketAddr;
use std::path::PathBuf;

use agentscd::gateway::standalone::{self, Gateway, SERVICE, Settings};
use clap::Parser;

/// The standalone model gateway.
#[derive(Debug, Parser)]
#[command(name = "agentsc-gateway", version)]
struct Args {
    /// Where to listen (plain HTTP: bind to loopback, or put TLS in front of it).
    #[arg(long, env = "AGENTSC_GATEWAY_LISTEN", default_value = "127.0.0.1:8090")]
    listen: SocketAddr,
    /// The tenants file (YAML): who may call, with what token, budget and own providers.
    #[arg(long, env = "AGENTSC_GATEWAY_TENANTS_FILE")]
    tenants_file: PathBuf,
    /// Prices of models the built-in table lacks (YAML: `<model>: {input, output,
    /// cache_read}`, USD per 1M tokens). Unlisted models are priced at the top tier.
    #[arg(long, env = "AGENTSC_PRICES_FILE")]
    prices_file: Option<PathBuf>,
    /// Record prompts and answers in the audit records (off: tokens, cost and errors only).
    #[arg(long, env = "AGENTSC_GATEWAY_AUDIT_PAYLOADS")]
    audit_payloads: bool,
    /// The `namespace` of the audit records.
    #[arg(long, env = "AGENTSC_NAMESPACE", default_value = "")]
    namespace: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    let llm = agentsc_common::llm_contract::Contract::from_process_env()
        .map_err(|e| anyhow::anyhow!("the LLM connection contract: {e}"))?;
    for w in &llm.warnings {
        tracing::warn!("{w}");
    }
    match &llm.contract {
        Some(c) => tracing::info!("{}", c.describe()),
        None => tracing::info!(
            "no LLM connection contract (LLM_PROVIDER, LLM_GATEWAY_URL): tenants' own providers only"
        ),
    }
    if let Some(path) = &args.prices_file {
        let n = standalone::load_prices(path)?;
        tracing::info!(models = n, "prices added to the price table");
    }
    let tenants = standalone::load_tenants(&args.tenants_file)?;
    let gw = Gateway::new(Settings {
        tenants,
        contract: llm.contract,
        audit_payloads: args.audit_payloads,
        audit: agentsc_common::audit::AuditWriter::stdout(SERVICE, &args.namespace, vec![]),
    })
    .map_err(|e| anyhow::anyhow!("--tenants-file: {e}"))?;
    let (addr, server) = standalone::serve(gw, args.listen).await?;
    tracing::info!(%addr, "model gateway listening");
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
        _ = server => anyhow::bail!("the model gateway stopped"),
    }
    tracing::info!("shutting down");
    Ok(())
}
