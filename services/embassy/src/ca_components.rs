//! The `ca` and `webhook` components of `embassy serve` (docs/design/agent-platform.md §2, §7,
//! §13): `CertificateAuthority.IssueCertificate` on `--grpc-addr`, the admission webhooks on
//! `--webhook-addr`, the `--tls-secret` writer and the webhook `caBundle` reconcile.
//!
//! TODO(B3b): start them here. Nothing runs in this build: [`spawn`] returns no tasks.
use std::sync::Arc;

use tokio::task::JoinHandle;

use crate::context::ServeContext;

/// Start the components of `ctx.args.components` that this module owns; each task runs until
/// `ctx.shutdown` is cancelled and returns its error if it fails.
pub async fn spawn(ctx: Arc<ServeContext>) -> anyhow::Result<Vec<JoinHandle<anyhow::Result<()>>>> {
    tracing::debug!(
        components = %ctx.args.components,
        "the ca and webhook components are not built yet; nothing to start"
    );
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cp_audit::CpAudit;
    use arc_swap::ArcSwap;
    use clap::Parser;
    use tokio_util::sync::CancellationToken;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        serve: crate::serve::ServeArgs,
    }

    #[tokio::test]
    async fn nothing_is_started_yet() {
        let args = Cli::try_parse_from(["serve", "--components", "webhook", "--tls-dir", "/tls"])
            .unwrap()
            .serve;
        let ctx = Arc::new(ServeContext {
            config: Arc::new(ArcSwap::from_pointee(args.load_config().unwrap())),
            args,
            store: None,
            ca: None,
            serving: None,
            cp_audit: Arc::new(CpAudit::new(None)),
            shutdown: CancellationToken::new(),
        });
        assert!(spawn(ctx).await.unwrap().is_empty());
    }
}
