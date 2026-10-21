//! What every component of `embassy serve` shares (docs/design/agent-platform.md §2, §8).
//!
//! [`crate::serve::run`] builds one [`ServeContext`] after validating the flags and hands an
//! `Arc` of it to each component it starts (the control plane, the API and UI, and
//! [`crate::ca_components::spawn`]).
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio_util::sync::CancellationToken;

use crate::ca::CaMaterial;
use crate::config::ControlPlaneConfig;
use crate::cp_audit::CpAudit;
use crate::serve::ServeArgs;
use crate::servingcert::ServingCertSource;
use crate::store::Store;

/// The shared state of one `embassy serve` process.
pub struct ServeContext {
    /// The validated flags.
    pub args: ServeArgs,
    /// The current `ControlPlaneConfig`; replaced as a whole when `--config` changes, so every
    /// request reads one consistent snapshot (`config.load()`).
    pub config: Arc<ArcSwap<ControlPlaneConfig>>,
    /// `--store`: `None` only for processes that need none (the webhook alone).
    pub store: Option<Arc<dyn Store>>,
    /// `--ca-dir` / `--ca-secret`: present when the `ca` component runs.
    pub ca: Option<Arc<CaMaterial>>,
    /// The serving certificate (in memory from the CA, or from `--tls-dir`): present when a
    /// component serves TLS (`ca`, `webhook`, `controlplane`, `--http-tls`).
    pub serving: Option<Arc<ServingCertSource>>,
    /// The control-plane audit log (design §8.5).
    pub cp_audit: Arc<CpAudit>,
    /// Cancelled on shutdown (a signal, or a component that failed); components stop serving
    /// and return.
    pub shutdown: CancellationToken,
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

    #[test]
    fn the_context_is_shareable_across_tasks() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<ServeContext>();
        assert_send_sync::<Arc<ServeContext>>();
    }

    #[tokio::test]
    async fn a_one_process_context_holds_everything() {
        let dir = tempfile::tempdir().unwrap();
        let store = format!("file:{}", dir.path().display());
        let args = Cli::try_parse_from([
            "serve",
            "--ca-dir",
            "/ca",
            "--store",
            store.as_str(),
            "--dns-name",
            "localhost",
        ])
        .unwrap()
        .serve;
        args.validate().unwrap();
        let ca = agentsc_pki::ca_init().unwrap();
        let ca = Arc::new(CaMaterial::from_pems(&ca.cert_pem, &ca.key_pem).unwrap());
        let serving = ServingCertSource::in_memory(ca.clone(), args.dns_names.clone()).unwrap();
        let ctx = Arc::new(ServeContext {
            config: Arc::new(ArcSwap::from_pointee(args.load_config().unwrap())),
            args,
            store: None,
            ca: Some(ca),
            serving: Some(Arc::new(serving)),
            cp_audit: Arc::new(CpAudit::new(None)),
            shutdown: CancellationToken::new(),
        });

        // a config reload is visible to every holder of the context
        let mut next = ControlPlaneConfig::clone(&ctx.config.load());
        next.events.retain_bytes *= 2;
        ctx.config.store(Arc::new(next));
        assert_eq!(
            ctx.config.load().events.retain_bytes,
            2 * crate::config::DEFAULT_RETAIN_BYTES
        );

        // the serving certificate comes from the context's CA
        let serving = ctx.serving.as_ref().unwrap().current();
        assert_eq!(serving.ca_pem, ctx.ca.as_ref().unwrap().roots_pem());

        // shutdown reaches every clone of the token
        let token = ctx.shutdown.clone();
        ctx.shutdown.cancel();
        assert!(token.is_cancelled());
    }
}
