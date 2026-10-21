//! Kubernetes integration (design §8.4 `kubernetes` store, §13). Stubs for now.
//!
//! TODO(B3b): the `kubernetes` implementation of [`crate::store::Store`] over `Charter` custom
//! resources (list+watch with bookmarks, resync 10 min; version in annotation
//! `attache.io/version`, epoch = `metadata.uid`; history as `ControllerRevision`s, keep 20;
//! memory and proposals in the `status` subresource; `Valid`/`Synced` conditions; kubectl edits
//! audited with `actor: k8s:<field manager>`), the `--ca-secret` loader, and the caBundle
//! reconcile of both webhook configurations every 30 s.
use std::sync::Arc;

use anyhow::bail;

use crate::ca::CaMaterial;
use crate::serve::ServeArgs;
use crate::store::Store;

/// What every Kubernetes entry point reports in this build.
pub const NOT_BUILT: &str = "kubernetes support is not built yet";

/// The `--store kubernetes` store.
pub async fn open_store(args: &ServeArgs) -> anyhow::Result<Arc<dyn Store>> {
    bail!(
        "--store kubernetes (components {}): {NOT_BUILT}; use --store file:<dir>",
        args.components
    )
}

/// The CA material in Secret `<namespace>/<name>` (`--ca-secret`, keys `ca.crt` and `ca.key`).
pub async fn load_ca_secret(namespace: &str, name: &str) -> anyhow::Result<CaMaterial> {
    bail!("--ca-secret {namespace}/{name}: {NOT_BUILT}; use --ca-dir <dir>")
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

    #[tokio::test]
    async fn the_stubs_say_kubernetes_is_not_built() {
        let args = Cli::try_parse_from(["serve", "--store", "kubernetes"])
            .unwrap()
            .serve;
        let e = open_store(&args).await.err().unwrap().to_string();
        assert!(e.contains(NOT_BUILT), "{e}");
        assert!(e.contains("--store kubernetes"), "{e}");

        let e = load_ca_secret("attache-system", "attache-ca")
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains(NOT_BUILT), "{e}");
        assert!(e.contains("attache-system/attache-ca"), "{e}");
    }
}
