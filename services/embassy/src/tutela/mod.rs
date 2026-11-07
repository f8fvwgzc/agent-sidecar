//! Tutela in service mode (docs/adr/0005-agents-in-tutelad.md, CONTRACT.md §5.3): embassy is an
//! app of `tutelad` (Tutela ADR-0044) and the registry's agents are principals of the app's tenant.
//!
//! - [`client`]: `tutelad`'s HTTP API as the app: its own token by `client_credentials`, the
//!   agent routes of `tutela.admin.v1`, and token exchange. Every call goes through
//!   `tutela-safenet`, as the OIDC client's do.
//! - [`sync`]: makes `tutelad`'s agents what the registry says, again and again. Registration is
//!   retried until it lands; a quarantine never waits for it.
//! - [`agent_token`]: embassy signs its agents' own access tokens, the actor of a delegated token.
//!
//! The section is optional (`tutela` in the ControlPlaneConfig): without it nothing here runs, and
//! attache works in library mode as before (Tutela INTEGRATION §1, standalone mode).
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use arc_swap::ArcSwapOption;
use serde::Deserialize;
use tokio::sync::Notify;

use crate::config::{ControlPlaneConfig, TutelaConfig};

pub mod agent_token;
pub mod client;
pub mod delegation;
pub mod sync;

/// The app's credentials, as `tutelad bootstrap` writes them (Tutela CONTRACTS.md 7.13.9).
#[derive(Clone, Deserialize)]
pub struct Credentials {
    /// `app_<uuidv7>`.
    pub client_id: String,
    /// `tut_sk_…`. Never logged.
    pub client_secret: String,
    /// `ten_<uuidv7>`: the app's tenant, where its agents are registered.
    pub tenant: String,
    /// `tutelad`'s own issuer (`TUTELA_ISSUER`).
    pub issuer: String,
    /// `<issuer>/oauth2/token`.
    pub token_url: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("client_id", &self.client_id)
            .field("tenant", &self.tenant)
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

impl Credentials {
    /// From a directory with one file per key (a mounted Secret), or from the JSON file
    /// `tutelad bootstrap --secrets-dir` writes.
    pub fn read(path: &Path) -> anyhow::Result<Credentials> {
        let creds: Credentials = if path.is_dir() {
            let key = |name: &str| -> anyhow::Result<String> {
                let text = std::fs::read_to_string(path.join(name))
                    .with_context(|| format!("read {name} in {}", path.display()))?;
                Ok(text.trim().to_string())
            };
            Credentials {
                client_id: key("client_id")?,
                client_secret: key("client_secret")?,
                tenant: key("tenant")?,
                issuer: key("issuer")?,
                token_url: key("token_url")?,
            }
        } else {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("read {}", path.display()))?;
            serde_json::from_str(&text)
                .with_context(|| format!("{} is not the app's credentials", path.display()))?
        };
        anyhow::ensure!(
            creds.client_secret.starts_with("tut_sk_"),
            "the client_secret in {} is not a tut_sk_ key",
            path.display()
        );
        creds
            .tenant
            .parse::<tutela_contracts::tenant::TenantId>()
            .map_err(|e| {
                anyhow::anyhow!(
                    "the tenant in {}: {}",
                    path.display(),
                    agentsc_common::error::chain(&e)
                )
            })?;
        Ok(creds)
    }
}

/// `url` may be `tutelad`'s: `https`, or `http` to loopback with `dev_loopback`; no query or
/// fragment. Safenet checks the address again on every request.
pub fn check_url(url: &str, dev_loopback: bool) -> Result<url::Url, String> {
    let u = url::Url::parse(url).map_err(|e| e.to_string())?;
    let loopback = match u.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d == "localhost",
        None => return Err("no host".into()),
    };
    match u.scheme() {
        "https" => {}
        "http" if dev_loopback && loopback => {}
        "http" => return Err("must be https (http only to loopback with dev_loopback)".into()),
        s => return Err(format!("scheme {s:?} is not https")),
    }
    if u.query().is_some() || u.fragment().is_some() {
        return Err("has a query or a fragment".into());
    }
    Ok(u)
}

/// What the `tutela` section makes: the client, the signer of agent tokens, and the verifier of
/// the person's tokens apps send (`tutela.delegation`).
pub struct Connection {
    pub config: TutelaConfig,
    pub client: client::Client,
    pub signer: Option<agent_token::Signer>,
    pub verifier: Option<Arc<tutela_sdk::Verifier>>,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("tenant", &self.client.credentials().tenant)
            .field(
                "signer",
                &self.signer.as_ref().map(agent_token::Signer::kid),
            )
            .finish_non_exhaustive()
    }
}

impl Connection {
    /// Reads the credentials and the key. Needs the process's rustls provider installed.
    pub fn load(config: &TutelaConfig) -> anyhow::Result<Connection> {
        let creds = Credentials::read(&config.credentials).context("tutela.credentials")?;
        let verifier = delegation::verifier(config, &creds).context("tutela.delegation")?;
        let client = client::Client::new(config, creds).context("tutela")?;
        let signer = config
            .agent_tokens
            .as_ref()
            .map(agent_token::Signer::load)
            .transpose()
            .context("tutela.agent_tokens")?;
        Ok(Connection {
            config: config.clone(),
            client,
            signer,
            verifier,
        })
    }
}

/// The hub's handle on Tutela: the connection the config makes (none without a `tutela`
/// section), and the bell that starts a sync at once.
#[derive(Debug, Default)]
pub struct Tutela {
    current: ArcSwapOption<Connection>,
    nudge: Notify,
}

impl Tutela {
    /// Apply `config`'s `tutela` section: at start and on every config reload, before the config
    /// is installed. A section that cannot be loaded leaves the running connection.
    pub fn reload(&self, config: &ControlPlaneConfig) -> anyhow::Result<()> {
        let next = match &config.tutela {
            Some(t) => {
                if self.current.load().as_ref().is_some_and(|c| &c.config == t) {
                    return Ok(());
                }
                Some(Arc::new(Connection::load(t)?))
            }
            None => None,
        };
        if let Some(c) = &next {
            tracing::info!(
                tenant = %c.client.credentials().tenant,
                client_id = %c.client.credentials().client_id,
                agent_tokens = c.signer.as_ref().map(|s| s.kid().to_string()),
                "tutela: agents are principals of tutelad"
            );
        }
        self.current.store(next);
        self.nudge();
        Ok(())
    }

    /// The connection, when the config has a `tutela` section.
    pub fn connection(&self) -> Option<Arc<Connection>> {
        self.current.load_full()
    }

    /// Sync with `tutelad` now (a registry change, a quarantine).
    pub fn nudge(&self) {
        self.nudge.notify_one();
    }

    /// Wait for [`Tutela::nudge`].
    pub async fn nudged(&self) {
        self.nudge.notified().await;
    }
}

/// Why embassy signs no agent token.
#[derive(Debug, thiserror::Error)]
pub enum TokenRefusal {
    #[error("this embassy signs no agent tokens (no tutela.agent_tokens)")]
    NotConfigured,
    #[error("no such agent")]
    NotFound,
    #[error("the agent is retired")]
    Retired,
    #[error("the agent is quarantined")]
    Quarantined,
    #[error("the agent is not registered in tutelad yet")]
    NotRegistered,
    #[error("the agent is disabled in tutelad")]
    Disabled,
    #[error("the registry store failed: {0}")]
    Store(crate::store::StoreError),
    #[error("signing the agent token failed: {0}")]
    Sign(String),
}

/// An agent token for registry agent `id` (`agt_<uuidv7>`): signed only while the agent is
/// active and not quarantined, and registered and enabled in `tutelad` as embassy last heard.
/// It carries the epoch `tutelad` last answered.
pub async fn agent_token(hub: &crate::hub::Hub, id: &str) -> Result<String, TokenRefusal> {
    let conn = hub.tutela.connection().ok_or(TokenRefusal::NotConfigured)?;
    let signer = conn.signer.as_ref().ok_or(TokenRefusal::NotConfigured)?;
    let secops = hub.secops().ok_or(TokenRefusal::NotConfigured)?;
    let a = match secops.get_agent(id).await {
        Ok(a) => a,
        Err(crate::store::StoreError::NotFound) => return Err(TokenRefusal::NotFound),
        Err(e) => return Err(TokenRefusal::Store(e)),
    };
    if a.status != crate::secops::AgentStatus::Active {
        return Err(TokenRefusal::Retired);
    }
    if a.quarantine.is_some() {
        return Err(TokenRefusal::Quarantined);
    }
    let t = a.tutela.ok_or(TokenRefusal::NotRegistered)?;
    if t.disabled {
        return Err(TokenRefusal::Disabled);
    }
    let creds = conn.client.credentials();
    signer
        .sign(
            &agent_token::AgentClaims {
                agent: &t.principal,
                tenant: &creds.tenant,
                audience: conn.client.audience(),
                azp: &creds.client_id,
                epoch: t.epoch,
            },
            u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0),
        )
        .map_err(|e| TokenRefusal::Sign(format!("{e:#}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_url_is_https_or_loopback_in_dev() {
        assert!(check_url("https://tutelad.internal:8080", false).is_ok());
        assert!(check_url("http://127.0.0.1:8080", true).is_ok());
        assert!(check_url("http://localhost:8080", true).is_ok());
        assert!(check_url("http://127.0.0.1:8080", false).is_err());
        assert!(check_url("http://tutelad.internal", true).is_err());
        assert!(check_url("ftp://tutelad.internal", false).is_err());
        assert!(check_url("https://tutelad.internal/?a=b", false).is_err());
    }

    #[test]
    fn credentials_come_from_a_secret_directory_or_its_json_file() {
        let dir = tempfile::tempdir().unwrap();
        let values = [
            ("client_id", "app_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c"),
            ("client_secret", "tut_sk_abc_def"),
            ("tenant", "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c"),
            ("issuer", "https://tutela.example.test"),
            ("token_url", "https://tutela.example.test/oauth2/token"),
        ];
        let secret = dir.path().join("secret");
        std::fs::create_dir(&secret).unwrap();
        for (k, v) in values {
            std::fs::write(secret.join(k), format!("{v}\n")).unwrap();
        }
        let c = Credentials::read(&secret).unwrap();
        assert_eq!(c.client_secret, "tut_sk_abc_def");
        assert!(!format!("{c:?}").contains("tut_sk_"), "{c:?}");
        let json = dir.path().join("attache.json");
        let obj: serde_json::Map<String, serde_json::Value> = values
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect();
        std::fs::write(&json, serde_json::to_string(&obj).unwrap()).unwrap();
        assert_eq!(Credentials::read(&json).unwrap().tenant, values[2].1);
        std::fs::write(secret.join("tenant"), "acme").unwrap();
        let e = Credentials::read(&secret).unwrap_err();
        assert!(format!("{e:#}").contains("the tenant in"), "{e:#}");
    }
}
