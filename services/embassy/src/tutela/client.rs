//! `tutelad`'s HTTP API, as attache's app (Tutela CONTRACTS.md 4.8, 4.9, 7.13.1).
//!
//! - **Its own token.** `POST /oauth2/token` with `grant_type=client_credentials`, the app's client
//!   id and secret in HTTP Basic, for `tutelad`'s own audience. Kept until 30 s before it ends,
//!   and asked again after a 401 (a rotated secret, a raised epoch).
//! - **Agents.** `RegisterAgent`, `GetPrincipal`, `SetDisabled` and `RevokeSessions` of
//!   `tutela.admin.v1`, over HTTP: principals go in the body, never in the URL. The app's service
//!   account needs `manage_agents` at every org of the tenant and nothing else.
//! - **Token exchange** (RFC 8693), with the same client authentication, so a token attache asks
//!   for carries its client id as `azp`.
//!
//! Every request goes through `tutela-safenet` (`https`, public addresses unless
//! `tutela.private_host`, loopback only with `tutela.dev_loopback`, no redirects).
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::Credentials;
use crate::config::TutelaConfig;

/// How long before its `exp` the app's token is asked for again.
const TOKEN_MARGIN: Duration = Duration::from_secs(30);

/// What went wrong with a call to `tutelad`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The request did not get an answer: `tutelad` is down, or the network is.
    #[error("tutelad could not be reached")]
    Unreachable(#[source] tutela_safenet::SafenetError),
    /// `tutelad` answered with an error: a problem document's code (`forbidden`, `not_found`,
    /// `exists`, ...) or an OAuth error (`invalid_client`, `invalid_grant`, `invalid_target`, ...).
    #[error("tutelad answered {status} {code}{}", detail.as_deref().map(|d| format!(" ({d})")).unwrap_or_default())]
    Refused {
        status: u16,
        code: String,
        detail: Option<String>,
    },
    /// A 2xx answer that is not what the contract says.
    #[error("tutelad's answer does not follow its contract")]
    Answer(#[source] serde_json::Error),
}

impl Error {
    /// Worth trying again later: no answer, or `tutelad` itself failed (5xx, 429).
    pub fn is_unavailable(&self) -> bool {
        match self {
            Error::Unreachable(_) => true,
            Error::Refused { status, .. } => *status >= 500 || *status == 429,
            Error::Answer(_) => false,
        }
    }

    /// The problem or OAuth error code of a refusal.
    pub fn code(&self) -> Option<&str> {
        match self {
            Error::Refused { code, .. } => Some(code),
            _ => None,
        }
    }

    /// The HTTP status of a refusal.
    pub fn status(&self) -> Option<u16> {
        match self {
            Error::Refused { status, .. } => Some(*status),
            _ => None,
        }
    }
}

/// A principal's state (Tutela CONTRACTS.md 7.13.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalState {
    /// `agent:agt_<uuidv7>`, made by `tutelad`.
    pub principal: String,
    pub epoch: u64,
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload: Option<String>,
    /// The tenant revision after a change that moved it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rev: Option<u64>,
}

/// A token `POST /oauth2/token` issued.
#[derive(Clone, Deserialize)]
pub struct Issued {
    pub access_token: String,
    pub expires_in: u64,
    #[serde(default)]
    pub issued_token_type: Option<String>,
}

impl std::fmt::Debug for Issued {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issued")
            .field("expires_in", &self.expires_in)
            .finish_non_exhaustive()
    }
}

/// An RFC 8693 token exchange (Tutela CONTRACTS.md 4.8). Without `actor_token` it exchanges the
/// subject for another audience; with one it asks for a delegated token (`typ: agent+jwt`).
#[derive(Clone, Default)]
pub struct Exchange<'a> {
    pub subject_token: &'a str,
    pub audience: &'a str,
    pub actor_token: Option<&'a str>,
    /// The capability snapshot, a JSON object of at most 4096 bytes. Tutela never reads it.
    pub cap: Option<&'a str>,
    pub run_id: Option<&'a str>,
    pub node_id: Option<&'a str>,
}

const ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";

#[derive(Deserialize)]
struct ProblemDoc {
    #[serde(rename = "type")]
    kind: Option<String>,
    detail: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// `tutelad`, as the app the credentials name.
pub struct Client {
    http: tutela_safenet::Client,
    base: String,
    audience: String,
    creds: Credentials,
    token: Mutex<Option<(String, Instant)>>,
}

impl Client {
    pub fn new(config: &TutelaConfig, creds: Credentials) -> anyhow::Result<Client> {
        let base = config.url.clone().unwrap_or_else(|| creds.issuer.clone());
        let parsed = super::check_url(&base, config.dev_loopback)
            .map_err(|e| anyhow::anyhow!("tutelad's URL {base:?}: {e}"))?;
        super::check_url(&creds.token_url, config.dev_loopback)
            .map_err(|e| anyhow::anyhow!("token_url {:?}: {e}", creds.token_url))?;
        let mut policy = tutela_safenet::Policy::new();
        if config.dev_loopback {
            policy = policy.dev_loopback();
        }
        if config.private_host {
            for url in [parsed.as_str(), creds.token_url.as_str()] {
                let host = url::Url::parse(url)?
                    .host_str()
                    .map(str::to_string)
                    .unwrap_or_default();
                policy = policy.allow_private_host(&host).map_err(|e| {
                    anyhow::anyhow!("tutela.private_host: {}", agentsc_common::error::chain(&e))
                })?;
            }
        }
        let http = tutela_safenet::Client::new(policy).map_err(|e| {
            anyhow::anyhow!(
                "build the tutelad client: {}",
                agentsc_common::error::chain(&e)
            )
        })?;
        Ok(Client {
            http,
            base: base.trim_end_matches('/').to_string(),
            audience: config.audience.clone(),
            creds,
            token: Mutex::new(None),
        })
    }

    pub fn credentials(&self) -> &Credentials {
        &self.creds
    }

    /// `tutelad`'s own audience.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    fn basic(&self) -> String {
        let pair = format!("{}:{}", self.creds.client_id, self.creds.client_secret);
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(pair)
        )
    }

    /// `POST /oauth2/token` as the app; `form` without the client's credentials.
    async fn token_endpoint(&self, form: &[(&str, &str)]) -> Result<Issued, Error> {
        let body = {
            let mut ser = url::form_urlencoded::Serializer::new(String::new());
            for (k, v) in form {
                ser.append_pair(k, v);
            }
            ser.finish().into_bytes()
        };
        let auth = self.basic();
        let resp = self
            .http
            .post(
                &self.creds.token_url,
                "application/x-www-form-urlencoded",
                body,
                &[("authorization", &auth), ("accept", "application/json")],
            )
            .await
            .map_err(Error::Unreachable)?;
        answer(resp)
    }

    /// The app's own token: `client_credentials`, kept until shortly before it ends.
    pub async fn service_token(&self) -> Result<String, Error> {
        let mut held = self.token.lock().await;
        if let Some((token, until)) = held.as_ref()
            && Instant::now() < *until
        {
            return Ok(token.clone());
        }
        let issued = self
            .token_endpoint(&[
                ("grant_type", "client_credentials"),
                ("audience", &self.audience),
            ])
            .await?;
        let life = Duration::from_secs(issued.expires_in)
            .saturating_sub(TOKEN_MARGIN)
            .max(Duration::from_secs(5));
        *held = Some((issued.access_token.clone(), Instant::now() + life));
        Ok(issued.access_token)
    }

    async fn forget_token(&self) {
        *self.token.lock().await = None;
    }

    /// `POST <path>` of the admin API with the app's token; once more with a new token after 401.
    async fn admin<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<T, Error> {
        let mut retried = false;
        loop {
            let token = self.service_token().await?;
            let auth = format!("Bearer {token}");
            let resp = self
                .http
                .post(
                    &format!("{}{path}", self.base),
                    "application/json",
                    body.to_string().into_bytes(),
                    &[("authorization", &auth), ("accept", "application/json")],
                )
                .await
                .map_err(Error::Unreachable)?;
            if resp.status == 401 && !retried {
                retried = true;
                self.forget_token().await;
                continue;
            }
            return answer(resp);
        }
    }

    /// `RegisterAgent` without a workload: `tutelad` makes a new `agent:agt_<uuidv7>`. attache
    /// runs several agents per workload, and Tutela binds a workload to one agent, so attache
    /// keeps the mapping itself (docs/adr/0005-agents-in-tutelad.md).
    pub async fn register_agent(&self) -> Result<PrincipalState, Error> {
        self.admin("/v1/admin/agents", &serde_json::json!({})).await
    }

    /// `GetPrincipal`. 404 `not_found` for an agent that is not registered in the app's tenant.
    pub async fn principal_state(&self, principal: &str) -> Result<PrincipalState, Error> {
        self.admin(
            "/v1/admin/principals/state",
            &serde_json::json!({ "principal": principal }),
        )
        .await
    }

    /// `SetDisabled`: `true` disables and raises the epoch (its tokens stop); `false` enables and
    /// keeps the epoch, so a token from before stays refused.
    pub async fn set_disabled(
        &self,
        principal: &str,
        disabled: bool,
    ) -> Result<PrincipalState, Error> {
        self.admin(
            "/v1/admin/principals/disabled",
            &serde_json::json!({ "principal": principal, "disabled": disabled }),
        )
        .await
    }

    /// `RevokeSessions`: raises the epoch, so every token the principal holds is refused.
    pub async fn revoke_sessions(&self, principal: &str) -> Result<PrincipalState, Error> {
        self.admin(
            "/v1/admin/principals/revoke-sessions",
            &serde_json::json!({ "principal": principal }),
        )
        .await
    }

    /// An RFC 8693 token exchange as the app ([`Exchange`]).
    pub async fn exchange(&self, x: &Exchange<'_>) -> Result<Issued, Error> {
        let mut form: Vec<(&str, &str)> = vec![
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", x.subject_token),
            ("subject_token_type", ACCESS_TOKEN),
            ("audience", x.audience),
        ];
        if let Some(a) = x.actor_token {
            form.push(("actor_token", a));
            form.push(("actor_token_type", JWT));
        }
        for (k, v) in [("cap", x.cap), ("run_id", x.run_id), ("node_id", x.node_id)] {
            if let Some(v) = v {
                form.push((k, v));
            }
        }
        self.token_endpoint(&form).await
    }
}

/// A 2xx answer's JSON, or the refusal its problem document or OAuth error names.
fn answer<T: for<'de> Deserialize<'de>>(resp: tutela_safenet::Response) -> Result<T, Error> {
    if resp.is_success() {
        return serde_json::from_slice(&resp.body).map_err(Error::Answer);
    }
    let doc: Option<ProblemDoc> = serde_json::from_slice(&resp.body).ok();
    let (code, detail) = match doc {
        Some(d) => (
            d.error.or_else(|| {
                d.kind
                    .and_then(|t| t.strip_prefix("urn:tutela:problem:").map(str::to_string))
            }),
            d.error_description.or(d.detail),
        ),
        None => (None, None),
    };
    Err(Error::Refused {
        status: resp.status,
        code: code.unwrap_or_else(|| "unknown".into()),
        detail,
    })
}
