//! Console sign-in through an OIDC issuer (`auth.oidc`, Tutela `docs/INTEGRATION.md` §3 step 2,
//! design §8.3). `att_` tokens keep working next to it.
//!
//! 1. `GET /api/v1/auth/oidc/login` sends the browser to the issuer with the authorization code
//!    flow and PKCE. `state`, `nonce` and the PKCE verifier wait in the signed, HttpOnly
//!    `agentsc_oidc` cookie for up to [`PENDING_LIFETIME_S`]. It is `SameSite=Lax`: the callback is
//!    a navigation from another site, and a `Strict` cookie would not come back on it.
//! 2. `GET /api/v1/auth/oidc/callback` checks `state`, redeems the code at the token endpoint,
//!    verifies the ID token with `tutela-sdk` ([`tutela_sdk::Verifier`], an external issuer whose
//!    tenant comes from the trust list; audience `client_id`), and checks `nonce`.
//! 3. `(iss, sub)` names the person, never an e-mail. `auth.oidc.users` maps a subject, and
//!    `auth.oidc.groups` maps a group of the token's `groups_claim`; the first match in the file
//!    wins, because an [`crate::auth::Identity`] has one role across its namespaces and merging
//!    groups could raise a role into a namespace it was never given. No match: no session.
//! 4. The session is the usual `agentsc_session` cookie (HttpOnly, `SameSite=Strict`), holding
//!    `(iss, sub, group)`. As with tokens, the configuration is read again on every request, so a
//!    person who leaves `auth.oidc` loses the session at once. A person disabled only at the
//!    issuer keeps it until it expires, so it lasts `session_seconds`, an hour by default, and not
//!    the 12 hours of a token's session: signing in again is one click.
//!
//! All outbound calls go through `tutela-safenet`: `https` to public addresses only, unless
//! `private_host` names the issuer's host or `dev_loopback` allows loopback.
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tutela_contracts::claims::Audience;
use tutela_contracts::tenant::{Issuer, TenantId, TrustList};
use tutela_sdk::{
    Alg, CacheRules, IssuerConfig, JwksSource, SafenetSource, SystemClock, Verifier, VerifierConfig,
};

use super::session;
use crate::config::{OidcConfig, Role};

/// The state cookie.
pub const STATE_COOKIE: &str = "agentsc_oidc";
/// The path of both ends of the flow, the state cookie's scope.
pub const BASE_PATH: &str = "/api/v1/auth/oidc";
/// The callback, as `redirect_url` must end.
pub const CALLBACK_PATH: &str = "/api/v1/auth/oidc/callback";
/// How long a sign-in may take at the issuer.
pub const PENDING_LIFETIME_S: i64 = 600;

/// What waits in the state cookie while the browser is at the issuer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub state: String,
    pub nonce: String,
    pub verifier: String,
    pub exp: i64,
}

/// Who signed in: what a session keeps of them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcSubject {
    pub iss: String,
    pub sub: String,
    /// The `auth.oidc.groups` entry that let them in; `None` for an `auth.oidc.users` entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

/// What the configuration gives a subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub name: String,
    pub role: Role,
    pub namespaces: Vec<String>,
    pub payloads: bool,
}

/// Why a sign-in ended without a session. The text is safe to log and audit, and never holds a
/// token or a code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The flow failed: the browser is told only that.
    Failed(String),
    /// A valid person with no entry in `auth.oidc`.
    NoAccess { sub: String },
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

/// The issuer's settings, ready to use. Rebuilt on every config reload.
pub struct Oidc {
    pub config: OidcConfig,
    verifier: Arc<Verifier>,
    http: tutela_safenet::Client,
    client_secret: Option<String>,
}

impl std::fmt::Debug for Oidc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Oidc")
            .field("issuer", &self.config.issuer)
            .finish_non_exhaustive()
    }
}

/// The settings for `tutela-sdk`. The error names the setting at fault.
pub fn verifier_config(config: &OidcConfig) -> Result<VerifierConfig, String> {
    let audience: Audience = config
        .client_id
        .parse()
        .map_err(|e| format!("auth.oidc.client_id: {e}"))?;
    let iss: Issuer = config
        .issuer
        .parse()
        .map_err(|e| format!("auth.oidc.issuer: {e}"))?;
    let tenant: TenantId = config
        .tenant
        .parse()
        .map_err(|e| format!("auth.oidc.tenant: {e}"))?;
    let mut trust = if config.dev_loopback {
        TrustList::dev_mode()
    } else {
        TrustList::new()
    };
    trust
        .insert(iss.clone(), tenant)
        .map_err(|e| format!("auth.oidc.issuer: {e}"))?;
    let algs = config
        .algs
        .iter()
        .map(|a| Alg::parse(a).ok_or_else(|| format!("auth.oidc.algs: {a:?}")))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(VerifierConfig {
        audience,
        trust,
        issuers: vec![IssuerConfig {
            iss,
            jwks_uri: config.jwks_uri(),
            algs,
            // Keycloak's tokens are not in Tutela's format, and its header says `typ: JWT`
            external: true,
            allow_typ_jwt: true,
        }],
        delegation: false,
        delegation_aware: false,
        denied_kids: HashSet::new(),
        cache: CacheRules::default(),
    })
}

fn policy(config: &OidcConfig) -> anyhow::Result<tutela_safenet::Policy> {
    let mut policy = tutela_safenet::Policy::new();
    if config.dev_loopback {
        policy = policy.dev_loopback();
    }
    if config.private_host {
        let url = url::Url::parse(&config.issuer).context("parse auth.oidc.issuer")?;
        let host = url.host_str().context("auth.oidc.issuer has no host")?;
        policy = policy
            .allow_private_host(host)
            .context("allow auth.oidc.private_host")?;
    }
    Ok(policy)
}

impl Oidc {
    /// For `config`, reading the client secret: JWKS and the token endpoint go through
    /// `tutela-safenet`. Needs the process's rustls provider installed first.
    pub fn load(config: &OidcConfig) -> anyhow::Result<Oidc> {
        let source =
            SafenetSource::new(policy(config)?).context("build the auth.oidc JWKS client")?;
        Self::with_source(config, Arc::new(source))
    }

    /// [`Oidc::load`] with its own JWKS source.
    pub fn with_source(config: &OidcConfig, source: Arc<dyn JwksSource>) -> anyhow::Result<Oidc> {
        let verifier = Verifier::with(
            verifier_config(config).map_err(anyhow::Error::msg)?,
            source,
            Arc::new(SystemClock),
        );
        let http =
            tutela_safenet::Client::new(policy(config)?).context("build the auth.oidc client")?;
        let client_secret = config
            .client_secret_file
            .as_deref()
            .map(read_secret)
            .transpose()?;
        Ok(Oidc {
            config: config.clone(),
            verifier: Arc::new(verifier),
            http,
            client_secret,
        })
    }

    /// The issuer's URL to send the browser to, and the state cookie's value to set.
    pub fn begin(&self, key: &[u8], now: i64) -> anyhow::Result<(String, String)> {
        let pending = Pending {
            state: random_text()?,
            nonce: random_text()?,
            verifier: random_text()?,
            exp: now + PENDING_LIFETIME_S,
        };
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pending.verifier.as_bytes()));
        let mut url = url::Url::parse(&self.config.authorization_endpoint())
            .context("parse auth.oidc.authorization_endpoint")?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("scope", "openid")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_url)
            .append_pair("state", &pending.state)
            .append_pair("nonce", &pending.nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        Ok((url.to_string(), session::sign_json(key, &pending)))
    }

    /// Redeem `code`, verify the ID token and find what the configuration gives its subject.
    pub async fn finish(
        &self,
        code: &str,
        pending: &Pending,
    ) -> Result<(OidcSubject, Grant), Refused> {
        let failed = |what: String| Refused::Failed(what);
        let resp = self
            .http
            .post(
                &self.config.token_endpoint(),
                "application/x-www-form-urlencoded",
                self.token_request(code, pending),
                &[("accept", "application/json")],
            )
            .await
            .map_err(|e| failed(format!("the token endpoint: {e}")))?;
        if !resp.is_success() {
            return Err(failed(format!(
                "the token endpoint answered {}",
                resp.status
            )));
        }
        let token: TokenResponse = serde_json::from_slice(&resp.body)
            .map_err(|_| failed("the token endpoint sent no id_token".into()))?;
        let verified = self
            .verifier
            .verify(&token.id_token)
            .await
            .map_err(|e| failed(format!("the ID token: {}", e.step().as_str())))?;
        let tutela_sdk::Identity::External(external) = verified else {
            return Err(failed("the ID token is not the issuer's".into()));
        };
        let claims =
            claims_of(&token.id_token).ok_or_else(|| failed("the ID token's claims".into()))?;
        let nonce = claims
            .get("nonce")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if !bool::from(nonce.as_bytes().ct_eq(pending.nonce.as_bytes())) {
            return Err(failed("the ID token's nonce".into()));
        }
        let groups: Vec<&str> = claims
            .get(&self.config.groups_claim)
            .and_then(serde_json::Value::as_array)
            .map(|g| g.iter().filter_map(serde_json::Value::as_str).collect())
            .unwrap_or_default();
        let group = self.pick(&external.sub, &groups);
        let Some(group) = group else {
            return Err(Refused::NoAccess { sub: external.sub });
        };
        let subject = OidcSubject {
            iss: self.config.issuer.clone(),
            sub: external.sub,
            group,
        };
        match self.grant(&subject) {
            Some(grant) => Ok((subject, grant)),
            None => Err(Refused::NoAccess { sub: subject.sub }),
        }
    }

    /// The body of the token request.
    fn token_request(&self, code: &str, pending: &Pending) -> Vec<u8> {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair("redirect_uri", &self.config.redirect_url)
            .append_pair("client_id", &self.config.client_id)
            .append_pair("code_verifier", &pending.verifier);
        if let Some(secret) = &self.client_secret {
            form.append_pair("client_secret", secret);
        }
        form.finish().into_bytes()
    }

    /// The entry that lets `sub` in: `Some(None)` for `auth.oidc.users`, `Some(Some(group))` for
    /// the first entry of `auth.oidc.groups` among `groups`, `None` for no entry.
    fn pick(&self, sub: &str, groups: &[&str]) -> Option<Option<String>> {
        if self.config.users.iter().any(|u| u.sub == sub) {
            return Some(None);
        }
        self.config
            .groups
            .iter()
            .find(|g| groups.contains(&g.group.as_str()))
            .map(|g| Some(g.group.clone()))
    }

    /// What the configuration gives `subject` now. `None` when it no longer lets them in.
    pub fn grant(&self, subject: &OidcSubject) -> Option<Grant> {
        if subject.iss != self.config.issuer {
            return None;
        }
        match &subject.group {
            None => self
                .config
                .users
                .iter()
                .find(|u| u.sub == subject.sub)
                .map(|u| Grant {
                    name: u.name.clone(),
                    role: u.role,
                    namespaces: u.namespaces.clone(),
                    payloads: u.payloads,
                }),
            Some(group) => self
                .config
                .groups
                .iter()
                .find(|g| g.group == *group)
                .map(|g| Grant {
                    name: format!("oidc:{}", subject.sub),
                    role: g.role,
                    namespaces: g.namespaces.clone(),
                    payloads: g.payloads,
                }),
        }
    }

    /// Where a console signing out sends the browser, to end the issuer's session too.
    pub fn end_session_url(&self) -> Option<String> {
        let mut url = url::Url::parse(&self.config.end_session_endpoint()).ok()?;
        let back = url::Url::parse(&self.config.redirect_url).ok()?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.config.client_id)
            .append_pair(
                "post_logout_redirect_uri",
                &format!("{}/", back.origin().ascii_serialization()),
            );
        Some(url.to_string())
    }
}

/// The claims of a token whose signature was already verified.
fn claims_of(token: &str) -> Option<serde_json::Value> {
    let payload = token.split('.').nth(1)?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()
}

fn read_secret(path: &Path) -> anyhow::Result<String> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read auth.oidc.client_secret_file {}", path.display()))?;
    let secret = text.trim();
    if secret.is_empty() {
        anyhow::bail!("auth.oidc.client_secret_file {} is empty", path.display());
    }
    Ok(secret.to_string())
}

/// 32 random bytes, base64url: `state`, `nonce` or a PKCE verifier (43 characters, RFC 7636).
fn random_text() -> anyhow::Result<String> {
    use rand::TryRng;
    let mut bytes = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| anyhow::anyhow!("read random bytes from the operating system: {e}"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// The state cookie's value in a `Cookie` header.
pub fn state_from_cookie_header(header: &str) -> Option<&str> {
    header
        .split(';')
        .map(str::trim)
        .find_map(|kv| kv.strip_prefix(STATE_COOKIE)?.strip_prefix('='))
        .filter(|v| !v.is_empty())
}

/// `Set-Cookie` for the state of a sign-in.
pub fn state_cookie(value: &str, secure: bool) -> String {
    let mut c = format!(
        "{STATE_COOKIE}={value}; HttpOnly; SameSite=Lax; Path={BASE_PATH}; Max-Age={PENDING_LIFETIME_S}"
    );
    if secure {
        c.push_str("; Secure");
    }
    c
}

/// `Set-Cookie` that clears the state.
pub fn clear_state_cookie(secure: bool) -> String {
    let mut c = format!("{STATE_COOKIE}=; HttpOnly; SameSite=Lax; Path={BASE_PATH}; Max-Age=0");
    if secure {
        c.push_str("; Secure");
    }
    c
}
