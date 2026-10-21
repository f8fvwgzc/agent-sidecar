//! API authentication and authorization (design §8.1, §8.3, §15 rules 1–2).
//!
//! - **Bearer tokens**: `Authorization: Bearer att_...`; the token's SHA-256 is compared in
//!   constant time with every [`crate::config::TokenEntry::sha256`] (see [`crate::token`]).
//! - **Sessions**: `POST /login` sets the `agentsc_session` cookie, an HMAC-SHA256-signed
//!   `{token_name, exp}` ([`session`]); the token is looked up again on every request, so a
//!   session dies when its token leaves the config.
//! - **Login rate limit**: 5 failures per minute per client IP ([`LoginLimiter`]).
//! - **`--dev`**: an anonymous viewer when the config says `auth.anonymous: viewer`, and a
//!   one-time admin token ([`Auth::with_dev_token`]).
//!
//! The request checks every response gets (the Host check, CSRF and content type on mutations,
//! the security headers) are in [`http`]; roles on the charter diff are in
//! [`crate::api::write`].
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use arc_swap::ArcSwap;
use subtle::ConstantTimeEq;

use crate::api::types::WhoAmI;
use crate::config::{ALL_NAMESPACES, Anonymous, ControlPlaneConfig, Role, TokenEntry};
use crate::store::{Actor, ActorKind};

pub mod http;
pub mod session;

/// Failed logins allowed per client IP and window.
pub const LOGIN_FAILURES: usize = 5;
/// The login rate-limit window.
pub const LOGIN_WINDOW: Duration = Duration::from_secs(60);
/// The shortest session key (`auth.session_key_file`).
pub const MIN_SESSION_KEY: usize = 32;
/// The name of the anonymous `--dev` viewer.
pub const ANONYMOUS: &str = "anonymous";
/// The name of the one-time `--dev` admin token.
pub const DEV_ADMIN: &str = "dev-admin";

/// Who is calling: a token (by bearer or session), or the `--dev` anonymous viewer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub name: String,
    pub role: Role,
    /// `["*"]` = every namespace.
    pub namespaces: Vec<String>,
    pub payloads: bool,
    /// `Token` (bearer or anonymous) or `Session`.
    pub kind: ActorKind,
    pub anonymous: bool,
}

impl Identity {
    fn from_entry(t: &TokenEntry, kind: ActorKind) -> Self {
        Self {
            name: t.name.clone(),
            role: t.role,
            namespaces: t.namespaces.clone(),
            payloads: t.payloads,
            kind,
            anonymous: false,
        }
    }

    /// The `--dev` anonymous viewer: every namespace, no payloads.
    pub fn anonymous() -> Self {
        Self {
            name: ANONYMOUS.into(),
            role: Role::Viewer,
            namespaces: vec![ALL_NAMESPACES.into()],
            payloads: false,
            kind: ActorKind::Token,
            anonymous: true,
        }
    }

    pub fn allows_namespace(&self, namespace: &str) -> bool {
        self.namespaces
            .iter()
            .any(|n| n == ALL_NAMESPACES || n == namespace)
    }

    pub fn has_role(&self, role: Role) -> bool {
        self.role >= role
    }

    pub fn actor(&self) -> Actor {
        Actor {
            name: self.name.clone(),
            kind: self.kind,
            role: Some(self.role),
        }
    }

    pub fn whoami(&self) -> WhoAmI {
        WhoAmI {
            name: self.name.clone(),
            role: self.role,
            namespaces: self.namespaces.clone(),
            payloads: self.payloads,
        }
    }
}

/// Failed logins per client IP over a sliding [`LOGIN_WINDOW`].
#[derive(Debug, Default)]
pub struct LoginLimiter {
    failures: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
}

impl LoginLimiter {
    /// `Err(seconds)` when `ip` used up its failures: how long until the next attempt counts.
    pub fn check(&self, ip: IpAddr, now: Instant) -> Result<(), u64> {
        let mut map = self.failures.lock().unwrap_or_else(|p| p.into_inner());
        let Some(q) = map.get_mut(&ip) else {
            return Ok(());
        };
        while q
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= LOGIN_WINDOW)
        {
            q.pop_front();
        }
        if q.is_empty() {
            map.remove(&ip);
            return Ok(());
        }
        if q.len() >= LOGIN_FAILURES {
            let oldest = q.front().copied().unwrap_or(now);
            let left = LOGIN_WINDOW.saturating_sub(now.saturating_duration_since(oldest));
            return Err(left.as_secs().max(1));
        }
        Ok(())
    }

    pub fn record_failure(&self, ip: IpAddr, now: Instant) {
        let mut map = self.failures.lock().unwrap_or_else(|p| p.into_inner());
        // bound the table: a flood from many addresses forgets the quietest ones
        if map.len() >= 65_536 && !map.contains_key(&ip) {
            map.retain(|_, q| {
                q.back()
                    .is_some_and(|t| now.saturating_duration_since(*t) < LOGIN_WINDOW)
            });
        }
        let q = map.entry(ip).or_default();
        q.push_back(now);
        while q.len() > LOGIN_FAILURES {
            q.pop_front();
        }
    }
}

/// Tokens, sessions and the login limiter of one process.
pub struct Auth {
    config: Arc<ArcSwap<ControlPlaneConfig>>,
    /// The session HMAC key: `auth.session_key_file`, or [`Auth::generated`].
    key: ArcSwap<Vec<u8>>,
    /// Generated at start; used while the config names no key file.
    generated: Vec<u8>,
    dev: bool,
    dev_token: Option<TokenEntry>,
    /// Session cookies get `Secure` (`--http-tls`).
    pub secure_cookies: bool,
    pub limiter: LoginLimiter,
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Auth")
            .field("dev", &self.dev)
            .field("secure_cookies", &self.secure_cookies)
            .finish_non_exhaustive()
    }
}

/// Read a session key file: at least [`MIN_SESSION_KEY`] bytes.
pub fn read_session_key(path: &Path) -> anyhow::Result<Vec<u8>> {
    let key = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if key.len() < MIN_SESSION_KEY {
        bail!(
            "{} has {} bytes; a session key needs at least {MIN_SESSION_KEY}",
            path.display(),
            key.len()
        );
    }
    Ok(key)
}

fn random_key() -> anyhow::Result<Vec<u8>> {
    use rand::TryRngCore;
    let mut key = vec![0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut key)
        .map_err(|e| anyhow::anyhow!("read random bytes from the operating system: {e}"))?;
    Ok(key)
}

impl Auth {
    /// `dev`: `--dev` (honours `auth.anonymous: viewer`); `secure_cookies`: `--http-tls`.
    pub fn new(
        config: Arc<ArcSwap<ControlPlaneConfig>>,
        dev: bool,
        secure_cookies: bool,
    ) -> anyhow::Result<Self> {
        let generated = random_key()?;
        let auth = Self {
            key: ArcSwap::from_pointee(generated.clone()),
            generated,
            config,
            dev,
            dev_token: None,
            secure_cookies,
            limiter: LoginLimiter::default(),
        };
        let cfg = auth.config.load_full();
        auth.reload_key(&cfg)?;
        Ok(auth)
    }

    /// Admit `token` as the one-time `--dev` admin token (`dev-admin`, admin of every namespace,
    /// payloads visible) for the life of this process.
    pub fn with_dev_token(mut self, token: &str) -> Self {
        self.dev_token = Some(TokenEntry {
            name: DEV_ADMIN.into(),
            role: Role::Admin,
            sha256: crate::token::sha256_hex(token),
            namespaces: vec![ALL_NAMESPACES.into()],
            payloads: true,
        });
        self
    }

    /// Use the session key `config` names (or the generated one): at start and on every
    /// config reload, before the config is installed.
    pub fn reload_key(&self, config: &ControlPlaneConfig) -> anyhow::Result<()> {
        let key = match &config.auth.session_key_file {
            Some(path) => read_session_key(path)?,
            None => self.generated.clone(),
        };
        self.key.store(Arc::new(key));
        Ok(())
    }

    /// Whether `auth.anonymous: viewer` is honoured now (`--dev` only).
    pub fn anonymous_allowed(&self) -> bool {
        self.dev && self.config.load().auth.anonymous == Anonymous::Viewer
    }

    fn entries(&self, config: &ControlPlaneConfig) -> Vec<TokenEntry> {
        let mut out = config.auth.tokens.clone();
        if let Some(d) = &self.dev_token {
            out.push(d.clone());
        }
        out
    }

    /// The identity of a bearer token, comparing its hash with every configured hash in
    /// constant time.
    pub fn from_token(&self, token: &str) -> Option<Identity> {
        if !crate::token::is_well_formed(token) {
            return None;
        }
        let hash = crate::token::sha256_hex(token);
        let config = self.config.load();
        let mut found: Option<TokenEntry> = None;
        for entry in self.entries(&config) {
            let eq: bool = hash.as_bytes().ct_eq(entry.sha256.as_bytes()).into();
            if eq && found.is_none() {
                found = Some(entry);
            }
        }
        found.map(|e| Identity::from_entry(&e, ActorKind::Token))
    }

    /// A new session cookie value for the token named `name`.
    pub fn new_session(&self, name: &str) -> String {
        let exp = chrono::Utc::now().timestamp() + session::LIFETIME.as_secs() as i64;
        session::sign(&self.key.load(), name, exp)
    }

    /// The identity of a session cookie value: a valid signature, not expired, and the token
    /// still configured.
    pub fn from_session(&self, value: &str) -> Option<Identity> {
        let now = chrono::Utc::now().timestamp();
        let claims = session::verify(&self.key.load(), value, now)?;
        let config = self.config.load();
        self.entries(&config)
            .iter()
            .find(|t| t.name == claims.token_name)
            .map(|t| Identity::from_entry(t, ActorKind::Session))
    }

    /// Whether `ident` is still admitted (a long-lived SSE stream checks this): its token is
    /// still configured, or anonymous viewers are still allowed.
    pub fn still_valid(&self, ident: &Identity) -> bool {
        if ident.anonymous {
            return self.anonymous_allowed();
        }
        let config = self.config.load();
        self.entries(&config).iter().any(|t| t.name == ident.name)
    }

    /// `Set-Cookie` for a new session.
    pub fn session_cookie(&self, value: &str) -> String {
        let mut c = format!(
            "{}={value}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
            session::COOKIE,
            session::LIFETIME.as_secs()
        );
        if self.secure_cookies {
            c.push_str("; Secure");
        }
        c
    }

    /// `Set-Cookie` that clears the session.
    pub fn clear_cookie(&self) -> String {
        let mut c = format!(
            "{}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
            session::COOKIE
        );
        if self.secure_cookies {
            c.push_str("; Secure");
        }
        c
    }
}

/// The caller of a request: `Authorization: Bearer` (an invalid token is refused, never
/// replaced by the cookie), else the session cookie, else the `--dev` anonymous viewer.
pub fn authenticate(auth: &Auth, headers: &axum::http::HeaderMap) -> Option<Identity> {
    use axum::http::header;
    if let Some(v) = headers.get(header::AUTHORIZATION) {
        let s = v.to_str().ok()?.trim();
        let (scheme, token) = s.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("bearer") {
            return None;
        }
        return auth.from_token(token.trim());
    }
    for v in headers.get_all(header::COOKIE) {
        if let Some(value) = v.to_str().ok().and_then(session::from_cookie_header)
            && let Some(id) = auth.from_session(value)
        {
            return Some(id);
        }
    }
    auth.anonymous_allowed().then(Identity::anonymous)
}

/// Write the one-time `--dev` admin token to `path` (mode 0600, replaced if it exists).
pub fn write_dev_token(path: &Path, token: &str) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    let _ = std::fs::remove_file(path);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    use std::io::Write;
    f.write_all(format!("{token}\n").as_bytes())
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(tokens: Vec<TokenEntry>) -> Arc<ArcSwap<ControlPlaneConfig>> {
        let mut c = ControlPlaneConfig::default();
        c.auth.tokens = tokens;
        Arc::new(ArcSwap::from_pointee(c))
    }

    fn entry(name: &str, token: &str, role: Role) -> TokenEntry {
        TokenEntry {
            name: name.into(),
            role,
            sha256: crate::token::sha256_hex(token),
            namespaces: vec!["shop".into()],
            payloads: false,
        }
    }

    #[test]
    fn tokens_resolve_by_hash() {
        let t = crate::token::generate().unwrap();
        let other = crate::token::generate().unwrap();
        let cfg = config_with(vec![entry("alice", &t, Role::Editor)]);
        let auth = Auth::new(cfg.clone(), false, false).unwrap();
        let id = auth.from_token(&t).unwrap();
        assert_eq!((id.name.as_str(), id.role), ("alice", Role::Editor));
        assert_eq!(id.kind, ActorKind::Token);
        assert!(id.allows_namespace("shop") && !id.allows_namespace("other"));
        assert!(auth.from_token(&other).is_none());
        assert!(auth.from_token("att_short").is_none());
        assert!(auth.from_token("").is_none());
    }

    #[test]
    fn sessions_die_with_their_token() {
        let t = crate::token::generate().unwrap();
        let cfg = config_with(vec![entry("alice", &t, Role::Admin)]);
        let auth = Auth::new(cfg.clone(), false, true).unwrap();
        let value = auth.new_session("alice");
        let id = auth.from_session(&value).unwrap();
        assert_eq!(id.kind, ActorKind::Session);
        assert!(auth.still_valid(&id));
        // tampered
        let mut bad = value.clone();
        bad.push('x');
        assert!(auth.from_session(&bad).is_none());
        // the token leaves the config
        cfg.store(Arc::new(ControlPlaneConfig::default()));
        assert!(auth.from_session(&value).is_none());
        assert!(!auth.still_valid(&id));
        let c = auth.session_cookie(&value);
        assert!(
            c.contains("HttpOnly; SameSite=Strict; Path=/; Max-Age=43200; Secure"),
            "{c}"
        );
        assert!(auth.clear_cookie().contains("Max-Age=0"));
    }

    #[test]
    fn session_keys_come_from_the_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let short = dir.path().join("short");
        std::fs::write(&short, b"too short").unwrap();
        let mut c = ControlPlaneConfig::default();
        c.auth.session_key_file = Some(short.clone());
        let e = Auth::new(Arc::new(ArcSwap::from_pointee(c)), false, false).unwrap_err();
        assert!(e.to_string().contains("at least 32"), "{e}");

        let good = dir.path().join("key");
        std::fs::write(&good, [7u8; 40]).unwrap();
        let mut c = ControlPlaneConfig::default();
        c.auth.session_key_file = Some(good);
        c.auth.tokens = vec![entry(
            "bob",
            &crate::token::generate().unwrap(),
            Role::Viewer,
        )];
        let cfg = Arc::new(ArcSwap::from_pointee(c.clone()));
        let a = Auth::new(cfg.clone(), false, false).unwrap();
        let b = Auth::new(cfg, false, false).unwrap();
        // one key file: a session from one process is valid in another
        let v = a.new_session("bob");
        assert!(b.from_session(&v).is_some());
        // generated keys differ per process
        c.auth.session_key_file = None;
        let cfg = Arc::new(ArcSwap::from_pointee(c));
        let x = Auth::new(cfg.clone(), false, false).unwrap();
        let y = Auth::new(cfg, false, false).unwrap();
        assert!(y.from_session(&x.new_session("bob")).is_none());
    }

    #[test]
    fn anonymous_needs_dev_and_the_config() {
        let mut c = ControlPlaneConfig::default();
        c.auth.anonymous = Anonymous::Viewer;
        let cfg = Arc::new(ArcSwap::from_pointee(c));
        assert!(
            !Auth::new(cfg.clone(), false, false)
                .unwrap()
                .anonymous_allowed()
        );
        let dev = Auth::new(cfg, true, false).unwrap();
        assert!(dev.anonymous_allowed());
        assert!(dev.still_valid(&Identity::anonymous()));
        let none = Auth::new(
            Arc::new(ArcSwap::from_pointee(ControlPlaneConfig::default())),
            true,
            false,
        )
        .unwrap();
        assert!(!none.anonymous_allowed());
    }

    #[test]
    fn the_dev_token_is_an_admin() {
        let t = crate::token::generate().unwrap();
        let auth = Auth::new(
            Arc::new(ArcSwap::from_pointee(ControlPlaneConfig::default())),
            true,
            false,
        )
        .unwrap()
        .with_dev_token(&t);
        let id = auth.from_token(&t).unwrap();
        assert_eq!((id.name.as_str(), id.role), (DEV_ADMIN, Role::Admin));
        assert!(id.payloads && id.allows_namespace("anything"));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/token");
        write_dev_token(&path, &t).unwrap();
        write_dev_token(&path, &t).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), t);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn five_failures_per_minute_per_ip() {
        let l = LoginLimiter::default();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let other: IpAddr = "10.0.0.2".parse().unwrap();
        let t0 = Instant::now();
        for i in 0..5 {
            assert!(l.check(ip, t0 + Duration::from_secs(i)).is_ok());
            l.record_failure(ip, t0 + Duration::from_secs(i));
        }
        let wait = l.check(ip, t0 + Duration::from_secs(10)).unwrap_err();
        assert_eq!(wait, 50);
        assert!(l.check(other, t0).is_ok());
        // the oldest failure leaves the window
        assert!(l.check(ip, t0 + Duration::from_secs(60)).is_ok());
    }
}
