//! `ControlPlaneConfig` (design §8.2): API tokens and roles, certificate issuance, the sidecar
//! image allow-list ([`crate::sidecar_images`], design §13), write policy and the UI event ring.
//! Loaded from `embassy serve --config <file>` (YAML); every struct refuses unknown fields, and
//! [`ControlPlaneConfig::validate`] reports every problem at once.
//!
//! Tokens are stored as SHA-256 only: the lowercase hex digest of the whole token text,
//! `att_` included (see [`crate::token`]).
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::names::{RESERVED_SERVICE, is_dns_label, is_sha256_hex};

pub const API_VERSION: &str = "agentsc.io/v1alpha1";
pub const KIND: &str = "ControlPlaneConfig";
/// `issuance.workload_cert_ttl` default and bounds (design §7).
pub const DEFAULT_WORKLOAD_CERT_TTL: Duration = Duration::from_secs(24 * 3600);
pub const MIN_WORKLOAD_CERT_TTL: Duration = Duration::from_secs(3600);
pub const MAX_WORKLOAD_CERT_TTL: Duration = Duration::from_secs(720 * 3600);
/// `events.retain_bytes` default (64 MiB) and bounds.
pub const DEFAULT_RETAIN_BYTES: u64 = 64 * 1024 * 1024;
pub const MIN_RETAIN_BYTES: u64 = 1024 * 1024;
pub const MAX_RETAIN_BYTES: u64 = 16 * 1024 * 1024 * 1024;
/// The namespace scope that means "every namespace".
pub const ALL_NAMESPACES: &str = "*";

/// The role of an API identity (design §8.3). Ordered: `Viewer < Editor < Admin`.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Viewer,
    Editor,
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Editor => "editor",
            Role::Admin => "admin",
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneConfig {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub issuance: IssuanceConfig,
    /// The images that may run as the sidecar containers; empty = not enforced (development).
    #[serde(default)]
    pub sidecar_images: SidecarImagesConfig,
    /// Checked on every write after the charter validator; absent = no extra policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyConfig>,
    #[serde(default)]
    pub events: EventsConfig,
    /// Risk scoring of agents (crate::secops::risk, CONTRACT.md §5.5).
    #[serde(default)]
    pub risk: RiskConfig,
}

/// `risk`: what the risk score does (crate::secops::risk).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskConfig {
    /// A run score at or above this quarantines the agent; absent = never by score.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantine_score: Option<f64>,
}

impl Default for ControlPlaneConfig {
    /// What `embassy serve` runs with when `--config` is not given: no tokens (only `--dev`
    /// can then reach the API), Kubernetes issuance on, default TTL and event ring, and no
    /// sidecar image allow-list (not enforced; [`crate::sidecar_images`] warns).
    fn default() -> Self {
        Self {
            api_version: API_VERSION.into(),
            kind: KIND.into(),
            auth: AuthConfig::default(),
            issuance: IssuanceConfig::default(),
            sidecar_images: SidecarImagesConfig::default(),
            policy: None,
            events: EventsConfig::default(),
            risk: RiskConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    #[serde(default)]
    pub tokens: Vec<TokenEntry>,
    #[serde(default)]
    pub anonymous: Anonymous,
    /// 32+ random bytes; the HMAC key for session cookies. Absent: generated in memory at start
    /// (sessions then end when the process restarts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_key_file: Option<PathBuf>,
}

/// `auth.anonymous`: what a request without credentials gets. `viewer` is honoured only with
/// `embassy serve --dev`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Anonymous {
    #[default]
    None,
    Viewer,
}

/// One API token (`auth.tokens[]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenEntry {
    /// DNS-1123 label, unique; the actor name in audit records and history.
    pub name: String,
    pub role: Role,
    /// Lowercase hex SHA-256 of the token text.
    pub sha256: String,
    /// Namespaces this token may see and change; `["*"]` = all.
    pub namespaces: Vec<String>,
    /// May see audit `input`/`output` payloads.
    #[serde(default)]
    pub payloads: bool,
}

impl TokenEntry {
    pub fn allows_namespace(&self, namespace: &str) -> bool {
        self.namespaces
            .iter()
            .any(|n| n == ALL_NAMESPACES || n == namespace)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceConfig {
    /// Accept Kubernetes projected service-account tokens (TokenReview).
    #[serde(default = "default_true")]
    pub kubernetes: bool,
    #[serde(default = "default_workload_cert_ttl")]
    pub workload_cert_ttl: HumanDuration,
    #[serde(default)]
    pub join_tokens: Vec<JoinTokenEntry>,
}

impl Default for IssuanceConfig {
    fn default() -> Self {
        Self {
            kubernetes: true,
            workload_cert_ttl: default_workload_cert_ttl(),
            join_tokens: Vec::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_workload_cert_ttl() -> HumanDuration {
    HumanDuration(DEFAULT_WORKLOAD_CERT_TTL)
}

/// A join token for `IssueCertificate` outside Kubernetes (`issuance.join_tokens[]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinTokenEntry {
    pub name: String,
    pub sha256: String,
    /// The one namespace this token may obtain identities in.
    pub namespace: String,
    /// The services (exact names, no wildcards) it may obtain identities for.
    pub services: Vec<String>,
    /// RFC 3339. An expired entry stays valid config; issuance refuses it.
    pub expires_at: DateTime<Utc>,
}

impl JoinTokenEntry {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }
}

/// `sidecar_images` (design §13, [`crate::sidecar_images`]): the image digests the sidecar
/// containers (`agentscd`, `agentsc-runtime`) may run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarImagesConfig {
    /// `sha256:<64 lowercase hex>` digests of signed sidecar images (the release workflow's).
    /// Empty: not enforced (a development build has no registry digest).
    #[serde(default)]
    pub allowed_digests: Vec<String>,
}

impl SidecarImagesConfig {
    /// Is the allow-list enforced (non-empty)?
    pub fn enforced(&self) -> bool {
        !self.allowed_digests.is_empty()
    }

    /// Is `digest` (`sha256:<hex>`) allowed? Always true when not enforced.
    pub fn allows(&self, digest: &str) -> bool {
        !self.enforced() || self.allowed_digests.iter().any(|d| d == digest)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Every charter must have `authz.default: deny`.
    #[serde(default)]
    pub require_authz_default_deny: bool,
    /// Origins (`scheme://host[:port]`) `http` tools may use. Absent: any origin; `[]`: none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_origin_allowlist: Option<Vec<String>>,
    /// No agent may use `learning.mode: auto`.
    #[serde(default)]
    pub forbid_learning_auto: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsConfig {
    /// Size of the in-memory ring of recent audit records for the UI.
    #[serde(default = "default_retain_bytes")]
    pub retain_bytes: u64,
}

impl Default for EventsConfig {
    fn default() -> Self {
        Self {
            retain_bytes: DEFAULT_RETAIN_BYTES,
        }
    }
}

fn default_retain_bytes() -> u64 {
    DEFAULT_RETAIN_BYTES
}

/// A duration written as a sum of `<integer><unit>` terms, units `d`, `h`, `m`, `s`
/// (`24h`, `90m`, `1h30m`). Serialized in the largest unit that divides it exactly
/// (hours, minutes or seconds), so `24h` stays `24h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HumanDuration(pub Duration);

impl HumanDuration {
    pub fn as_duration(self) -> Duration {
        self.0
    }
}

impl std::str::FromStr for HumanDuration {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = || format!("{s:?} is not a duration like 24h, 90m or 1h30m");
        if s.is_empty() {
            return Err(bad());
        }
        let mut total: u64 = 0;
        let mut digits = String::new();
        for c in s.chars() {
            if c.is_ascii_digit() {
                digits.push(c);
                continue;
            }
            let unit: u64 = match c {
                'd' => 86_400,
                'h' => 3_600,
                'm' => 60,
                's' => 1,
                _ => return Err(bad()),
            };
            let n: u64 = digits.parse().map_err(|_| bad())?;
            digits.clear();
            total = n
                .checked_mul(unit)
                .and_then(|v| total.checked_add(v))
                .ok_or_else(bad)?;
        }
        if !digits.is_empty() {
            return Err(bad());
        }
        Ok(Self(Duration::from_secs(total)))
    }
}

impl std::fmt::Display for HumanDuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.0.as_secs();
        if s != 0 && s.is_multiple_of(3_600) {
            write!(f, "{}h", s / 3_600)
        } else if s != 0 && s.is_multiple_of(60) {
            write!(f, "{}m", s / 60)
        } else {
            write!(f, "{s}s")
        }
    }
}

impl Serialize for HumanDuration {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for HumanDuration {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Why a config could not be used.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parse ControlPlaneConfig: {0}")]
    Parse(String),
    #[error("invalid ControlPlaneConfig:\n  {}", .0.join("\n  "))]
    Invalid(Vec<String>),
}

impl ControlPlaneConfig {
    /// Parse YAML (unknown fields are errors, with their path). Does not validate.
    pub fn from_yaml(text: &str) -> Result<Self, ConfigError> {
        serde_yaml_ng::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Read, parse and validate a config file. `cp_namespace` is `--cp-namespace`.
    pub fn load(path: &Path, cp_namespace: &str) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let config = Self::from_yaml(&text)?;
        config
            .validate(cp_namespace)
            .map_err(ConfigError::Invalid)?;
        Ok(config)
    }

    /// Every problem, each naming its field. `cp_namespace` (the control plane's own namespace)
    /// may not appear in a join token.
    pub fn validate(&self, cp_namespace: &str) -> Result<(), Vec<String>> {
        let mut errs = Vec::new();
        if let Some(q) = self.risk.quarantine_score
            && !(q.is_finite() && q >= 0.0)
        {
            errs.push(format!(
                "risk.quarantine_score must be a number >= 0, not {q}"
            ));
        }
        if self.api_version != API_VERSION {
            errs.push(format!(
                "apiVersion must be {API_VERSION}, not {:?}",
                self.api_version
            ));
        }
        if self.kind != KIND {
            errs.push(format!("kind must be {KIND}, not {:?}", self.kind));
        }

        let mut names = BTreeSet::new();
        let mut hashes = BTreeSet::new();
        for (i, t) in self.auth.tokens.iter().enumerate() {
            let at = format!("auth.tokens[{i}]");
            if !is_dns_label(&t.name) {
                errs.push(format!("{at}.name {:?} is not a DNS-1123 label", t.name));
            } else if !names.insert(t.name.as_str()) {
                errs.push(format!("{at}.name {:?} is used twice", t.name));
            }
            check_sha256(&mut errs, &mut hashes, &at, &t.sha256);
            if t.namespaces.is_empty() {
                errs.push(format!(
                    "{at}.namespaces is empty (use [\"*\"] for every namespace)"
                ));
            }
            let mut seen = BTreeSet::new();
            for (j, ns) in t.namespaces.iter().enumerate() {
                if ns == ALL_NAMESPACES {
                    if t.namespaces.len() > 1 {
                        errs.push(format!("{at}.namespaces: \"*\" must be the only entry"));
                    }
                } else if !is_dns_label(ns) {
                    errs.push(format!(
                        "{at}.namespaces[{j}] {ns:?} is not a DNS-1123 label"
                    ));
                }
                if !seen.insert(ns.as_str()) {
                    errs.push(format!("{at}.namespaces[{j}] {ns:?} is listed twice"));
                }
            }
        }
        if let Some(p) = &self.auth.session_key_file
            && p.as_os_str().is_empty()
        {
            errs.push("auth.session_key_file is empty".into());
        }

        let ttl = self.issuance.workload_cert_ttl.0;
        if !(MIN_WORKLOAD_CERT_TTL..=MAX_WORKLOAD_CERT_TTL).contains(&ttl) {
            errs.push(format!(
                "issuance.workload_cert_ttl {} is outside 1h..=720h",
                self.issuance.workload_cert_ttl
            ));
        }
        let mut join_names = BTreeSet::new();
        for (i, j) in self.issuance.join_tokens.iter().enumerate() {
            let at = format!("issuance.join_tokens[{i}]");
            if !is_dns_label(&j.name) {
                errs.push(format!("{at}.name {:?} is not a DNS-1123 label", j.name));
            } else if !join_names.insert(j.name.as_str()) {
                errs.push(format!("{at}.name {:?} is used twice", j.name));
            }
            check_sha256(&mut errs, &mut hashes, &at, &j.sha256);
            if !is_dns_label(&j.namespace) {
                errs.push(format!(
                    "{at}.namespace {:?} is not a DNS-1123 label",
                    j.namespace
                ));
            } else if j.namespace == cp_namespace {
                errs.push(format!(
                    "{at}.namespace {:?} is the control-plane namespace, which is never issued certificates",
                    j.namespace
                ));
            }
            if j.services.is_empty() {
                errs.push(format!("{at}.services is empty"));
            }
            let mut seen = BTreeSet::new();
            for (k, svc) in j.services.iter().enumerate() {
                if svc.contains('*') {
                    errs.push(format!(
                        "{at}.services[{k}] {svc:?}: wildcards are not allowed"
                    ));
                } else if !is_dns_label(svc) {
                    errs.push(format!(
                        "{at}.services[{k}] {svc:?} is not a DNS-1123 label"
                    ));
                } else if svc == RESERVED_SERVICE {
                    errs.push(format!(
                        "{at}.services[{k}] {svc:?} is reserved for the control plane"
                    ));
                }
                if !seen.insert(svc.as_str()) {
                    errs.push(format!("{at}.services[{k}] {svc:?} is listed twice"));
                }
            }
        }

        let mut digests = BTreeSet::new();
        for (i, d) in self.sidecar_images.allowed_digests.iter().enumerate() {
            let at = format!("sidecar_images.allowed_digests[{i}]");
            if !crate::sidecar_images::is_digest(d) {
                errs.push(format!(
                    "{at} {d:?} is not a digest (sha256: and 64 lowercase hex characters)"
                ));
            } else if !digests.insert(d.as_str()) {
                errs.push(format!("{at} {d:?} is listed twice"));
            }
        }

        if let Some(origins) = self
            .policy
            .as_ref()
            .and_then(|p| p.http_origin_allowlist.as_ref())
        {
            for (i, o) in origins.iter().enumerate() {
                if let Err(e) = check_origin(o) {
                    errs.push(format!("policy.http_origin_allowlist[{i}] {o:?}: {e}"));
                }
            }
        }

        let rb = self.events.retain_bytes;
        if !(MIN_RETAIN_BYTES..=MAX_RETAIN_BYTES).contains(&rb) {
            errs.push(format!(
                "events.retain_bytes {rb} is outside {MIN_RETAIN_BYTES}..={MAX_RETAIN_BYTES}"
            ));
        }

        if errs.is_empty() { Ok(()) } else { Err(errs) }
    }

    /// The API token whose hash is `sha256` (lowercase hex).
    pub fn token_by_sha256(&self, sha256: &str) -> Option<&TokenEntry> {
        self.auth.tokens.iter().find(|t| t.sha256 == sha256)
    }
}

fn check_sha256<'a>(
    errs: &mut Vec<String>,
    seen: &mut BTreeSet<&'a str>,
    at: &str,
    sha256: &'a str,
) {
    if !is_sha256_hex(sha256) {
        errs.push(format!(
            "{at}.sha256 must be 64 lowercase hex characters (sha256 of the token)"
        ));
    } else if !seen.insert(sha256) {
        errs.push(format!(
            "{at}.sha256 is the hash of a token that is already configured"
        ));
    }
}

/// An origin exactly as `url` serializes it: `http(s)://host[:port]`, no path, query,
/// fragment or user info.
fn check_origin(o: &str) -> Result<(), String> {
    let u = url::Url::parse(o).map_err(|e| e.to_string())?;
    if !matches!(u.scheme(), "http" | "https") {
        return Err("the scheme must be http or https".into());
    }
    let canonical = u.origin().ascii_serialization();
    if canonical != o {
        return Err(format!("write it as the bare origin {canonical:?}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(c: char) -> String {
        std::iter::repeat_n(c, 64).collect()
    }

    fn design_example() -> String {
        // design §8.2, with real hashes
        format!(
            r#"apiVersion: agentsc.io/v1alpha1
kind: ControlPlaneConfig
auth:
  tokens:
    - name: alice
      role: admin
      sha256: "{a}"
      namespaces: ["*"]
      payloads: true
  anonymous: none
  session_key_file: /etc/agentsc/session/key
issuance:
  kubernetes: true
  workload_cert_ttl: 24h
  join_tokens:
    - {{ name: compose-orders, sha256: "{b}", namespace: demo, services: [orders], expires_at: "2027-01-01T00:00:00Z" }}
sidecar_images:
  allowed_digests: ["sha256:{d}"]
policy:
  require_authz_default_deny: true
  http_origin_allowlist: ["https://api.partner.example"]
  forbid_learning_auto: false
events:
  retain_bytes: 67108864
"#,
            a = hash('a'),
            b = hash('b'),
            d = hash('d')
        )
    }

    #[test]
    fn parses_and_validates_the_design_example() {
        let c = ControlPlaneConfig::from_yaml(&design_example()).unwrap();
        c.validate("agentsc-system").unwrap();
        assert_eq!(c.auth.tokens[0].role, Role::Admin);
        assert!(c.auth.tokens[0].payloads);
        assert!(c.auth.tokens[0].allows_namespace("anything"));
        assert_eq!(
            c.issuance.workload_cert_ttl.as_duration(),
            Duration::from_secs(86_400)
        );
        let j = &c.issuance.join_tokens[0];
        assert_eq!(j.services, ["orders"]);
        assert!(!j.is_expired("2026-10-21T10:00:00Z".parse().unwrap()));
        assert!(j.is_expired("2027-01-01T00:00:00Z".parse().unwrap()));
        assert_eq!(
            c.policy.as_ref().unwrap().http_origin_allowlist.as_deref(),
            Some(&["https://api.partner.example".to_string()][..])
        );
        assert_eq!(c.events.retain_bytes, DEFAULT_RETAIN_BYTES);
        let digest = format!("sha256:{}", hash('d'));
        assert!(c.sidecar_images.enforced());
        assert!(c.sidecar_images.allows(&digest));
        assert!(!c.sidecar_images.allows(&format!("sha256:{}", hash('e'))));
        assert_eq!(c.token_by_sha256(&hash('a')).unwrap().name, "alice");
        assert!(
            c.token_by_sha256(&hash('b')).is_none(),
            "join tokens are not API tokens"
        );
    }

    #[test]
    fn serializes_back_to_an_equal_config() {
        let c = ControlPlaneConfig::from_yaml(&design_example()).unwrap();
        let text = serde_yaml_ng::to_string(&c).unwrap();
        assert!(text.contains("workload_cert_ttl: 24h"), "{text}");
        assert_eq!(ControlPlaneConfig::from_yaml(&text).unwrap(), c);
    }

    #[test]
    fn minimal_config_gets_defaults() {
        let c = ControlPlaneConfig::from_yaml(
            "apiVersion: agentsc.io/v1alpha1\nkind: ControlPlaneConfig\n",
        )
        .unwrap();
        c.validate("agentsc-system").unwrap();
        assert_eq!(c, ControlPlaneConfig::default());
        assert_eq!(c.auth.anonymous, Anonymous::None);
        assert!(c.issuance.kubernetes);
        assert!(c.policy.is_none());
        // no allow-list: not enforced, so every digest passes
        assert!(!c.sidecar_images.enforced());
        assert!(c.sidecar_images.allows("sha256:anything"));
    }

    #[test]
    fn unknown_fields_are_errors_with_their_path() {
        let err = ControlPlaneConfig::from_yaml(
            "apiVersion: agentsc.io/v1alpha1\nkind: ControlPlaneConfig\nauth:\n  tokenz: []\n",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("tokenz"), "{err}");
        assert!(err.contains("auth"), "{err}");
    }

    #[test]
    fn roles_are_an_enum() {
        let y = format!(
            "apiVersion: agentsc.io/v1alpha1\nkind: ControlPlaneConfig\nauth:\n  tokens:\n    - {{name: a, role: root, sha256: \"{}\", namespaces: [x]}}\n",
            hash('a')
        );
        let err = ControlPlaneConfig::from_yaml(&y).unwrap_err().to_string();
        assert!(err.contains("root"), "{err}");
        assert!(Role::Viewer < Role::Editor && Role::Editor < Role::Admin);
    }

    #[test]
    fn reports_every_problem() {
        let mut c = ControlPlaneConfig {
            api_version: "v1".into(),
            kind: "Charter".into(),
            ..Default::default()
        };
        c.auth.tokens = vec![
            TokenEntry {
                name: "Alice".into(),
                role: Role::Admin,
                sha256: "ABC".into(),
                namespaces: vec![],
                payloads: false,
            },
            TokenEntry {
                name: "bob".into(),
                role: Role::Viewer,
                sha256: hash('c'),
                namespaces: vec!["*".into(), "shop".into(), "shop".into(), "Bad".into()],
                payloads: false,
            },
            TokenEntry {
                name: "bob".into(),
                role: Role::Viewer,
                sha256: hash('c'),
                namespaces: vec!["shop".into()],
                payloads: false,
            },
        ];
        c.auth.session_key_file = Some(PathBuf::new());
        c.issuance.workload_cert_ttl = "30m".parse().unwrap();
        c.issuance.join_tokens = vec![JoinTokenEntry {
            name: "j".into(),
            sha256: hash('c'),
            namespace: "agentsc-system".into(),
            services: vec!["*".into(), "embassy".into(), "Orders".into()],
            expires_at: "2027-01-01T00:00:00Z".parse().unwrap(),
        }];
        c.policy = Some(PolicyConfig {
            http_origin_allowlist: Some(vec![
                "https://api.partner.example/".into(),
                "ftp://x".into(),
                "https://user@h.example".into(),
            ]),
            ..Default::default()
        });
        c.events.retain_bytes = 10;
        c.sidecar_images.allowed_digests = vec![
            hash('d'),
            format!("sha256:{}", hash('D')),
            format!("sha256:{}", hash('d')),
            format!("sha256:{}", hash('d')),
        ];
        let errs = c.validate("agentsc-system").unwrap_err();
        let all = errs.join("\n");
        for want in [
            "apiVersion must be",
            "kind must be",
            "auth.tokens[0].name \"Alice\"",
            "auth.tokens[0].sha256 must be 64 lowercase hex",
            "auth.tokens[0].namespaces is empty",
            "auth.tokens[1].namespaces: \"*\" must be the only entry",
            "auth.tokens[1].namespaces[2] \"shop\" is listed twice",
            "auth.tokens[1].namespaces[3] \"Bad\"",
            "auth.tokens[2].name \"bob\" is used twice",
            "auth.tokens[2].sha256 is the hash of a token that is already configured",
            "auth.session_key_file is empty",
            "issuance.workload_cert_ttl 30m is outside",
            "issuance.join_tokens[0].sha256 is the hash of a token",
            "issuance.join_tokens[0].namespace \"agentsc-system\" is the control-plane namespace",
            "issuance.join_tokens[0].services[0] \"*\": wildcards are not allowed",
            "issuance.join_tokens[0].services[1] \"embassy\" is reserved",
            "issuance.join_tokens[0].services[2] \"Orders\"",
            "policy.http_origin_allowlist[0]",
            "policy.http_origin_allowlist[1]",
            "policy.http_origin_allowlist[2]",
            "events.retain_bytes 10 is outside",
            "sidecar_images.allowed_digests[0] \"dddd",
            "sidecar_images.allowed_digests[1] \"sha256:DDDD",
            "sidecar_images.allowed_digests[3] \"sha256:dddd",
        ] {
            assert!(all.contains(want), "missing {want:?} in:\n{all}");
        }
    }

    #[test]
    fn durations() {
        for (s, secs, back) in [
            ("24h", 86_400, "24h"),
            ("1d", 86_400, "24h"),
            ("90m", 5_400, "90m"),
            ("1h30m", 5_400, "90m"),
            ("45s", 45, "45s"),
            ("720h", 2_592_000, "720h"),
        ] {
            let d: HumanDuration = s.parse().unwrap();
            assert_eq!(d.0.as_secs(), secs, "{s}");
            assert_eq!(d.to_string(), back, "{s}");
        }
        for bad in ["", "24", "h", "1x", "-1h", "1.5h", "99999999999999999999d"] {
            assert!(bad.parse::<HumanDuration>().is_err(), "{bad}");
        }
    }

    #[test]
    fn load_reads_parses_and_validates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, design_example()).unwrap();
        ControlPlaneConfig::load(&path, "agentsc-system").unwrap();
        // the join token's namespace is `demo`: as the control-plane namespace it is refused
        let err = ControlPlaneConfig::load(&path, "demo").unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)), "{err}");
        let err = ControlPlaneConfig::load(&dir.path().join("missing.yaml"), "x").unwrap_err();
        assert!(err.to_string().contains("missing.yaml"), "{err}");
    }
}
