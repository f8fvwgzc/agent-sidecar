//! `embassy token create` (design §8.1): a new secret token and the config entry that admits it.
//!
//! A token is `att_` followed by 32 random bytes from the OS, base64url-encoded without padding
//! (43 characters). The config never stores the token, only the lowercase hex SHA-256 of its
//! whole text (`att_` included); the token is printed once.
use base64::Engine;
use chrono::{DateTime, SubsecRound, Utc};
use clap::Args;
use rand::TryRngCore;
use sha2::{Digest, Sha256};

use crate::config::{
    ALL_NAMESPACES, ControlPlaneConfig, HumanDuration, JoinTokenEntry, Role, TokenEntry,
};

pub const PREFIX: &str = "att_";
/// Random bytes in a token.
pub const SECRET_BYTES: usize = 32;
/// `att_` + 43 base64url characters.
pub const TOKEN_LEN: usize = 4 + 43;

/// A new token from the operating system's random source.
pub fn generate() -> anyhow::Result<String> {
    let mut secret = [0u8; SECRET_BYTES];
    rand::rngs::OsRng
        .try_fill_bytes(&mut secret)
        .map_err(|e| anyhow::anyhow!("read random bytes from the operating system: {e}"))?;
    Ok(format!(
        "{PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret)
    ))
}

/// Whether `token` has the shape `generate` produces (checked before hashing a presented token).
pub fn is_well_formed(token: &str) -> bool {
    token.len() == TOKEN_LEN
        && token.starts_with(PREFIX)
        && token[PREFIX.len()..]
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// The lowercase hex SHA-256 of the token text, as the config stores it.
pub fn sha256_hex(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// `embassy token create`.
#[derive(Debug, Clone, Args)]
pub struct CreateArgs {
    /// Token name (DNS-1123 label): the actor in audit records and history.
    #[arg(long)]
    pub name: String,
    /// API role.
    #[arg(long, value_enum, default_value_t = Role::Viewer)]
    pub role: Role,
    /// Namespaces the API token may see and change ("*" = all).
    #[arg(long, value_delimiter = ',', default_value = ALL_NAMESPACES)]
    pub namespaces: Vec<String>,
    /// The API token may see audit input/output payloads.
    #[arg(long)]
    pub payloads: bool,
    /// Create a join token for IssueCertificate (issuance.join_tokens) instead of an API token.
    #[arg(long, requires_all = ["namespace", "services"], conflicts_with_all = ["role", "namespaces", "payloads"])]
    pub join: bool,
    /// Join token: the namespace it may obtain identities in.
    #[arg(long, requires = "join")]
    pub namespace: Option<String>,
    /// Join token: the services (comma-separated, no wildcards) it may obtain identities for.
    #[arg(long, value_delimiter = ',', requires = "join")]
    pub services: Vec<String>,
    /// Join token: lifetime from now.
    #[arg(long, default_value = "8760h", requires = "join")]
    pub expires_in: HumanDuration,
    /// The control-plane namespace (join tokens may not name it).
    #[arg(long, default_value = "agentsc-system")]
    pub cp_namespace: String,
}

/// What `token create` prints: the token (shown once) and the config entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Created {
    pub token: String,
    pub entry: Entry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Api(TokenEntry),
    Join(JoinTokenEntry),
}

impl Created {
    /// The token on the first line (for scripts: `head -n1`), then a YAML list with the one
    /// config entry, which `tail -n +2` turns into valid YAML.
    pub fn render(&self) -> anyhow::Result<String> {
        let (section, yaml) = match &self.entry {
            Entry::Api(e) => ("auth.tokens", serde_yaml_ng::to_string(&[e])?),
            Entry::Join(e) => ("issuance.join_tokens", serde_yaml_ng::to_string(&[e])?),
        };
        Ok(format!(
            "{}\n# The token above is shown only once. Add this entry to the ControlPlaneConfig {section}:\n{yaml}",
            self.token
        ))
    }
}

/// Create a token and its entry; the entry is checked with the config validator first.
pub fn create(args: &CreateArgs, now: DateTime<Utc>) -> anyhow::Result<Created> {
    let token = generate()?;
    let sha256 = sha256_hex(&token);
    let mut config = ControlPlaneConfig::default();
    let entry = if args.join {
        let namespace = args
            .namespace
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--join needs --namespace"))?;
        let ttl = chrono::Duration::from_std(args.expires_in.as_duration())
            .map_err(|e| anyhow::anyhow!("--expires-in {}: {e}", args.expires_in))?;
        let expires_at = now
            .trunc_subsecs(0)
            .checked_add_signed(ttl)
            .ok_or_else(|| anyhow::anyhow!("--expires-in {} is too far away", args.expires_in))?;
        let e = JoinTokenEntry {
            name: args.name.clone(),
            sha256,
            namespace,
            services: args.services.clone(),
            expires_at,
        };
        config.issuance.join_tokens.push(e.clone());
        Entry::Join(e)
    } else {
        let e = TokenEntry {
            name: args.name.clone(),
            role: args.role,
            sha256,
            namespaces: args.namespaces.clone(),
            payloads: args.payloads,
        };
        config.auth.tokens.push(e.clone());
        Entry::Api(e)
    };
    if let Err(errs) = config.validate(&args.cp_namespace) {
        anyhow::bail!("token create: {}", errs.join("; "));
    }
    Ok(Created { token, entry })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        args: CreateArgs,
    }

    fn args(a: &[&str]) -> Result<CreateArgs, clap::Error> {
        Cli::try_parse_from(std::iter::once("create").chain(a.iter().copied())).map(|c| c.args)
    }

    fn now() -> DateTime<Utc> {
        "2026-10-21T10:00:00.123456Z".parse().unwrap()
    }

    #[test]
    fn tokens_are_att_and_43_base64url_chars() {
        let a = generate().unwrap();
        let b = generate().unwrap();
        assert_ne!(a, b);
        for t in [&a, &b] {
            assert_eq!(t.len(), 47, "{t}");
            assert!(t.starts_with("att_"));
            assert!(is_well_formed(t), "{t}");
            let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&t[4..])
                .unwrap();
            assert_eq!(raw.len(), 32);
        }
        assert!(!is_well_formed("att_short"));
        assert!(!is_well_formed(&format!("xyz_{}", &a[4..])));
        assert!(!is_well_formed(&format!("att_{}=", &a[4..46])));
        // FIPS 180-2 test vector: the hash is over the token text, lowercase hex
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn api_token_entry_round_trips_into_the_config() {
        let a = args(&[
            "--name",
            "alice",
            "--role",
            "admin",
            "--namespaces",
            "shop,agentsc-demo",
            "--payloads",
        ])
        .unwrap();
        let c = create(&a, now()).unwrap();
        let out = c.render().unwrap();
        let mut lines = out.lines();
        assert_eq!(lines.next(), Some(c.token.as_str()));
        let yaml: String = lines.map(|l| format!("{l}\n")).collect();
        let entries: Vec<TokenEntry> = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(
            entries,
            [TokenEntry {
                name: "alice".into(),
                role: Role::Admin,
                sha256: sha256_hex(&c.token),
                namespaces: vec!["shop".into(), "agentsc-demo".into()],
                payloads: true,
            }]
        );
        assert!(out.contains("auth.tokens"), "{out}");
        assert!(!yaml.contains(&c.token), "the entry never holds the token");
    }

    #[test]
    fn api_token_defaults_are_least_privilege() {
        let c = create(&args(&["--name", "ci"]).unwrap(), now()).unwrap();
        match c.entry {
            Entry::Api(e) => {
                assert_eq!(e.role, Role::Viewer);
                assert_eq!(e.namespaces, ["*"]);
                assert!(!e.payloads);
            }
            Entry::Join(_) => panic!("api token expected"),
        }
    }

    #[test]
    fn join_token_entry_round_trips_into_the_config() {
        let a = args(&[
            "--name",
            "compose-orders",
            "--join",
            "--namespace",
            "demo",
            "--services",
            "orders",
            "--expires-in",
            "720h",
        ])
        .unwrap();
        let c = create(&a, now()).unwrap();
        let out = c.render().unwrap();
        assert!(out.contains("issuance.join_tokens"), "{out}");
        let yaml: String = out.lines().skip(1).map(|l| format!("{l}\n")).collect();
        let entries: Vec<JoinTokenEntry> = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].sha256, sha256_hex(&c.token));
        assert_eq!(entries[0].namespace, "demo");
        assert_eq!(entries[0].services, ["orders"]);
        assert_eq!(
            entries[0].expires_at,
            "2026-11-20T10:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
    }

    #[test]
    fn bad_entries_are_refused() {
        for (a, want) in [
            (&["--name", "Alice"][..], "is not a DNS-1123 label"),
            (
                &["--name", "a", "--namespaces", "*,shop"],
                "must be the only entry",
            ),
            (
                &[
                    "--name",
                    "j",
                    "--join",
                    "--namespace",
                    "agentsc-system",
                    "--services",
                    "orders",
                ],
                "control-plane namespace",
            ),
            (
                &[
                    "--name",
                    "j",
                    "--join",
                    "--namespace",
                    "demo",
                    "--services",
                    "embassy",
                ],
                "reserved",
            ),
        ] {
            let err = create(&args(a).unwrap(), now()).unwrap_err().to_string();
            assert!(err.contains(want), "{a:?}: {err}");
        }
    }

    #[test]
    fn flag_combinations_are_checked_by_the_parser() {
        assert!(args(&[]).is_err(), "--name is required");
        assert!(
            args(&["--name", "j", "--join"]).is_err(),
            "--join needs --namespace and --services"
        );
        assert!(
            args(&["--name", "j", "--namespace", "demo"]).is_err(),
            "--namespace needs --join"
        );
        assert!(
            args(&[
                "--name",
                "j",
                "--join",
                "--namespace",
                "d",
                "--services",
                "o",
                "--role",
                "admin"
            ])
            .is_err(),
            "--role is for API tokens"
        );
        assert!(args(&["--name", "a", "--role", "root"]).is_err());
    }
}
