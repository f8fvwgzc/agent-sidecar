//! A real `tutelad` (Tutela v0.2.0) on a real PostgreSQL, for the tests of attache's service mode
//! (crate::tutela, #24, #25). Each test gets its own database and its own `tutelad` process.
//!
//! The deployment is made as an operator makes it (Tutela MIGRATION-0.2.md, CONTRACTS.md 7.13.9):
//! `tutelad migrate` as the owner role (migrations 1 to 14 and `grant_service`); the app manifest
//! with `tutela apply`, approved by a registered approver key (it adds the role `agent_admin`,
//! which holds only `org:manage_agents`); `tutelad bootstrap` for two tenants, each with an app
//! `attache` (`agent_admin` at the org) and an app `other` (`viewer`); then `tutelad serve`.
//!
//! - `ATTACHE_TUTELAD_BIN`: the `tutelad` binary. `ATTACHE_TUTELA_BIN`: the `tutela` CLI (default:
//!   `tutela` next to `tutelad`).
//! - `ATTACHE_TUTELAD_DATABASE_URL` (default `AGENTSC_TEST_POSTGRES_URL`): a `postgres://` URL of
//!   a role that may create roles and databases, on loopback.
//! - Without them a test says so and passes, unless `ATTACHE_REQUIRE_TUTELAD=1`: then it fails.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Test values only.
pub const MASTER_KEY: &str = "6d61737465722d6b65792d666f722d74657374732d6f6e6c792d303030303031";
pub const PEPPER: &str = "7065707065722d666f722d74657374732d6f6e6c792d30303030303030303031";
const OWNER: &str = "attache_tutela_owner";
const SERVICE: &str = "attache_tutela_service";

/// The app manifest: one role that holds `org:manage_agents` and nothing else.
pub const MANIFEST: &str = r#"version = 1

[app]
name = "attache"

[roles.agent_admin]
label = "Agent admin"
grants = { "org:manage_agents" = true }
assignable_to = ["sa"]
"#;

/// The audiences of the trust file besides `tutela-authz` (which is delegation-aware).
pub const DELEGATION_AWARE: &str = "symphony";
pub const NOT_DELEGATION_AWARE: &str = "crm-api";
/// attache's own audience: people's tokens reach attache addressed to it (delegation-aware).
pub const ATTACHE: &str = "attache";

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A free port on loopback (bound and let go: a test-only race).
pub fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

struct Env_ {
    tutelad: PathBuf,
    tutela: PathBuf,
    base: url::Url,
}

fn env() -> Option<Env_> {
    let required = std::env::var("ATTACHE_REQUIRE_TUTELAD").as_deref() == Ok("1");
    let bin = std::env::var("ATTACHE_TUTELAD_BIN")
        .ok()
        .filter(|s| !s.is_empty());
    let db = std::env::var("ATTACHE_TUTELAD_DATABASE_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("AGENTSC_TEST_POSTGRES_URL")
                .ok()
                .filter(|s| !s.is_empty())
        });
    let (Some(bin), Some(db)) = (bin, db) else {
        assert!(
            !required,
            "ATTACHE_REQUIRE_TUTELAD=1 but ATTACHE_TUTELAD_BIN or ATTACHE_TUTELAD_DATABASE_URL \
             (or AGENTSC_TEST_POSTGRES_URL) is not set"
        );
        eprintln!(
            "skipped: set ATTACHE_TUTELAD_BIN and ATTACHE_TUTELAD_DATABASE_URL to run the tutelad tests"
        );
        return None;
    };
    let tutelad = PathBuf::from(bin);
    let tutela = std::env::var("ATTACHE_TUTELA_BIN")
        .ok()
        .filter(|s| !s.is_empty())
        .map_or_else(|| tutelad.with_file_name("tutela"), PathBuf::from);
    for b in [&tutelad, &tutela] {
        assert!(b.is_file(), "{} is not a file", b.display());
    }
    Some(Env_ {
        tutelad,
        tutela,
        base: url::Url::parse(&db).expect("a postgres:// URL"),
    })
}

/// A key=value connection string on the base server, for `db` as `user`.
fn conn_string(base: &url::Url, db: &str, user: &str, password: &str) -> String {
    format!(
        "host={} port={} dbname={db} user={user} password={password} sslmode=disable",
        base.host_str().unwrap_or("127.0.0.1"),
        base.port().unwrap_or(5432)
    )
}

async fn connect(conn: &str) -> tokio_postgres::Client {
    let (client, c) = tokio_postgres::connect(conn, tokio_postgres::NoTls)
        .await
        .expect("connect to the test PostgreSQL");
    tokio::spawn(async move {
        let _ = c.await;
    });
    client
}

async fn make_role(admin: &tokio_postgres::Client, role: &str) {
    let exists = admin
        .query_opt("SELECT 1 FROM pg_roles WHERE rolname = $1", &[&role])
        .await
        .unwrap()
        .is_some();
    if !exists {
        // two tests may race to make it; one wins
        let _ = admin
            .batch_execute(&format!(
                "CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{role}'"
            ))
            .await;
    }
}

/// A person's identity provider, shaped like Keycloak: an external issuer of `tutelad`'s trust
/// file, ES256, `typ: JWT`. Its JWKS is served on loopback.
pub struct Idp {
    pub iss: String,
    key: Arc<EcdsaKeyPair>,
    kid: String,
}

impl Idp {
    async fn start() -> Idp {
        let key = Arc::new(EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap());
        let p = key.public_key().as_ref();
        let (x, y) = (B64.encode(&p[1..33]), B64.encode(&p[33..65]));
        let thumb = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
        let kid = B64.encode(Sha256::digest(thumb.as_bytes()));
        let jwks = json!({"keys": [{"kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": kid,
                                    "alg": "ES256", "use": "sig"}]});
        let app = axum::Router::new().route(
            "/idp/jwks",
            axum::routing::get(move || {
                let j = jwks.clone();
                async move { axum::Json(j) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        Idp {
            iss: format!("http://{addr}/idp"),
            key,
            kid,
        }
    }

    /// A person's access token for `tutelad` (`aud=tutela-authz`), `life` seconds long.
    pub fn person(&self, sub: &str, life: u64) -> String {
        let t = now();
        let claims = json!({"iss": self.iss, "sub": sub, "aud": "tutela-authz", "azp": "people-app",
                            "iat": t, "exp": t + life, "jti": uuid::Uuid::now_v7().to_string()});
        let header = json!({"typ": "JWT", "alg": "ES256", "kid": self.kid});
        let input = format!(
            "{}.{}",
            B64.encode(header.to_string()),
            B64.encode(claims.to_string())
        );
        let sig = self
            .key
            .sign(&SystemRandom::new(), input.as_bytes())
            .unwrap();
        format!("{input}.{}", B64.encode(sig.as_ref()))
    }
}

/// One tenant of the deployment.
#[derive(Debug, Clone)]
pub struct Tenant {
    pub tid: String,
    /// The credentials of the app `attache` (`agent_admin` at the org).
    pub attache: PathBuf,
    /// The credentials of the app `other` (`viewer`: no admin key).
    pub other: PathBuf,
    /// The credentials of the app `owner` (the seeded `owner`: every admin key), for what a
    /// tenant's admin does in a test (revoke a person).
    pub owner: PathBuf,
}

/// A running `tutelad`.
pub struct Tutelad {
    pub url: String,
    pub ops: String,
    pub a: Tenant,
    pub b: Tenant,
    pub idp: Idp,
    /// The issuer embassy's agent tokens name (its trust file entry), and its JWKS.
    pub embassy_iss: String,
    pub dir: tempfile::TempDir,
    bin: PathBuf,
    port: u16,
    ops_port: u16,
    service_url: String,
    child: Option<tokio::process::Child>,
    admin: tokio_postgres::Client,
    db: String,
    base: url::Url,
    extra: Vec<(String, String)>,
}

async fn run(bin: &Path, args: &[&str], envs: &[(&str, &str)]) -> String {
    let out = tokio::process::Command::new(bin)
        .args(args)
        .envs(envs.iter().copied())
        .output()
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "{} {args:?} failed: {}\n{text}",
        bin.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    text
}

impl Tutelad {
    /// A deployment whose trust file lists `embassy_port`'s agent-token issuer
    /// (`http://127.0.0.1:<port>`, JWKS at `/.well-known/agent-jwks.json`) for tenant A.
    pub async fn start(embassy_port: u16) -> Option<Tutelad> {
        Self::start_with(embassy_port, Vec::new()).await
    }

    /// [`Tutelad::start`] with more settings for `tutelad serve` (forwarding to the ledger).
    pub async fn start_with(embassy_port: u16, extra: Vec<(String, String)>) -> Option<Tutelad> {
        let e = env()?;
        let dir = tempfile::tempdir().unwrap();
        let admin = connect(&conn_string(
            &e.base,
            e.base.path().trim_start_matches('/'),
            e.base.username(),
            e.base.password().unwrap_or(""),
        ))
        .await;
        make_role(&admin, OWNER).await;
        make_role(&admin, SERVICE).await;
        let db = format!("attache_tutela_{}", uuid::Uuid::now_v7().simple());
        admin
            .batch_execute(&format!("CREATE DATABASE {db} OWNER {OWNER}"))
            .await
            .unwrap();
        let owner_url = conn_string(&e.base, &db, OWNER, OWNER);
        let service_url = conn_string(&e.base, &db, SERVICE, SERVICE);
        let (port, ops_port) = (free_port(), free_port());
        let url = format!("http://127.0.0.1:{port}");
        let idp = Idp::start().await;
        let owner_env = [
            ("TUTELA_OWNER_DATABASE_URL", owner_url.as_str()),
            ("TUTELA_SERVICE_ROLE", SERVICE),
            ("TUTELA_DATABASE_URL", owner_url.as_str()),
            ("TUTELA_ISSUER", url.as_str()),
            ("TUTELA_MASTER_KEY", MASTER_KEY),
            ("TUTELA_KEY_PEPPER", PEPPER),
            ("TUTELA_DEV_MODE", "1"),
        ];
        run(&e.tutelad, &["migrate"], &owner_env).await;
        // the app manifest, approved as a widening change must be
        let manifest = dir.path().join("tutela.resources.toml");
        std::fs::write(&manifest, MANIFEST).unwrap();
        let key = dir.path().join("approver.key");
        let keygen = run(
            &e.tutela,
            &["approvers", "keygen", "--out", key.to_str().unwrap()],
            &[],
        )
        .await;
        let public = keygen
            .lines()
            .find_map(|l| l.strip_prefix("public key:"))
            .unwrap()
            .trim()
            .to_string();
        run(
            &e.tutela,
            &[
                "approvers",
                "add",
                "--name",
                "harness",
                "--public-key",
                &public,
            ],
            &owner_env,
        )
        .await;
        let digest = hex::encode(Sha256::digest(MANIFEST.as_bytes()));
        let approval = run(
            &e.tutela,
            &[
                "approve",
                "--app",
                "attache",
                "--from",
                "none",
                "--to",
                &digest,
                "--key",
                key.to_str().unwrap(),
            ],
            &[],
        )
        .await;
        run(
            &e.tutela,
            &[
                "apply",
                "--file",
                manifest.to_str().unwrap(),
                "--approval",
                approval.trim(),
            ],
            &owner_env,
        )
        .await;
        // two tenants, each with its apps
        let secrets = dir.path().join("secrets");
        std::fs::create_dir(&secrets).unwrap();
        let mut tenants = Vec::new();
        for name in ["a", "b"] {
            let tid = run(&e.tutelad, &["tenant", "new-id"], &[])
                .await
                .trim()
                .to_string();
            let plan = json!({
                "tenant": {"id": tid, "name": format!("tenant-{name}"),
                           "admin_upstream": [format!("{}=owner-{name}", idp.iss)]},
                "apps": [
                    {"name": "attache", "secret": format!("{name}-attache"),
                     "roles": [{"role": "agent_admin", "scope": "org"}]},
                    {"name": "other", "secret": format!("{name}-other"),
                     "roles": [{"role": "viewer", "scope": "org"}]},
                    {"name": "owner", "secret": format!("{name}-owner"),
                     "roles": [{"role": "owner", "scope": "org"}]},
                ],
            });
            let plan_file = dir.path().join(format!("plan-{name}.json"));
            std::fs::write(&plan_file, plan.to_string()).unwrap();
            run(
                &e.tutelad,
                &[
                    "bootstrap",
                    "--plan",
                    plan_file.to_str().unwrap(),
                    "--secrets-dir",
                    secrets.to_str().unwrap(),
                ],
                &owner_env,
            )
            .await;
            tenants.push(Tenant {
                tid,
                attache: secrets.join(format!("{name}-attache.json")),
                other: secrets.join(format!("{name}-other.json")),
                owner: secrets.join(format!("{name}-owner.json")),
            });
        }
        let (a, b) = (tenants[0].clone(), tenants[1].clone());
        let embassy_iss = format!("http://127.0.0.1:{embassy_port}");
        let trust = format!(
            r#"[[issuer]]
iss = "{idp}"
jwks_uri = "{idp}/jwks"
algs = ["ES256"]
tenants = ["{a}"]
external = true
allow_typ_jwt = true

[[issuer]]
iss = "{emb}"
jwks_uri = "{emb}/.well-known/agent-jwks.json"
algs = ["ES256"]
tenants = ["{a}"]

[[audience]]
name = "{aware}"
delegation_aware = true

[[audience]]
name = "{unaware}"
delegation_aware = false

[[audience]]
name = "{attache}"
delegation_aware = true
"#,
            idp = idp.iss,
            emb = embassy_iss,
            a = a.tid,
            aware = DELEGATION_AWARE,
            unaware = NOT_DELEGATION_AWARE,
            attache = ATTACHE,
        );
        std::fs::write(dir.path().join("trust.toml"), trust).unwrap();
        let mut t = Tutelad {
            ops: format!("http://127.0.0.1:{ops_port}"),
            url,
            a,
            b,
            idp,
            embassy_iss,
            bin: e.tutelad,
            port,
            ops_port,
            service_url,
            child: None,
            admin,
            db,
            base: e.base.clone(),
            extra,
            dir,
        };
        t.serve().await;
        Some(t)
    }

    /// Start `tutelad serve` (again, on the same port and database) and wait until it is ready.
    pub async fn serve(&mut self) {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.path().join("tutelad.log"))
            .unwrap();
        let child = tokio::process::Command::new(&self.bin)
            .arg("serve")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("TUTELA_DATABASE_URL", &self.service_url)
            .env("TUTELA_TRUST_FILE", self.dir.path().join("trust.toml"))
            .env("TUTELA_ISSUER", &self.url)
            .env("TUTELA_MASTER_KEY", MASTER_KEY)
            .env("TUTELA_KEY_PEPPER", PEPPER)
            .env("TUTELA_DEV_MODE", "1")
            .env("TUTELA_LISTEN", format!("127.0.0.1:{}", self.port))
            .env("TUTELA_OPS_LISTEN", format!("127.0.0.1:{}", self.ops_port))
            .env("TUTELA_REVISION_CHECK_MS", "200")
            .env("TUTELA_SHUTDOWN_DRAIN_SECS", "0")
            .env("TUTELA_LOG", "info")
            .envs(self.extra.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        self.child = Some(child);
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        let start = std::time::Instant::now();
        loop {
            if let Ok(r) = http.get(format!("{}/readyz", self.ops)).send().await
                && r.status().is_success()
            {
                return;
            }
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "tutelad did not get ready:\n{}",
                self.log()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Stop `tutelad serve` (the database stays).
    pub async fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill().await;
            let _ = c.wait().await;
        }
    }

    /// A superuser connection to this deployment's database (row-level security does not apply).
    pub async fn superuser(&self) -> tokio_postgres::Client {
        connect(&conn_string(
            &self.base,
            &self.db,
            self.base.username(),
            self.base.password().unwrap_or(""),
        ))
        .await
    }

    /// Per audit chain (a tenant id, or the deployment's): its last `seq`, and how far the
    /// forwarder has shipped it (0 before any).
    pub async fn audit_heads(&self) -> std::collections::BTreeMap<String, (i64, i64)> {
        let db = self.superuser().await;
        let rows = db
            .query(
                "SELECT r.tenant_id, max(r.seq), coalesce(max(f.shipped_seq), 0) \
                 FROM tutela.audit_record r LEFT JOIN tutela.audit_forward f \
                 ON f.tenant_id = r.tenant_id GROUP BY r.tenant_id",
                &[],
            )
            .await
            .unwrap();
        rows.iter()
            .map(|r| (r.get::<_, String>(0), (r.get(1), r.get(2))))
            .collect()
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("tutelad.log")).unwrap_or_default()
    }

    /// Stop and drop the database.
    pub async fn finish(mut self) {
        self.stop().await;
        let _ = self
            .admin
            .batch_execute(&format!("DROP DATABASE {} WITH (FORCE)", self.db))
            .await;
    }

    /// `tutela` for embassy: the app `attache` of tenant A, loopback.
    pub fn config(&self, creds: &Path) -> embassy::config::TutelaConfig {
        serde_json::from_value(json!({
            "credentials": creds,
            "url": self.url,
            "dev_loopback": true,
            "sync_seconds": 5,
        }))
        .unwrap()
    }

    /// A person's token from the IdP, exchanged at `tutelad` (no client authentication, as a
    /// browser app does) for a `tutelad` access token (`aud=tutela-authz`).
    pub async fn person_token(&self, sub: &str) -> String {
        let r = self
            .post_form(&[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                ("subject_token", &self.idp.person(sub, 600)),
                (
                    "subject_token_type",
                    "urn:ietf:params:oauth:token-type:access_token",
                ),
                ("audience", "tutela-authz"),
            ])
            .await;
        assert_eq!(r.0, 200, "{}", r.1);
        r.1["access_token"].as_str().unwrap().to_string()
    }

    /// A person's token for `audience`, as an app hands it to attache: the IdP's token (`life`
    /// seconds) exchanged at `tutelad` with no client authentication, kept as `azp`
    /// `people-app` (no app of the tenant, so attache's app may exchange it again).
    pub async fn person_token_for(&self, sub: &str, audience: &str, life: u64) -> String {
        let r = self
            .post_form(&[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                ("subject_token", &self.idp.person(sub, life)),
                (
                    "subject_token_type",
                    "urn:ietf:params:oauth:token-type:access_token",
                ),
                ("audience", audience),
            ])
            .await;
        assert_eq!(r.0, 200, "{}", r.1);
        r.1["access_token"].as_str().unwrap().to_string()
    }

    /// `POST /oauth2/token` with no client authentication: status and JSON.
    pub async fn post_form(&self, form: &[(&str, &str)]) -> (u16, Value) {
        let mut ser = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in form {
            ser.append_pair(k, v);
        }
        let body = ser.finish();
        let r = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post(format!("{}/oauth2/token", self.url))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        (status, r.json().await.unwrap_or(Value::Null))
    }

    /// `GET /v1/whoami` with `token`: its status.
    pub async fn whoami(&self, token: &str) -> u16 {
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("{}/v1/whoami", self.url))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    }

    /// Wait until `whoami(token)` is `want`, at most 3 s (`TUTELA_REVISION_CHECK_MS` is 200).
    pub async fn until_whoami(&self, token: &str, want: u16) {
        let start = std::time::Instant::now();
        loop {
            let got = self.whoami(token).await;
            if got == want {
                return;
            }
            assert!(
                start.elapsed() < Duration::from_secs(3),
                "whoami is {got}, not {want}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

/// The claims of a JWT, unverified (to look at what a test got).
pub fn claims(token: &str) -> Value {
    let part = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&B64.decode(part).unwrap()).unwrap()
}
