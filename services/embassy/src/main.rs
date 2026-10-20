//! `embassy` — CA init, leaf issuance, and in-cluster bootstrap into Secrets (CONTRACT.md §5, §7).
use std::path::PathBuf;

use anyhow::Context;
use attache_pki::{PemBundle, TlsMaterial};
use base64::Engine;
use clap::{Parser, Subcommand};
use serde_json::{Value, json};

#[derive(Parser)]
#[command(name = "embassy", version, about = "attache control plane: cluster CA")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new CA (ca.crt, ca.key) in a directory.
    CaInit {
        #[arg(long)]
        out: PathBuf,
    },
    /// Issue a leaf certificate for a service (tls.crt, tls.key, ca.crt) into a directory.
    CertIssue {
        #[arg(long)]
        ca: PathBuf,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        service: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = attache_pki::LEAF_TTL_DAYS)]
        ttl_days: i64,
    },
    /// In-cluster: ensure the CA Secret exists and (re)issue one Secret per service.
    Bootstrap {
        #[arg(long, env = "ATTACHE_NAMESPACE")]
        namespace: String,
        /// Comma-separated service names.
        #[arg(long, env = "ATTACHE_SERVICES", value_delimiter = ',')]
        services: Vec<String>,
        #[arg(long, default_value = "attache-ca")]
        ca_secret: String,
        #[arg(long, default_value = "attache-cert-")]
        cert_secret_prefix: String,
        #[arg(long, default_value = "https://kubernetes.default.svc")]
        api_server: String,
    },
}

fn read_bundle(dir: &std::path::Path) -> anyhow::Result<PemBundle> {
    Ok(PemBundle {
        cert_pem: std::fs::read_to_string(dir.join("ca.crt"))
            .with_context(|| format!("read {}/ca.crt", dir.display()))?,
        key_pem: std::fs::read_to_string(dir.join("ca.key"))
            .with_context(|| format!("read {}/ca.key", dir.display()))?,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();
    match Cli::parse().cmd {
        Cmd::CaInit { out } => {
            let ca = attache_pki::ca_init()?;
            std::fs::create_dir_all(&out)?;
            std::fs::write(out.join("ca.crt"), &ca.cert_pem)?;
            std::fs::write(out.join("ca.key"), &ca.key_pem)?;
            println!("CA written to {}", out.display());
        }
        Cmd::CertIssue {
            ca,
            namespace,
            service,
            out,
            ttl_days,
        } => {
            let ca = read_bundle(&ca)?;
            let leaf = attache_pki::issue_leaf(&ca, &namespace, &service, ttl_days)?;
            TlsMaterial::write(&leaf, &ca.cert_pem, &out)?;
            println!(
                "issued spiffe://attache/ns/{namespace}/svc/{service} into {}",
                out.display()
            );
        }
        Cmd::Bootstrap {
            namespace,
            services,
            ca_secret,
            cert_secret_prefix,
            api_server,
        } => {
            bootstrap(
                &namespace,
                &services,
                &ca_secret,
                &cert_secret_prefix,
                &api_server,
            )
            .await?;
        }
    }
    Ok(())
}

/// Minimal Kubernetes client: service-account token + cluster CA, Secrets only.
struct Kube {
    http: reqwest::Client,
    base: String,
    token: String,
    namespace: String,
}

impl Kube {
    fn in_cluster(api_server: &str, namespace: &str) -> anyhow::Result<Self> {
        let sa = "/var/run/secrets/kubernetes.io/serviceaccount";
        let token =
            std::fs::read_to_string(format!("{sa}/token")).context("read service account token")?;
        let ca = std::fs::read(format!("{sa}/ca.crt")).context("read cluster CA")?;
        let http = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
            .build()?;
        Ok(Self {
            http,
            base: api_server.trim_end_matches('/').to_string(),
            token: token.trim().to_string(),
            namespace: namespace.into(),
        })
    }

    async fn get_secret(&self, name: &str) -> anyhow::Result<Option<Value>> {
        let url = format!(
            "{}/api/v1/namespaces/{}/secrets/{name}",
            self.base, self.namespace
        );
        let resp = self.http.get(&url).bearer_auth(&self.token).send().await?;
        match resp.status().as_u16() {
            200 => Ok(Some(resp.json().await?)),
            404 => Ok(None),
            s => anyhow::bail!("GET {url}: {s} {}", resp.text().await.unwrap_or_default()),
        }
    }

    async fn upsert_secret(
        &self,
        name: &str,
        data: &[(&str, &str)],
        labels: Value,
    ) -> anyhow::Result<()> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let data: serde_json::Map<String, Value> = data
            .iter()
            .map(|(k, v)| (k.to_string(), Value::String(b64.encode(v))))
            .collect();
        let body = json!({
            "apiVersion": "v1", "kind": "Secret", "type": "Opaque",
            "metadata": { "name": name, "namespace": self.namespace, "labels": labels },
            "data": data,
        });
        let exists = self.get_secret(name).await?.is_some();
        let (method, url) = if exists {
            (
                reqwest::Method::PUT,
                format!(
                    "{}/api/v1/namespaces/{}/secrets/{name}",
                    self.base, self.namespace
                ),
            )
        } else {
            (
                reqwest::Method::POST,
                format!("{}/api/v1/namespaces/{}/secrets", self.base, self.namespace),
            )
        };
        let resp = self
            .http
            .request(method.clone(), &url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!(
                "{method} {url}: {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }
        Ok(())
    }
}

fn secret_field(secret: &Value, key: &str) -> Option<String> {
    let b64 = base64::engine::general_purpose::STANDARD;
    secret
        .get("data")?
        .get(key)?
        .as_str()
        .and_then(|s| b64.decode(s).ok())
        .and_then(|b| String::from_utf8(b).ok())
}

async fn bootstrap(
    namespace: &str,
    services: &[String],
    ca_secret: &str,
    prefix: &str,
    api_server: &str,
) -> anyhow::Result<()> {
    if services.is_empty() {
        anyhow::bail!("--services is required");
    }
    let kube = Kube::in_cluster(api_server, namespace)?;
    let labels =
        json!({ "app.kubernetes.io/managed-by": "embassy", "attache.io/component": "pki" });
    let ca = match kube.get_secret(ca_secret).await? {
        Some(existing) => match (
            secret_field(&existing, "ca.crt"),
            secret_field(&existing, "ca.key"),
        ) {
            (Some(cert_pem), Some(key_pem)) => {
                tracing::info!(secret = ca_secret, "reusing existing CA");
                PemBundle { cert_pem, key_pem }
            }
            _ => anyhow::bail!("secret {ca_secret} exists but lacks ca.crt/ca.key"),
        },
        None => {
            let ca = attache_pki::ca_init()?;
            kube.upsert_secret(
                ca_secret,
                &[("ca.crt", &ca.cert_pem), ("ca.key", &ca.key_pem)],
                labels.clone(),
            )
            .await?;
            tracing::info!(secret = ca_secret, "created new CA");
            ca
        }
    };
    for service in services {
        let leaf = attache_pki::issue_leaf(&ca, namespace, service, attache_pki::LEAF_TTL_DAYS)?;
        let name = format!("{prefix}{service}");
        let mut l = labels.clone();
        l["attache.io/service"] = json!(service);
        kube.upsert_secret(
            &name,
            &[
                ("ca.crt", &ca.cert_pem),
                ("tls.crt", &leaf.cert_pem),
                ("tls.key", &leaf.key_pem),
            ],
            l,
        )
        .await?;
        tracing::info!(secret = %name, identity = %attache_common::identity::SpiffeId { namespace: namespace.into(), service: service.clone() }.uri(), "issued");
    }
    println!(
        "bootstrap complete: CA {ca_secret}, {} leaf secret(s)",
        services.len()
    );
    Ok(())
}
