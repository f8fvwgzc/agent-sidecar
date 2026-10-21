//! `embassy serve` (design §8.1): the flags, their validation, and the wiring of the components.
//!
//! [`run`] is the entry point. Today it validates the flags, loads and validates the
//! `ControlPlaneConfig`, and stops with a "not implemented yet" error: the components are wired
//! here by the control-plane units (B3a: `controlplane`, `api`, `ui`; B3b: `ca`, `webhook`).
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::Args;

use crate::config::ControlPlaneConfig;
use crate::names::{ObjectRef, is_dns_label, is_dns_subdomain};

/// One component of `embassy serve --components` (design §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Component {
    /// `IssueCertificate` on `--grpc-addr`.
    Ca,
    /// Mutating and validating admission on `--webhook-addr`.
    Webhook,
    /// `Connect` on `--grpc-addr`.
    Controlplane,
    /// REST/SSE on `--http-addr`.
    Api,
    /// Static UI files on `--http-addr`.
    Ui,
}

impl Component {
    pub const ALL: [Component; 5] = [
        Component::Ca,
        Component::Webhook,
        Component::Controlplane,
        Component::Api,
        Component::Ui,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Component::Ca => "ca",
            Component::Webhook => "webhook",
            Component::Controlplane => "controlplane",
            Component::Api => "api",
            Component::Ui => "ui",
        }
    }
}

impl std::fmt::Display for Component {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The parsed `--components` list: a non-empty set (duplicates collapse).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentSet(pub BTreeSet<Component>);

impl ComponentSet {
    pub fn all() -> Self {
        Self(Component::ALL.into_iter().collect())
    }

    pub fn has(&self, c: Component) -> bool {
        self.0.contains(&c)
    }
}

impl std::str::FromStr for ComponentSet {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut set = BTreeSet::new();
        for part in s.split(',') {
            let part = part.trim();
            let c = Component::ALL
                .into_iter()
                .find(|c| c.as_str() == part)
                .ok_or_else(|| {
                    format!(
                        "unknown component {part:?} (expected ca, webhook, controlplane, api, ui)"
                    )
                })?;
            set.insert(c);
        }
        Ok(Self(set))
    }
}

impl std::fmt::Display for ComponentSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<_> = self.0.iter().map(|c| c.as_str()).collect();
        f.write_str(&names.join(","))
    }
}

/// `--store file:<dir> | kubernetes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreSpec {
    File(PathBuf),
    Kubernetes,
}

impl std::str::FromStr for StoreSpec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "kubernetes" {
            return Ok(Self::Kubernetes);
        }
        match s.strip_prefix("file:") {
            Some(dir) if !dir.is_empty() => Ok(Self::File(PathBuf::from(dir))),
            Some(_) => Err("file: needs a directory, e.g. file:/var/lib/attache".into()),
            None => Err(format!(
                "{s:?} is not a store (expected file:<dir> or kubernetes)"
            )),
        }
    }
}

fn parse_dns_name(s: &str) -> Result<String, String> {
    if is_dns_subdomain(s) {
        Ok(s.to_string())
    } else {
        Err(format!("{s:?} is not a DNS name"))
    }
}

/// Every flag of `embassy serve` (design §8.1).
#[derive(Debug, Clone, Args)]
pub struct ServeArgs {
    /// Comma-separated components to run: ca, webhook, controlplane, api, ui.
    #[arg(long, default_value = "ca,webhook,controlplane,api,ui")]
    pub components: ComponentSet,
    /// REST/SSE/UI listener.
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub http_addr: SocketAddr,
    /// ControlPlane and/or CertificateAuthority listener.
    #[arg(long, default_value = "0.0.0.0:15012")]
    pub grpc_addr: SocketAddr,
    /// Admission webhook listener.
    #[arg(long, default_value = "0.0.0.0:9443")]
    pub webhook_addr: SocketAddr,
    /// CA material in a directory (ca.crt may hold several roots; the first key-matching one signs).
    #[arg(long, conflicts_with = "ca_secret")]
    pub ca_dir: Option<PathBuf>,
    /// CA material in a Kubernetes Secret, <namespace>/<name>.
    #[arg(long)]
    pub ca_secret: Option<ObjectRef>,
    /// Where the ca component writes the serving certificate (Kubernetes Secret <namespace>/<name>).
    #[arg(long)]
    pub tls_secret: Option<ObjectRef>,
    /// Where the controlplane component reads the serving certificate (mounted Secret).
    #[arg(long)]
    pub tls_dir: Option<PathBuf>,
    /// file:<dir> or kubernetes.
    #[arg(long)]
    pub store: Option<StoreSpec>,
    /// ControlPlaneConfig file (reloaded on change).
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Serving-certificate DNS SAN and allowed Host header (repeatable).
    #[arg(long = "dns-name", value_parser = parse_dns_name)]
    pub dns_names: Vec<String>,
    /// Serve the HTTP API over TLS with the serving certificate.
    #[arg(long)]
    pub http_tls: bool,
    /// Adopt sidecar start-up charters automatically (file store only).
    #[arg(long)]
    pub auto_adopt: bool,
    /// The MutatingWebhookConfiguration whose caBundle is kept current.
    #[arg(long, default_value = "attache-sidecar-injector")]
    pub webhook_config_name: String,
    /// The ValidatingWebhookConfiguration whose caBundle is kept current.
    #[arg(long, default_value = "attache-charter-validator")]
    pub validating_webhook_name: String,
    /// Image injected as the attached sidecar.
    #[arg(long)]
    pub injector_image: Option<String>,
    /// The control plane's own namespace (never issued certificates, never injected).
    #[arg(long, default_value = "attache-system")]
    pub cp_namespace: String,
    /// Serve UI files from this directory instead of the embedded copy (development).
    #[arg(long)]
    pub ui_dir: Option<PathBuf>,
    /// Allow the anonymous viewer and write a one-time admin token to a 0600 file.
    #[arg(long)]
    pub dev: bool,
}

impl ServeArgs {
    pub fn has(&self, c: Component) -> bool {
        self.components.has(c)
    }

    /// Flag combinations that cannot work, each named. clap already refused unknown values,
    /// malformed addresses and `--ca-dir` with `--ca-secret`.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        use Component::*;
        let mut errs = Vec::new();
        if self.components.0.is_empty() {
            errs.push("--components is empty".into());
        }
        if !is_dns_label(&self.cp_namespace) {
            errs.push(format!(
                "--cp-namespace {:?} is not a DNS-1123 label",
                self.cp_namespace
            ));
        }
        for (flag, name) in [
            ("--webhook-config-name", &self.webhook_config_name),
            ("--validating-webhook-name", &self.validating_webhook_name),
        ] {
            if !is_dns_subdomain(name) {
                errs.push(format!("{flag} {name:?} is not a DNS-1123 subdomain"));
            }
        }

        let ca_material = self.ca_dir.is_some() || self.ca_secret.is_some();
        if self.has(Ca) && !ca_material {
            errs.push("the ca component needs --ca-dir or --ca-secret".into());
        }
        if !self.has(Ca) && ca_material {
            errs.push("--ca-dir and --ca-secret are only used by the ca component".into());
        }
        if self.tls_secret.is_some() && !self.has(Ca) {
            errs.push("--tls-secret is written by the ca component, which is not enabled".into());
        }

        // Serving certificate: the ca component makes one (in memory or in --tls-secret);
        // without it, the components that serve TLS read it from --tls-dir.
        let needs_serving_cert = self.has(Controlplane) || self.has(Webhook) || self.http_tls;
        if needs_serving_cert && !self.has(Ca) && self.tls_dir.is_none() {
            let users: Vec<&str> = [
                (self.has(Controlplane), "controlplane"),
                (self.has(Webhook), "webhook"),
                (self.http_tls, "--http-tls"),
            ]
            .into_iter()
            .filter_map(|(on, name)| on.then_some(name))
            .collect();
            errs.push(format!(
                "{} need(s) the serving certificate: run the ca component too or give --tls-dir",
                users.join(", ")
            ));
        }
        if self.http_tls && !(self.has(Api) || self.has(Ui)) {
            errs.push("--http-tls needs the api or ui component".into());
        }

        if (self.has(Controlplane) || self.has(Api)) && self.store.is_none() {
            errs.push(
                "the controlplane and api components need --store file:<dir> or --store kubernetes"
                    .into(),
            );
        }
        if self.has(Ca) && self.store.is_none() {
            // IssueCertificate admits a pod's service account only if it is the service's name
            // or listed in the stored charter's service.service_accounts (design §7).
            errs.push(
                "the ca component needs --store file:<dir> or --store kubernetes \
                 (IssueCertificate checks service.service_accounts in the stored charter)"
                    .into(),
            );
        }
        if self.auto_adopt {
            if !matches!(self.store, Some(StoreSpec::File(_))) {
                errs.push("--auto-adopt works only with --store file:<dir>".into());
            }
            if !self.has(Controlplane) {
                errs.push("--auto-adopt needs the controlplane component".into());
            }
        }
        if self.ui_dir.is_some() && !self.has(Ui) {
            errs.push("--ui-dir needs the ui component".into());
        }
        if self.dev && !(self.has(Api) || self.has(Ui)) {
            errs.push("--dev needs the api or ui component".into());
        }

        // Enabled listeners must not share an address.
        let mut listeners: Vec<(&str, SocketAddr)> = Vec::new();
        if self.has(Api) || self.has(Ui) {
            listeners.push(("--http-addr", self.http_addr));
        }
        if self.has(Ca) || self.has(Controlplane) {
            listeners.push(("--grpc-addr", self.grpc_addr));
        }
        if self.has(Webhook) {
            listeners.push(("--webhook-addr", self.webhook_addr));
        }
        for (i, (a, x)) in listeners.iter().enumerate() {
            for (b, y) in &listeners[i + 1..] {
                if x == y && x.port() != 0 {
                    errs.push(format!("{a} and {b} are both {x}"));
                }
            }
        }

        if errs.is_empty() { Ok(()) } else { Err(errs) }
    }

    /// The config `--config` names, validated; the built-in default without `--config`.
    pub fn load_config(&self) -> anyhow::Result<ControlPlaneConfig> {
        match &self.config {
            Some(path) => ControlPlaneConfig::load(path, &self.cp_namespace)
                .with_context(|| format!("--config {}", path.display())),
            None => Ok(ControlPlaneConfig::default()),
        }
    }
}

/// Run `embassy serve`.
pub async fn run(args: ServeArgs) -> anyhow::Result<()> {
    if let Err(errs) = args.validate() {
        bail!("embassy serve: invalid flags:\n  {}", errs.join("\n  "));
    }
    let config = args.load_config()?;
    tracing::info!(
        components = %args.components,
        tokens = config.auth.tokens.len(),
        join_tokens = config.issuance.join_tokens.len(),
        "configuration is valid"
    );
    bail!(
        "embassy serve is not implemented yet: the flags and the ControlPlaneConfig are valid, \
         but no component ({}) can be started in this build",
        args.components
    )
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

    fn parse(args: &[&str]) -> Result<ServeArgs, clap::Error> {
        Cli::try_parse_from(std::iter::once("serve").chain(args.iter().copied())).map(|c| c.serve)
    }

    fn errors(args: &[&str]) -> String {
        parse(args).unwrap().validate().unwrap_err().join("\n")
    }

    #[test]
    fn defaults_follow_the_design() {
        let a = parse(&[]).unwrap();
        assert_eq!(a.components, ComponentSet::all());
        assert_eq!(a.http_addr, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(a.grpc_addr, "0.0.0.0:15012".parse().unwrap());
        assert_eq!(a.webhook_addr, "0.0.0.0:9443".parse().unwrap());
        assert_eq!(a.webhook_config_name, "attache-sidecar-injector");
        assert_eq!(a.validating_webhook_name, "attache-charter-validator");
        assert_eq!(a.cp_namespace, "attache-system");
        assert!(a.store.is_none() && a.config.is_none() && a.dns_names.is_empty());
        assert!(!a.http_tls && !a.auto_adopt && !a.dev);
        // all components need CA material and a store
        let e = a.validate().unwrap_err().join("\n");
        assert!(
            e.contains("the ca component needs --ca-dir or --ca-secret"),
            "{e}"
        );
        assert!(e.contains("need --store"), "{e}");
    }

    #[test]
    fn every_flag_parses() {
        let a = parse(&[
            "--components",
            "api,ui,controlplane,api",
            "--http-addr",
            "[::1]:8081",
            "--grpc-addr",
            "127.0.0.1:15013",
            "--webhook-addr",
            "127.0.0.1:9444",
            "--ca-secret",
            "attache-system/attache-ca",
            "--tls-secret",
            "attache-system/embassy-tls",
            "--tls-dir",
            "/etc/attache/tls",
            "--store",
            "file:/var/lib/attache",
            "--config",
            "/etc/attache/config.yaml",
            "--dns-name",
            "embassy.attache-system.svc",
            "--dns-name",
            "localhost",
            "--http-tls",
            "--auto-adopt",
            "--webhook-config-name",
            "inj",
            "--validating-webhook-name",
            "val",
            "--injector-image",
            "ghcr.io/x/attached:0.2.0",
            "--cp-namespace",
            "attache-cp",
            "--ui-dir",
            "ui",
            "--dev",
        ])
        .unwrap();
        assert_eq!(
            a.components.0.iter().copied().collect::<Vec<_>>(),
            [Component::Controlplane, Component::Api, Component::Ui]
        );
        assert_eq!(a.components.to_string(), "controlplane,api,ui");
        assert_eq!(a.http_addr, "[::1]:8081".parse().unwrap());
        assert_eq!(a.ca_secret.as_ref().unwrap().name, "attache-ca");
        assert_eq!(
            a.tls_secret.as_ref().unwrap().to_string(),
            "attache-system/embassy-tls"
        );
        assert_eq!(a.store, Some(StoreSpec::File("/var/lib/attache".into())));
        assert_eq!(a.dns_names, ["embassy.attache-system.svc", "localhost"]);
        assert_eq!(
            a.injector_image.as_deref(),
            Some("ghcr.io/x/attached:0.2.0")
        );
        assert_eq!(a.cp_namespace, "attache-cp");
        assert!(a.http_tls && a.auto_adopt && a.dev);
        // CA material and --tls-secret without the ca component
        let e = a.validate().unwrap_err().join("\n");
        assert!(
            e.contains("--ca-dir and --ca-secret are only used by the ca component"),
            "{e}"
        );
        assert!(
            e.contains("--tls-secret is written by the ca component"),
            "{e}"
        );
    }

    #[test]
    fn bad_values_are_refused_by_the_parser() {
        for args in [
            &["--components", "ca,api,gateway"][..],
            &["--components", ""],
            &["--components", "ca,,api"],
            &["--store", "s3://bucket"],
            &["--store", "file:"],
            &["--ca-secret", "attache-ca"],
            &["--dns-name", "Bad_Name"],
            &["--http-addr", "localhost"],
            &["--ca-dir", "/ca", "--ca-secret", "ns/attache-ca"],
        ] {
            assert!(parse(args).is_err(), "{args:?} should be refused");
        }
        assert_eq!(
            parse(&["--store", "kubernetes"]).unwrap().store,
            Some(StoreSpec::Kubernetes)
        );
    }

    #[test]
    fn one_process_mode_is_valid() {
        // compose (design §14): all components, file store, auto-adopt
        let a = parse(&[
            "--ca-dir",
            "/data/ca",
            "--store",
            "file:/data/store",
            "--auto-adopt",
            "--http-addr",
            "0.0.0.0:8080",
        ])
        .unwrap();
        a.validate().unwrap();
    }

    #[test]
    fn helm_deployments_are_valid() {
        // embassy-ca: ca,webhook (design §2)
        parse(&[
            "--components",
            "ca,webhook",
            "--ca-secret",
            "attache-system/attache-ca",
            "--tls-secret",
            "attache-system/embassy-tls",
            "--store",
            "kubernetes",
            "--injector-image",
            "attache/attached:0.2.0",
        ])
        .unwrap()
        .validate()
        .unwrap();
        // embassy: controlplane,api,ui reading the mounted serving certificate
        parse(&[
            "--components",
            "controlplane,api,ui",
            "--tls-dir",
            "/etc/attache/tls",
            "--store",
            "kubernetes",
            "--http-addr",
            "0.0.0.0:8080",
        ])
        .unwrap()
        .validate()
        .unwrap();
    }

    #[test]
    fn incompatible_flags_are_named() {
        let e = errors(&["--components", "controlplane,api", "--store", "kubernetes"]);
        assert!(
            e.contains("controlplane need(s) the serving certificate"),
            "{e}"
        );

        let e = errors(&["--components", "webhook,ui", "--http-tls"]);
        assert!(
            e.contains("webhook, --http-tls need(s) the serving certificate"),
            "{e}"
        );

        let e = errors(&["--components", "ca", "--ca-dir", "/ca", "--http-tls"]);
        assert!(
            e.contains("--http-tls needs the api or ui component"),
            "{e}"
        );

        let e = errors(&[
            "--components",
            "ca,controlplane",
            "--ca-dir",
            "/ca",
            "--store",
            "kubernetes",
            "--auto-adopt",
        ]);
        assert!(
            e.contains("--auto-adopt works only with --store file:<dir>"),
            "{e}"
        );

        let e = errors(&["--components", "ca", "--ca-dir", "/ca", "--auto-adopt"]);
        assert!(
            e.contains("--auto-adopt needs the controlplane component"),
            "{e}"
        );

        let e = errors(&[
            "--components",
            "api",
            "--store",
            "kubernetes",
            "--ui-dir",
            "ui",
        ]);
        assert!(e.contains("--ui-dir needs the ui component"), "{e}");

        let e = errors(&["--components", "ca", "--ca-dir", "/ca", "--dev"]);
        assert!(e.contains("--dev needs the api or ui component"), "{e}");

        // IssueCertificate reads service.service_accounts from the stored charter
        for components in ["ca", "ca,webhook"] {
            let e = errors(&["--components", components, "--ca-dir", "/ca"]);
            assert!(
                e.contains("the ca component needs --store file:<dir> or --store kubernetes"),
                "{components}: {e}"
            );
            assert!(e.contains("service.service_accounts"), "{e}");
        }
        for store in ["kubernetes", "file:/data/store"] {
            parse(&["--components", "ca", "--ca-dir", "/ca", "--store", store])
                .unwrap()
                .validate()
                .unwrap();
        }
        // the webhook alone needs no store (validator and policy only)
        parse(&["--components", "webhook", "--tls-dir", "/tls"])
            .unwrap()
            .validate()
            .unwrap();

        let e = errors(&[
            "--components",
            "ca,webhook",
            "--ca-dir",
            "/ca",
            "--webhook-addr",
            "0.0.0.0:15012",
        ]);
        assert!(
            e.contains("--grpc-addr and --webhook-addr are both 0.0.0.0:15012"),
            "{e}"
        );

        let e = errors(&["--components", "ui", "--cp-namespace", "Attache"]);
        assert!(e.contains("--cp-namespace \"Attache\""), "{e}");

        let e = errors(&["--components", "ui", "--webhook-config-name", "a_b"]);
        assert!(e.contains("--webhook-config-name \"a_b\""), "{e}");
    }

    #[tokio::test]
    async fn run_validates_then_reports_not_implemented() {
        let bad = parse(&["--components", "ca"]).unwrap();
        let e = run(bad).await.unwrap_err().to_string();
        assert!(e.contains("invalid flags"), "{e}");

        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.yaml");
        std::fs::write(&cfg, "apiVersion: attache.io/v1alpha1\nkind: Charter\n").unwrap();
        let store = format!("file:{}", dir.path().display());
        let a = parse(&[
            "--components",
            "api",
            "--store",
            &store,
            "--config",
            cfg.to_str().unwrap(),
        ])
        .unwrap();
        let e = format!("{:#}", run(a).await.unwrap_err());
        assert!(e.contains("kind must be ControlPlaneConfig"), "{e}");

        std::fs::write(
            &cfg,
            "apiVersion: attache.io/v1alpha1\nkind: ControlPlaneConfig\n",
        )
        .unwrap();
        let a = parse(&[
            "--components",
            "api",
            "--store",
            &store,
            "--config",
            cfg.to_str().unwrap(),
        ])
        .unwrap();
        let e = run(a).await.unwrap_err().to_string();
        assert!(e.contains("not implemented yet"), "{e}");
        assert!(e.contains("(api)"), "{e}");
    }
}
