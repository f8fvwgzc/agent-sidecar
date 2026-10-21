use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

/// The default of `--peer-address-template` (design §6.1).
pub const DEFAULT_PEER_ADDRESS_TEMPLATE: &str = "{service}.{namespace}.svc.cluster.local:{port}";

/// attached — the attache sidecar (CONTRACT.md §2 and design §6.1 list every flag).
#[derive(Parser, Debug, Clone)]
#[command(name = "attached", version, about)]
pub struct Config {
    #[arg(
        long,
        env = "ATTACHE_CHARTER",
        default_value = "/etc/attache/charter/charter.yaml"
    )]
    pub charter: PathBuf,
    #[arg(long, env = "ATTACHE_TLS_DIR", default_value = "/etc/attache/tls")]
    pub tls_dir: PathBuf,
    #[arg(long, env = "ATTACHE_HTTP_ADDR", default_value = "127.0.0.1:3500")]
    pub http_addr: SocketAddr,
    #[arg(long, env = "ATTACHE_GRPC_ADDR", default_value = "127.0.0.1:50001")]
    pub grpc_addr: SocketAddr,
    #[arg(long, env = "ATTACHE_MESH_ADDR", default_value = "0.0.0.0:50002")]
    pub mesh_addr: SocketAddr,
    #[arg(long, env = "ATTACHE_SOCKET_DIR", default_value = "/run/attache")]
    pub socket_dir: PathBuf,
    /// Command that starts the agent runtime; `--listen` and `--sidecar` are appended.
    #[arg(long, env = "ATTACHE_RUNTIME_CMD", default_value = "attache-runtime")]
    pub runtime_cmd: String,
    /// Do not spawn the runtime (something else runs it, or tests). Env accepts 1/0, true/false, yes/no, on/off.
    #[arg(
        long,
        env = "ATTACHE_NO_RUNTIME",
        num_args = 0..=1,
        default_value = "false",
        default_missing_value = "true",
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    pub no_runtime: bool,

    /// Managed mode: the control plane's `Connect` address (`host:port`).
    #[arg(long, env = "ATTACHE_CONTROL_PLANE")]
    pub control_plane: Option<String>,
    /// `IssueCertificate` address (`host:port`); default: the control-plane address.
    #[arg(long, env = "ATTACHE_CA_ADDRESS")]
    pub ca_address: Option<String>,
    /// Managed mode: this pod's service (authoritative).
    #[arg(long, env = "ATTACHE_SERVICE")]
    pub service: Option<String>,
    /// Managed mode: this pod's namespace (authoritative).
    #[arg(long, env = "ATTACHE_NAMESPACE")]
    pub namespace: Option<String>,
    /// Managed mode: the app port (authoritative).
    #[arg(long, env = "ATTACHE_APP_PORT")]
    pub app_port: Option<u16>,
    /// Instance label sent to the control plane (default: the host name).
    #[arg(long, env = "POD_NAME")]
    pub pod_name: Option<String>,
    /// Trust roots (PEM file) for the control plane and the mesh when `--tls-dir` has no `ca.crt`.
    #[arg(long)]
    pub ca_file: Option<PathBuf>,
    /// The same as PEM text (env `ATTACHE_CA_PEM`).
    #[arg(
        long = "ca-pem",
        env = "ATTACHE_CA_PEM",
        hide = true,
        hide_env_values = true
    )]
    pub ca_pem: Option<String>,
    /// Projected service-account token for `IssueCertificate`, re-read for every request.
    #[arg(
        long,
        env = "ATTACHE_K8S_TOKEN_FILE",
        default_value = "/var/run/secrets/attache/token"
    )]
    pub k8s_token_file: PathBuf,
    /// Join token for `IssueCertificate` (outside Kubernetes), re-read for every request.
    #[arg(long, env = "ATTACHE_JOIN_TOKEN_FILE")]
    pub join_token_file: Option<PathBuf>,
    /// Persisted key, certificate, CA, last charter and memory (default `<socket-dir>/state`).
    #[arg(long, env = "ATTACHE_STATE_DIR")]
    pub state_dir: Option<PathBuf>,
    /// Require `Authorization: Bearer <token>` on the app HTTP and gRPC APIs (token in this file).
    #[arg(long)]
    pub app_token_file: Option<PathBuf>,
    /// The same as token text (env `ATTACHE_APP_TOKEN`).
    #[arg(
        long = "app-token",
        env = "ATTACHE_APP_TOKEN",
        hide = true,
        hide_env_values = true
    )]
    pub app_token: Option<String>,
    /// Mesh address of a peer that `mesh.peers` does not list.
    #[arg(
        long,
        env = "ATTACHE_PEER_ADDRESS_TEMPLATE",
        default_value = DEFAULT_PEER_ADDRESS_TEMPLATE
    )]
    pub peer_address_template: String,
    /// Charter `telemetry.otlp_endpoint` values allowed (globs, comma separated; empty = refused).
    #[arg(long, env = "ATTACHE_OTLP_ENDPOINT_ALLOW", value_delimiter = ',')]
    pub otlp_endpoint_allow: Vec<String>,

    /// Intervals and windows of design §6; tests shorten them.
    #[arg(skip)]
    pub timing: Timing,
}

/// The intervals and windows design §6 fixes. [`Default`] is the design's values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timing {
    /// How often the `--charter` file's content hash is checked (2 s).
    pub charter_poll: Duration,
    /// How long after an Execute returned its request id still takes `ReportEvent` model calls
    /// and `ProposeLesson` (120 s).
    pub run_window: Duration,
    /// Heartbeat interval on the `Connect` stream (10 s).
    pub heartbeat: Duration,
    /// Reconnect backoff bounds, full jitter (1 s .. 60 s).
    pub reconnect_min: Duration,
    pub reconnect_max: Duration,
    /// Pause between failed renewals, ± 20 % (60 s).
    pub renew_retry: Duration,
    /// An audit batch is sent after at most this long (1 s).
    pub audit_flush: Duration,
    /// Timeout of one `IssueCertificate` call (10 s).
    pub issue_timeout: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            charter_poll: Duration::from_secs(2),
            run_window: Duration::from_secs(120),
            heartbeat: Duration::from_secs(10),
            reconnect_min: Duration::from_secs(1),
            reconnect_max: Duration::from_secs(60),
            renew_retry: Duration::from_secs(60),
            audit_flush: Duration::from_secs(1),
            issue_timeout: Duration::from_secs(10),
        }
    }
}

fn non_empty(v: &Option<String>) -> Option<&str> {
    v.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

impl Config {
    /// A config for tests and local runs: everything on ephemeral localhost ports.
    pub fn for_test(charter: PathBuf, tls_dir: PathBuf, socket_dir: PathBuf) -> Self {
        Self {
            charter,
            tls_dir,
            http_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            grpc_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            mesh_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            socket_dir,
            runtime_cmd: "attache-runtime".into(),
            no_runtime: true,
            control_plane: None,
            ca_address: None,
            service: None,
            namespace: None,
            app_port: None,
            pod_name: None,
            ca_file: None,
            ca_pem: None,
            k8s_token_file: PathBuf::from("/var/run/secrets/attache/token"),
            join_token_file: None,
            state_dir: None,
            app_token_file: None,
            app_token: None,
            peer_address_template: DEFAULT_PEER_ADDRESS_TEMPLATE.into(),
            otlp_endpoint_allow: Vec::new(),
            timing: Timing::default(),
        }
    }

    /// Managed mode: a control-plane address is set (design §6.1).
    pub fn control_plane_addr(&self) -> Option<&str> {
        non_empty(&self.control_plane)
    }

    pub fn managed(&self) -> bool {
        self.control_plane_addr().is_some()
    }

    /// Where `IssueCertificate` is served: `--ca-address`, else the control plane.
    pub fn ca_addr(&self) -> Option<&str> {
        non_empty(&self.ca_address).or_else(|| self.control_plane_addr())
    }

    pub fn service_flag(&self) -> Option<&str> {
        non_empty(&self.service)
    }

    pub fn namespace_flag(&self) -> Option<&str> {
        non_empty(&self.namespace)
    }

    pub fn state_dir(&self) -> PathBuf {
        self.state_dir
            .clone()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| self.socket_dir.join("state"))
    }

    /// The instance label: `--pod-name`, else the host name.
    pub fn pod(&self) -> String {
        if let Some(p) = non_empty(&self.pod_name) {
            return p.to_string();
        }
        std::env::var("HOSTNAME")
            .ok()
            .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| "unknown".into())
    }

    /// `--otlp-endpoint-allow` without empty entries.
    pub fn otlp_allow(&self) -> Vec<String> {
        self.otlp_endpoint_allow
            .iter()
            .map(|g| g.trim().to_string())
            .filter(|g| !g.is_empty())
            .collect()
    }

    /// The trust roots for the control plane (and the mesh, when no `--tls-dir` CA exists), as
    /// PEM: `--tls-dir`'s `ca.crt`, else `--ca-file`, else `ATTACHE_CA_PEM`.
    pub fn trust_roots_pem(&self) -> anyhow::Result<Option<String>> {
        let tls_ca = self.tls_dir.join("ca.crt");
        if let Ok(pem) = std::fs::read_to_string(&tls_ca) {
            return Ok(Some(pem));
        }
        if let Some(path) = &self.ca_file {
            let pem = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("--ca-file {}: {e}", path.display()))?;
            return Ok(Some(pem));
        }
        Ok(non_empty(&self.ca_pem).map(str::to_string))
    }

    /// The app API token, from `--app-token-file` or `ATTACHE_APP_TOKEN` (design §6.6).
    pub fn app_token(&self) -> anyhow::Result<Option<String>> {
        if let Some(path) = &self.app_token_file {
            let text = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("--app-token-file {}: {e}", path.display()))?;
            let token = text.trim().to_string();
            anyhow::ensure!(
                !token.is_empty(),
                "--app-token-file {} is empty",
                path.display()
            );
            return Ok(Some(token));
        }
        Ok(non_empty(&self.app_token).map(str::to_string))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_runtime_accepts_the_documented_forms() {
        assert!(
            Config::try_parse_from(["attached", "--no-runtime"])
                .unwrap()
                .no_runtime
        );
        assert!(!Config::try_parse_from(["attached"]).unwrap().no_runtime);
        assert!(
            Config::try_parse_from(["attached", "--no-runtime", "1"])
                .unwrap()
                .no_runtime
        );
        assert!(
            !Config::try_parse_from(["attached", "--no-runtime", "0"])
                .unwrap()
                .no_runtime
        );
    }

    #[test]
    fn v02_flags_parse_with_their_defaults() {
        let c = Config::try_parse_from([
            "attached",
            "--control-plane",
            "embassy.attache-system.svc:15012",
            "--service",
            "orders",
            "--namespace",
            "shop",
            "--app-port",
            "8080",
            "--pod-name",
            "orders-0",
            "--ca-file",
            "/ca.crt",
            "--join-token-file",
            "/join",
            "--state-dir",
            "/state",
            "--app-token-file",
            "/token",
            "--peer-address-template",
            "{service}-sidecar:{port}",
            "--otlp-endpoint-allow",
            "http://otel-collector:4318,https://*.example",
        ])
        .unwrap();
        assert!(c.managed());
        assert_eq!(c.ca_addr(), Some("embassy.attache-system.svc:15012"));
        assert_eq!(c.service_flag(), Some("orders"));
        assert_eq!(c.namespace_flag(), Some("shop"));
        assert_eq!(c.app_port, Some(8080));
        assert_eq!(c.pod(), "orders-0");
        assert_eq!(c.state_dir(), PathBuf::from("/state"));
        assert_eq!(c.peer_address_template, "{service}-sidecar:{port}");
        assert_eq!(
            c.otlp_allow(),
            ["http://otel-collector:4318", "https://*.example"]
        );
        assert_eq!(
            c.k8s_token_file,
            PathBuf::from("/var/run/secrets/attache/token")
        );

        let d = Config::try_parse_from(["attached", "--socket-dir", "/run/x"]).unwrap();
        assert!(!d.managed());
        assert_eq!(d.state_dir(), PathBuf::from("/run/x/state"));
        assert_eq!(d.peer_address_template, DEFAULT_PEER_ADDRESS_TEMPLATE);
        assert!(d.otlp_allow().is_empty());
        assert_eq!(d.timing, Timing::default());

        let e = Config::try_parse_from([
            "attached",
            "--control-plane",
            "cp:15012",
            "--ca-address",
            "ca:15012",
        ])
        .unwrap();
        assert_eq!(e.ca_addr(), Some("ca:15012"));
    }
}
