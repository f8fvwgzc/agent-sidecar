use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

/// The default of `--max-response-bytes`: 3 MiB.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 3 * 1024 * 1024;
/// The default of `--peer-address-template` (design §6.1). `{cluster_domain}` is
/// `--cluster-domain` (`cluster.local` unless set).
pub const DEFAULT_PEER_ADDRESS_TEMPLATE: &str = "{service}.{namespace}.svc.{cluster_domain}:{port}";

/// agentscd — the agentsc sidecar (CONTRACT.md §2 and design §6.1 list every flag).
#[derive(Parser, Debug, Clone)]
#[command(name = "agentscd", version, about)]
pub struct Config {
    #[arg(
        long,
        env = "AGENTSC_CHARTER",
        default_value = "/etc/agentsc/charter/charter.yaml"
    )]
    pub charter: PathBuf,
    #[arg(long, env = "AGENTSC_TLS_DIR", default_value = "/etc/agentsc/tls")]
    pub tls_dir: PathBuf,
    #[arg(long, env = "AGENTSC_HTTP_ADDR", default_value = "127.0.0.1:3500")]
    pub http_addr: SocketAddr,
    #[arg(long, env = "AGENTSC_GRPC_ADDR", default_value = "127.0.0.1:50001")]
    pub grpc_addr: SocketAddr,
    #[arg(long, env = "AGENTSC_MESH_ADDR", default_value = "0.0.0.0:50002")]
    pub mesh_addr: SocketAddr,
    #[arg(long, env = "AGENTSC_SOCKET_DIR", default_value = "/run/agentsc")]
    pub socket_dir: PathBuf,
    /// Command that starts the agent runtime; `--listen` and `--sidecar` are appended.
    #[arg(long, env = "AGENTSC_RUNTIME_CMD", default_value = "agentsc-runtime")]
    pub runtime_cmd: String,
    /// Do not spawn the runtime (something else runs it, or tests). Env accepts 1/0, true/false, yes/no, on/off.
    #[arg(
        long,
        env = "AGENTSC_NO_RUNTIME",
        num_args = 0..=1,
        default_value = "false",
        default_missing_value = "true",
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    pub no_runtime: bool,

    /// Managed mode: the control plane's `Connect` address (`host:port`).
    #[arg(long, env = "AGENTSC_CONTROL_PLANE")]
    pub control_plane: Option<String>,
    /// `IssueCertificate` address (`host:port`); default: the control-plane address.
    #[arg(long, env = "AGENTSC_CA_ADDRESS")]
    pub ca_address: Option<String>,
    /// Managed mode: this pod's service (authoritative).
    #[arg(long, env = "AGENTSC_SERVICE")]
    pub service: Option<String>,
    /// Managed mode: this pod's namespace (authoritative).
    #[arg(long, env = "AGENTSC_NAMESPACE")]
    pub namespace: Option<String>,
    /// Managed mode: the app port (authoritative).
    #[arg(long, env = "AGENTSC_APP_PORT")]
    pub app_port: Option<u16>,
    /// Instance label sent to the control plane (default: the host name).
    #[arg(long, env = "POD_NAME")]
    pub pod_name: Option<String>,
    /// Trust roots (PEM file) for the control plane and the mesh when `--tls-dir` has no `ca.crt`.
    #[arg(long)]
    pub ca_file: Option<PathBuf>,
    /// The same as PEM text (env `AGENTSC_CA_PEM`).
    #[arg(
        long = "ca-pem",
        env = "AGENTSC_CA_PEM",
        hide = true,
        hide_env_values = true
    )]
    pub ca_pem: Option<String>,
    /// Projected service-account token for `IssueCertificate`, re-read for every request.
    #[arg(
        long,
        env = "AGENTSC_K8S_TOKEN_FILE",
        default_value = "/var/run/secrets/agentsc/token"
    )]
    pub k8s_token_file: PathBuf,
    /// Join token for `IssueCertificate` (outside Kubernetes), re-read for every request.
    #[arg(long, env = "AGENTSC_JOIN_TOKEN_FILE")]
    pub join_token_file: Option<PathBuf>,
    /// Persisted key, certificate, CA, last charter and memory (default `<socket-dir>/state`).
    #[arg(long, env = "AGENTSC_STATE_DIR")]
    pub state_dir: Option<PathBuf>,
    /// Require `Authorization: Bearer <token>` on the app HTTP and gRPC APIs (token in this file).
    #[arg(long)]
    pub app_token_file: Option<PathBuf>,
    /// The same as token text, from env `AGENTSC_APP_TOKEN` only: a secret never goes on the
    /// command line, where process listings show it (design §6.1 defines no such flag).
    #[arg(skip = std::env::var(APP_TOKEN_ENV).ok())]
    pub app_token: Option<String>,
    /// Mesh address of a peer that `mesh.peers` does not list.
    #[arg(
        long,
        env = "AGENTSC_PEER_ADDRESS_TEMPLATE",
        default_value = DEFAULT_PEER_ADDRESS_TEMPLATE
    )]
    pub peer_address_template: String,
    /// The SPIFFE trust domain of this install: own identity, peers' and the control plane's
    /// (`spiffe://<trust domain>/...`); must equal embassy's.
    #[arg(
        long,
        env = "AGENTSC_TRUST_DOMAIN",
        default_value = agentsc_common::identity::DEFAULT_TRUST_DOMAIN
    )]
    pub trust_domain: String,
    /// The Kubernetes cluster DNS domain (`{cluster_domain}` in `--peer-address-template`).
    #[arg(
        long,
        env = "AGENTSC_CLUSTER_DOMAIN",
        default_value = agentsc_common::identity::DEFAULT_CLUSTER_DOMAIN
    )]
    pub cluster_domain: String,
    /// Charter `telemetry.otlp_endpoint` values allowed (globs, comma separated; empty = refused).
    #[arg(long, env = "AGENTSC_OTLP_ENDPOINT_ALLOW", value_delimiter = ',')]
    pub otlp_endpoint_allow: Vec<String>,
    /// Bytes of service-call responses the response cache keeps (0 disables it; cache.rs).
    #[arg(
        long,
        env = "AGENTSC_MESH_CACHE_BYTES",
        default_value_t = crate::cache::DEFAULT_CAPACITY_BYTES
    )]
    pub mesh_cache_bytes: u64,
    /// The longest a cached service-call response is served, in seconds, whatever the app's max-age says.
    #[arg(
        long,
        env = "AGENTSC_MESH_CACHE_MAX_AGE",
        default_value_t = crate::cache::DEFAULT_MAX_AGE_SECS
    )]
    pub mesh_cache_max_age: u64,
    /// Refuse new work (rule `audit.unavailable`: invocations 503 / `UNAVAILABLE`, mesh and tool
    /// calls `UNAVAILABLE`) and report not ready while the audit sink fails, until a write
    /// succeeds again (docs/operations.md). Off: failures are logged and counted, work goes on.
    /// Env accepts 1/0, true/false, yes/no, on/off.
    #[arg(
        long,
        env = "AGENTSC_AUDIT_FAIL_CLOSED",
        num_args = 0..=1,
        default_value = "false",
        default_missing_value = "true",
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    pub audit_fail_closed: bool,

    /// The largest response body a tool or mesh call reads from the app, a peer or an http tool's
    /// origin; a longer one fails the call (`http.response_too_large`). The default fits the
    /// mesh's 4 MiB gRPC messages.
    #[arg(
        long,
        env = "AGENTSC_MAX_RESPONSE_BYTES",
        default_value_t = DEFAULT_MAX_RESPONSE_BYTES
    )]
    pub max_response_bytes: usize,
    /// The Anthropic API key, read by the sidecar only (the model gateway, CONTRACT.md §4.4): a
    /// file, re-read at start-up, e.g. a mounted Secret. Env `ANTHROPIC_API_KEY` is the other way.
    #[arg(long, env = "AGENTSC_ANTHROPIC_API_KEY_FILE")]
    pub anthropic_api_key_file: Option<PathBuf>,
    /// The same as text, from env `ANTHROPIC_API_KEY` only: never a command-line flag. The runtime
    /// is started without it (runtime.rs).
    #[arg(skip = std::env::var(ANTHROPIC_KEY_ENV).ok())]
    pub anthropic_api_key: Option<String>,
    /// Where the model gateway sends Anthropic Messages API calls.
    #[arg(
        long,
        env = "AGENTSC_ANTHROPIC_BASE_URL",
        default_value = crate::gateway::anthropic::DEFAULT_BASE_URL
    )]
    pub anthropic_base_url: String,
    /// The LLM connection contract v1 (`LLM_*`, docs/LLM-CONNECTION.md), read by `main` from the
    /// environment: the model gateway's upstream when no Anthropic key is configured above
    /// (`LLM_PROVIDER=anthropic`, or gateway mode, so the pod holds no provider key).
    #[arg(skip)]
    pub llm_contract: Option<agentsc_common::llm_contract::Contract>,

    /// Intervals and windows of design §6; tests shorten them.
    #[arg(skip)]
    pub timing: Timing,
    /// The environment the OpenTelemetry settings (`OTEL_EXPORTER_OTLP_*`,
    /// `OTEL_RESOURCE_ATTRIBUTES`) are read from: `None` is the process environment; tests pin
    /// it so the ambient environment never changes what they see.
    #[arg(skip)]
    pub otel_env: Option<BTreeMap<String, String>>,
}

/// The env variable that carries the app API token as text (design §6.1).
pub const APP_TOKEN_ENV: &str = "AGENTSC_APP_TOKEN";
/// The env variable that carries the Anthropic API key as text.
pub const ANTHROPIC_KEY_ENV: &str = "ANTHROPIC_API_KEY";
/// Secrets the sidecar may hold that the runtime it spawns never gets (runtime.rs).
pub const RUNTIME_ENV_DENY: &[&str] = &[
    ANTHROPIC_KEY_ENV,
    "ANTHROPIC_AUTH_TOKEN",
    "AGENTSC_ANTHROPIC_API_KEY_FILE",
    "OPENAI_API_KEY",
    APP_TOKEN_ENV,
    // the LLM connection contract's secrets (agentsc_common::llm_contract::SECRET_VARIABLES)
    "LLM_API_KEY",
    "LLM_API_KEY_FILE",
    "LLM_GATEWAY_TOKEN_FILE",
];

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
    /// A config for tests and local runs: everything on ephemeral localhost ports, and an empty
    /// OpenTelemetry environment (see [`Config::otel_env`]).
    pub fn for_test(charter: PathBuf, tls_dir: PathBuf, socket_dir: PathBuf) -> Self {
        Self {
            charter,
            tls_dir,
            http_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            grpc_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            mesh_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            socket_dir,
            runtime_cmd: "agentsc-runtime".into(),
            no_runtime: true,
            control_plane: None,
            ca_address: None,
            service: None,
            namespace: None,
            app_port: None,
            pod_name: None,
            ca_file: None,
            ca_pem: None,
            k8s_token_file: PathBuf::from("/var/run/secrets/agentsc/token"),
            join_token_file: None,
            state_dir: None,
            app_token_file: None,
            app_token: None,
            peer_address_template: DEFAULT_PEER_ADDRESS_TEMPLATE.into(),
            trust_domain: agentsc_common::identity::DEFAULT_TRUST_DOMAIN.into(),
            cluster_domain: agentsc_common::identity::DEFAULT_CLUSTER_DOMAIN.into(),
            otlp_endpoint_allow: Vec::new(),
            mesh_cache_bytes: crate::cache::DEFAULT_CAPACITY_BYTES,
            mesh_cache_max_age: crate::cache::DEFAULT_MAX_AGE_SECS,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            audit_fail_closed: false,
            anthropic_api_key_file: None,
            anthropic_api_key: None,
            anthropic_base_url: crate::gateway::anthropic::DEFAULT_BASE_URL.into(),
            llm_contract: None,
            timing: Timing::default(),
            otel_env: Some(BTreeMap::new()),
        }
    }

    /// Look up an OpenTelemetry environment variable (see [`Config::otel_env`]).
    pub fn otel_env_var(&self, name: &str) -> Option<String> {
        match &self.otel_env {
            Some(env) => env.get(name).cloned(),
            None => agentsc_otel::process_env(name),
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
    /// PEM: `--tls-dir`'s `ca.crt`, else `--ca-file`, else `AGENTSC_CA_PEM`.
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

    /// The Anthropic API key, from `--anthropic-api-key-file` or `ANTHROPIC_API_KEY`; `None`: the
    /// gateway has no Anthropic provider and the runtime runs every agent on the mock model.
    pub fn anthropic_key(&self) -> anyhow::Result<Option<String>> {
        if let Some(path) = &self.anthropic_api_key_file {
            let text = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("--anthropic-api-key-file {}: {e}", path.display()))?;
            let key = text.trim().to_string();
            anyhow::ensure!(
                !key.is_empty(),
                "--anthropic-api-key-file {} is empty",
                path.display()
            );
            return Ok(Some(key));
        }
        Ok(non_empty(&self.anthropic_api_key).map(str::to_string))
    }

    /// The app API token, from `--app-token-file` or `AGENTSC_APP_TOKEN` (design §6.6).
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
            Config::try_parse_from(["agentscd", "--no-runtime"])
                .unwrap()
                .no_runtime
        );
        assert!(!Config::try_parse_from(["agentscd"]).unwrap().no_runtime);
        assert!(
            Config::try_parse_from(["agentscd", "--no-runtime", "1"])
                .unwrap()
                .no_runtime
        );
        assert!(
            !Config::try_parse_from(["agentscd", "--no-runtime", "0"])
                .unwrap()
                .no_runtime
        );
    }

    #[test]
    fn v02_flags_parse_with_their_defaults() {
        let c = Config::try_parse_from([
            "agentscd",
            "--control-plane",
            "embassy.agentsc-system.svc:15012",
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
            "--mesh-cache-bytes",
            "0",
            "--mesh-cache-max-age",
            "30",
        ])
        .unwrap();
        assert!(c.managed());
        assert_eq!((c.mesh_cache_bytes, c.mesh_cache_max_age), (0, 30));
        assert_eq!(c.ca_addr(), Some("embassy.agentsc-system.svc:15012"));
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
            PathBuf::from("/var/run/secrets/agentsc/token")
        );

        let d = Config::try_parse_from(["agentscd", "--socket-dir", "/run/x"]).unwrap();
        assert!(!d.managed());
        assert_eq!(d.state_dir(), PathBuf::from("/run/x/state"));
        assert_eq!(d.peer_address_template, DEFAULT_PEER_ADDRESS_TEMPLATE);
        assert!(d.otlp_allow().is_empty());
        assert_eq!(d.mesh_cache_bytes, crate::cache::DEFAULT_CAPACITY_BYTES);
        assert_eq!(d.mesh_cache_max_age, crate::cache::DEFAULT_MAX_AGE_SECS);
        assert_eq!(d.timing, Timing::default());
        assert!(!d.audit_fail_closed, "fail-closed is off by default");

        for (args, on) in [
            (&["agentscd", "--audit-fail-closed"][..], true),
            (&["agentscd", "--audit-fail-closed", "yes"][..], true),
            (&["agentscd", "--audit-fail-closed", "0"][..], false),
        ] {
            assert_eq!(
                Config::try_parse_from(args).unwrap().audit_fail_closed,
                on,
                "{args:?}"
            );
        }

        let e = Config::try_parse_from([
            "agentscd",
            "--control-plane",
            "cp:15012",
            "--ca-address",
            "ca:15012",
        ])
        .unwrap();
        assert_eq!(e.ca_addr(), Some("ca:15012"));
    }

    #[test]
    fn the_app_token_is_never_a_command_line_flag() {
        let err = Config::try_parse_from(["agentscd", "--app-token", "s3cret"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
        let c = Config::try_parse_from(["agentscd", "--app-token-file", "/token"]).unwrap();
        assert_eq!(c.app_token_file, Some(PathBuf::from("/token")));
        let help = <Config as clap::CommandFactory>::command()
            .render_long_help()
            .to_string();
        assert!(!help.contains("--app-token "), "{help}");
    }

    #[test]
    fn the_provider_key_is_never_a_command_line_flag() {
        let err = Config::try_parse_from(["agentscd", "--anthropic-api-key", "sk-x"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("key");
        std::fs::write(&file, "sk-from-file\n").unwrap();
        let mut c = Config::for_test("c".into(), "t".into(), "s".into());
        assert_eq!(c.anthropic_key().unwrap(), None);
        c.anthropic_api_key = Some("sk-from-env".into());
        assert_eq!(c.anthropic_key().unwrap().as_deref(), Some("sk-from-env"));
        c.anthropic_api_key_file = Some(file);
        assert_eq!(
            c.anthropic_key().unwrap().as_deref(),
            Some("sk-from-file"),
            "the file wins"
        );
        assert!(RUNTIME_ENV_DENY.contains(&ANTHROPIC_KEY_ENV));
        for secret in agentsc_common::llm_contract::SECRET_VARIABLES {
            assert!(RUNTIME_ENV_DENY.contains(&secret), "{secret}");
        }
    }
}
