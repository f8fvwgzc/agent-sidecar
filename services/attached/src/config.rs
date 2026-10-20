use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

/// attached — the attache sidecar (CONTRACT.md §2 lists every flag).
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
    /// Do not spawn the runtime (something else runs it, or tests).
    #[arg(long, env = "ATTACHE_NO_RUNTIME", default_value_t = false)]
    pub no_runtime: bool,
}

impl Config {
    /// A config for tests and local runs: everything on ephemeral localhost ports.
    pub fn for_test(charter: PathBuf, tls_dir: PathBuf, socket_dir: PathBuf) -> Self {
        Self {
            charter,
            tls_dir,
            http_addr: "127.0.0.1:0".parse().unwrap(),
            grpc_addr: "127.0.0.1:0".parse().unwrap(),
            mesh_addr: "127.0.0.1:0".parse().unwrap(),
            socket_dir,
            runtime_cmd: "attache-runtime".into(),
            no_runtime: true,
        }
    }
}
