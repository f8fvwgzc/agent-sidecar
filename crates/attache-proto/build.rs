use std::path::{Path, PathBuf};

const PROTOS: [&str; 4] = [
    "attache/v1alpha1/common.proto",
    "attache/v1alpha1/app.proto",
    "attache/v1alpha1/mesh.proto",
    "attache/v1alpha1/runtime.proto",
];

/// `rpc Connect` would collide with the `connect(endpoint)` constructor tonic generates on every
/// client, so the control-plane protocol is compiled on its own, without that constructor
/// (`ControlPlaneClient::new(channel)`), into `$OUT_DIR/controlplane/`. It imports nothing, and
/// `lib.rs` includes both outputs into the one `attache.v1alpha1` module.
const CONTROL_PLANE: &str = "attache/v1alpha1/controlplane.proto";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../proto");
    let files = PROTOS.map(|file| root.join(file));
    println!("cargo:rerun-if-changed={}", root.display());
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&files, std::slice::from_ref(&root))?;

    let out = PathBuf::from(std::env::var("OUT_DIR")?).join("controlplane");
    std::fs::create_dir_all(&out)?;
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .build_transport(false)
        .out_dir(&out)
        .compile_protos(&[root.join(CONTROL_PLANE)], &[root])?;
    Ok(())
}
