use std::path::Path;

const PROTOS: [&str; 4] = [
    "attache/v1alpha1/common.proto",
    "attache/v1alpha1/app.proto",
    "attache/v1alpha1/mesh.proto",
    "attache/v1alpha1/runtime.proto",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../proto");
    let files = PROTOS.map(|file| root.join(file));
    println!("cargo:rerun-if-changed={}", root.display());
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&files, &[root])?;
    Ok(())
}
