//! The `ui` component (design §8.1, §11): the embedded console, its pinned d3 (hash-checked
//! against `ui/vendor/SHA256SUMS` on disk and in the binary), content types and `--ui-dir`.
mod common;

use std::path::{Path, PathBuf};

use common::Env;
use embassy::ui_assets;
use sha2::{Digest, Sha256};

fn ui() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ui")
}

/// `<sha256>  <file>` lines.
fn sums(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let (hash, file) = l.split_once("  ").expect("<sha256>  <file>");
            (hash.to_string(), file.trim().to_string())
        })
        .collect()
}

#[test]
fn vendor_hashes_match_the_files_on_disk_and_the_embedded_bytes() {
    let on_disk = std::fs::read_to_string(ui().join("vendor/SHA256SUMS")).unwrap();
    let embedded = ui_assets::embedded_file("vendor/SHA256SUMS").expect("SHA256SUMS is embedded");
    assert_eq!(
        embedded,
        on_disk.as_bytes(),
        "the embedded SHA256SUMS is the file"
    );
    let list = sums(&on_disk);
    assert!(!list.is_empty());
    for (hash, file) in list {
        let disk = std::fs::read(ui().join("vendor").join(&file)).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&disk)),
            hash,
            "vendor/{file} on disk"
        );
        let bytes = ui_assets::embedded_file(&format!("vendor/{file}"))
            .unwrap_or_else(|| panic!("vendor/{file} is not embedded"));
        assert_eq!(
            hex::encode(Sha256::digest(bytes)),
            hash,
            "vendor/{file} embedded"
        );
    }
}

#[test]
fn every_console_file_is_embedded_as_it_is_on_disk() {
    for (path, bytes) in ui_assets::embedded() {
        let disk = std::fs::read(ui().join(path)).unwrap();
        assert_eq!(&disk[..], *bytes, "{path}");
    }
    for want in [
        "index.html",
        "styles.css",
        "favicon.svg",
        "js/main.js",
        "js/api.js",
    ] {
        assert!(ui_assets::embedded_file(want).is_some(), "{want}");
    }
}

#[tokio::test]
async fn files_are_served_with_their_types_and_the_security_headers() {
    let env = Env::start().await;
    for (path, ct, file) in [
        ("/", "text/html; charset=utf-8", "index.html"),
        ("/index.html", "text/html; charset=utf-8", "index.html"),
        (
            "/js/main.js",
            "text/javascript; charset=utf-8",
            "js/main.js",
        ),
        ("/styles.css", "text/css; charset=utf-8", "styles.css"),
        ("/favicon.svg", "image/svg+xml", "favicon.svg"),
        (
            "/vendor/d3.v7.9.0.min.js",
            "text/javascript; charset=utf-8",
            "vendor/d3.v7.9.0.min.js",
        ),
    ] {
        let r = env
            .http
            .get(format!("{}{path}", env.base))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "{path}");
        assert_eq!(r.headers()["content-type"], ct, "{path}");
        assert_eq!(
            r.headers()["content-security-policy"],
            embassy::auth::http::CSP
        );
        assert_eq!(r.headers()["x-frame-options"], "DENY");
        let body = r.bytes().await.unwrap();
        assert_eq!(
            &body[..],
            &std::fs::read(ui().join(file)).unwrap()[..],
            "{path}"
        );
    }
    for path in [
        "/tests/check_ui.py",
        "/fixtures/graph.json",
        "/README.md",
        "/nope.js",
    ] {
        let r = env
            .http
            .get(format!("{}{path}", env.base))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404, "{path}");
    }
    env.stop().await;
}

#[tokio::test]
async fn ui_dir_serves_from_disk() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("index.html"), "<p>dev build</p>").unwrap();
    std::fs::create_dir_all(dir.path().join("js")).unwrap();
    std::fs::write(dir.path().join("js/app.js"), "export {};").unwrap();
    let files = ui_assets::UiFiles::Dir(dir.path().to_path_buf());
    let r = ui_assets::serve(&files, &axum::http::Method::GET, &"/".parse().unwrap()).await;
    assert_eq!(r.status(), 200);
    let body = axum::body::to_bytes(r.into_body(), 1024).await.unwrap();
    assert_eq!(&body[..], b"<p>dev build</p>");
    let r = ui_assets::serve(
        &files,
        &axum::http::Method::GET,
        &"/js/app.js".parse().unwrap(),
    )
    .await;
    assert_eq!(
        r.headers()["content-type"],
        "text/javascript; charset=utf-8"
    );
    let r = ui_assets::serve(
        &files,
        &axum::http::Method::HEAD,
        &"/js/app.js".parse().unwrap(),
    )
    .await;
    assert_eq!(r.status(), 200);
    let r = ui_assets::serve(
        &files,
        &axum::http::Method::GET,
        &"/missing.js".parse().unwrap(),
    )
    .await;
    assert_eq!(r.status(), 404);
}
