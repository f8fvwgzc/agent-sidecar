//! The `ui` component: the console's static files (design §8.1, §11), embedded at compile time
//! (`build.rs`) or, with `--ui-dir`, read from disk. Served for `GET`/`HEAD` outside `/api/v1`;
//! `/` is `index.html`; `.js` is `text/javascript; charset=utf-8`.
//!
//! Caching (docs/adr/0002-response-caching.md): the console's own files are `no-cache` (kept,
//! revalidated on every load; [`crate::api::cache::conditional`] adds the `ETag` and answers
//! `304`), so a new embassy is picked up on the next reload. `vendor/` files carry their version
//! in their name (`d3.v7.9.0.min.js`), so they are immutable for a year.
use std::path::{Component, Path, PathBuf};

use axum::body::Body;
use axum::http::{HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

use crate::api::error::Fail;

mod generated {
    include!(concat!(env!("OUT_DIR"), "/ui_files.rs"));
}

/// Where the files come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiFiles {
    Embedded,
    /// `--ui-dir`.
    Dir(PathBuf),
}

/// Every embedded file: (path relative to `ui/`, bytes).
pub fn embedded() -> &'static [(&'static str, &'static [u8])] {
    generated::FILES
}

/// One embedded file.
pub fn embedded_file(path: &str) -> Option<&'static [u8]> {
    embedded().iter().find(|(p, _)| *p == path).map(|(_, b)| *b)
}

/// The `Content-Type` of a file by its extension.
pub fn content_type(path: &str) -> &'static str {
    let ext = path.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    match ext.to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "svg" => "image/svg+xml",
        "json" => "application/json",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "txt" | "license" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// `Cache-Control` of the console's own files: kept by the browser, revalidated every time.
pub const CACHE_CONTROL: &str = "no-cache";
/// `Cache-Control` of `vendor/` files, whose names carry their version.
pub const VENDOR_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

/// The `Cache-Control` a console file gets.
pub fn cache_control(rel: &str) -> &'static str {
    if rel.starts_with("vendor/") && rel != "vendor/SHA256SUMS" {
        VENDOR_CACHE_CONTROL
    } else {
        CACHE_CONTROL
    }
}

/// The file a request path names: `index.html` for `/`; `None` for anything that could leave
/// the directory or names a dot file, `*.md`, `tests/` or `fixtures/`.
pub fn file_path(uri_path: &str) -> Option<String> {
    let p = uri_path.trim_start_matches('/');
    let p = if p.is_empty() { "index.html" } else { p };
    if p.contains('\\') || p.contains('\0') {
        return None;
    }
    let parts: Vec<&str> = p.split('/').collect();
    if parts
        .iter()
        .any(|s| s.is_empty() || *s == "." || *s == ".." || s.starts_with('.'))
    {
        return None;
    }
    if p.ends_with(".md") || matches!(parts.first(), Some(&"tests") | Some(&"fixtures")) {
        return None;
    }
    Some(p.to_string())
}

async fn read_dir_file(dir: &Path, rel: &str) -> Option<Vec<u8>> {
    let path = dir.join(rel);
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return None;
    }
    // no symlink may lead outside the directory
    let root = tokio::fs::canonicalize(dir).await.ok()?;
    let real = tokio::fs::canonicalize(&path).await.ok()?;
    if !real.starts_with(&root) {
        return None;
    }
    let meta = tokio::fs::metadata(&real).await.ok()?;
    if !meta.is_file() {
        return None;
    }
    tokio::fs::read(&real).await.ok()
}

/// Answer one request for a console file.
pub async fn serve(files: &UiFiles, method: &Method, uri: &Uri) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return (StatusCode::METHOD_NOT_ALLOWED, "").into_response();
    }
    let Some(rel) = file_path(uri.path()) else {
        return Fail::not_found("no such file").into_response();
    };
    let bytes: Option<Vec<u8>> = match files {
        UiFiles::Embedded => embedded_file(&rel).map(<[u8]>::to_vec),
        UiFiles::Dir(dir) => read_dir_file(dir, &rel).await,
    };
    let Some(bytes) = bytes else {
        return Fail::not_found("no such file").into_response();
    };
    let mut resp = Response::new(if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(bytes)
    });
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_type(&rel)),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control(&rel)),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(file_path("/").as_deref(), Some("index.html"));
        assert_eq!(file_path("/js/main.js").as_deref(), Some("js/main.js"));
        for bad in [
            "/../etc/passwd",
            "/js/../../x",
            "/.git/config",
            "/README.md",
            "/tests/check_ui.py",
            "/fixtures/graph.json",
            "/js//main.js",
            "/a\\b",
        ] {
            assert_eq!(file_path(bad), None, "{bad}");
        }
        assert_eq!(content_type("js/main.js"), "text/javascript; charset=utf-8");
        assert_eq!(content_type("index.html"), "text/html; charset=utf-8");
        assert_eq!(content_type("styles.css"), "text/css; charset=utf-8");
        assert_eq!(content_type("favicon.svg"), "image/svg+xml");
        assert_eq!(content_type("x.bin"), "application/octet-stream");
        assert_eq!(cache_control("index.html"), "no-cache");
        assert_eq!(cache_control("js/main.js"), "no-cache");
        assert_eq!(cache_control("vendor/SHA256SUMS"), "no-cache");
        assert_eq!(cache_control("vendor/d3.v7.9.0.min.js"), VENDOR_CACHE_CONTROL);
    }

    #[test]
    fn the_console_is_embedded() {
        assert!(embedded_file("index.html").is_some());
        assert!(embedded_file("js/main.js").is_some());
        assert!(embedded_file("vendor/SHA256SUMS").is_some());
        assert!(embedded().iter().all(|(p, _)| !p.starts_with("tests/")
            && !p.starts_with("fixtures/")
            && !p.ends_with(".md")));
    }

    #[tokio::test]
    async fn the_directory_source_stays_inside() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<p>dev</p>").unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), "s").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path().join("secret"), dir.path().join("link.js"))
            .unwrap();
        let files = UiFiles::Dir(dir.path().to_path_buf());
        let r = serve(&files, &Method::GET, &"/".parse().unwrap()).await;
        assert_eq!(r.status(), StatusCode::OK);
        let r = serve(&files, &Method::GET, &"/link.js".parse().unwrap()).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        let r = serve(&files, &Method::POST, &"/".parse().unwrap()).await;
        assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
