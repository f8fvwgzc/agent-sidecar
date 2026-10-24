//! Conditional GETs (docs/adr/0002-response-caching.md).
//!
//! Every `200` to a `GET` or `HEAD` whose body is in memory leaves with an `ETag`: the handlers'
//! version tags (`"3"` on a charter, a memory document or an agent view) stay as they are, every
//! other body gets a content hash (`"h-<hex>"`). A request whose `If-None-Match` names that tag
//! is answered `304 Not Modified` with no body. Unless the handler set them, the response also
//! gets `Cache-Control: private, no-cache` (a private cache may keep a copy but must revalidate
//! it before every use; nothing is ever served stale) and `Vary: Cookie, Authorization` (the
//! body depends on the identity).
//!
//! Streaming responses (the SSE stream, whose size is unknown) and bodies over
//! [`MAX_HASHED_BODY`] pass through untouched, and so does anything with `Cache-Control:
//! no-store`. The console's transport keeps the last body per URL and sends its tag back
//! (`ui/js/api.js`), so an unchanged graph, service list or trace costs a round trip and no
//! payload.
use axum::body::{Body, to_bytes};
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http_body::Body as _;
use sha2::{Digest, Sha256};

/// The largest body that is hashed for an `ETag`; bigger ones pass through.
pub const MAX_HASHED_BODY: usize = 4 * 1024 * 1024;
/// `Cache-Control` of an API response whose handler set none.
pub const DEFAULT_CACHE_CONTROL: &str = "private, no-cache";
/// `Vary` of an API response whose handler set none: the identity decides the body.
pub const DEFAULT_VARY: &str = "Cookie, Authorization";

/// A strong entity tag of `body`: `"h-<32 hex characters of its SHA-256>"`. The `h-` keeps it
/// apart from the handlers' version tags, which are decimal and which the console parses.
pub fn content_etag(body: &[u8]) -> HeaderValue {
    let digest = Sha256::digest(body);
    HeaderValue::from_str(&format!("\"h-{}\"", hex::encode(&digest[..16]))).expect("hex is ASCII")
}

/// The tag without a `W/` prefix or surrounding spaces.
fn opaque(tag: &str) -> &str {
    let t = tag.trim();
    t.strip_prefix("W/").unwrap_or(t)
}

/// Whether one of the `If-None-Match` values names `etag`: a comma-separated list of tags,
/// compared weakly (RFC 9110 §8.8.3.2), or `*`.
pub fn none_match(if_none_match: &[HeaderValue], etag: &HeaderValue) -> bool {
    let Ok(etag) = etag.to_str() else {
        return false;
    };
    let want = opaque(etag);
    if_none_match
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .any(|t| t == "*" || opaque(t) == want)
}

/// `Cache-Control` has the `no-store` directive.
fn no_store(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|d| d.trim().eq_ignore_ascii_case("no-store"))
}

/// The middleware: see the module docs.
pub async fn conditional(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    if method != Method::GET && method != Method::HEAD {
        return next.run(req).await;
    }
    let if_none_match: Vec<HeaderValue> = req
        .headers()
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .cloned()
        .collect();
    let resp = next.run(req).await;
    if resp.status() != StatusCode::OK || no_store(resp.headers()) {
        return resp;
    }
    let (mut parts, body) = resp.into_parts();
    let (etag, body) = match parts.headers.get(header::ETAG).cloned() {
        Some(tag) => (tag, body),
        None => {
            // only a body whose size is known now is in memory; a stream stays a stream
            let Some(size) = body.size_hint().exact() else {
                return Response::from_parts(parts, body);
            };
            if size > MAX_HASHED_BODY as u64 {
                return Response::from_parts(parts, body);
            }
            let bytes = match to_bytes(body, MAX_HASHED_BODY).await {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!(error = %e, "reading a response body for its ETag failed");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            };
            let tag = content_etag(&bytes);
            parts.headers.insert(header::ETAG, tag.clone());
            (tag, Body::from(bytes))
        }
    };
    if !parts.headers.contains_key(header::CACHE_CONTROL) {
        parts.headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(DEFAULT_CACHE_CONTROL),
        );
    }
    if !parts.headers.contains_key(header::VARY) {
        parts
            .headers
            .insert(header::VARY, HeaderValue::from_static(DEFAULT_VARY));
    }
    if none_match(&if_none_match, &etag) {
        parts.status = StatusCode::NOT_MODIFIED;
        parts.headers.remove(header::CONTENT_LENGTH);
        return Response::from_parts(parts, Body::empty());
    }
    Response::from_parts(parts, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::routing::get;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    fn app() -> Router {
        Router::new()
            .route(
                "/json",
                get(|| async { axum::Json(serde_json::json!({"a": 1})) }),
            )
            .route(
                "/versioned",
                get(|| async {
                    super::super::with_etag(StatusCode::OK, &serde_json::json!({"v": 3}), "3")
                }),
            )
            .route(
                "/stream",
                get(|| async {
                    let chunks: Vec<Result<&'static [u8], std::io::Error>> =
                        vec![Ok(b"a"), Ok(b"b")];
                    let body = Body::from_stream(futures::stream::iter(chunks));
                    Response::new(body)
                }),
            )
            .route(
                "/secret",
                get(|| async {
                    (
                        [(header::CACHE_CONTROL, "no-store")],
                        axum::Json(serde_json::json!({"s": 1})),
                    )
                }),
            )
            .layer(axum::middleware::from_fn(conditional))
    }

    fn req(path: &str, inm: Option<&HeaderValue>) -> Request {
        let mut b = http::Request::builder().uri(path);
        if let Some(v) = inm {
            b = b.header(header::IF_NONE_MATCH, v);
        }
        b.body(Body::empty()).unwrap()
    }

    #[test]
    fn tags_are_strong_prefixed_hashes() {
        let a = content_etag(b"{}");
        assert!(a.to_str().unwrap().starts_with("\"h-"), "{a:?}");
        assert_eq!(a.to_str().unwrap().len(), 2 + 2 + 32);
        assert_eq!(a, content_etag(b"{}"));
        assert_ne!(a, content_etag(b"{ }"));
    }

    #[test]
    fn none_match_compares_weakly_and_in_lists() {
        let tag = HeaderValue::from_static("\"h-abc\"");
        let v = |s: &'static str| vec![HeaderValue::from_static(s)];
        assert!(none_match(&v("\"h-abc\""), &tag));
        assert!(none_match(&v("W/\"h-abc\""), &tag));
        assert!(none_match(&v("\"x\", \"h-abc\""), &tag));
        assert!(none_match(&v("*"), &tag));
        assert!(!none_match(&v("\"h-abd\""), &tag));
        assert!(!none_match(&[], &tag));
    }

    #[tokio::test]
    async fn a_json_body_gets_a_tag_and_then_a_304() {
        let r = app().oneshot(req("/json", None)).await.unwrap();
        assert_eq!(r.status(), 200);
        let tag = r.headers()[header::ETAG].clone();
        assert!(tag.to_str().unwrap().starts_with("\"h-"));
        assert_eq!(r.headers()[header::CACHE_CONTROL], DEFAULT_CACHE_CONTROL);
        assert_eq!(r.headers()[header::VARY], DEFAULT_VARY);
        let body = r.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], br#"{"a":1}"#);

        let r = app().oneshot(req("/json", Some(&tag))).await.unwrap();
        assert_eq!(r.status(), 304);
        assert_eq!(r.headers()[header::ETAG], tag);
        assert!(r.headers().get(header::CONTENT_LENGTH).is_none());
        assert!(
            r.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );

        let other = HeaderValue::from_static("\"h-00000000000000000000000000000000\"");
        let r = app().oneshot(req("/json", Some(&other))).await.unwrap();
        assert_eq!(r.status(), 200);
    }

    #[tokio::test]
    async fn a_handler_version_tag_is_kept_and_honoured() {
        let r = app().oneshot(req("/versioned", None)).await.unwrap();
        assert_eq!(r.headers()[header::ETAG], "\"3\"");
        let three = HeaderValue::from_static("\"3\"");
        let r = app().oneshot(req("/versioned", Some(&three))).await.unwrap();
        assert_eq!(r.status(), 304);
        assert_eq!(r.headers()[header::ETAG], "\"3\"");
    }

    #[tokio::test]
    async fn streams_and_no_store_pass_through() {
        let r = app().oneshot(req("/stream", None)).await.unwrap();
        assert_eq!(r.status(), 200);
        assert!(r.headers().get(header::ETAG).is_none());
        assert!(r.headers().get(header::CACHE_CONTROL).is_none());
        let body = r.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"ab");

        let r = app().oneshot(req("/secret", None)).await.unwrap();
        assert!(r.headers().get(header::ETAG).is_none());
        assert_eq!(r.headers()[header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    async fn only_safe_methods_are_conditional() {
        let app = Router::new()
            .route("/x", axum::routing::post(|| async { "ok" }))
            .layer(axum::middleware::from_fn(conditional));
        let r = app
            .oneshot(
                http::Request::builder()
                    .method(Method::POST)
                    .uri("/x")
                    .header(header::IF_NONE_MATCH, "*")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert!(r.headers().get(header::ETAG).is_none());
    }
}
