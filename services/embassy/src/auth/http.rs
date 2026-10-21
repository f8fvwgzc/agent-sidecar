//! What every HTTP response of `embassy serve` gets (design §8.1, §8.3, §15 rule 1): the Host
//! check (421), `X-Attache-CSRF: 1` and `Content-Type: application/json` on every mutating
//! request, and the security headers. No `Access-Control-Allow-*` header is ever sent.
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::api::error::Fail;
use crate::api::types::ErrorCode;

/// The `Content-Security-Policy` of every response.
pub const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
/// The CSRF header every mutating request carries, with the value `1`.
pub const CSRF_HEADER: &str = "x-attache-csrf";

/// The names a `Host` header may carry, besides `localhost`, `127.0.0.1` and `[::1]`.
#[derive(Debug, Clone, Default)]
pub struct HostPolicy {
    pub dns_names: Vec<String>,
}

impl HostPolicy {
    /// Whether `host` (`name` or `name:port`; IPv6 in brackets) is served here.
    pub fn allows(&self, host: &str) -> bool {
        let Some(name) = host_name(host.trim()) else {
            return false;
        };
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        matches!(name.as_str(), "localhost" | "127.0.0.1" | "[::1]")
            || self.dns_names.iter().any(|d| d.eq_ignore_ascii_case(&name))
    }
}

/// The name part of a Host value, without the port; `None` when it is malformed.
fn host_name(host: &str) -> Option<&str> {
    let port_ok = |p: &str| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit());
    if host.is_empty() {
        return None;
    }
    if host.starts_with('[') {
        let end = host.find(']')?;
        let (name, tail) = host.split_at(end + 1);
        return match tail.strip_prefix(':') {
            None if tail.is_empty() => Some(name),
            Some(p) if port_ok(p) => Some(name),
            _ => None,
        };
    }
    match host.rsplit_once(':') {
        None => Some(host),
        Some((name, p)) if port_ok(p) && !name.contains(':') && !name.is_empty() => Some(name),
        Some(_) => None,
    }
}

/// The request's host: the `Host` header, or the URI authority (HTTP/2).
fn request_host(req: &Request) -> Option<String> {
    req.headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| req.uri().authority().map(|a| a.as_str().to_string()))
}

fn is_mutation(m: &Method) -> bool {
    matches!(
        *m,
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH
    )
}

/// `application/json`, with or without parameters (`; charset=utf-8`).
pub fn is_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"))
}

/// The checks before routing: Host, then CSRF, then the content type.
pub fn precheck(policy: &HostPolicy, req: &Request) -> Result<(), Fail> {
    let host = request_host(req).unwrap_or_default();
    if !policy.allows(&host) {
        let shown: String = host.chars().take(100).collect();
        return Err(Fail::new(
            ErrorCode::MisdirectedRequest,
            [format!("host {shown:?} is not served here")],
        ));
    }
    if is_mutation(req.method()) {
        let csrf = req.headers().get(CSRF_HEADER).and_then(|v| v.to_str().ok());
        if csrf != Some("1") {
            return Err(Fail::new(
                ErrorCode::Forbidden,
                ["every mutating request needs the header X-Attache-CSRF: 1"],
            ));
        }
        if !is_json_content_type(req.headers()) {
            return Err(Fail::new(
                ErrorCode::Invalid,
                ["every mutating request needs Content-Type: application/json"],
            ));
        }
    }
    Ok(())
}

/// Set the security headers of design §8.1 and remove any CORS header.
pub fn secure_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    let cors: Vec<_> = headers
        .keys()
        .filter(|k| k.as_str().starts_with("access-control-"))
        .cloned()
        .collect();
    for k in cors {
        headers.remove(k);
    }
}

/// The middleware every route runs behind.
pub async fn guard(State(policy): State<Arc<HostPolicy>>, req: Request, next: Next) -> Response {
    let mut resp = match precheck(&policy, &req) {
        Ok(()) => next.run(req).await,
        Err(f) => f.into_response(),
    };
    secure_headers(resp.headers_mut());
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        let p = HostPolicy {
            dns_names: vec!["embassy.attache-system.svc".into()],
        };
        for ok in [
            "localhost",
            "localhost:8080",
            "LOCALHOST:1",
            "127.0.0.1",
            "127.0.0.1:8080",
            "[::1]",
            "[::1]:8080",
            "embassy.attache-system.svc",
            "Embassy.Attache-System.svc:443",
            "localhost.",
        ] {
            assert!(p.allows(ok), "{ok}");
        }
        for bad in [
            "",
            "evil.example",
            "evil.example:8080",
            "localhost:",
            "localhost:abc",
            "localhost:123456",
            "127.0.0.2",
            "[::2]",
            "[::1",
            "[::1]x",
            "::1",
            "localhost@evil",
            "embassy.attache-system.svc.evil",
        ] {
            assert!(!p.allows(bad), "{bad}");
        }
    }

    #[test]
    fn content_types() {
        let mut h = HeaderMap::new();
        assert!(!is_json_content_type(&h));
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        assert!(is_json_content_type(&h));
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("Application/JSON; charset=utf-8"),
        );
        assert!(is_json_content_type(&h));
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert!(!is_json_content_type(&h));
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        assert!(!is_json_content_type(&h));
    }

    #[test]
    fn security_headers_replace_cors() {
        let mut h = HeaderMap::new();
        h.insert("access-control-allow-origin", HeaderValue::from_static("*"));
        secure_headers(&mut h);
        assert!(h.get("access-control-allow-origin").is_none());
        assert_eq!(h[header::CONTENT_SECURITY_POLICY], CSP);
        assert_eq!(h[header::X_FRAME_OPTIONS], "DENY");
        assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(h[header::REFERRER_POLICY], "no-referrer");
    }
}
