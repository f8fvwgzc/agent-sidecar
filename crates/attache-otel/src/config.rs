//! Where and what to export: [`OtelConfig`] and its resolution rules (design §9).
use attache_charter::TelemetrySpec;

/// The OTLP/HTTP base endpoint, its headers and what to export.
///
/// Built by [`OtelConfig::resolve`]; `Debug` hides header values and any password in the
/// endpoint, so the config can be logged.
#[derive(Clone, PartialEq, Eq)]
pub struct OtelConfig {
    /// Base URL without a trailing `/`; requests go to `<endpoint>/v1/traces` and
    /// `<endpoint>/v1/metrics`.
    pub endpoint: String,
    /// Extra request headers (valid HTTP header names and values).
    pub headers: Vec<(String, String)>,
    /// Resource attributes, in order, keys unique.
    pub resource: Vec<(String, String)>,
    pub traces: bool,
    pub metrics: bool,
    /// Spans carry `url.full`, `url.path`, inputs and outputs only if true.
    pub export_payloads: bool,
}

impl std::fmt::Debug for OtelConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(k, _)| (k.as_str(), "[redacted]"))
            .collect();
        f.debug_struct("OtelConfig")
            .field("endpoint", &mask_password(&self.endpoint))
            .field("headers", &headers)
            .field("resource", &self.resource)
            .field("traces", &self.traces)
            .field("metrics", &self.metrics)
            .field("export_payloads", &self.export_payloads)
            .finish()
    }
}

/// The OTel SDK environment variables this crate reads.
pub const ENV_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
pub const ENV_HEADERS: &str = "OTEL_EXPORTER_OTLP_HEADERS";
pub const ENV_RESOURCE_ATTRIBUTES: &str = "OTEL_RESOURCE_ATTRIBUTES";

/// Reads the process environment; the `env` argument of [`OtelConfig::resolve`] in production.
pub fn process_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// The sidecar's own resource attributes (design §9), in this order: `service.name`,
/// `service.namespace`, `service.version` (the sidecar version) and `attache.identity` (the
/// workload's SPIFFE id).
pub fn sidecar_resource(
    service: &str,
    namespace: &str,
    sidecar_version: &str,
    identity: &str,
) -> Vec<(String, String)> {
    [
        ("service.name", service),
        ("service.namespace", namespace),
        ("service.version", sidecar_version),
        ("attache.identity", identity),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

impl OtelConfig {
    /// Decide whether and where to export (design §9).
    ///
    /// - If `OTEL_EXPORTER_OTLP_ENDPOINT` is set (and not empty), it is the endpoint, with the
    ///   headers from `OTEL_EXPORTER_OTLP_HEADERS`. An endpoint that is not an `http(s)` URL
    ///   with a host and without query or fragment turns export off (it is never replaced by the
    ///   charter's).
    /// - Otherwise the charter's `telemetry.otlp_endpoint` is used only if it is an
    ///   `http(s)://host[:port]` URL (no userinfo, path, query or fragment) that matches one of
    ///   `allow_globs` (`--otlp-endpoint-allow`), and it gets **no** environment headers.
    /// - Otherwise, or when the charter turns off both traces and metrics, export is off: `None`.
    ///
    /// `charter_telemetry` `None` means the charter has no `telemetry` block (the defaults).
    /// `resource` is the sidecar's own attributes (`service.name`, `service.namespace`,
    /// `service.version`, `attache.identity`); `OTEL_RESOURCE_ATTRIBUTES` adds to them but never
    /// overrides one of them. `env` looks up an environment variable ([`process_env`] in
    /// production; a map in tests).
    pub fn resolve(
        charter_telemetry: Option<&TelemetrySpec>,
        env: impl Fn(&str) -> Option<String>,
        allow_globs: &[String],
        resource: Vec<(String, String)>,
    ) -> Option<OtelConfig> {
        let defaults = TelemetrySpec::default();
        let telemetry = charter_telemetry.unwrap_or(&defaults);
        if !telemetry.traces && !telemetry.metrics {
            return None;
        }
        let env_endpoint = env(ENV_ENDPOINT).filter(|v| !v.trim().is_empty());
        let (endpoint, headers) = match env_endpoint {
            Some(raw) => match env_endpoint_base(&raw) {
                Some(base) => (base, parse_headers(&env(ENV_HEADERS).unwrap_or_default())),
                None => {
                    tracing::warn!(
                        "{ENV_ENDPOINT} is not an http(s) URL with a host and no query or fragment; OpenTelemetry export is off"
                    );
                    return None;
                }
            },
            None => {
                let raw = telemetry.otlp_endpoint.as_deref()?;
                match charter_endpoint_allowed(raw, allow_globs) {
                    Some(base) => (base, Vec::new()),
                    None => {
                        tracing::warn!(
                            endpoint = %mask_password(raw),
                            "telemetry.otlp_endpoint is not allowed by --otlp-endpoint-allow; OpenTelemetry export is off"
                        );
                        return None;
                    }
                }
            }
        };
        Some(OtelConfig {
            endpoint,
            headers,
            resource: merge_resource(resource, &env(ENV_RESOURCE_ATTRIBUTES).unwrap_or_default()),
            traces: telemetry.traces,
            metrics: telemetry.metrics,
            export_payloads: telemetry.export_payloads,
        })
    }
}

/// The env endpoint as a base URL: `http(s)` with a host, no query or fragment; a path is kept
/// (signal paths are appended to it), a trailing `/` is dropped.
fn env_endpoint_base(raw: &str) -> Option<String> {
    let url = url::Url::parse(raw.trim()).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none_or(str::is_empty)
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    Some(url.as_str().trim_end_matches('/').to_string())
}

/// The charter endpoint as a base URL if it has the `http(s)://host[:port]` shape and matches an
/// allow glob. The glob is matched (ASCII case-insensitively) against the normalized form
/// `scheme://host[:port]` and, so that `:443`/`:80` written or left out mean the same, against
/// the form with the scheme's default port spelled out.
pub fn charter_endpoint_allowed(raw: &str, allow_globs: &[String]) -> Option<String> {
    let (base, forms) = charter_endpoint_forms(raw)?;
    let allowed = allow_globs.iter().any(|g| {
        let g = g.trim().to_ascii_lowercase();
        !g.is_empty() && forms.iter().any(|f| glob_match(&g, f))
    });
    allowed.then_some(base)
}

/// `(normalized base, forms to match)` for a charter endpoint, or `None` when it is not
/// `http(s)://host[:port]` with at most a trailing `/`. The text is checked before and after URL
/// parsing, so a lenient parse (backslashes, tabs, dot segments) can never widen what a glob saw.
fn charter_endpoint_forms(raw: &str) -> Option<(String, Vec<String>)> {
    let lower = raw.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))?;
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.is_empty()
        || authority.chars().any(|c| {
            matches!(c, '/' | '?' | '#' | '@' | '\\') || c.is_whitespace() || c.is_control()
        })
    {
        return None;
    }
    let url = url::Url::parse(raw).ok()?;
    let host = url.host_str().filter(|h| !h.is_empty())?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let scheme = url.scheme();
    let base = match url.port() {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    };
    let mut forms = vec![base.clone()];
    if url.port().is_none()
        && let Some(p) = url.port_or_known_default()
    {
        forms.push(format!("{scheme}://{host}:{p}"));
    }
    // `url` drops a port equal to the scheme's default, so `base` is already the short form.
    Some((base, forms))
}

/// Shell-style glob: `*` matches any run of characters (including none), `?` exactly one;
/// everything else matches itself.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    // Position of the last `*` in the pattern and the text position it is matched up to.
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        match p.get(pi) {
            Some('*') => {
                star = Some((pi, ti));
                pi += 1;
            }
            Some(&c) if c == '?' || c == t[ti] => {
                pi += 1;
                ti += 1;
            }
            _ => match star {
                Some((sp, st)) => {
                    pi = sp + 1;
                    ti = st + 1;
                    star = Some((sp, st + 1));
                }
                None => return false,
            },
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

/// `OTEL_EXPORTER_OTLP_HEADERS`: `key=value` pairs separated by commas, values percent-encoded
/// (W3C Baggage style). Entries without `=`, with an empty key, or that are not a valid HTTP
/// header name and value are skipped.
pub fn parse_headers(raw: &str) -> Vec<(String, String)> {
    parse_pairs(raw)
        .into_iter()
        .filter(|(k, v)| {
            let ok = http::HeaderName::from_bytes(k.as_bytes()).is_ok()
                && http::HeaderValue::from_str(v).is_ok();
            if !ok {
                tracing::warn!(header = %k, "{ENV_HEADERS}: skipping an invalid header");
            }
            ok
        })
        .collect()
}

/// `OTEL_RESOURCE_ATTRIBUTES` added after `resource`; a key already present is not replaced.
fn merge_resource(mut resource: Vec<(String, String)>, env_attrs: &str) -> Vec<(String, String)> {
    for (k, v) in parse_pairs(env_attrs) {
        if !resource.iter().any(|(rk, _)| *rk == k) {
            resource.push((k, v));
        }
    }
    resource
}

/// Comma-separated `key=value` list, keys and values trimmed and percent-decoded; a later
/// duplicate key is dropped.
pub fn parse_pairs(raw: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for item in raw.split(',') {
        let Some((k, v)) = item.split_once('=') else {
            continue;
        };
        let k = percent_decode(k.trim());
        let v = percent_decode(v.trim());
        if k.is_empty() || out.iter().any(|(ok, _)| *ok == k) {
            continue;
        }
        out.push((k, v));
    }
    out
}

/// `%XX` → byte; anything else (including a malformed `%`) is kept as written.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(hex) = bytes.get(i + 1..i + 3)
            && let Ok(text) = std::str::from_utf8(hex)
            && let Ok(b) = u8::from_str_radix(text, 16)
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The URL with any password replaced, for logs.
pub(crate) fn mask_password(endpoint: &str) -> String {
    match url::Url::parse(endpoint) {
        Ok(mut u) if u.password().is_some() => {
            let _ = u.set_password(Some("redacted"));
            u.as_str().trim_end_matches('/').to_string()
        }
        _ => endpoint.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_star_and_question_mark() {
        assert!(glob_match("*", ""));
        assert!(glob_match("*", "http://anything:1"));
        assert!(glob_match("http://*:4318", "http://otel.obs.svc:4318"));
        assert!(!glob_match("http://*:4318", "http://otel:4317"));
        assert!(glob_match(
            "https://*.example.com",
            "https://a.b.example.com"
        ));
        assert!(!glob_match("https://*.example.com", "https://example.com"));
        assert!(glob_match("http://otel-?:4318", "http://otel-a:4318"));
        assert!(!glob_match("http://otel-?:4318", "http://otel-ab:4318"));
        assert!(glob_match("a*b*c", "abbbc"));
        assert!(!glob_match("a*b*c", "abbb"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "exactly"));
        assert!(!glob_match("", "x"));
    }

    #[test]
    fn charter_endpoint_shape_is_checked_before_and_after_parsing() {
        let allow = vec!["*".to_string()];
        for bad in [
            "http://user@otel:4318",
            "http://user:pw@otel:4318",
            "http://otel:4318/v1",
            "http://otel:4318/.",
            "http://otel:4318?x=1",
            "http://otel:4318#f",
            "http:\\\\otel:4318",
            "http://evil.com\\.example.com",
            "http://otel :4318",
            "ftp://otel:21",
            "http://",
            "otel:4318",
        ] {
            assert_eq!(charter_endpoint_allowed(bad, &allow), None, "{bad}");
        }
        assert_eq!(
            charter_endpoint_allowed("HTTP://OTEL-Collector:4318/", &allow).as_deref(),
            Some("http://otel-collector:4318")
        );
    }

    #[test]
    fn default_ports_match_either_spelling() {
        let with_port = vec!["https://otel.example.com:443".to_string()];
        assert_eq!(
            charter_endpoint_allowed("https://otel.example.com", &with_port).as_deref(),
            Some("https://otel.example.com")
        );
        let without = vec!["https://otel.example.com".to_string()];
        assert_eq!(
            charter_endpoint_allowed("https://otel.example.com:443", &without).as_deref(),
            Some("https://otel.example.com")
        );
        assert_eq!(
            charter_endpoint_allowed("https://otel.example.com:4318", &without),
            None
        );
    }

    #[test]
    fn pairs_are_trimmed_decoded_and_deduplicated() {
        assert_eq!(
            parse_pairs(" a = 1 ,b=x%20y%2Cz, novalue, =empty, a=2, c=%zz%4"),
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "x y,z".to_string()),
                ("c".to_string(), "%zz%4".to_string()),
            ]
        );
    }

    #[test]
    fn invalid_headers_are_skipped() {
        assert_eq!(
            parse_headers("authorization=Bearer%20t,bad name=x,x-ok=1,x-nl=a%0Ab"),
            vec![
                ("authorization".to_string(), "Bearer t".to_string()),
                ("x-ok".to_string(), "1".to_string()),
            ]
        );
    }

    #[test]
    fn sidecar_resource_has_the_design_keys_in_order() {
        let r = sidecar_resource(
            "orders",
            "shop",
            "0.2.0",
            "spiffe://attache/ns/shop/svc/orders",
        );
        let keys: Vec<&str> = r.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            [
                "service.name",
                "service.namespace",
                "service.version",
                "attache.identity"
            ]
        );
        assert_eq!(r[3].1, "spiffe://attache/ns/shop/svc/orders");
    }

    #[test]
    fn debug_hides_secrets() {
        let c = OtelConfig {
            endpoint: "http://u:secret-pw@otel:4318".into(),
            headers: vec![("authorization".into(), "Bearer secret-token".into())],
            resource: vec![],
            traces: true,
            metrics: true,
            export_payloads: false,
        };
        let s = format!("{c:?}");
        assert!(!s.contains("secret-pw"), "{s}");
        assert!(!s.contains("secret-token"), "{s}");
        assert!(s.contains("authorization"), "{s}");
    }
}
