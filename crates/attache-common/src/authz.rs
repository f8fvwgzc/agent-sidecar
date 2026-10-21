//! Authorization decisions (CONTRACT.md §5.1).
use attache_charter::{Charter, Decision, PathPattern};

pub use crate::identity::LOCAL;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verdict {
    pub allow: bool,
    pub rule: String,
    pub reason: String,
}

impl Verdict {
    pub fn allow(rule: impl Into<String>) -> Self {
        Self {
            allow: true,
            rule: rule.into(),
            reason: String::new(),
        }
    }
    pub fn deny(rule: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            allow: false,
            rule: rule.into(),
            reason: reason.into(),
        }
    }
    pub fn decision(&self) -> &'static str {
        if self.allow { "allow" } else { "deny" }
    }
}

/// The path the sidecar authorizes, audits and forwards — one string for all three (CONTRACT.md §5.1).
///
/// Escaped unreserved characters are decoded first (`/%61dmin` is `/admin`, `%2e%2e` is `..`) and
/// other escapes get uppercase hex; then the path is resolved with the same WHATWG URL parser
/// reqwest uses to send the request, so `.` and `..` are removed *before* matching instead of
/// after. Refused outright: a literal `;` in the path (Tomcat, Spring and Jetty cut `;…` path
/// parameters off a segment before routing, so `/admin;x/reset` would reach `/admin/reset`; an
/// escaped `%3B` is data to them and stays), an encoded `/`, `\` or NUL in the path (not in the
/// query, where they are only data), an empty segment (`//`), and backslashes, fragments,
/// whitespace and control characters anywhere.
pub fn canonical_path(raw: &str) -> Result<String, String> {
    if !raw.starts_with('/') {
        return Err(format!("path {raw:?} must start with /"));
    }
    if raw
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == '\\' || c == '#')
    {
        return Err(format!(
            "path {raw:?} contains whitespace, a control character, a backslash or a fragment"
        ));
    }
    let (path, query) = match raw.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (raw, None),
    };
    if path.contains(';') {
        return Err(format!(
            "path {raw:?} has a ';' path parameter (a ; that is data is sent as %3B)"
        ));
    }
    let path = attache_charter::normalize_percent_escapes(path)
        .map_err(|e| format!("path {raw:?} {e}"))?;
    let url = match query {
        Some(q) => format!("http://attache.invalid{path}?{q}"),
        None => format!("http://attache.invalid{path}"),
    };
    let url = url::Url::parse(&url).map_err(|e| format!("path {raw:?}: {e}"))?;
    if url.host_str() != Some("attache.invalid") {
        return Err(format!("path {raw:?} changes the target host"));
    }
    if url.path().contains("//") {
        return Err(format!("path {raw:?} has an empty segment (//)"));
    }
    let mut out = url.path().to_string();
    if let Some(q) = url.query() {
        out.push('?');
        out.push_str(q);
    }
    Ok(out)
}

/// The method the sidecar authorizes, audits and sends: uppercased, and one `is_method` knows.
pub fn canonical_method(raw: &str) -> Result<String, String> {
    let m = raw.to_ascii_uppercase();
    if attache_charter::is_method(&m) {
        Ok(m)
    } else {
        Err(format!(
            "method {raw:?} is not one of GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS"
        ))
    }
}

pub const RULE_PATH: &str = "guardrail.path";

/// May `caller` (`local` or a SPIFFE URI), acting for `caller_agent` (the calling sidecar's
/// `x-attache-agent` claim, or the local calling agent), invoke `agent`?
pub fn authorize_caller(
    charter: &Charter,
    caller: &str,
    caller_agent: Option<&str>,
    agent: &str,
) -> Verdict {
    let mut matched_identity = false;
    let mut agent_mismatch = false;
    for rule in &charter.authz.callers {
        if rule.identity != caller {
            continue;
        }
        matched_identity = true;
        if rule.agents.iter().any(|a| a == "*" || a == agent) {
            if rule.caller_agents.is_empty()
                || caller_agent.is_some_and(|ca| rule.caller_agents.iter().any(|x| x == ca))
            {
                return Verdict::allow(format!("authz.callers.{}", short_identity(caller)));
            }
            agent_mismatch = true;
        }
    }
    if agent_mismatch {
        return Verdict::deny(
            format!("authz.callers.{}", short_identity(caller)),
            format!(
                "identity {caller} may invoke {agent} only for caller_agents, and {:?} is not one",
                caller_agent.unwrap_or("-")
            ),
        );
    }
    if matched_identity {
        Verdict::deny(
            format!("authz.callers.{}", short_identity(caller)),
            format!("identity {caller} may not invoke agent {agent}"),
        )
    } else {
        Verdict::deny(
            "authz.callers.default",
            format!("no authz.callers rule for identity {caller}"),
        )
    }
}

/// May `agent` (called by `caller`) perform `method path` on `service`?
/// Used egress (service = target) and inbound (service = self).
pub fn authorize_service_call(
    charter: &Charter,
    caller: Option<&str>,
    agent: Option<&str>,
    service: &str,
    method: &str,
    path: &str,
) -> Verdict {
    let mut applied = false;
    let mut allowed_by: Option<String> = None;
    for rule in &charter.authz.services {
        if rule.service != service {
            continue;
        }
        if let Some(id) = &rule.identity
            && caller != Some(id.as_str())
        {
            continue;
        }
        if let Some(a) = &rule.agent
            && agent != Some(a.as_str())
        {
            continue;
        }
        applied = true;
        for p in &rule.deny {
            if PathPattern::parse(p)
                .map(|pp| pp.matches_ignore_case(method, path))
                .unwrap_or(false)
            {
                return Verdict::deny(
                    format!("authz.services.{}", rule.name),
                    format!("{method} {path} on {service} matches deny pattern {p:?}"),
                );
            }
        }
        if allowed_by.is_none() {
            for p in &rule.allow {
                if PathPattern::parse(p)
                    .map(|pp| pp.matches(method, path))
                    .unwrap_or(false)
                {
                    allowed_by = Some(format!("authz.services.{}", rule.name));
                    break;
                }
            }
        }
    }
    if let Some(rule) = allowed_by {
        return Verdict::allow(rule);
    }
    let what = if applied {
        "no allow pattern matched"
    } else {
        "no authz.services rule applies"
    };
    match charter.authz.default {
        Decision::Allow => Verdict::allow("authz.default.allow"),
        Decision::Deny => Verdict::deny(
            "authz.default.deny",
            format!(
                "{what} for {method} {path} on {service} (agent {}, caller {})",
                agent.unwrap_or("-"),
                caller.unwrap_or("-")
            ),
        ),
    }
}

fn short_identity(id: &str) -> String {
    match crate::identity::SpiffeId::parse(id) {
        Some(s) => s.service,
        None => id.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const INVENTORY: &str = include_str!("../../../examples/charters/inventory.charter.yaml");
    const ORDERS_ID: &str = "spiffe://attache/ns/attache-demo/svc/orders";

    #[test]
    fn callers() {
        let c = Charter::from_yaml(INVENTORY).unwrap();
        assert!(authorize_caller(&c, "local", None, "stock-analyst").allow);
        assert!(authorize_caller(&c, ORDERS_ID, Some("ops-assistant"), "stock-analyst").allow);
        let other = authorize_caller(&c, ORDERS_ID, Some("refund-bot"), "stock-analyst");
        assert!(
            !other.allow,
            "caller_agents restricts which orders agent may call"
        );
        assert_eq!(other.rule, "authz.callers.orders");
        assert!(!authorize_caller(&c, ORDERS_ID, None, "stock-analyst").allow);
        let v = authorize_caller(
            &c,
            "spiffe://attache/ns/attache-demo/svc/billing",
            Some("x"),
            "stock-analyst",
        );
        assert!(!v.allow);
        assert_eq!(v.rule, "authz.callers.default");
    }

    #[test]
    fn canonical_paths() {
        assert_eq!(
            canonical_path("/stock/WIDGET-1").unwrap(),
            "/stock/WIDGET-1"
        );
        assert_eq!(
            canonical_path("/stock/../admin/reset").unwrap(),
            "/admin/reset"
        );
        assert_eq!(
            canonical_path("/stock/%2e%2e/admin/reset").unwrap(),
            "/admin/reset"
        );
        assert_eq!(canonical_path("/stock/.%2E/admin/x").unwrap(), "/admin/x");
        assert_eq!(canonical_path("/stock/./a?x=1").unwrap(), "/stock/a?x=1");
        assert_eq!(canonical_path("/../../etc").unwrap(), "/etc");
        // escaped unreserved characters are decoded, other escapes only get uppercase hex
        assert_eq!(canonical_path("/%61dmin/reset").unwrap(), "/admin/reset");
        assert_eq!(canonical_path("/stock/%7E%2d%5F").unwrap(), "/stock/~-_");
        assert_eq!(canonical_path("/q/a%3ab%20c").unwrap(), "/q/a%3Ab%20c");
        assert_eq!(
            canonical_path("/q/a%2561").unwrap(),
            "/q/a%2561",
            "no double decoding"
        );
        assert_eq!(canonical_path("/x/%2E%2E/admin").unwrap(), "/admin");
        // a trailing slash is kept (the matcher ignores it); the query may carry encoded / \ NUL
        assert_eq!(canonical_path("/admin/").unwrap(), "/admin/");
        assert_eq!(
            canonical_path("/x?since=2026%2F10%2F21&u=http%3A%2F%2Fh%2Fy&b=%5c").unwrap(),
            "/x?since=2026%2F10%2F21&u=http%3A%2F%2Fh%2Fy&b=%5c"
        );
        assert_eq!(canonical_path("/x?a=1?b").unwrap(), "/x?a=1?b");
        // `;` is data only when escaped: %3B stays (with uppercase hex), and the query may carry `;`
        assert_eq!(canonical_path("/stock/A%3bx=1").unwrap(), "/stock/A%3Bx=1");
        assert_eq!(canonical_path("/x?a=1;b=2").unwrap(), "/x?a=1;b=2");
        for bad in [
            "/admin;x",
            "/admin;x/reset",
            "/%61dmin;x",
            "/admin;",
            "/stock/..;/admin/reset",
            "/admin;x/../reset",
            "stock",
            "http://evil/x",
            "/stock/..%2fadmin",
            "/stock/%2F",
            "/a%5Cb",
            "/a\\b",
            "/a#b",
            "/a b",
            "/a%00",
            "/a%",
            "/a%2",
            "/a%zz",
            "//admin/x",
            "/admin//x",
            "/a/.//b",
            "/x?q=a b",
        ] {
            assert!(canonical_path(bad).is_err(), "{bad} must be rejected");
        }
        assert_eq!(canonical_method("get").unwrap(), "GET");
        assert_eq!(canonical_method("Head").unwrap(), "HEAD");
        assert!(canonical_method("FETCH").is_err());
        assert!(canonical_method("").is_err());
        // what authz sees is what is sent: the traversal now meets the deny rule
        let c = Charter::from_yaml(INVENTORY).unwrap();
        let p = canonical_path("/stock/../admin/reset").unwrap();
        let v = authorize_service_call(
            &c,
            Some(ORDERS_ID),
            Some("ops-assistant"),
            "inventory",
            "GET",
            &p,
        );
        assert_eq!(v.rule, "authz.services.deny-admin");
    }

    /// With `default: allow` the deny patterns are all that stand in the way, so every spelling
    /// a router would send to `/admin` or a GET handler must meet them.
    #[test]
    fn deny_patterns_hold_against_other_spellings() {
        let mut c = Charter::from_yaml(INVENTORY).unwrap();
        c.authz.default = Decision::Allow;
        let rule = c
            .authz
            .services
            .iter_mut()
            .find(|r| r.name == "deny-admin")
            .unwrap();
        rule.deny.push("GET /export/*".into());
        let check = |method: &str, raw: &str| {
            let path = canonical_path(raw).unwrap();
            let method = canonical_method(method).unwrap();
            authorize_service_call(
                &c,
                Some(ORDERS_ID),
                Some("ops-assistant"),
                "inventory",
                &method,
                &path,
            )
        };
        for (method, raw) in [
            ("POST", "/admin/reset"),
            ("POST", "/%61dmin/reset"),
            ("POST", "/%41DMIN/reset"),
            ("post", "/admin"),
            ("POST", "/admin/"),
            ("POST", "/admin/reset/"),
            ("DELETE", "/ADMIN"),
            ("PUT", "/Admin/x?y=1"),
            ("GET", "/export/x"),
            ("HEAD", "/export/x"),
            ("head", "/EXPORT/x/"),
        ] {
            let v = check(method, raw);
            assert!(!v.allow, "{method} {raw} must be denied: {v:?}");
            assert_eq!(v.rule, "authz.services.deny-admin", "{method} {raw}");
        }
        for (method, raw) in [
            ("POST", "/administrator"),
            ("POST", "/export/x"),
            ("GET", "/export"),
        ] {
            assert!(check(method, raw).allow, "{method} {raw}");
        }
        for raw in ["//admin/x", "/admin//x", "/%2Fadmin"] {
            assert!(
                canonical_path(raw).is_err(),
                "{raw} never reaches the matcher"
            );
        }
        // Tomcat, Spring and Jetty cut `;…` off each segment before routing (`/admin;x/reset` is
        // their `/admin/reset`, `/stock/..;/admin` their `/admin`), so a literal `;` in the path
        // never reaches the matcher either.
        for raw in [
            "/admin;x",
            "/admin;x/reset",
            "/%61dmin;x",
            "/ADMIN;jsessionid=1/reset",
            "/stock/..;/admin/reset",
        ] {
            let err = canonical_path(raw).unwrap_err();
            assert!(err.contains("';' path parameter"), "{raw}: {err}");
        }
        // Those routers split on the raw `;` before decoding, so %3B is data: the segment below is
        // `admin;x`, not `admin`, and goes on (the deny rule is about /admin, not this path).
        assert_eq!(
            canonical_path("/admin%3Bx/reset").unwrap(),
            "/admin%3Bx/reset"
        );
        assert!(check("POST", "/admin%3Bx/reset").allow);
    }

    #[test]
    fn allow_patterns_take_head_for_get_but_not_case_variants() {
        let c = Charter::from_yaml(INVENTORY).unwrap();
        let check = |method: &str, path: &str| {
            authorize_service_call(
                &c,
                Some(ORDERS_ID),
                Some("ops-assistant"),
                "inventory",
                method,
                path,
            )
        };
        assert!(check("HEAD", "/stock/WIDGET-1").allow);
        assert!(check("GET", "/stock/").allow, "/stock/ is /stock");
        // a value holding `;` arrives as %3B (the runtime encodes it) and is an ordinary segment
        let semi = canonical_path("/stock/WIDGET%3b1").unwrap();
        assert!(check("GET", &semi).allow, "{semi}");
        let upper = check("GET", "/STOCK/WIDGET-1");
        assert!(!upper.allow, "{upper:?}");
        assert_eq!(upper.rule, "authz.default.deny");
    }

    #[test]
    fn service_rules_deny_wins_and_default_denies() {
        let c = Charter::from_yaml(INVENTORY).unwrap();
        let ok = authorize_service_call(
            &c,
            Some(ORDERS_ID),
            Some("ops-assistant"),
            "inventory",
            "GET",
            "/stock/WIDGET-1",
        );
        assert!(ok.allow, "{ok:?}");
        assert_eq!(ok.rule, "authz.services.orders-reads-stock");
        let denied = authorize_service_call(
            &c,
            Some(ORDERS_ID),
            Some("ops-assistant"),
            "inventory",
            "POST",
            "/admin/reset",
        );
        assert!(!denied.allow);
        assert_eq!(denied.rule, "authz.services.deny-admin");
        let unknown = authorize_service_call(
            &c,
            Some(ORDERS_ID),
            Some("ops-assistant"),
            "inventory",
            "DELETE",
            "/stock/x",
        );
        assert!(!unknown.allow);
        assert_eq!(unknown.rule, "authz.default.deny");
        let self_call = authorize_service_call(
            &c,
            Some("local"),
            Some("stock-analyst"),
            "inventory",
            "GET",
            "/stock",
        );
        assert!(self_call.allow);
    }
}
