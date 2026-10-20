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
/// It is resolved with the same WHATWG URL parser reqwest uses to send the request, so `..`,
/// `%2e%2e` and friends are removed *before* matching instead of after. Encoded `/` or `\`,
/// backslashes, fragments, whitespace and control characters are refused outright.
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
    let lower = raw.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") || lower.contains("%00") {
        return Err(format!(
            "path {raw:?} contains an encoded slash, backslash or NUL"
        ));
    }
    let url = url::Url::parse(&format!("http://attache.invalid{raw}"))
        .map_err(|e| format!("path {raw:?}: {e}"))?;
    if url.host_str() != Some("attache.invalid") {
        return Err(format!("path {raw:?} changes the target host"));
    }
    let mut out = url.path().to_string();
    if let Some(q) = url.query() {
        out.push('?');
        out.push_str(q);
    }
    Ok(out)
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
                .map(|pp| pp.matches(method, path))
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
        for bad in [
            "stock",
            "http://evil/x",
            "/stock/..%2fadmin",
            "/a\\b",
            "/a#b",
            "/a b",
            "/a%00",
        ] {
            assert!(canonical_path(bad).is_err(), "{bad} must be rejected");
        }
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
