//! Authorization decisions (CONTRACT.md §5.1).
use attache_charter::{Charter, Decision, PathPattern};
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

/// May `caller` (`local` or a SPIFFE URI) invoke `agent`?
pub fn authorize_caller(charter: &Charter, caller: &str, agent: &str) -> Verdict {
    let mut matched_identity = false;
    for rule in &charter.authz.callers {
        if rule.identity != caller {
            continue;
        }
        matched_identity = true;
        if rule.agents.iter().any(|a| a == "*" || a == agent) {
            return Verdict::allow(format!("authz.callers.{}", short_identity(caller)));
        }
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
        assert!(authorize_caller(&c, "local", "stock-analyst").allow);
        assert!(authorize_caller(&c, ORDERS_ID, "stock-analyst").allow);
        let v = authorize_caller(
            &c,
            "spiffe://attache/ns/attache-demo/svc/billing",
            "stock-analyst",
        );
        assert!(!v.allow);
        assert_eq!(v.rule, "authz.callers.default");
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
