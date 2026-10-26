//! SPIFFE-style identities: `spiffe://<trust domain>/ns/<namespace>/svc/<service>` (CONTRACT.md
//! §5).
//!
//! The trust domain is configured per install (`--trust-domain` / `AGENTSC_TRUST_DOMAIN` on
//! `agentscd` and `embassy`, default [`DEFAULT_TRUST_DOMAIN`]). [`SpiffeId::parse`] reads a
//! workload ID in any trust domain and keeps it, so a caller decides what to accept: an identity
//! outside the configured domain is never one of ours ([`SpiffeId::parse_in`]).
pub use agentsc_charter::{
    DEFAULT_CLUSTER_DOMAIN, DEFAULT_TRUST_DOMAIN, check_cluster_domain, check_trust_domain,
};

/// The trust domain of an install that configures none. Kept for code written before the trust
/// domain was configurable; new code takes the configured one.
pub const TRUST_DOMAIN: &str = DEFAULT_TRUST_DOMAIN;
pub const LOCAL: &str = agentsc_charter::LOCAL_IDENTITY;

/// The URI SAN of the control plane's serving certificate in `trust_domain` (design §6.3.3):
/// `spiffe://<trust domain>/control-plane`.
pub fn control_plane_uri(trust_domain: &str) -> String {
    format!("spiffe://{trust_domain}/control-plane")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeId {
    pub trust_domain: String,
    pub namespace: String,
    pub service: String,
}

impl SpiffeId {
    pub fn new(trust_domain: &str, namespace: &str, service: &str) -> SpiffeId {
        SpiffeId {
            trust_domain: trust_domain.to_string(),
            namespace: namespace.to_string(),
            service: service.to_string(),
        }
    }

    /// `spiffe://<td>/ns/<namespace>/svc/<service>` with a valid trust domain name and no empty
    /// or further path segment; `None` for anything else (the control plane's URI included).
    pub fn parse(uri: &str) -> Option<SpiffeId> {
        let rest = uri.strip_prefix("spiffe://")?;
        let (trust_domain, rest) = rest.split_once("/ns/")?;
        check_trust_domain(trust_domain).ok()?;
        let (namespace, service) = rest.split_once("/svc/")?;
        if namespace.is_empty()
            || service.is_empty()
            || namespace.contains('/')
            || service.contains('/')
        {
            return None;
        }
        Some(SpiffeId::new(trust_domain, namespace, service))
    }

    /// [`SpiffeId::parse`], only for an identity in `trust_domain`.
    pub fn parse_in(uri: &str, trust_domain: &str) -> Option<SpiffeId> {
        SpiffeId::parse(uri).filter(|id| id.trust_domain == trust_domain)
    }

    pub fn uri(&self) -> String {
        agentsc_charter::spiffe_id_in(&self.trust_domain, &self.namespace, &self.service)
    }

    /// DNS SANs every leaf certificate carries (CONTRACT.md §5): `<svc>`, `<svc>.<ns>`,
    /// `<svc>.<ns>.svc` and `<svc>.<ns>.svc.<cluster domain>`.
    pub fn dns_names(&self, cluster_domain: &str) -> Vec<String> {
        vec![
            self.service.clone(),
            format!("{}.{}", self.service, self.namespace),
            format!("{}.{}.svc", self.service, self.namespace),
            format!("{}.{}.svc.{cluster_domain}", self.service, self.namespace),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip() {
        let id = SpiffeId::parse("spiffe://agentsc/ns/agentsc-demo/svc/orders").unwrap();
        assert_eq!(id.trust_domain, "agentsc");
        assert_eq!(id.namespace, "agentsc-demo");
        assert_eq!(id.service, "orders");
        assert_eq!(id.uri(), "spiffe://agentsc/ns/agentsc-demo/svc/orders");
        assert!(SpiffeId::parse("spiffe://agentsc/ns/a/svc/b/c").is_none());
        assert!(SpiffeId::parse("spiffe://agentsc/ns//svc/b").is_none());
        assert!(SpiffeId::parse("spiffe://agentsc/control-plane").is_none());
        assert!(SpiffeId::parse("https://agentsc/ns/a/svc/b").is_none());
    }

    #[test]
    fn other_trust_domains_parse_but_are_kept_apart() {
        let id = SpiffeId::parse("spiffe://prod.example/ns/shop/svc/orders").unwrap();
        assert_eq!(id.trust_domain, "prod.example");
        assert_eq!(id.uri(), "spiffe://prod.example/ns/shop/svc/orders");
        assert_eq!(
            SpiffeId::parse_in("spiffe://prod.example/ns/shop/svc/orders", "prod.example"),
            Some(id)
        );
        assert!(
            SpiffeId::parse_in("spiffe://prod.example/ns/shop/svc/orders", "agentsc").is_none()
        );
        assert!(
            SpiffeId::parse_in("spiffe://agentsc/ns/shop/svc/orders", "prod.example").is_none()
        );
        // not a trust domain name: uppercase, a port, userinfo
        for bad in [
            "spiffe://Prod/ns/a/svc/b",
            "spiffe://prod:8443/ns/a/svc/b",
            "spiffe://me@prod/ns/a/svc/b",
            "spiffe:///ns/a/svc/b",
        ] {
            assert!(SpiffeId::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn dns_names_follow_the_cluster_domain() {
        let id = SpiffeId::new("agentsc", "shop", "orders");
        assert_eq!(
            id.dns_names(DEFAULT_CLUSTER_DOMAIN),
            [
                "orders",
                "orders.shop",
                "orders.shop.svc",
                "orders.shop.svc.cluster.local"
            ]
        );
        assert_eq!(
            id.dns_names("corp.internal")[3],
            "orders.shop.svc.corp.internal"
        );
        assert_eq!(
            control_plane_uri("prod.example"),
            "spiffe://prod.example/control-plane"
        );
    }
}
