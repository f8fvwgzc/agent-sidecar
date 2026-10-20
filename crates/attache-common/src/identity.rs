//! SPIFFE-style identities: `spiffe://attache/ns/<namespace>/svc/<service>`.
pub const TRUST_DOMAIN: &str = "attache";
pub const LOCAL: &str = attache_charter::LOCAL_IDENTITY;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeId {
    pub namespace: String,
    pub service: String,
}

impl SpiffeId {
    pub fn parse(uri: &str) -> Option<SpiffeId> {
        let rest = uri.strip_prefix(&format!("spiffe://{TRUST_DOMAIN}/ns/"))?;
        let (namespace, rest) = rest.split_once("/svc/")?;
        if namespace.is_empty() || rest.is_empty() || rest.contains('/') {
            return None;
        }
        Some(SpiffeId {
            namespace: namespace.to_string(),
            service: rest.to_string(),
        })
    }

    pub fn uri(&self) -> String {
        attache_charter::spiffe_id(&self.namespace, &self.service)
    }

    /// DNS SANs every leaf certificate carries (CONTRACT.md §5).
    pub fn dns_names(&self) -> Vec<String> {
        vec![
            self.service.clone(),
            format!("{}.{}", self.service, self.namespace),
            format!("{}.{}.svc", self.service, self.namespace),
            format!("{}.{}.svc.cluster.local", self.service, self.namespace),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip() {
        let id = SpiffeId::parse("spiffe://attache/ns/attache-demo/svc/orders").unwrap();
        assert_eq!(id.namespace, "attache-demo");
        assert_eq!(id.service, "orders");
        assert_eq!(id.uri(), "spiffe://attache/ns/attache-demo/svc/orders");
        assert!(SpiffeId::parse("spiffe://other/ns/a/svc/b").is_none());
        assert!(SpiffeId::parse("spiffe://attache/ns/a/svc/b/c").is_none());
    }
}
