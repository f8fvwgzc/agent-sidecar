//! Name and format checks shared by the config, the CLI and the API (design §3).

/// The service name that is never issued a certificate (design §3).
pub const RESERVED_SERVICE: &str = "embassy";

/// A DNS-1123 label: `^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`.
pub fn is_dns_label(s: &str) -> bool {
    let b = s.as_bytes();
    let alnum = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    !b.is_empty()
        && b.len() <= 63
        && b.first().is_some_and(alnum)
        && b.last().is_some_and(alnum)
        && b.iter().all(|c| alnum(c) || *c == b'-')
}

/// A DNS-1123 subdomain (a host name such as `embassy.agentsc-system.svc`): dot-separated
/// labels, at most 253 characters.
pub fn is_dns_subdomain(s: &str) -> bool {
    s.len() <= 253 && s.split('.').all(is_dns_label)
}

/// 64 lowercase hex characters (a SHA-256 digest as the config stores it).
pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// A Kubernetes object reference `<namespace>/<name>` (e.g. `--ca-secret agentsc-system/agentsc-ca`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectRef {
    pub namespace: String,
    pub name: String,
}

impl std::str::FromStr for ObjectRef {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (namespace, name) = s
            .split_once('/')
            .ok_or_else(|| format!("{s:?} is not <namespace>/<name>"))?;
        if !is_dns_label(namespace) {
            return Err(format!("namespace {namespace:?} is not a DNS-1123 label"));
        }
        if !is_dns_subdomain(name) {
            return Err(format!("name {name:?} is not a DNS-1123 subdomain"));
        }
        Ok(Self {
            namespace: namespace.to_string(),
            name: name.to_string(),
        })
    }
}

impl std::fmt::Display for ObjectRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.namespace, self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_labels() {
        for ok in ["a", "orders", "agentsc-demo", "a1", &"x".repeat(63)] {
            assert!(is_dns_label(ok), "{ok}");
        }
        for bad in ["", "-a", "a-", "A", "a_b", "a.b", "*", &"x".repeat(64)] {
            assert!(!is_dns_label(bad), "{bad}");
        }
    }

    #[test]
    fn dns_subdomains() {
        assert!(is_dns_subdomain("embassy.agentsc-system.svc"));
        assert!(is_dns_subdomain("localhost"));
        assert!(!is_dns_subdomain("embassy..svc"));
        assert!(!is_dns_subdomain(".svc"));
        assert!(!is_dns_subdomain("Embassy.svc"));
        assert!(!is_dns_subdomain(&format!("{}.x", "a".repeat(253))));
    }

    #[test]
    fn sha256_hex() {
        assert!(is_sha256_hex(&"ab".repeat(32)));
        assert!(!is_sha256_hex(&"AB".repeat(32)));
        assert!(!is_sha256_hex(&"ab".repeat(31)));
        assert!(!is_sha256_hex(&"zz".repeat(32)));
    }

    #[test]
    fn object_refs() {
        let r: ObjectRef = "agentsc-system/embassy-tls".parse().unwrap();
        assert_eq!(r.namespace, "agentsc-system");
        assert_eq!(r.name, "embassy-tls");
        assert_eq!(r.to_string(), "agentsc-system/embassy-tls");
        assert!("embassy-tls".parse::<ObjectRef>().is_err());
        assert!("Agentsc/x".parse::<ObjectRef>().is_err());
        assert!("ns/".parse::<ObjectRef>().is_err());
        assert!("ns/a/b".parse::<ObjectRef>().is_err());
    }
}
