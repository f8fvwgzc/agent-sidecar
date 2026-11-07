//! Principals as Tutela names them (CONTRACT.md §5.3, docs/design/agent-registry.md).
//!
//! On the wire a principal is one string, `<kind>:<id>`. The types are Tutela's own
//! (`tutela-contracts` at the `v0.2.0` tag, `principal.rs` and `id.rs`), re-exported here, so
//! attache reads and writes exactly what Tutela does. attache mints two kinds:
//!
//! - `agent:agt_<uuidv7>`: an agent of the registry, minted by embassy when a charter first
//!   declares it ([`new_agent_id`]). The id is the agent's, not the service's: it never changes
//!   while the agent keeps its `(namespace, service, name)`, and is never reused for another agent.
//! - `workload:spiffe://<trust domain>/ns/<namespace>/svc/<service>`: a workload, the identity in
//!   every certificate embassy issues ([`crate::identity::SpiffeId`], [`workload`],
//!   [`service_of`]).
pub use tutela_contracts::id::Uuid7;
pub use tutela_contracts::principal::{
    AgentId, Principal, PrincipalError, PrincipalKind, WorkloadId,
};

use crate::identity::SpiffeId;

/// A fresh agent id: a UUIDv7 of now, so ids sort by creation time.
pub fn new_agent_id() -> AgentId {
    AgentId::new(uuid7_now())
}

/// A UUIDv7 of now.
pub fn uuid7_now() -> Uuid7 {
    Uuid7::from_uuid(uuid::Uuid::now_v7()).expect("now_v7 sets version 7 and the RFC 9562 variant")
}

/// A UUIDv7 in Tutela's text form made of `bytes`: the version and variant bits are set and the
/// rest is kept, so the same bytes always give the same id (embassy's derived caller ids).
pub fn uuid7_from_bytes(bytes: [u8; 16]) -> Uuid7 {
    let uuid = uuid::Builder::from_bytes(bytes)
        .with_version(uuid::Version::SortRand)
        .with_variant(uuid::Variant::RFC4122)
        .into_uuid();
    Uuid7::from_uuid(uuid).expect("the builder set version 7 and the RFC 9562 variant")
}

/// The workload principal of a service identity. `None` only for a URI Tutela's SPIFFE rules
/// refuse (attache's own are always accepted).
pub fn workload(id: &SpiffeId) -> Option<Principal> {
    WorkloadId::parse(&id.uri()).ok().map(Principal::Workload)
}

/// The attache service identity a principal names: a `workload:` principal of the form
/// `spiffe://<trust domain>/ns/<namespace>/svc/<service>`. Any other principal, or another
/// SPIFFE path (Tutela's examples use `/sa/`, tutela#29), names none.
pub fn service_of(p: &Principal) -> Option<SpiffeId> {
    p.as_workload().and_then(|w| SpiffeId::parse(w.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tutela's own examples (tutela-contracts claims.rs and principal.rs tests).
    const TUTELA_AGENT: &str = "agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102";

    #[test]
    fn tutelas_agent_principal_reads_and_prints_the_same() {
        let p: Principal = TUTELA_AGENT.parse().unwrap();
        assert_eq!(p.to_string(), TUTELA_AGENT);
        let id = p.as_agent().unwrap();
        assert_eq!(id.to_string(), "agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102");
        assert_eq!(Principal::Agent(*id).to_string(), TUTELA_AGENT);
    }

    #[test]
    fn a_generated_id_is_a_uuidv7_tutela_accepts() {
        for _ in 0..64 {
            let id = new_agent_id();
            assert_eq!(id.to_string().parse::<AgentId>().unwrap(), id);
        }
        let (a, b) = (new_agent_id().to_string(), new_agent_id().to_string());
        assert!(a < b || a[..17] == b[..17], "ids sort by time");
    }

    #[test]
    fn ids_from_the_same_bytes_are_the_same_uuidv7() {
        let bytes = [0xab; 16];
        let a = uuid7_from_bytes(bytes);
        assert_eq!(a, uuid7_from_bytes(bytes));
        assert_ne!(a, uuid7_from_bytes([0xcd; 16]));
        let text = a.to_string();
        assert_eq!(text.as_bytes()[14], b'7');
        assert!(matches!(text.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
        assert_eq!(text.parse::<Uuid7>().unwrap(), a);
    }

    #[test]
    fn each_broken_rule_is_refused() {
        let ok = "agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102";
        ok.parse::<AgentId>().unwrap();
        for bad in [
            "usr_0193a1b2-c3d4-7b33-9c44-5d6e7f809102", // prefix
            "agt_0193a1b2-c3d4-7b33-9c44-5d6e7f80910",  // length
            "agt_0193a1b2xc3d4-7b33-9c44-5d6e7f809102", // hyphen
            "agt_0193A1B2-c3d4-7b33-9c44-5d6e7f809102", // hex
            "agt_0193a1b2-c3d4-4b33-9c44-5d6e7f809102", // version
            "agt_0193a1b2-c3d4-7b33-cc44-5d6e7f809102", // variant
        ] {
            assert!(bad.parse::<AgentId>().is_err(), "{bad}");
        }
        assert!(format!("nobody:{ok}").parse::<Principal>().is_err());
        assert!(format!("user:{ok}").parse::<Principal>().is_err());
    }

    #[test]
    fn a_workload_principal_is_attaches_service_identity() {
        let w = "workload:spiffe://agentsc/ns/shop/svc/orders";
        let p: Principal = w.parse().unwrap();
        let id = SpiffeId::new("agentsc", "shop", "orders");
        assert_eq!(service_of(&p), Some(id.clone()));
        assert_eq!(workload(&id), Some(p.clone()));
        assert_eq!(p.to_string(), w);
        // Tutela's example path (`/sa/`) is a valid principal that names no attache workload
        // (tutela#29), and neither does an agent
        let other: Principal = "workload:spiffe://prod-eu1.attache.example.test/ns/shop/sa/orders"
            .parse()
            .unwrap();
        assert_eq!(service_of(&other), None);
        assert_eq!(service_of(&TUTELA_AGENT.parse().unwrap()), None);
    }
}
