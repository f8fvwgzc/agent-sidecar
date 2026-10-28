//! Principals as Tutela names them (CONTRACT.md §5.3, docs/design/agent-registry.md).
//!
//! On the wire a principal is one string, `<kind>:<id>`. attache names two kinds:
//!
//! - `agent:agt_<uuidv7>`: an agent of the registry, minted by embassy when a charter first
//!   declares it. The id is the agent's, not the service's: it never changes while the agent keeps
//!   its `(namespace, service, name)`, and is never reused for another agent.
//! - `workload:spiffe://<trust domain>/ns/<namespace>/svc/<service>`: a workload, the identity in
//!   every certificate embassy issues ([`crate::identity::SpiffeId`]).
//!
//! The text rules are Tutela's (`tutela-contracts`, `principal.rs` and `id.rs`): a UUIDv7 in its
//! 36-character lowercase form, with version digit `7` and variant digit `8`, `9`, `a` or `b`.
//! attache checks the text itself instead of linking `tutela-contracts`, which has no tagged
//! release yet (#26); the conformance tests below use Tutela's own examples.
use std::fmt;
use std::str::FromStr;

use crate::identity::SpiffeId;

/// The prefix of an agent id.
pub const AGENT_ID_PREFIX: &str = "agt_";
/// The kind prefix of an agent principal.
pub const AGENT_KIND: &str = "agent:";
/// The kind prefix of a workload principal.
pub const WORKLOAD_KIND: &str = "workload:";

/// Why a principal or an agent id was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PrincipalError {
    #[error("an agent id must start with `agt_`")]
    AgentPrefix,
    #[error("a UUIDv7 must be exactly 36 characters")]
    UuidLength,
    #[error("a UUIDv7 must have `-` after the 8th, 12th, 16th and 20th hex digit")]
    UuidHyphen,
    #[error("a UUIDv7 must use lowercase hex digits (0-9, a-f) only")]
    UuidHex,
    #[error("the UUID version digit must be 7")]
    UuidVersion,
    #[error("the UUID variant digit must be 8, 9, a or b")]
    UuidVariant,
    #[error("a principal is `agent:agt_<uuidv7>` or `workload:spiffe://<td>/ns/<ns>/svc/<svc>`")]
    Kind,
    #[error("a workload principal names `spiffe://<trust domain>/ns/<namespace>/svc/<service>`")]
    Workload,
}

/// Checks a UUIDv7 in Tutela's text form.
fn check_uuid7(s: &str) -> Result<(), PrincipalError> {
    let b = s.as_bytes();
    if b.len() != 36 {
        return Err(PrincipalError::UuidLength);
    }
    for (i, &c) in b.iter().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            if c != b'-' {
                return Err(PrincipalError::UuidHyphen);
            }
        } else if !matches!(c, b'0'..=b'9' | b'a'..=b'f') {
            return Err(PrincipalError::UuidHex);
        }
    }
    if b[14] != b'7' {
        return Err(PrincipalError::UuidVersion);
    }
    if !matches!(b[19], b'8' | b'9' | b'a' | b'b') {
        return Err(PrincipalError::UuidVariant);
    }
    Ok(())
}

/// An agent id, `agt_<uuidv7>`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentId(String);

impl AgentId {
    /// A fresh id: a UUIDv7 of now, so ids sort by creation time.
    pub fn generate() -> AgentId {
        AgentId(format!("{AGENT_ID_PREFIX}{}", uuid::Uuid::now_v7()))
    }

    /// `agt_<uuidv7>`, exactly as Tutela reads it.
    pub fn parse(s: &str) -> Result<AgentId, PrincipalError> {
        let uuid = s
            .strip_prefix(AGENT_ID_PREFIX)
            .ok_or(PrincipalError::AgentPrefix)?;
        check_uuid7(uuid)?;
        Ok(AgentId(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The principal, `agent:agt_<uuidv7>`.
    pub fn principal(&self) -> String {
        format!("{AGENT_KIND}{}", self.0)
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for AgentId {
    type Err = PrincipalError;
    fn from_str(s: &str) -> Result<AgentId, PrincipalError> {
        AgentId::parse(s)
    }
}

/// A principal attache names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Principal {
    Agent(AgentId),
    Workload(SpiffeId),
}

impl Principal {
    /// `agent:agt_<uuidv7>` or `workload:spiffe://<td>/ns/<ns>/svc/<svc>`.
    pub fn parse(s: &str) -> Result<Principal, PrincipalError> {
        if let Some(id) = s.strip_prefix(AGENT_KIND) {
            return AgentId::parse(id).map(Principal::Agent);
        }
        if let Some(uri) = s.strip_prefix(WORKLOAD_KIND) {
            return SpiffeId::parse(uri)
                .map(Principal::Workload)
                .ok_or(PrincipalError::Workload);
        }
        Err(PrincipalError::Kind)
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Principal::Agent(id) => write!(f, "{AGENT_KIND}{id}"),
            Principal::Workload(w) => write!(f, "{WORKLOAD_KIND}{}", w.uri()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tutela's own examples (tutela-contracts claims.rs and principal.rs tests).
    const TUTELA_AGENT: &str = "agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102";

    #[test]
    fn tutelas_agent_principal_reads_and_prints_the_same() {
        let p = Principal::parse(TUTELA_AGENT).unwrap();
        assert_eq!(p.to_string(), TUTELA_AGENT);
        let Principal::Agent(id) = p else { panic!() };
        assert_eq!(id.as_str(), "agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102");
        assert_eq!(id.principal(), TUTELA_AGENT);
    }

    #[test]
    fn a_generated_id_is_a_uuidv7_tutela_accepts() {
        for _ in 0..64 {
            let id = AgentId::generate();
            assert_eq!(AgentId::parse(id.as_str()).unwrap(), id);
        }
        let (a, b) = (AgentId::generate(), AgentId::generate());
        assert!(
            a < b || a.as_str()[..17] == b.as_str()[..17],
            "ids sort by time"
        );
    }

    #[test]
    fn each_rule_has_its_error() {
        let ok = "agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102";
        AgentId::parse(ok).unwrap();
        let cases = [
            (
                "usr_0193a1b2-c3d4-7b33-9c44-5d6e7f809102",
                PrincipalError::AgentPrefix,
            ),
            (
                "agt_0193a1b2-c3d4-7b33-9c44-5d6e7f80910",
                PrincipalError::UuidLength,
            ),
            (
                "agt_0193a1b2xc3d4-7b33-9c44-5d6e7f809102",
                PrincipalError::UuidHyphen,
            ),
            (
                "agt_0193A1B2-c3d4-7b33-9c44-5d6e7f809102",
                PrincipalError::UuidHex,
            ),
            (
                "agt_0193a1b2-c3d4-4b33-9c44-5d6e7f809102",
                PrincipalError::UuidVersion,
            ),
            (
                "agt_0193a1b2-c3d4-7b33-cc44-5d6e7f809102",
                PrincipalError::UuidVariant,
            ),
        ];
        for (s, err) in cases {
            assert_eq!(AgentId::parse(s), Err(err), "{s}");
        }
        assert_eq!(
            Principal::parse(&format!("user:{ok}")),
            Err(PrincipalError::Kind)
        );
    }

    #[test]
    fn a_workload_principal_is_attaches_service_identity() {
        let w = "workload:spiffe://agentsc/ns/shop/svc/orders";
        let p = Principal::parse(w).unwrap();
        assert_eq!(
            p,
            Principal::Workload(SpiffeId::new("agentsc", "shop", "orders"))
        );
        assert_eq!(p.to_string(), w);
        // Tutela's example path (`/sa/`) names no attache workload (tutela#29)
        assert_eq!(
            Principal::parse("workload:spiffe://prod-eu1.attache.example.test/ns/shop/sa/orders"),
            Err(PrincipalError::Workload)
        );
    }
}
