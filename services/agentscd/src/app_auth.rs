//! The optional app API token (design §6.6): with `--app-token-file` / `AGENTSC_APP_TOKEN`, every
//! app HTTP and gRPC request needs `Authorization: Bearer <token>`, compared in constant time;
//! otherwise 401 / `UNAUTHENTICATED` and an `authz` record with rule `app.unauthenticated`.
//! `/healthz` and `/readyz` stay open.
use agentsc_common::audit::{AuditRecord, Direction, Kind};
use agentsc_common::authz::Verdict;
use agentsc_common::trace::{TraceContext, new_request_id};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::state::AppState;

pub const RULE_UNAUTHENTICATED: &str = "app.unauthenticated";

pub fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Constant-time comparison of two digests.
fn same(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Whether `authorization` (the header value) carries the expected token. Comparing digests keeps
/// the time independent of where the token differs and of its length.
pub fn authorized(expected: &[u8; 32], authorization: Option<&str>) -> bool {
    let presented = authorization
        .and_then(|h| {
            let (scheme, rest) = h.trim().split_once(' ')?;
            scheme.eq_ignore_ascii_case("bearer").then(|| rest.trim())
        })
        .unwrap_or("");
    let ok = same(expected, &digest(presented));
    ok && !presented.is_empty()
}

/// `Ok` when no token is configured or the request carries it; else the refusal reason, after
/// writing the `authz` record.
pub fn check(
    state: &AppState,
    authorization: Option<&str>,
    traceparent: Option<&str>,
    callee: &str,
) -> Result<(), Verdict> {
    let Some(expected) = &state.app_token else {
        return Ok(());
    };
    if authorized(expected, authorization) {
        return Ok(());
    }
    let reason = if authorization.is_some() {
        "the app API token does not match"
    } else {
        "the app API needs Authorization: Bearer <token>"
    };
    let v = Verdict::deny(RULE_UNAUTHENTICATED, reason);
    let trace = traceparent
        .map(TraceContext::from_traceparent)
        .unwrap_or_else(TraceContext::new_root);
    let rec = AuditRecord::new(
        Kind::Authz,
        Direction::Inbound,
        &new_request_id(),
        &trace,
        None,
        agentsc_charter::LOCAL_IDENTITY,
        None,
        callee,
        Value::Null,
        Value::Null,
    )
    .verdict(&v);
    state.audit.write(rec);
    Err(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_tokens_are_compared_whole() {
        let expected = digest("s3cret-token");
        assert!(authorized(&expected, Some("Bearer s3cret-token")));
        assert!(authorized(&expected, Some("bearer  s3cret-token ")));
        assert!(!authorized(&expected, Some("Bearer s3cret-toke")));
        assert!(!authorized(&expected, Some("Bearer s3cret-token2")));
        assert!(!authorized(&expected, Some("Basic s3cret-token")));
        assert!(!authorized(&expected, Some("s3cret-token")));
        assert!(!authorized(&expected, None));
        assert!(
            !authorized(&digest(""), Some("Bearer ")),
            "an empty token never passes"
        );
    }
}
