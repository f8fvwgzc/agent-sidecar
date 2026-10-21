//! The `agentsc_session` cookie (design §8.3): `<payload>.<mac>`, both base64url without
//! padding; the payload is the JSON `{"token_name": ..., "exp": <unix seconds>}` and the MAC is
//! HMAC-SHA256 over the encoded payload with the session key.
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// The cookie name.
pub const COOKIE: &str = "agentsc_session";
/// A session's lifetime.
pub const LIFETIME: Duration = Duration::from_secs(12 * 3600);
/// Longer values are refused before any work.
const MAX_VALUE: usize = 1024;

/// What a session carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub token_name: String,
    pub exp: i64,
}

fn mac(key: &[u8], payload: &str) -> Option<Hmac<Sha256>> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).ok()?;
    m.update(payload.as_bytes());
    Some(m)
}

/// A signed cookie value for `token_name`, valid until `exp` (unix seconds).
pub fn sign(key: &[u8], token_name: &str, exp: i64) -> String {
    let claims = Claims {
        token_name: token_name.to_string(),
        exp,
    };
    let json = serde_json::to_vec(&claims).unwrap_or_default();
    let payload = URL_SAFE_NO_PAD.encode(json);
    let tag = mac(key, &payload)
        .map(|m| URL_SAFE_NO_PAD.encode(m.finalize().into_bytes()))
        .unwrap_or_default();
    format!("{payload}.{tag}")
}

/// The claims of a cookie value whose MAC is valid (checked in constant time) and which has not
/// expired at `now` (unix seconds).
pub fn verify(key: &[u8], value: &str, now: i64) -> Option<Claims> {
    if value.len() > MAX_VALUE {
        return None;
    }
    let (payload, tag) = value.split_once('.')?;
    let tag = URL_SAFE_NO_PAD.decode(tag).ok()?;
    mac(key, payload)?.verify_slice(&tag).ok()?;
    let json = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: Claims = serde_json::from_slice(&json).ok()?;
    (claims.exp > now).then_some(claims)
}

/// The `agentsc_session` value in a `Cookie` header.
pub fn from_cookie_header(header: &str) -> Option<&str> {
    header
        .split(';')
        .map(str::trim)
        .find_map(|kv| kv.strip_prefix(COOKIE)?.strip_prefix('='))
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = &[1u8; 32];

    #[test]
    fn signs_and_verifies() {
        let v = sign(KEY, "alice", 2000);
        assert_eq!(
            verify(KEY, &v, 1999),
            Some(Claims {
                token_name: "alice".into(),
                exp: 2000
            })
        );
        // expired
        assert_eq!(verify(KEY, &v, 2000), None);
        // another key
        assert_eq!(verify(&[2u8; 32], &v, 1), None);
        // a forged payload with the old MAC
        let (_, tag) = v.split_once('.').unwrap();
        let forged = URL_SAFE_NO_PAD.encode(br#"{"token_name":"root","exp":9999999999}"#);
        assert_eq!(verify(KEY, &format!("{forged}.{tag}"), 1), None);
        for bad in ["", ".", "x", "a.b", &"a".repeat(2000)] {
            assert_eq!(verify(KEY, bad, 1), None, "{bad}");
        }
    }

    #[test]
    fn reads_the_cookie_header() {
        assert_eq!(
            from_cookie_header("a=1; agentsc_session=xyz.abc; b=2"),
            Some("xyz.abc")
        );
        assert_eq!(from_cookie_header("agentsc_session="), None);
        assert_eq!(from_cookie_header("agentsc_sessionx=1"), None);
        assert_eq!(from_cookie_header("other=1"), None);
    }
}
