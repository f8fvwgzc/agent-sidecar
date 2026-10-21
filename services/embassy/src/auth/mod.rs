//! API authentication and authorization (design §8.1, §8.3, §15 rules 1–2). Empty for now.
//!
//! TODO(B3a): bearer tokens (constant-time compare of SHA-256 against
//! [`crate::config::TokenEntry::sha256`], see [`crate::token`]); `POST /login` sessions in the
//! `attache_session` cookie (HMAC-SHA256 over `{token_name, exp}`, 12 h, `HttpOnly;
//! SameSite=Strict; Path=/`, `Secure` over TLS, invalid once the token leaves the config);
//! login rate limit (5 failures per minute per client IP); `X-Attache-CSRF: 1` and
//! `Content-Type: application/json` on every mutation; the Host check (421) and the security
//! headers on every response; namespace scopes and payload visibility; roles enforced on the
//! diff between the stored and the new charter (403 `forbidden` with one detail per reason).
