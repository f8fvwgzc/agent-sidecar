//! Token-bucket rate limits for `IssueCertificate` and the REST API (design §7, §8.1, §10).
//!
//! One [`RateLimiter`] per surface and process, one bucket per client key. A bucket holds up to
//! `burst` tokens and gains `per_minute` of them a minute; every request takes one token from each
//! of its keys, or from none: an empty bucket refuses the request with the time until its next
//! token (`RESOURCE_EXHAUSTED` with `retry-after` metadata, or HTTP 429 with `Retry-After`).
//! `per_minute: 0` turns a surface's limit off. The keys:
//!
//! - **`IssueCertificate`** ([`issuance_keys`]): the peer address (`addr:<ip>`) and the credential
//!   (`k8s:` or `join:` and the first 16 hex digits of the token's SHA-256), each a bucket of its
//!   own, so neither many tokens from one address nor one token from many addresses get past
//!   the limit. The credential is not verified yet (verifying it is the work being limited), so
//!   nothing it claims — a service-account subject or a pod name — is a key: a forged token
//!   naming another pod would otherwise empty that pod's bucket.
//! - **REST** ([`api_layer`], `/api/v1` except `healthz` and `readyz`): the authenticated client
//!   (`id:<token name>`, the same bucket for its bearer token and its sessions); without one (and
//!   for the `--dev` anonymous viewer) the remote address (`addr:<ip>`).
//!
//! A key's first refusal after it was last allowed is reported ([`Limited::first`]): issuance
//! writes a `cert_denied` control-plane audit record and the API logs a warning, as their other
//! refusals do; later refusals of the same run are only counted ([`Limited::refused`]) and logged
//! at debug level, so a flood cannot flood the audit log.
//!
//! The table holds at most [`MAX_KEYS`] buckets. When it is full, buckets that have refilled
//! completely (no different from a new one) are dropped; if that frees nothing, a new key is
//! refused until some bucket refills.
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};

use crate::api::ClientAddr;
use crate::api::error::Fail;
use crate::api::types::ErrorCode;
use crate::hub::Hub;

/// The most buckets one limiter keeps.
pub const MAX_KEYS: usize = 65_536;
/// `--issuance-rate-limit` and `--issuance-burst` defaults: a sidecar asks for a certificate at
/// start-up and at two thirds of its lifetime, retrying failures with backoff, so even a
/// crash-looping pod stays far below this; a node's worth of pods behind one NAT address can
/// start at once.
pub const ISSUANCE_DEFAULT: RateLimit = RateLimit {
    per_minute: 12,
    burst: 20,
};
/// `--api-rate-limit` and `--api-burst` defaults: the console loads a page with a few dozen
/// requests and then lives on the event stream.
pub const API_DEFAULT: RateLimit = RateLimit {
    per_minute: 1200,
    burst: 300,
};

/// One surface's limit: `burst` tokens per key, `per_minute` new ones a minute (0 = no limit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    pub per_minute: u32,
    pub burst: u32,
}

impl RateLimit {
    pub fn is_off(&self) -> bool {
        self.per_minute == 0
    }

    /// Why this limit cannot work, if it cannot.
    pub fn problem(&self, flag: &str) -> Option<String> {
        (!self.is_off() && self.burst == 0)
            .then(|| format!("{flag}: the burst must be at least 1 when the rate is not 0"))
    }
}

/// A refusal.
#[derive(Debug, Clone, PartialEq)]
pub struct Limited {
    /// The key whose bucket is empty.
    pub key: String,
    /// Until that bucket has a token again.
    pub retry_after: Duration,
    /// The key's first refusal since it was last allowed (the one to audit).
    pub first: bool,
    /// The key's refusals since it was last allowed, this one included.
    pub refused: u64,
}

impl Limited {
    /// [`Limited::retry_after`] in whole seconds, rounded up, at least 1 (`Retry-After`).
    pub fn retry_after_secs(&self) -> u64 {
        let ms = self.retry_after.as_millis();
        u64::try_from(ms.div_ceil(1000)).unwrap_or(u64::MAX).max(1)
    }
}

#[derive(Debug, Clone)]
struct Bucket {
    tokens: f64,
    at: Instant,
    refused: u64,
}

/// The buckets of one surface (see the module docs).
#[derive(Debug)]
pub struct RateLimiter {
    limit: RateLimit,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    pub fn new(limit: RateLimit) -> Self {
        Self {
            limit,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn limit(&self) -> RateLimit {
        self.limit
    }

    fn per_second(&self) -> f64 {
        f64::from(self.limit.per_minute) / 60.0
    }

    /// `bucket` as of `now`.
    fn refill(&self, bucket: &mut Bucket, now: Instant) {
        let elapsed = now.saturating_duration_since(bucket.at).as_secs_f64();
        bucket.tokens =
            (bucket.tokens + elapsed * self.per_second()).min(f64::from(self.limit.burst));
        bucket.at = now;
    }

    /// Take one token from each of `keys`'s buckets, or none and say why.
    pub fn check(&self, keys: &[String]) -> Result<(), Limited> {
        self.check_at(keys, Instant::now())
    }

    /// [`RateLimiter::check`] at `now` (tests drive the clock).
    pub fn check_at(&self, keys: &[String], now: Instant) -> Result<(), Limited> {
        if self.limit.is_off() || keys.is_empty() {
            return Ok(());
        }
        let burst = f64::from(self.limit.burst);
        let mut map = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        let missing = keys.iter().filter(|k| !map.contains_key(*k)).count();
        if map.len() + missing > MAX_KEYS {
            for b in map.values_mut() {
                self.refill(b, now);
            }
            map.retain(|_, b| b.tokens < burst);
        }
        let mut empty = None;
        for key in keys {
            if !map.contains_key(key) {
                if map.len() >= MAX_KEYS {
                    // full of buckets that are all still refilling: no room for a new client
                    return Err(Limited {
                        key: key.clone(),
                        retry_after: Duration::from_secs_f64(1.0 / self.per_second()),
                        first: false,
                        refused: 1,
                    });
                }
                map.insert(
                    key.clone(),
                    Bucket {
                        tokens: burst,
                        at: now,
                        refused: 0,
                    },
                );
            }
            let b = map.get_mut(key).expect("just inserted");
            self.refill(b, now);
            if b.tokens < 1.0 && empty.is_none() {
                empty = Some(key);
            }
        }
        match empty {
            None => {
                for key in keys {
                    if let Some(b) = map.get_mut(key) {
                        b.tokens -= 1.0;
                        b.refused = 0;
                    }
                }
                Ok(())
            }
            Some(key) => {
                let b = map.get_mut(key).expect("present");
                b.refused += 1;
                let wait = (1.0 - b.tokens) / self.per_second();
                Err(Limited {
                    key: key.clone(),
                    retry_after: Duration::from_secs_f64(wait.max(0.0)),
                    first: b.refused == 1,
                    refused: b.refused,
                })
            }
        }
    }

    /// Buckets held (tests).
    pub fn keys(&self) -> usize {
        self.buckets.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

/// `addr:<ip>` (the port changes with every connection).
pub fn addr_key(ip: IpAddr) -> String {
    format!("addr:{ip}")
}

/// The first 16 hex digits of a token's SHA-256: enough to tell tokens apart, never the token.
fn token_key(kind: &str, token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    format!("{kind}:{}", &hex::encode(digest)[..16])
}

/// The keys of an `IssueCertificate` request (module docs): its peer address and its credential.
pub fn issuance_keys(
    peer: Option<SocketAddr>,
    req: &agentsc_proto::CertificateRequest,
) -> Vec<String> {
    let mut keys = Vec::with_capacity(2);
    if let Some(p) = peer {
        keys.push(addr_key(p.ip()));
    }
    if !req.kubernetes_token.is_empty() {
        keys.push(token_key("k8s", &req.kubernetes_token));
    }
    if !req.join_token.is_empty() {
        keys.push(token_key("join", &req.join_token));
    }
    keys
}

/// The gRPC answer to a refused `IssueCertificate`: `RESOURCE_EXHAUSTED`, with the wait in the
/// message and as `retry-after` metadata (seconds).
pub fn resource_exhausted(what: &str, l: &Limited) -> tonic::Status {
    let secs = l.retry_after_secs();
    let mut st = tonic::Status::resource_exhausted(format!(
        "rate limited: too many {what}; retry in {secs} s"
    ));
    if let Ok(v) = secs.to_string().parse() {
        st.metadata_mut().insert("retry-after", v);
    }
    st
}

/// Paths under `/api/v1` that are never limited (probes).
const UNLIMITED: [&str; 2] = ["/healthz", "/readyz"];

/// The REST limit, as middleware on the `/api/v1` routes (module docs): 429 `rate_limited` with
/// `Retry-After`; the first refusal of a run is logged as a warning.
pub async fn api_layer(State(hub): State<Arc<Hub>>, req: Request, next: Next) -> Response {
    let limiter = &hub.api_limiter;
    if limiter.limit().is_off() || UNLIMITED.contains(&req.uri().path()) {
        return next.run(req).await;
    }
    let ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<ClientAddr>>()
        .map(|c| c.0.0.ip());
    let key = match crate::auth::authenticate(&hub.auth, req.headers()) {
        Some(ident) if !ident.anonymous => format!("id:{}", ident.name),
        _ => match ip {
            Some(ip) => addr_key(ip),
            None => "addr:unknown".into(),
        },
    };
    match limiter.check(std::slice::from_ref(&key)) {
        Ok(()) => next.run(req).await,
        Err(l) => {
            let secs = l.retry_after_secs();
            if l.first {
                tracing::warn!(client = %key, method = %req.method(), path = %req.uri().path(), retry_after_s = secs, "API rate limit: refusing requests");
            } else {
                tracing::debug!(client = %key, refused = l.refused, "API rate limit: refused");
            }
            let mut f = Fail::new(
                ErrorCode::RateLimited,
                [format!("too many requests; retry in {secs} s")],
            );
            if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                f = f.with_header(header::RETRY_AFTER, v);
            }
            f.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(k: &[&str]) -> Vec<String> {
        k.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_burst_then_refusals_then_refill() {
        let l = RateLimiter::new(RateLimit {
            per_minute: 60,
            burst: 3,
        });
        let t0 = Instant::now();
        let a = keys(&["addr:10.0.0.1"]);
        for i in 0..3 {
            assert!(l.check_at(&a, t0).is_ok(), "request {i} of the burst");
        }
        let refused = l.check_at(&a, t0).unwrap_err();
        assert_eq!(refused.key, "addr:10.0.0.1");
        assert!(refused.first);
        assert_eq!(refused.refused, 1);
        assert_eq!(refused.retry_after_secs(), 1, "one token a second");
        let again = l.check_at(&a, t0 + Duration::from_millis(500)).unwrap_err();
        assert!(!again.first, "a run of refusals is reported once");
        assert_eq!(again.refused, 2);
        assert!(again.retry_after <= Duration::from_millis(500));
        // another key has its own bucket
        assert!(l.check_at(&keys(&["addr:10.0.0.2"]), t0).is_ok());
        // a second later one token is back, and only one
        let t1 = t0 + Duration::from_secs(1);
        assert!(l.check_at(&a, t1).is_ok());
        let after = l.check_at(&a, t1).unwrap_err();
        assert!(after.first, "allowed in between: a new run");
        // a long pause refills to the burst, never beyond
        let t2 = t1 + Duration::from_secs(3600);
        for _ in 0..3 {
            assert!(l.check_at(&a, t2).is_ok());
        }
        assert!(l.check_at(&a, t2).is_err());
    }

    #[test]
    fn every_key_must_have_a_token_and_a_refusal_takes_none() {
        let l = RateLimiter::new(RateLimit {
            per_minute: 6,
            burst: 1,
        });
        let t0 = Instant::now();
        // the credential's bucket is used up from one address ...
        assert!(l.check_at(&keys(&["addr:a", "join:x"]), t0).is_ok());
        // ... so the same credential from another address is refused, and that address keeps
        // its token
        let e = l.check_at(&keys(&["addr:b", "join:x"]), t0).unwrap_err();
        assert_eq!(e.key, "join:x");
        assert_eq!(e.retry_after_secs(), 10);
        assert!(l.check_at(&keys(&["addr:b", "join:y"]), t0).is_ok());
    }

    #[test]
    fn off_means_unlimited_and_the_table_is_bounded() {
        let off = RateLimiter::new(RateLimit {
            per_minute: 0,
            burst: 0,
        });
        let t0 = Instant::now();
        for _ in 0..1000 {
            assert!(off.check_at(&keys(&["addr:a"]), t0).is_ok());
        }
        assert_eq!(off.keys(), 0);
        assert_eq!(
            RateLimit {
                per_minute: 1,
                burst: 0
            }
            .problem("--api-burst")
            .unwrap(),
            "--api-burst: the burst must be at least 1 when the rate is not 0"
        );

        let l = RateLimiter::new(RateLimit {
            per_minute: 60,
            burst: 2,
        });
        for i in 0..MAX_KEYS {
            assert!(l.check_at(&[format!("addr:{i}")], t0).is_ok());
        }
        assert_eq!(l.keys(), MAX_KEYS);
        // every bucket is still refilling: a new key is refused, not let in unlimited
        assert!(l.check_at(&keys(&["addr:new"]), t0).is_err());
        // once they have refilled, they are dropped to make room
        let later = t0 + Duration::from_secs(5);
        assert!(l.check_at(&keys(&["addr:new"]), later).is_ok());
        assert_eq!(l.keys(), 1);
    }

    #[test]
    fn issuance_keys_are_the_address_and_a_digest_of_the_credential() {
        let req = |k8s: &str, join: &str| agentsc_proto::CertificateRequest {
            kubernetes_token: k8s.into(),
            join_token: join.into(),
            ..Default::default()
        };
        let peer: SocketAddr = "10.1.2.3:41000".parse().unwrap();
        let k = issuance_keys(Some(peer), &req("eyJhbGciOi.secret.sig", ""));
        assert_eq!(k.len(), 2);
        assert_eq!(k[0], "addr:10.1.2.3");
        assert!(k[1].starts_with("k8s:") && k[1].len() == 4 + 16, "{k:?}");
        assert!(!k[1].contains("secret"), "never the token itself");
        let j = issuance_keys(None, &req("", "att_join"));
        assert_eq!(j.len(), 1);
        assert!(j[0].starts_with("join:"));
        // the port is not part of the key: every connection has a new one
        let other_port: SocketAddr = "10.1.2.3:41001".parse().unwrap();
        assert_eq!(issuance_keys(Some(other_port), &req("", ""))[0], k[0]);

        let st = resource_exhausted(
            "certificate requests",
            &Limited {
                key: "addr:x".into(),
                retry_after: Duration::from_millis(4200),
                first: true,
                refused: 1,
            },
        );
        assert_eq!(st.code(), tonic::Code::ResourceExhausted);
        assert_eq!(st.metadata().get("retry-after").unwrap(), "5");
        assert!(st.message().contains("retry in 5 s"), "{}", st.message());
    }
}
