//! A response cache for service calls (docs/adr/0002-response-caching.md).
//!
//! The app owns the policy. A `GET` or `HEAD` whose response says `Cache-Control: max-age=N`
//! (or `s-maxage=N`) and nothing that forbids it (`no-store`, `no-cache`, `private`, `Vary: *`)
//! is kept for `N` seconds, less its `Age`, at most `--mesh-cache-max-age`, and served again to
//! the same service, caller, agent, method and path when the request carries the same values of
//! the response's `Vary` headers. A response without `Cache-Control` is never kept: a cache the
//! app did not ask for would hide its writes from its readers.
//!
//! Both ends of a mesh call keep one: the callee's sidecar in front of its app
//! ([`crate::mesh`]), so a peer's repeated read never reaches the app, and the caller's sidecar
//! in front of the network ([`crate::tools`]), so a run's repeated read never leaves the pod. A
//! write (any other method) through a sidecar to a service empties that service's entries there,
//! so a run that writes then reads sees its own write. Authz runs before every lookup: a hit is
//! only ever served to a caller that may make the call now.
//!
//! A hit carries `Age` (seconds since the app answered, across both caches) and
//! `x-agentsc-cache: hit`. Bounded by bytes (`--mesh-cache-bytes`, 0 disables); the least
//! recently used entry goes first. Nothing is persisted: a restart starts empty.
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use agentsc_proto::ServiceResponse;

use crate::state::lock;

/// `--mesh-cache-bytes` default: 16 MiB.
pub const DEFAULT_CAPACITY_BYTES: u64 = 16 * 1024 * 1024;
/// `--mesh-cache-max-age` default: five minutes, whatever the app's `max-age` says.
pub const DEFAULT_MAX_AGE_SECS: u64 = 300;
/// The response header of a hit (value `hit`).
pub const HEADER: &str = "x-agentsc-cache";

/// Whether a (canonical, upper-case) method's responses may come from the cache.
pub fn cacheable_method(method: &str) -> bool {
    matches!(method, "GET" | "HEAD")
}

/// What identifies a cached response.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key {
    /// The service called.
    pub service: String,
    /// Who called it (`local`, or the peer's SPIFFE id on the callee side).
    pub caller: String,
    /// The agent on whose behalf.
    pub agent: String,
    pub method: String,
    pub path: String,
}

/// A cached response, served.
#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    /// The stored response with `Age` and [`HEADER`] added.
    pub response: ServiceResponse,
    pub age: Duration,
}

fn response_header<'a>(resp: &'a ServiceResponse, name: &str) -> Option<&'a str> {
    resp.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn request_header<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn age_of(resp: &ServiceResponse) -> u64 {
    response_header(resp, "age")
        .and_then(|a| a.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

/// How long `resp` may be served from a cache, by its `Cache-Control` and `Age`, at most `cap`;
/// `None` when it may not be cached at all.
pub fn freshness(resp: &ServiceResponse, cap: Duration) -> Option<Duration> {
    if resp.status != 200 {
        return None;
    }
    let cc = response_header(resp, "cache-control")?;
    let mut max_age: Option<u64> = None;
    let mut s_maxage: Option<u64> = None;
    for directive in cc.split(',') {
        let d = directive.trim().to_ascii_lowercase();
        let (name, value) = match d.split_once('=') {
            Some((n, v)) => (n.trim(), Some(v.trim().trim_matches('"'))),
            None => (d.as_str(), None),
        };
        match name {
            "no-store" | "no-cache" | "private" => return None,
            "max-age" => max_age = value.and_then(|v| v.parse().ok()),
            "s-maxage" => s_maxage = value.and_then(|v| v.parse().ok()),
            _ => {}
        }
    }
    let secs = s_maxage.or(max_age)?;
    if response_header(resp, "vary").is_some_and(|v| v.split(',').any(|h| h.trim() == "*")) {
        return None;
    }
    let ttl = secs.saturating_sub(age_of(resp));
    if ttl == 0 {
        return None;
    }
    Some(Duration::from_secs(ttl).min(cap))
}

/// The request headers a response varies on (`Vary`), lower case.
fn vary_names(resp: &ServiceResponse) -> Vec<String> {
    response_header(resp, "vary")
        .map(|v| {
            v.split(',')
                .map(|h| h.trim().to_ascii_lowercase())
                .filter(|h| !h.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

struct Entry {
    /// The response as stored: without `Age` and [`HEADER`], which a hit adds.
    response: ServiceResponse,
    /// The `Vary` header names and the request values they had when this was stored.
    vary: Vec<(String, String)>,
    stored: Instant,
    expires: Instant,
    /// The `Age` the response already had when it was stored (a callee's hit).
    initial_age: Duration,
    size: usize,
    /// The clock value of the last use (least recently used = smallest).
    touched: u64,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<Key, Entry>,
    bytes: usize,
    clock: u64,
}

fn entry_size(key: &Key, resp: &ServiceResponse, vary: &[(String, String)]) -> usize {
    key.service.len()
        + key.caller.len()
        + key.agent.len()
        + key.method.len()
        + key.path.len()
        + resp.body.len()
        + resp
            .headers
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum::<usize>()
        + vary.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>()
        + 64
}

fn evict_one(inner: &mut Inner) {
    let victim = inner
        .entries
        .iter()
        .min_by_key(|(_, e)| e.touched)
        .map(|(k, _)| k.clone());
    if let Some(k) = victim
        && let Some(e) = inner.entries.remove(&k)
    {
        inner.bytes -= e.size;
    }
}

/// The cache; see the module docs.
pub struct ResponseCache {
    capacity: usize,
    max_age: Duration,
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for ResponseCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseCache")
            .field("capacity", &self.capacity)
            .field("max_age", &self.max_age)
            .field("entries", &self.len())
            .field("bytes", &self.bytes())
            .finish()
    }
}

impl ResponseCache {
    /// A cache of at most `capacity_bytes` whose entries live at most `max_age`.
    pub fn new(capacity_bytes: u64, max_age: Duration) -> Self {
        Self {
            capacity: usize::try_from(capacity_bytes).unwrap_or(usize::MAX),
            max_age,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// A cache that keeps nothing.
    pub fn disabled() -> Self {
        Self::new(0, Duration::ZERO)
    }

    pub fn enabled(&self) -> bool {
        self.capacity > 0
    }

    pub fn len(&self) -> usize {
        lock(&self.inner).entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn bytes(&self) -> usize {
        lock(&self.inner).bytes
    }

    /// The fresh response stored for `key` whose `Vary` values `request_headers` match.
    pub fn get(&self, key: &Key, request_headers: &HashMap<String, String>) -> Option<Hit> {
        self.get_at(key, request_headers, Instant::now())
    }

    fn get_at(
        &self,
        key: &Key,
        request_headers: &HashMap<String, String>,
        now: Instant,
    ) -> Option<Hit> {
        if !self.enabled() {
            return None;
        }
        let mut inner = lock(&self.inner);
        inner.clock += 1;
        let clock = inner.clock;
        let Inner { entries, bytes, .. } = &mut *inner;
        let entry = entries.get_mut(key)?;
        if entry.expires <= now {
            let size = entry.size;
            entries.remove(key);
            *bytes -= size;
            return None;
        }
        if entry
            .vary
            .iter()
            .any(|(name, value)| request_header(request_headers, name).unwrap_or("") != value)
        {
            return None;
        }
        entry.touched = clock;
        let age = entry.initial_age + now.duration_since(entry.stored);
        let mut response = entry.response.clone();
        response
            .headers
            .insert("age".to_string(), age.as_secs().to_string());
        response
            .headers
            .insert(HEADER.to_string(), "hit".to_string());
        Some(Hit { response, age })
    }

    /// Keep `response` for `key` if its `Cache-Control` allows it; returns whether it was kept.
    pub fn store(
        &self,
        key: Key,
        response: &ServiceResponse,
        request_headers: &HashMap<String, String>,
    ) -> bool {
        self.store_at(key, response, request_headers, Instant::now())
    }

    fn store_at(
        &self,
        key: Key,
        response: &ServiceResponse,
        request_headers: &HashMap<String, String>,
        now: Instant,
    ) -> bool {
        if !self.enabled() {
            return false;
        }
        let Some(ttl) = freshness(response, self.max_age) else {
            return false;
        };
        let initial_age = Duration::from_secs(age_of(response));
        let vary: Vec<(String, String)> = vary_names(response)
            .into_iter()
            .map(|name| {
                let value = request_header(request_headers, &name)
                    .unwrap_or("")
                    .to_string();
                (name, value)
            })
            .collect();
        let mut copy = response.clone();
        copy.headers
            .retain(|k, _| !k.eq_ignore_ascii_case("age") && !k.eq_ignore_ascii_case(HEADER));
        let size = entry_size(&key, &copy, &vary);
        if size > self.capacity {
            return false;
        }
        let mut inner = lock(&self.inner);
        inner.clock += 1;
        let clock = inner.clock;
        if let Some(old) = inner.entries.remove(&key) {
            inner.bytes -= old.size;
        }
        while inner.bytes + size > self.capacity && !inner.entries.is_empty() {
            evict_one(&mut inner);
        }
        inner.bytes += size;
        inner.entries.insert(
            key,
            Entry {
                response: copy,
                vary,
                stored: now,
                expires: now + ttl,
                initial_age,
                size,
                touched: clock,
            },
        );
        true
    }

    /// Forget every entry of `service` (after a write to it); returns how many went.
    pub fn invalidate_service(&self, service: &str) -> usize {
        let mut inner = lock(&self.inner);
        let mut freed = 0;
        let mut gone = 0;
        inner.entries.retain(|k, e| {
            if k.service == service {
                freed += e.size;
                gone += 1;
                false
            } else {
                true
            }
        });
        inner.bytes -= freed;
        gone
    }

    /// Forget everything.
    pub fn clear(&self) {
        let mut inner = lock(&self.inner);
        inner.entries.clear();
        inner.bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u32, headers: &[(&str, &str)], body: &str) -> ServiceResponse {
        ServiceResponse {
            status,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    fn key(path: &str) -> Key {
        Key {
            service: "inventory".into(),
            caller: "local".into(),
            agent: "ops".into(),
            method: "GET".into(),
            path: path.into(),
        }
    }

    fn headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    const MIN: Duration = Duration::from_secs(60);

    #[test]
    fn the_app_decides_with_cache_control() {
        let cap = Duration::from_secs(300);
        assert_eq!(
            freshness(&resp(200, &[], "x"), cap),
            None,
            "no Cache-Control: no cache"
        );
        assert_eq!(
            freshness(&resp(200, &[("Cache-Control", "max-age=30")], "x"), cap),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            freshness(
                &resp(
                    200,
                    &[("cache-control", "public, s-maxage=20, max-age=30")],
                    "x"
                ),
                cap
            ),
            Some(Duration::from_secs(20)),
            "s-maxage wins: this is a shared cache"
        );
        assert_eq!(
            freshness(
                &resp(200, &[("Cache-Control", "max-age=\"900\"")], "x"),
                cap
            ),
            Some(cap),
            "capped by --mesh-cache-max-age"
        );
        assert_eq!(
            freshness(
                &resp(200, &[("Cache-Control", "max-age=30"), ("Age", "25")], "x"),
                cap
            ),
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            freshness(
                &resp(200, &[("Cache-Control", "max-age=30"), ("Age", "30")], "x"),
                cap
            ),
            None
        );
        for forbidden in [
            "no-store",
            "max-age=30, no-store",
            "No-Cache, max-age=30",
            "private, max-age=30",
            "max-age=0",
            "max-age=abc",
            "public",
        ] {
            assert_eq!(
                freshness(&resp(200, &[("Cache-Control", forbidden)], "x"), cap),
                None,
                "{forbidden}"
            );
        }
        assert_eq!(
            freshness(
                &resp(200, &[("Cache-Control", "max-age=30"), ("Vary", "*")], "x"),
                cap
            ),
            None
        );
        for status in [201, 204, 301, 404, 500] {
            assert_eq!(
                freshness(&resp(status, &[("Cache-Control", "max-age=30")], "x"), cap),
                None,
                "{status}"
            );
        }
        assert!(cacheable_method("GET") && cacheable_method("HEAD"));
        assert!(
            !cacheable_method("POST") && !cacheable_method("DELETE") && !cacheable_method("get")
        );
    }

    #[test]
    fn hits_carry_age_and_expire() {
        let cache = ResponseCache::new(1 << 20, MIN);
        let t0 = Instant::now();
        let none = headers(&[]);
        assert!(cache.store_at(
            key("/stock"),
            &resp(200, &[("Cache-Control", "max-age=10")], "{\"n\":1}"),
            &none,
            t0
        ));
        assert_eq!(cache.len(), 1);
        let hit = cache
            .get_at(&key("/stock"), &none, t0 + Duration::from_secs(3))
            .unwrap();
        assert_eq!(hit.age, Duration::from_secs(3));
        assert_eq!(hit.response.headers["age"], "3");
        assert_eq!(hit.response.headers[HEADER], "hit");
        assert_eq!(hit.response.body, b"{\"n\":1}");
        assert_eq!(cache.get_at(&key("/other"), &none, t0), None);
        assert_eq!(
            cache.get_at(&key("/stock"), &none, t0 + Duration::from_secs(10)),
            None,
            "expired"
        );
        assert_eq!(cache.len(), 0, "an expired entry is dropped on the way out");

        // a response that was already a hit elsewhere: its age carries over, its TTL shrinks
        let aged = resp(
            200,
            &[
                ("Cache-Control", "max-age=10"),
                ("Age", "4"),
                (HEADER, "hit"),
            ],
            "x",
        );
        assert!(cache.store_at(key("/aged"), &aged, &none, t0));
        let hit = cache
            .get_at(&key("/aged"), &none, t0 + Duration::from_secs(2))
            .unwrap();
        assert_eq!(hit.age, Duration::from_secs(6));
        assert_eq!(
            cache.get_at(&key("/aged"), &none, t0 + Duration::from_secs(6)),
            None
        );

        // not stored: a response the app did not mark, or a disabled cache
        assert!(!cache.store_at(key("/plain"), &resp(200, &[], "x"), &none, t0));
        let off = ResponseCache::disabled();
        assert!(!off.enabled());
        assert!(!off.store_at(
            key("/stock"),
            &resp(200, &[("Cache-Control", "max-age=10")], "x"),
            &none,
            t0
        ));
        assert_eq!(off.get_at(&key("/stock"), &none, t0), None);
    }

    #[test]
    fn vary_separates_requests_and_writes_invalidate() {
        let cache = ResponseCache::new(1 << 20, MIN);
        let t0 = Instant::now();
        let en = headers(&[("Accept-Language", "en")]);
        let de = headers(&[("accept-language", "de")]);
        let r = resp(
            200,
            &[("Cache-Control", "max-age=10"), ("Vary", "Accept-Language")],
            "hello",
        );
        assert!(cache.store_at(key("/greet"), &r, &en, t0));
        assert!(cache.get_at(&key("/greet"), &en, t0).is_some());
        assert_eq!(
            cache.get_at(&key("/greet"), &de, t0),
            None,
            "another language is a miss"
        );
        assert_eq!(cache.get_at(&key("/greet"), &headers(&[]), t0), None);

        let mut other = key("/greet");
        other.service = "orders".into();
        assert!(cache.store_at(
            other.clone(),
            &resp(200, &[("Cache-Control", "max-age=10")], "o"),
            &en,
            t0
        ));
        assert_eq!(cache.invalidate_service("inventory"), 1);
        assert_eq!(cache.get_at(&key("/greet"), &en, t0), None);
        assert!(
            cache.get_at(&other, &en, t0).is_some(),
            "another service's entries stay"
        );
        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.bytes(), 0);
    }

    #[test]
    fn the_cache_is_bounded_and_evicts_the_least_recently_used() {
        let one = resp(200, &[("Cache-Control", "max-age=60")], &"x".repeat(100));
        let size = entry_size(&key("/a"), &one, &[]);
        let cache = ResponseCache::new((size * 2) as u64, MIN);
        let t0 = Instant::now();
        let none = headers(&[]);
        assert!(cache.store_at(key("/a"), &one, &none, t0));
        assert!(cache.store_at(key("/b"), &one, &none, t0));
        assert_eq!(cache.len(), 2);
        // /a is used, so /b is the least recently used and goes when /c arrives
        assert!(cache.get_at(&key("/a"), &none, t0).is_some());
        assert!(cache.store_at(key("/c"), &one, &none, t0));
        assert_eq!(cache.len(), 2);
        assert!(cache.get_at(&key("/a"), &none, t0).is_some());
        assert_eq!(cache.get_at(&key("/b"), &none, t0), None);
        assert!(cache.bytes() <= size * 2);
        // bigger than the whole cache: not stored
        let huge = resp(
            200,
            &[("Cache-Control", "max-age=60")],
            &"x".repeat(size * 3),
        );
        assert!(!cache.store_at(key("/huge"), &huge, &none, t0));
        assert_eq!(cache.len(), 2);
        // storing the same key again replaces, never double-counts
        assert!(cache.store_at(key("/a"), &one, &none, t0));
        assert_eq!(cache.len(), 2);
        assert!(cache.bytes() <= size * 2);
        assert!(format!("{cache:?}").contains("entries"));
    }
}
