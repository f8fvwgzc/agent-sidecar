//! Deadlines across hops (CONTRACT.md §4.3). A gRPC caller's `grpc-timeout` becomes an instant on
//! arrival; every call made on its behalf gets what is left of it, less a margin, so the inner call
//! gives up first and the outer one still answers and audits.
use std::time::{Duration, Instant};

use tonic::metadata::MetadataMap;

/// The longest one invocation may run in the runtime, and so the longest any hop waits for one.
pub const RUN_TIMEOUT: Duration = Duration::from_secs(300);
/// The longest a forward to the app or an http tool may take.
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
/// Taken off the remaining time at every hop.
pub const HOP_MARGIN: Duration = Duration::from_millis(500);

/// When the caller stops waiting, from its `grpc-timeout` metadata (`None`: it set no deadline).
pub fn from_metadata(md: &MetadataMap) -> Option<Instant> {
    let v = md.get("grpc-timeout")?.to_str().ok()?;
    let (n, unit) = v.split_at(v.len().checked_sub(1)?);
    if n.is_empty() || n.len() > 8 {
        return None;
    }
    let n: u64 = n.parse().ok()?;
    let d = match unit {
        "H" => Duration::from_secs(n * 3600),
        "M" => Duration::from_secs(n * 60),
        "S" => Duration::from_secs(n),
        "m" => Duration::from_millis(n),
        "u" => Duration::from_micros(n),
        "n" => Duration::from_nanos(n),
        _ => return None,
    };
    Instant::now().checked_add(d)
}

/// How long the next hop may take: what is left before `deadline`, less the margin, at most `cap`.
pub fn budget(deadline: Option<Instant>, cap: Duration) -> Duration {
    match deadline {
        None => cap,
        Some(d) => d
            .saturating_duration_since(Instant::now())
            .saturating_sub(HOP_MARGIN)
            .min(cap),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_timeout_becomes_a_shrinking_budget() {
        let mut md = MetadataMap::new();
        assert_eq!(from_metadata(&md), None);
        assert_eq!(budget(None, RUN_TIMEOUT), RUN_TIMEOUT);
        md.insert("grpc-timeout", "10S".parse().unwrap());
        let b = budget(from_metadata(&md), RUN_TIMEOUT);
        assert!(
            b <= Duration::from_secs(10) - HOP_MARGIN && b > Duration::from_secs(9),
            "{b:?}"
        );
        assert_eq!(
            budget(from_metadata(&md), HTTP_TIMEOUT.min(Duration::from_secs(2))),
            Duration::from_secs(2)
        );
        md.insert("grpc-timeout", "100m".parse().unwrap());
        assert_eq!(
            budget(from_metadata(&md), RUN_TIMEOUT),
            Duration::ZERO,
            "less than the margin left"
        );
        for bad in ["", "S", "10x", "123456789S"] {
            md.insert("grpc-timeout", bad.parse().unwrap());
            assert_eq!(from_metadata(&md), None, "{bad:?}");
        }
    }
}
