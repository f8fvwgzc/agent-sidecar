//! The REST API is rate limited per client (ratelimit.rs, `--api-rate-limit` / `--api-burst`):
//! a client that spends its burst gets 429 `rate_limited` with `Retry-After`; other clients and
//! the probes are not affected.
mod common;

use common::*;

#[tokio::test]
async fn a_client_over_its_rate_gets_429_and_others_do_not() {
    let env = Env::start_with(Opts {
        args: vec![
            "--api-rate-limit".into(),
            "1".into(),
            "--api-burst".into(),
            "3".into(),
        ],
        ..Default::default()
    })
    .await;
    for i in 0..3 {
        assert_eq!(
            env.get("/services", "alice").await.status,
            200,
            "request {i}"
        );
    }
    let r = env.get("/services", "alice").await;
    assert_eq!(r.status, 429, "{}", r.text);
    assert_eq!(r.error(), "rate_limited");
    let wait: u64 = r.headers["retry-after"].to_str().unwrap().parse().unwrap();
    assert!((1..=60).contains(&wait), "{wait}");
    assert_eq!(
        env.get("/services", "bob").await.status,
        200,
        "another client has its own bucket"
    );
    let probe = env
        .http
        .get(format!("{}/readyz", env.base))
        .send()
        .await
        .unwrap();
    assert_ne!(probe.status().as_u16(), 429, "probes are never limited");
}
