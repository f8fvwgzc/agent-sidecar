//! The workload certificate in managed mode (design §6.3.1–2).
//!
//! Order: a valid, unexpired `--tls-dir` certificate for `--service`/`--namespace`; else an
//! unexpired matching one persisted in `<state-dir>`; else a new ECDSA P-256 key and a CSR sent to
//! `IssueCertificate` with the Kubernetes or join token, re-read from its file for every request.
//! Renewal starts at two thirds of the lifetime and is retried every 60 s ± 20 % with a fresh
//! token until expiry; a new certificate reaches the mesh through the rustls resolvers without a
//! restart. An expired certificate is dropped (the sidecar is not ready without one, §6.3.4) and
//! a new one is obtained as at start-up.
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use agentsc_common::authz::Verdict;
use agentsc_pki::TlsMaterial;
use agentsc_proto::CertificateRequest;
use agentsc_proto::certificate_authority_client::CertificateAuthorityClient;
use anyhow::Context;
use rand::Rng;

use crate::config::Config;
use crate::persist::StateDir;
use crate::reload::build_config_record;
use crate::state::AppState;
use crate::tls::WorkloadTls;

pub const RULE_ISSUED: &str = "cert.issued";
pub const RULE_RENEW_FAILED: &str = "cert.renew_failed";
pub const RULE_ISSUE_FAILED: &str = "cert.issue_failed";
pub const RULE_EXPIRED: &str = "cert.expired";
/// `IssueCertificate` answers are small (design §3: 64 KiB).
const MAX_ISSUE_MESSAGE: usize = 64 * 1024;

fn usable(t: WorkloadTls, config: &Config, service: &str, namespace: &str) -> Option<WorkloadTls> {
    let id = &t.material.identity;
    let ours = id.trust_domain == config.trust_domain;
    (ours && id.service == service && id.namespace == namespace && !t.expired()).then_some(t)
}

/// A certificate to start with, without asking the CA: `--tls-dir`, then `<state-dir>`.
pub fn initial(
    config: &Config,
    service: &str,
    namespace: &str,
    state_dir: &StateDir,
) -> Option<WorkloadTls> {
    if let Some(t) = TlsMaterial::load(&config.tls_dir)
        .ok()
        .and_then(|m| WorkloadTls::from_material(m).ok())
        .and_then(|t| usable(t, config, service, namespace))
    {
        tracing::info!(dir = %config.tls_dir.display(), "using the --tls-dir certificate");
        return Some(t);
    }
    if let Some(t) = state_dir
        .load_tls()
        .and_then(|(ca, cert, key)| WorkloadTls::from_pems(&ca, &cert, &key).ok())
        .and_then(|t| usable(t, config, service, namespace))
    {
        tracing::info!(dir = %state_dir.dir.display(), "using the persisted certificate");
        return Some(t);
    }
    None
}

/// The token for `IssueCertificate`, read now: the join token if `--join-token-file` is set, else
/// the projected Kubernetes token. Returns `(kubernetes_token, join_token)`.
fn read_token(config: &Config) -> anyhow::Result<(String, String)> {
    if let Some(path) = &config.join_token_file {
        let t = std::fs::read_to_string(path)
            .with_context(|| format!("read join token {}", path.display()))?;
        let t = t.trim().to_string();
        anyhow::ensure!(!t.is_empty(), "join token file {} is empty", path.display());
        return Ok((String::new(), t));
    }
    let path = &config.k8s_token_file;
    let t = std::fs::read_to_string(path)
        .with_context(|| format!("read Kubernetes token {}", path.display()))?;
    let t = t.trim().to_string();
    anyhow::ensure!(
        !t.is_empty(),
        "Kubernetes token file {} is empty",
        path.display()
    );
    Ok((t, String::new()))
}

/// A new key, a CSR and one `IssueCertificate` call.
pub async fn issue(state: &AppState) -> anyhow::Result<WorkloadTls> {
    let config = &state.config;
    let addr = config
        .ca_addr()
        .ok_or_else(|| anyhow::anyhow!("no --ca-address or --control-plane"))?;
    let (kubernetes_token, join_token) = read_token(config)?;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let csr_pem = params.serialize_request(&key)?.pem()?;
    let roots = state
        .trust_roots
        .clone()
        .ok_or_else(|| anyhow::anyhow!("no trust roots for the CA"))?;
    let cfg = crate::tls::control_plane_client_config(roots, None, &state.trust_domain)?;
    let timeout = config.timing.issue_timeout;
    let channel =
        crate::tls::tls_channel(addr, crate::tls::server_name_of(addr)?, cfg, Some(timeout))?;
    let mut client =
        CertificateAuthorityClient::new(channel).max_decoding_message_size(MAX_ISSUE_MESSAGE);
    let mut req = tonic::Request::new(CertificateRequest {
        csr_pem,
        kubernetes_token,
        join_token,
        namespace: state.namespace.clone(),
        service: state.service.clone(),
    });
    req.set_timeout(timeout);
    let resp = tokio::time::timeout(timeout, client.issue_certificate(req))
        .await
        .map_err(|_| anyhow::anyhow!("IssueCertificate timed out after {timeout:?}"))?
        .map_err(|st| anyhow::anyhow!("IssueCertificate: {} {}", st.code(), st.message()))?
        .into_inner();
    let ca_pem = if resp.ca_pem.trim().is_empty() {
        state.trust_pem.clone().unwrap_or_default()
    } else {
        resp.ca_pem
    };
    let tls = WorkloadTls::from_pems(&ca_pem, &resp.cert_pem, &key.serialize_pem())
        .context("the issued certificate")?;
    let id = &tls.material.identity;
    anyhow::ensure!(
        id.uri() == state.self_identity,
        "the CA issued {} instead of {}",
        id.uri(),
        state.self_identity
    );
    anyhow::ensure!(!tls.expired(), "the CA issued an expired certificate");
    Ok(tls)
}

/// A `config` record for the certificate (callee `certificate`). A failed issuance or renewal is
/// a failure, not a policy decision: decision `allow` with `error`, as for tool calls.
fn cert_record(state: &AppState, tls: Option<&WorkloadTls>, v: &Verdict, error: Option<String>) {
    let mut v = v.clone();
    if let Some(t) = tls {
        let until = chrono::DateTime::from_timestamp(t.not_after, 0)
            .map(|d| d.to_rfc3339())
            .unwrap_or_default();
        v.reason = format!("{} valid until {until}", t.material.identity.uri());
    }
    let sha = tls.map(|t| t.cert_sha256.clone()).unwrap_or_default();
    let mut rec = build_config_record(
        "control-plane",
        "certificate",
        "control-plane",
        "",
        "",
        &sha,
        &[],
        &v,
    );
    if let Some(e) = error {
        tracing::warn!(rule = %v.rule, error = %e, "certificate");
        rec.error = Some(e);
    }
    state.audit.write(rec);
}

/// Make `tls` the workload certificate: persist it, swap it in, drop cached peer channels.
pub fn install(state: &AppState, tls: WorkloadTls) {
    if let Err(e) = state.state_dir.save_tls(
        &tls.material.key_pem,
        &tls.material.cert_pem,
        &tls.material.ca_pem,
    ) {
        tracing::warn!(error = %e, "cannot persist the certificate in the state dir");
    }
    cert_record(state, Some(&tls), &Verdict::allow(RULE_ISSUED), None);
    tracing::info!(
        identity = %tls.material.identity.uri(),
        expires_in_s = tls.expires_in_s(),
        "workload certificate installed"
    );
    state
        .cert_not_after
        .store(tls.not_after, std::sync::atomic::Ordering::Relaxed);
    state.tls.store(Some(Arc::new(tls)));
    state.clear_mesh_clients();
    state.tls_generation.send_modify(|g| *g += 1);
}

/// Renewal failed until the certificate expired: drop it, so the sidecar is not ready and
/// presents no expired certificate, and record why.
fn drop_expired(state: &AppState, expired: &WorkloadTls) {
    let current = state.tls();
    if current
        .as_ref()
        .is_some_and(|t| t.cert_sha256 == expired.cert_sha256)
    {
        state.tls.store(None);
        state.clear_mesh_clients();
        state.tls_generation.send_modify(|g| *g += 1);
    }
    cert_record(
        state,
        Some(expired),
        &Verdict::allow(RULE_EXPIRED),
        Some("renewal failed until the certificate expired; obtaining a new one".into()),
    );
}

/// How long until `tls` expires (zero once it has).
fn until_expiry(tls: &WorkloadTls) -> Duration {
    Duration::from_secs(tls.expires_in_s().max(0) as u64)
}

/// `base` ± 20 %.
pub fn jittered(base: Duration) -> Duration {
    let f = rand::rng().random_range(0.8..=1.2);
    base.mul_f64(f)
}

/// Full-jitter backoff between `min` and `min(max, min·2^attempt)`.
pub fn backoff(min: Duration, max: Duration, attempt: u32) -> Duration {
    let cap = min
        .saturating_mul(1u32 << attempt.min(16))
        .min(max)
        .max(min);
    let lo = min.as_secs_f64();
    let hi = cap.as_secs_f64();
    if hi <= lo {
        return min;
    }
    Duration::from_secs_f64(rand::rng().random_range(lo..=hi))
}

async fn sleep_until(at: SystemTime) {
    if let Ok(d) = at.duration_since(SystemTime::now()) {
        tokio::time::sleep(d).await;
    }
}

/// Obtain the certificate if there is none, then renew it for the life of the sidecar.
pub async fn run(state: Arc<AppState>) {
    let timing = state.config.timing.clone();
    let mut attempt = 0u32;
    loop {
        let Some(current) = state.tls() else {
            match issue(&state).await {
                Ok(t) => {
                    install(&state, t);
                    attempt = 0;
                }
                Err(e) => {
                    cert_record(
                        &state,
                        None,
                        &Verdict::allow(RULE_ISSUE_FAILED),
                        Some(format!("{e:#}")),
                    );
                    tokio::time::sleep(backoff(
                        timing.reconnect_min,
                        timing.reconnect_max,
                        attempt,
                    ))
                    .await;
                    attempt = attempt.saturating_add(1);
                }
            }
            continue;
        };
        sleep_until(current.renew_at()).await;
        // retried with a fresh token until expiry (design §6.3.2), then obtained anew
        loop {
            if current.expired() {
                drop_expired(&state, &current);
                attempt = 0;
                break;
            }
            match issue(&state).await {
                Ok(t) => {
                    install(&state, t);
                    break;
                }
                Err(e) => {
                    cert_record(
                        &state,
                        Some(&current),
                        &Verdict::allow(RULE_RENEW_FAILED),
                        Some(format!("{e:#}")),
                    );
                    let pause = jittered(timing.renew_retry).min(until_expiry(&current));
                    tokio::time::sleep(pause).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_stays_within_bounds() {
        let (min, max) = (Duration::from_secs(1), Duration::from_secs(60));
        for attempt in 0..40 {
            let d = backoff(min, max, attempt);
            assert!(d >= min && d <= max, "{attempt}: {d:?}");
        }
        assert_eq!(backoff(min, max, 0), min);
        for _ in 0..100 {
            let d = jittered(Duration::from_secs(60));
            assert!(d >= Duration::from_secs(48) && d <= Duration::from_secs(72));
        }
    }
}
