//! `CertificateAuthority.IssueCertificate` (design §7, component `ca`). Empty for now.
//!
//! TODO(B3b): DNS-label, non-reserved names ([`crate::names`]); only the CSR's public key
//! (ECDSA P-256, self-signature verified); a fresh leaf with URI SAN
//! `spiffe://attache/ns/<ns>/svc/<svc>`, the four DNS SANs, EKU serverAuth + clientAuth and
//! lifetime `issuance.workload_cert_ttl`; Kubernetes tokens via TokenReview (audience
//! `attache`), the pod lookup, the `ATTACHE_SERVICE` container env and the service-account check;
//! join tokens from [`crate::config::JoinTokenEntry`]; a `cp_audit` record (`cert_issue`,
//! `cert_denied`) for every issuance and refusal.
