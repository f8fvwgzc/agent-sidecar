//! The control-plane serving certificate (design §7). Empty for now.
//!
//! TODO(B3b): `embassy-ca` creates and renews Secret `--tls-secret` (in one-process mode, an
//! in-memory certificate): URI SAN `spiffe://attache/control-plane`, DNS SANs from `--dns-name`,
//! EKU serverAuth, 30-day lifetime, renewed at two thirds. The controlplane component reads it
//! from `--tls-dir` when the ca component runs elsewhere; the webhooks and `--http-tls` use the
//! same certificate.
