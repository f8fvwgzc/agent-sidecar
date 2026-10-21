//! CA material for the `ca` component (docs/design/agent-platform.md §7, §8.1 `--ca-dir` /
//! `--ca-secret`).
//!
//! `ca.crt` may hold several root certificates (during a CA rotation, or when the v0.1 CA is
//! reused, design §13); all of them are trust roots, and the first one that is a CA and whose
//! public key is `ca.key`'s signs. [`CaMaterial::roots_pem`] is the trust bundle handed to
//! sidecars (`CertificateResponse.ca_pem`), webhooks (`caBundle`) and the serving certificate;
//! it is re-encoded from the parsed certificates, so nothing but `CERTIFICATE` blocks (never a
//! key pasted into `ca.crt`) leaves this process.
//!
//! The Kubernetes form (`--ca-secret <ns>/<name>`) is loaded by
//! [`crate::k8s::load_ca_secret`] and ends up in the same type.
use std::fmt;
use std::path::Path;
use std::time::Duration;

use agentsc_pki::{CaKeyPair, IssuedCert, IssuedKeyPair, VerifiedPublicKey};
use anyhow::Context;

/// The CA trust bundle and the signing key pair.
pub struct CaMaterial {
    /// Every root of `ca.crt`, re-encoded (`CERTIFICATE` blocks only, LF line endings).
    roots_pem: String,
    /// The first root that is a CA certificate for `ca.key`.
    signer: CaKeyPair,
}

impl fmt::Debug for CaMaterial {
    /// Never prints the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaMaterial")
            .field(
                "roots",
                &self.roots_pem.matches("BEGIN CERTIFICATE").count(),
            )
            .field("signer", &self.signer)
            .finish()
    }
}

impl CaMaterial {
    /// `<dir>/ca.crt` (one or more roots) and `<dir>/ca.key` (PKCS#8 PEM), the layout of
    /// `embassy ca-init` and of `--ca-dir`.
    pub fn load_dir(dir: impl AsRef<Path>) -> anyhow::Result<Self> {
        let dir = dir.as_ref();
        let read = |name: &str| {
            let path = dir.join(name);
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))
        };
        let crt = read("ca.crt")?;
        let key = read("ca.key")?;
        Self::from_pems(&crt, &key).with_context(|| format!("the CA in {}", dir.display()))
    }

    /// From the text of `ca.crt` and `ca.key`.
    pub fn from_pems(crt: &str, key: &str) -> anyhow::Result<Self> {
        let roots = agentsc_pki::certs_from_pem(crt).context("ca.crt")?;
        let signer = CaKeyPair::from_pems(crt, key).context("ca.key and ca.crt")?;
        Ok(Self {
            roots_pem: agentsc_pki::certs_to_pem(&roots),
            signer,
        })
    }

    /// Every trust root, PEM (may hold several certificates).
    pub fn roots_pem(&self) -> &str {
        &self.roots_pem
    }

    /// The root that signs, with its key.
    pub fn signer(&self) -> &CaKeyPair {
        &self.signer
    }

    /// A workload leaf for `spiffe://agentsc/ns/<namespace>/svc/<service>` (design §7): only
    /// the verified CSR key is used; DNS SANs `<svc>`, `<svc>.<ns>`, `<svc>.<ns>.svc`,
    /// `<svc>.<ns>.svc.cluster.local`; EKU serverAuth + clientAuth; valid for `ttl` (capped at
    /// the CA's expiry). The caller has already checked the names (DNS labels, not reserved) and
    /// the caller's right to the identity.
    pub fn sign_workload(
        &self,
        public_key: &VerifiedPublicKey,
        namespace: &str,
        service: &str,
        ttl: Duration,
    ) -> anyhow::Result<IssuedCert> {
        agentsc_pki::issue_workload_leaf(&self.signer, public_key, namespace, service, ttl)
            .with_context(|| format!("sign a certificate for {namespace}/{service}"))
    }

    /// A server-only leaf with a fresh P-256 key: URI SAN `uri_san`, DNS SANs `dns_names`, EKU
    /// serverAuth only, valid for `ttl` (capped at the CA's expiry). The control-plane serving
    /// certificate uses [`crate::servingcert::CONTROL_PLANE_SPIFFE_ID`].
    pub fn sign_server(
        &self,
        dns_names: &[String],
        uri_san: &str,
        ttl: Duration,
    ) -> anyhow::Result<IssuedKeyPair> {
        agentsc_pki::issue_server_leaf(&self.signer, dns_names, uri_san, ttl)
            .with_context(|| format!("sign a serving certificate for {uri_san}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::RootCertStore;
    use rustls::client::WebPkiServerVerifier;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::server::WebPkiClientVerifier;
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
    use std::sync::Arc;

    const HOUR: Duration = Duration::from_secs(3600);

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    fn roots(pem: &str) -> Arc<RootCertStore> {
        let mut store = RootCertStore::empty();
        for c in agentsc_pki::certs_from_pem(pem).unwrap() {
            store.add(c).unwrap();
        }
        Arc::new(store)
    }

    fn der(pem: &str) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(pem.as_bytes()).unwrap()
    }

    fn csr() -> VerifiedPublicKey {
        let key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::default()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap();
        agentsc_pki::verify_csr_p256(&csr).unwrap()
    }

    fn write_ca(dir: &Path, crt: &str, key: &str) {
        std::fs::write(dir.join("ca.crt"), crt).unwrap();
        std::fs::write(dir.join("ca.key"), key).unwrap();
    }

    #[test]
    fn ca_material_is_shareable() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CaMaterial>();
    }

    #[test]
    fn load_dir_reads_ca_init_output() {
        let dir = tempfile::tempdir().unwrap();
        let ca = agentsc_pki::ca_init().unwrap();
        write_ca(dir.path(), &ca.cert_pem, &ca.key_pem);
        let m = CaMaterial::load_dir(dir.path()).unwrap();
        assert_eq!(der(m.roots_pem()), der(&ca.cert_pem));
        assert_eq!(m.signer().cert_der(), &der(&ca.cert_pem));
        assert!(!format!("{m:?}").contains("PRIVATE"));

        // missing files name the path
        std::fs::remove_file(dir.path().join("ca.key")).unwrap();
        let e = format!("{:#}", CaMaterial::load_dir(dir.path()).unwrap_err());
        assert!(e.contains("ca.key"), "{e}");
        let e = format!(
            "{:#}",
            CaMaterial::load_dir(dir.path().join("nope")).unwrap_err()
        );
        assert!(e.contains("ca.crt"), "{e}");

        // a key that is not the CA's
        let other = agentsc_pki::ca_init().unwrap();
        write_ca(dir.path(), &ca.cert_pem, &other.key_pem);
        let e = format!("{:#}", CaMaterial::load_dir(dir.path()).unwrap_err());
        assert!(e.contains("not") || e.contains("none"), "{e}");
        assert!(e.contains(&dir.path().display().to_string()), "{e}");
    }

    #[test]
    fn several_roots_are_trusted_and_the_key_matching_one_signs() {
        let old = agentsc_pki::ca_init().unwrap();
        let new = agentsc_pki::ca_init().unwrap();
        // the new key, a bundle with the old root first and a stray private key block
        let crt = format!(
            "{}\n# rotation\n{}{}",
            old.cert_pem, new.key_pem, new.cert_pem
        );
        let m = CaMaterial::from_pems(&crt, &new.key_pem).unwrap();
        assert_eq!(m.roots_pem().matches("BEGIN CERTIFICATE").count(), 2);
        assert!(!m.roots_pem().contains("PRIVATE KEY"));
        assert!(!m.roots_pem().contains("rotation"));
        assert_eq!(m.signer().cert_der(), &der(&new.cert_pem));

        // a workload leaf from the new root verifies against the bundle as a client certificate
        let leaf = m.sign_workload(&csr(), "shop", "orders", HOUR).unwrap();
        let verifier =
            WebPkiClientVerifier::builder_with_provider(roots(m.roots_pem()), provider())
                .build()
                .unwrap();
        verifier
            .verify_client_cert(&der(&leaf.cert_pem), &[], UnixTime::now())
            .unwrap();
        // ...and not against the old root alone
        let old_only =
            WebPkiClientVerifier::builder_with_provider(roots(&old.cert_pem), provider())
                .build()
                .unwrap();
        assert!(
            old_only
                .verify_client_cert(&der(&leaf.cert_pem), &[], UnixTime::now())
                .is_err()
        );
    }

    #[test]
    fn workload_and_server_leaves_have_their_usages() {
        let ca = agentsc_pki::ca_init().unwrap();
        let m = CaMaterial::from_pems(&ca.cert_pem, &ca.key_pem).unwrap();
        let roots = roots(m.roots_pem());

        // workload: client and server
        let leaf = m
            .sign_workload(&csr(), "shop", "orders", 24 * HOUR)
            .unwrap();
        let id = agentsc_pki::sole_spiffe_id_of(&leaf.cert_der)
            .unwrap()
            .unwrap();
        assert_eq!(id.uri(), "spiffe://agentsc/ns/shop/svc/orders");
        let server_verifier =
            WebPkiServerVerifier::builder_with_provider(roots.clone(), provider())
                .build()
                .unwrap();
        server_verifier
            .verify_server_cert(
                &leaf.cert_der,
                &[],
                &ServerName::try_from("orders.shop.svc").unwrap(),
                &[],
                UnixTime::now(),
            )
            .unwrap();

        // server: serverAuth only, so never a client identity
        let dns = vec!["localhost".to_string()];
        let server = m
            .sign_server(&dns, crate::servingcert::CONTROL_PLANE_SPIFFE_ID, HOUR)
            .unwrap();
        server_verifier
            .verify_server_cert(
                &der(&server.cert_pem),
                &[],
                &ServerName::try_from("localhost").unwrap(),
                &[],
                UnixTime::now(),
            )
            .unwrap();
        let client_verifier = WebPkiClientVerifier::builder_with_provider(roots, provider())
            .build()
            .unwrap();
        assert!(
            client_verifier
                .verify_client_cert(&der(&server.cert_pem), &[], UnixTime::now())
                .is_err()
        );

        // names are checked
        let e = format!(
            "{:#}",
            m.sign_workload(&csr(), "Shop", "orders", HOUR).unwrap_err()
        );
        assert!(e.contains("DNS-1123"), "{e}");
    }
}
