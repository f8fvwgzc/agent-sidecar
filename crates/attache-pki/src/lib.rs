//! One CA per cluster, one leaf per service, SPIFFE URI SAN + DNS SANs (CONTRACT.md §5).
use attache_common::identity::SpiffeId;
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use time::{Duration, OffsetDateTime};

mod signing;
pub use signing::{
    BACKDATE, CaKeyPair, IssuedCert, IssuedKeyPair, VerifiedPublicKey, certs_from_pem,
    certs_to_pem, issue_server_leaf, issue_workload_leaf, not_after_of, pem_block,
    sole_spiffe_id_of, uri_sans_of, verify_csr_der_p256, verify_csr_p256,
};

pub const CA_COMMON_NAME: &str = "attache embassy CA";
pub const CA_TTL_DAYS: i64 = 3650;
pub const LEAF_TTL_DAYS: i64 = 365;

#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    #[error("certificate generation failed: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("certificate parse failed: {0}")]
    Parse(String),
    #[error("pem: {0}")]
    Pem(#[from] rustls_pki_types::pem::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// A certificate signing request that is malformed, not ECDSA P-256, or whose
    /// self-signature does not verify.
    #[error("certificate request refused: {0}")]
    Csr(String),
    /// Unusable input or material: a name that is not a DNS label, a zero lifetime, an expired
    /// CA, a key that matches no CA certificate.
    #[error("{0}")]
    Invalid(String),
}

#[derive(Debug, Clone)]
pub struct PemBundle {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Create a new self-signed CA.
pub fn ca_init() -> Result<PemBundle, PkiError> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_COMMON_NAME);
    dn.push(DnType::OrganizationName, "attache");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.not_before = OffsetDateTime::now_utc() - Duration::minutes(5);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(CA_TTL_DAYS);
    let cert = params.self_signed(&key)?;
    Ok(PemBundle {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// Issue a leaf for `spiffe://attache/ns/<namespace>/svc/<service>` signed by the CA.
pub fn issue_leaf(
    ca: &PemBundle,
    namespace: &str,
    service: &str,
    ttl_days: i64,
) -> Result<PemBundle, PkiError> {
    let id = SpiffeId {
        namespace: namespace.into(),
        service: service.into(),
    };
    let ca_key = KeyPair::from_pem(&ca.key_pem)?;
    let issuer = Issuer::from_ca_cert_pem(&ca.cert_pem, ca_key)?;
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("{service}.{namespace}"));
    dn.push(DnType::OrganizationName, "attache");
    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;
    params.use_authority_key_identifier_extension = true;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params
        .subject_alt_names
        .push(SanType::URI(Ia5String::try_from(id.uri())?));
    for dns in id.dns_names() {
        params
            .subject_alt_names
            .push(SanType::DnsName(Ia5String::try_from(dns)?));
    }
    params.not_before = OffsetDateTime::now_utc() - Duration::minutes(5);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(ttl_days);
    let cert = params.signed_by(&key, &issuer)?;
    Ok(PemBundle {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// The SPIFFE URI SAN of a DER certificate, if it has one in our trust domain.
pub fn spiffe_id_of(der: &[u8]) -> Result<Option<SpiffeId>, PkiError> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(der).map_err(|e| PkiError::Parse(e.to_string()))?;
    let san = cert
        .subject_alternative_name()
        .map_err(|e| PkiError::Parse(e.to_string()))?;
    Ok(san.and_then(|ext| {
        ext.value.general_names.iter().find_map(|g| match g {
            x509_parser::extensions::GeneralName::URI(u) => SpiffeId::parse(u),
            _ => None,
        })
    }))
}

/// DNS SANs of a DER certificate.
pub fn dns_names_of(der: &[u8]) -> Result<Vec<String>, PkiError> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(der).map_err(|e| PkiError::Parse(e.to_string()))?;
    let san = cert
        .subject_alternative_name()
        .map_err(|e| PkiError::Parse(e.to_string()))?;
    Ok(san
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(|g| match g {
                    x509_parser::extensions::GeneralName::DNSName(d) => Some(d.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default())
}

/// What `attached` loads from `--tls-dir`: ca.crt, tls.crt, tls.key.
pub struct TlsMaterial {
    pub ca_pem: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub identity: SpiffeId,
}

impl TlsMaterial {
    pub fn load(dir: impl AsRef<std::path::Path>) -> Result<Self, PkiError> {
        let dir = dir.as_ref();
        let ca_pem = std::fs::read_to_string(dir.join("ca.crt"))?;
        let cert_pem = std::fs::read_to_string(dir.join("tls.crt"))?;
        let key_pem = std::fs::read_to_string(dir.join("tls.key"))?;
        Self::from_pems(ca_pem, cert_pem, key_pem)
    }

    pub fn from_pems(ca_pem: String, cert_pem: String, key_pem: String) -> Result<Self, PkiError> {
        let leaf = CertificateDer::from_pem_slice(cert_pem.as_bytes())?;
        let identity = spiffe_id_of(&leaf)?
            .ok_or_else(|| PkiError::Parse("tls.crt has no spiffe://attache/ URI SAN".into()))?;
        let _ = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())?;
        Ok(Self {
            ca_pem,
            cert_pem,
            key_pem,
            identity,
        })
    }

    pub fn write(
        bundle: &PemBundle,
        ca_pem: &str,
        dir: impl AsRef<std::path::Path>,
    ) -> Result<(), PkiError> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join("ca.crt"), ca_pem)?;
        std::fs::write(dir.join("tls.crt"), &bundle.cert_pem)?;
        std::fs::write(dir.join("tls.key"), &bundle.key_pem)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_parse_round_trip() {
        let ca = ca_init().unwrap();
        let leaf = issue_leaf(&ca, "attache-demo", "orders", 30).unwrap();
        let der = CertificateDer::from_pem_slice(leaf.cert_pem.as_bytes()).unwrap();
        let id = spiffe_id_of(&der).unwrap().expect("URI SAN");
        assert_eq!(id.uri(), "spiffe://attache/ns/attache-demo/svc/orders");
        let dns = dns_names_of(&der).unwrap();
        assert!(dns.contains(&"orders.attache-demo.svc.cluster.local".to_string()));
        let mat = TlsMaterial::from_pems(
            ca.cert_pem.clone(),
            leaf.cert_pem.clone(),
            leaf.key_pem.clone(),
        )
        .unwrap();
        assert_eq!(mat.identity.service, "orders");
        // The CA itself has no SPIFFE SAN and must not load as an identity.
        let ca_der = CertificateDer::from_pem_slice(ca.cert_pem.as_bytes()).unwrap();
        assert!(spiffe_id_of(&ca_der).unwrap().is_none());
    }

    #[test]
    fn leaf_chains_to_ca() {
        use x509_parser::prelude::*;
        let ca = ca_init().unwrap();
        let leaf = issue_leaf(&ca, "ns", "svc", 1).unwrap();
        let ca_der = CertificateDer::from_pem_slice(ca.cert_pem.as_bytes()).unwrap();
        let leaf_der = CertificateDer::from_pem_slice(leaf.cert_pem.as_bytes()).unwrap();
        let (_, ca_cert) = parse_x509_certificate(&ca_der).unwrap();
        let (_, leaf_cert) = parse_x509_certificate(&leaf_der).unwrap();
        assert!(ca_cert.is_ca());
        assert!(!leaf_cert.is_ca());
        assert_eq!(leaf_cert.issuer(), ca_cert.subject());
        leaf_cert
            .verify_signature(Some(ca_cert.public_key()))
            .expect("leaf signed by CA");
    }
}
