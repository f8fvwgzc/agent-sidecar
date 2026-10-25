//! Signing with a loaded CA (docs/design/agent-platform.md §7): workload leaves for
//! `IssueCertificate` from a verified CSR public key, and the control-plane serving certificate.
//!
//! The CSR path trusts nothing in the request but its public key: [`verify_csr_p256`] accepts
//! only an ECDSA P-256 key whose self-signature verifies, and returns just that key as a
//! [`VerifiedPublicKey`] (subject, SANs, extensions and attributes are ignored).
//! [`issue_workload_leaf`] accepts only a [`VerifiedPublicKey`], so a key that did not come out of
//! a verified CSR cannot be signed, and builds the leaf fresh.
use std::fmt;
use std::time::{Duration as StdDuration, SystemTime, UNIX_EPOCH};

use agentsc_common::identity::SpiffeId;
use rcgen::string::Ia5String;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData, SanType, SerialNumber, SignatureAlgorithm,
};
use ring::rand::SecureRandom;
use ring::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA384_ASN1, UnparsedPublicKey, VerificationAlgorithm,
};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, CertificateSigningRequestDer};
use time::OffsetDateTime;
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::der_parser::oid::Oid;
use x509_parser::extensions::GeneralName;
use x509_parser::oid_registry::{
    OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ECDSA_WITH_SHA256, OID_SIG_ECDSA_WITH_SHA384,
};
use x509_parser::prelude::FromDer;

use crate::PkiError;

/// Clock-skew allowance: a leaf is valid from this long before it was signed.
pub const BACKDATE: StdDuration = StdDuration::from_secs(5 * 60);

/// Every `CERTIFICATE` block of `pem`, in order; each must be one well-formed X.509 certificate.
/// Other blocks (a private key pasted into the same file, say) are skipped. At least one
/// certificate is required.
pub fn certs_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>, PkiError> {
    let mut certs = Vec::new();
    for item in CertificateDer::pem_slice_iter(pem.as_bytes()) {
        let der = item?;
        let n = certs.len() + 1;
        let (rest, _) = x509_parser::parse_x509_certificate(&der)
            .map_err(|e| PkiError::Parse(format!("certificate {n}: {e}")))?;
        if !rest.is_empty() {
            return Err(PkiError::Parse(format!(
                "certificate {n}: trailing bytes after the certificate"
            )));
        }
        certs.push(der);
    }
    if certs.is_empty() {
        return Err(PkiError::Parse("no CERTIFICATE block found".into()));
    }
    Ok(certs)
}

/// PEM text of `certs` (one `CERTIFICATE` block each, LF line endings), and nothing else.
pub fn certs_to_pem(certs: &[CertificateDer<'_>]) -> String {
    certs.iter().map(|c| pem_block("CERTIFICATE", c)).collect()
}

/// One PEM block (RFC 7468): `-----BEGIN <label>-----`, base64 in 64-character lines,
/// `-----END <label>-----`, LF line endings, a final newline.
pub fn pem_block(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    // base64 is ASCII, so every 64-byte chunk is valid UTF-8
    for line in b64.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(line));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// The signing half of a CA: one CA certificate and its private key.
///
/// [`CaKeyPair::from_pems`] takes a bundle of roots (`ca.crt` may hold several during a
/// rotation) and picks the first CA certificate whose public key is the key's.
pub struct CaKeyPair {
    cert_der: CertificateDer<'static>,
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
    not_after: OffsetDateTime,
}

impl fmt::Debug for CaKeyPair {
    /// Never prints the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaKeyPair")
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

impl CaKeyPair {
    /// The first certificate in `roots_pem` that is a CA (basicConstraints `CA:TRUE`) and whose
    /// SubjectPublicKeyInfo equals the public key of `key_pem` (PKCS#8 PEM).
    pub fn from_pems(roots_pem: &str, key_pem: &str) -> Result<Self, PkiError> {
        let key = KeyPair::from_pem(key_pem)?;
        let key_spki = key.subject_public_key_info();
        let roots = certs_from_pem(roots_pem)?;
        let n = roots.len();
        for der in roots {
            let (_, cert) = x509_parser::parse_x509_certificate(&der)
                .map_err(|e| PkiError::Parse(e.to_string()))?;
            if !cert.is_ca() || cert.public_key().raw != key_spki.as_slice() {
                continue;
            }
            let not_after = cert.validity().not_after.to_datetime();
            let issuer = Issuer::from_ca_cert_der(&der, key)?;
            let cert_pem = certs_to_pem(std::slice::from_ref(&der));
            return Ok(Self {
                cert_der: der,
                cert_pem,
                issuer,
                not_after,
            });
        }
        Err(PkiError::Invalid(format!(
            "none of the {n} certificate(s) is a CA certificate for this private key"
        )))
    }

    /// From a v0.1 [`crate::PemBundle`] (`ca.crt`, `ca.key`).
    pub fn from_bundle(bundle: &crate::PemBundle) -> Result<Self, PkiError> {
        Self::from_pems(&bundle.cert_pem, &bundle.key_pem)
    }

    /// The signing CA certificate alone, as PEM.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    /// When the CA certificate expires; no leaf it signs outlives it.
    pub fn not_after(&self) -> SystemTime {
        self.not_after.into()
    }

    /// `(not_before, not_after)` of a leaf signed now with `ttl`: backdated by [`BACKDATE`],
    /// and never past the CA's own expiry.
    fn leaf_validity(
        &self,
        ttl: StdDuration,
    ) -> Result<(OffsetDateTime, OffsetDateTime), PkiError> {
        if ttl.is_zero() {
            return Err(PkiError::Invalid("the certificate lifetime is zero".into()));
        }
        let now = OffsetDateTime::now_utc();
        if self.not_after <= now {
            return Err(PkiError::Invalid("the CA certificate has expired".into()));
        }
        let ttl = ::time::Duration::try_from(ttl)
            .map_err(|_| PkiError::Invalid("the certificate lifetime is too long".into()))?;
        let backdate = ::time::Duration::try_from(BACKDATE)
            .map_err(|_| PkiError::Invalid("backdate out of range".into()))?;
        let not_after = now
            .checked_add(ttl)
            .map_or(self.not_after, |t| t.min(self.not_after));
        Ok((now.checked_sub(backdate).unwrap_or(now), not_after))
    }
}

/// An ECDSA P-256 public key taken from a CSR whose self-signature verified
/// ([`verify_csr_p256`]); nothing else of the CSR is kept.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedPublicKey {
    /// The uncompressed EC point (65 bytes).
    point: Vec<u8>,
    /// The CSR's SubjectPublicKeyInfo, DER.
    spki_der: Vec<u8>,
}

impl VerifiedPublicKey {
    /// The SubjectPublicKeyInfo (DER) as it appeared in the CSR.
    pub fn spki_der(&self) -> &[u8] {
        &self.spki_der
    }

    /// Lowercase hex SHA-256 of [`Self::spki_der`]: the public-key fingerprint audit records
    /// carry (`cert_issue`, `cert_denied`).
    pub fn sha256_hex(&self) -> String {
        hex_lower(ring::digest::digest(&ring::digest::SHA256, &self.spki_der).as_ref())
    }
}

impl fmt::Debug for VerifiedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedPublicKey")
            .field("sha256", &self.sha256_hex())
            .finish()
    }
}

impl PublicKeyData for VerifiedPublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.point
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

fn csr_err(msg: impl Into<String>) -> PkiError {
    PkiError::Csr(msg.into())
}

/// Parse one PEM `CERTIFICATE REQUEST`, check that its key is ECDSA P-256 and that its
/// self-signature (ecdsa-with-SHA256 or ecdsa-with-SHA384) verifies, and return only the key.
/// Subject, SANs, extensions and attributes are ignored. Exactly one CSR block is accepted.
pub fn verify_csr_p256(csr_pem: &str) -> Result<VerifiedPublicKey, PkiError> {
    let mut blocks = CertificateSigningRequestDer::pem_slice_iter(csr_pem.as_bytes());
    let der = match (blocks.next(), blocks.next()) {
        (Some(first), None) => first?,
        (None, _) => return Err(csr_err("no CERTIFICATE REQUEST block found")),
        (Some(_), Some(_)) => return Err(csr_err("more than one CERTIFICATE REQUEST block")),
    };
    verify_csr_der_p256(&der)
}

/// [`verify_csr_p256`] for a DER-encoded CSR.
pub fn verify_csr_der_p256(der: &[u8]) -> Result<VerifiedPublicKey, PkiError> {
    let (rest, csr) = X509CertificationRequest::from_der(der)
        .map_err(|e| csr_err(format!("not a certificate request: {e}")))?;
    if !rest.is_empty() {
        return Err(csr_err("trailing bytes after the certificate request"));
    }
    let info = &csr.certification_request_info;
    let spki = &info.subject_pki;
    if spki.algorithm.algorithm != OID_KEY_TYPE_EC_PUBLIC_KEY {
        return Err(csr_err(format!(
            "the key is not an EC key (algorithm {}); only ECDSA P-256 is accepted",
            spki.algorithm.algorithm
        )));
    }
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| Oid::try_from(p).ok());
    if curve.as_ref() != Some(&OID_EC_P256) {
        return Err(csr_err(
            "the EC key is not on curve P-256 (prime256v1); only ECDSA P-256 is accepted",
        ));
    }
    let point = spki.subject_public_key.data.as_ref();
    if spki.subject_public_key.unused_bits != 0 || point.len() != 65 || point.first() != Some(&4) {
        return Err(csr_err("the P-256 public key is not an uncompressed point"));
    }
    let alg: &'static dyn VerificationAlgorithm =
        if csr.signature_algorithm.algorithm == OID_SIG_ECDSA_WITH_SHA256 {
            &ECDSA_P256_SHA256_ASN1
        } else if csr.signature_algorithm.algorithm == OID_SIG_ECDSA_WITH_SHA384 {
            &ECDSA_P256_SHA384_ASN1
        } else {
            return Err(csr_err(format!(
                "signature algorithm {} is not ecdsa-with-SHA256 or ecdsa-with-SHA384",
                csr.signature_algorithm.algorithm
            )));
        };
    if csr.signature_value.unused_bits != 0 {
        return Err(csr_err("malformed signature"));
    }
    UnparsedPublicKey::new(alg, point)
        .verify(info.raw, csr.signature_value.data.as_ref())
        .map_err(|_| csr_err("the CSR self-signature does not verify"))?;
    Ok(VerifiedPublicKey {
        point: point.to_vec(),
        spki_der: spki.raw.to_vec(),
    })
}

/// A certificate signed for a key the caller already holds.
#[derive(Debug, Clone)]
pub struct IssuedCert {
    pub cert_pem: String,
    pub cert_der: CertificateDer<'static>,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
}

/// A certificate with the fresh private key it was issued for.
#[derive(Clone)]
pub struct IssuedKeyPair {
    pub cert_pem: String,
    /// PKCS#8 PEM.
    pub key_pem: String,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
}

impl fmt::Debug for IssuedKeyPair {
    /// Never prints the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedKeyPair")
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

/// A DNS-1123 label: 1..=63 of `[a-z0-9-]`, starting and ending alphanumeric.
fn is_dns_label(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b.first() != Some(&b'-')
        && b.last() != Some(&b'-')
}

/// A random positive 16-byte serial (RFC 5280: unique per CA; rcgen's default is a hash of
/// the public key, which repeats when a key is renewed).
fn random_serial() -> Result<SerialNumber, PkiError> {
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| PkiError::Invalid("the system random generator failed".into()))?;
    // positive, and no leading zero byte
    bytes[0] = (bytes[0] & 0x7f) | 0x40;
    Ok(SerialNumber::from_slice(&bytes))
}

fn leaf_params(
    common_name: &str,
    eku: Vec<ExtendedKeyUsagePurpose>,
    sans: Vec<SanType>,
    (not_before, not_after): (OffsetDateTime, OffsetDateTime),
) -> Result<CertificateParams, PkiError> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn.push(DnType::OrganizationName, "agentsc");
    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;
    params.serial_number = Some(random_serial()?);
    params.use_authority_key_identifier_extension = true;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = eku;
    params.subject_alt_names = sans;
    params.not_before = not_before;
    params.not_after = not_after;
    Ok(params)
}

/// [`issue_workload_leaf_in`] in the default trust domain (`agentsc`) and cluster domain
/// (`cluster.local`).
pub fn issue_workload_leaf(
    ca: &CaKeyPair,
    public_key: &VerifiedPublicKey,
    namespace: &str,
    service: &str,
    ttl: StdDuration,
) -> Result<IssuedCert, PkiError> {
    issue_workload_leaf_in(
        ca,
        public_key,
        agentsc_common::identity::DEFAULT_TRUST_DOMAIN,
        agentsc_common::identity::DEFAULT_CLUSTER_DOMAIN,
        namespace,
        service,
        ttl,
    )
}

/// The workload leaf of design §7 for `public_key`: URI SAN
/// `spiffe://<trust_domain>/ns/<namespace>/svc/<service>`, DNS SANs `<svc>`, `<svc>.<ns>`,
/// `<svc>.<ns>.svc`, `<svc>.<ns>.svc.<cluster_domain>`, EKU serverAuth + clientAuth, valid for
/// `ttl` (backdated by [`BACKDATE`], capped at the CA's expiry). `namespace` and `service`
/// must be DNS-1123 labels, `trust_domain` a SPIFFE trust domain name and `cluster_domain` a DNS
/// name.
pub fn issue_workload_leaf_in(
    ca: &CaKeyPair,
    public_key: &VerifiedPublicKey,
    trust_domain: &str,
    cluster_domain: &str,
    namespace: &str,
    service: &str,
    ttl: StdDuration,
) -> Result<IssuedCert, PkiError> {
    for (what, value) in [("namespace", namespace), ("service", service)] {
        if !is_dns_label(value) {
            return Err(PkiError::Invalid(format!(
                "{what} {value:?} is not a DNS-1123 label"
            )));
        }
    }
    agentsc_common::identity::check_trust_domain(trust_domain).map_err(PkiError::Invalid)?;
    agentsc_common::identity::check_cluster_domain(cluster_domain).map_err(PkiError::Invalid)?;
    let id = SpiffeId::new(trust_domain, namespace, service);
    let mut sans = vec![SanType::URI(Ia5String::try_from(id.uri())?)];
    for dns in id.dns_names(cluster_domain) {
        sans.push(SanType::DnsName(Ia5String::try_from(dns)?));
    }
    let validity = ca.leaf_validity(ttl)?;
    let params = leaf_params(
        &format!("{service}.{namespace}"),
        vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ],
        sans,
        validity,
    )?;
    let cert = params.signed_by(public_key, &ca.issuer)?;
    Ok(IssuedCert {
        cert_pem: cert.pem(),
        cert_der: cert.der().clone(),
        not_before: validity.0.into(),
        not_after: validity.1.into(),
    })
}

/// A server-only leaf with a fresh ECDSA P-256 key: URI SAN `uri_san`, the DNS SANs
/// `dns_names` (may be empty), EKU serverAuth only (it cannot authenticate as a TLS client),
/// valid for `ttl` (backdated by [`BACKDATE`], capped at the CA's expiry). Used for the
/// control-plane serving certificate (`spiffe://agentsc/control-plane`, design §7).
pub fn issue_server_leaf(
    ca: &CaKeyPair,
    dns_names: &[String],
    uri_san: &str,
    ttl: StdDuration,
) -> Result<IssuedKeyPair, PkiError> {
    if uri_san.is_empty() {
        return Err(PkiError::Invalid("the URI SAN is empty".into()));
    }
    let mut sans = vec![SanType::URI(Ia5String::try_from(uri_san)?)];
    for dns in dns_names {
        if dns.is_empty() || dns.len() > 253 {
            return Err(PkiError::Invalid(format!("{dns:?} is not a DNS name")));
        }
        sans.push(SanType::DnsName(Ia5String::try_from(dns.as_str())?));
    }
    let validity = ca.leaf_validity(ttl)?;
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let common_name = dns_names
        .first()
        .map_or("agentsc control plane", String::as_str);
    let params = leaf_params(
        common_name,
        vec![ExtendedKeyUsagePurpose::ServerAuth],
        sans,
        validity,
    )?;
    let cert = params.signed_by(&key, &ca.issuer)?;
    Ok(IssuedKeyPair {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        not_before: validity.0.into(),
        not_after: validity.1.into(),
    })
}

/// The workload identity of a DER certificate, strictly: the certificate must carry exactly
/// one URI SAN and it must be `spiffe://<trust domain>/ns/<ns>/svc/<svc>` (a SPIFFE SVID has one
/// URI SAN). `Ok(None)` otherwise (no URI SAN, several, or another kind of URI such as
/// `spiffe://agentsc/control-plane`). The trust domain is kept: the caller compares it with its
/// own.
pub fn sole_spiffe_id_of(der: &[u8]) -> Result<Option<SpiffeId>, PkiError> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(der).map_err(|e| PkiError::Parse(e.to_string()))?;
    let san = cert
        .subject_alternative_name()
        .map_err(|e| PkiError::Parse(e.to_string()))?;
    let mut uris = san.into_iter().flat_map(|ext| {
        ext.value.general_names.iter().filter_map(|g| match g {
            GeneralName::URI(u) => Some(*u),
            _ => None,
        })
    });
    Ok(match (uris.next(), uris.next()) {
        (Some(uri), None) => SpiffeId::parse(uri),
        _ => None,
    })
}

/// The URI SANs of a DER certificate, in order.
pub fn uri_sans_of(der: &[u8]) -> Result<Vec<String>, PkiError> {
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
                    GeneralName::URI(u) => Some(u.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default())
}

/// When a DER certificate expires.
pub fn not_after_of(der: &[u8]) -> Result<SystemTime, PkiError> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(der).map_err(|e| PkiError::Parse(e.to_string()))?;
    let secs = cert.validity().not_after.timestamp();
    Ok(match u64::try_from(secs) {
        Ok(s) => UNIX_EPOCH + StdDuration::from_secs(s),
        Err(_) => UNIX_EPOCH,
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca_init;
    use x509_parser::prelude::*;

    const HOUR: StdDuration = StdDuration::from_secs(3600);

    fn ca() -> (crate::PemBundle, CaKeyPair) {
        let bundle = ca_init().unwrap();
        let pair = CaKeyPair::from_bundle(&bundle).unwrap();
        (bundle, pair)
    }

    /// A CSR for a new key of `alg` that asks for things the CA must ignore.
    fn csr_for(alg: &'static SignatureAlgorithm) -> (KeyPair, String) {
        let key = KeyPair::generate_for(alg).unwrap();
        let mut params = CertificateParams::new(vec![
            "evil.example".to_string(),
            "kubernetes.default.svc".to_string(),
        ])
        .unwrap();
        params.subject_alt_names.push(SanType::URI(
            Ia5String::try_from("spiffe://agentsc/ns/kube-system/svc/admin").unwrap(),
        ));
        params
            .distinguished_name
            .push(DnType::CommonName, "csr-subject");
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        // an extension rcgen's own CSR parser refuses; ignored here
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 99999, 1],
                vec![0x05, 0x00],
            ));
        let pem = params.serialize_request(&key).unwrap().pem().unwrap();
        (key, pem)
    }

    fn der_of(pem: &str) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(pem.as_bytes()).unwrap()
    }

    fn eku(der: &[u8]) -> (bool, bool) {
        let (_, cert) = parse_x509_certificate(der).unwrap();
        let eku = cert.extended_key_usage().unwrap().unwrap().value;
        (eku.server_auth, eku.client_auth)
    }

    fn assert_signed_by(leaf: &[u8], ca: &[u8]) {
        let (_, ca_cert) = parse_x509_certificate(ca).unwrap();
        let (_, leaf_cert) = parse_x509_certificate(leaf).unwrap();
        assert!(!leaf_cert.is_ca());
        assert_eq!(leaf_cert.issuer(), ca_cert.subject());
        leaf_cert
            .verify_signature(Some(ca_cert.public_key()))
            .expect("leaf signed by the CA");
    }

    fn secs_between(a: SystemTime, b: SystemTime) -> i64 {
        match b.duration_since(a) {
            Ok(d) => i64::try_from(d.as_secs()).unwrap(),
            Err(e) => -i64::try_from(e.duration().as_secs()).unwrap(),
        }
    }

    #[test]
    fn workload_leaf_uses_only_the_verified_csr_key() {
        let (bundle, ca) = ca();
        let (key, csr) = csr_for(&rcgen::PKCS_ECDSA_P256_SHA256);
        let verified = verify_csr_p256(&csr).unwrap();
        assert_eq!(
            verified.spki_der(),
            key.subject_public_key_info().as_slice()
        );
        assert_eq!(verified.sha256_hex().len(), 64);
        assert!(format!("{verified:?}").contains(&verified.sha256_hex()));

        let leaf = issue_workload_leaf(&ca, &verified, "shop", "orders", 24 * HOUR).unwrap();
        let der = der_of(&leaf.cert_pem);
        assert_eq!(der, leaf.cert_der);
        assert_signed_by(&der, &der_of(&bundle.cert_pem));
        let (_, cert) = parse_x509_certificate(&der).unwrap();
        // the CSR's key, nothing else of the CSR
        assert_eq!(cert.public_key().raw, verified.spki_der());
        assert!(!cert.is_ca());
        assert_eq!(
            uri_sans_of(&der).unwrap(),
            ["spiffe://agentsc/ns/shop/svc/orders"]
        );
        assert_eq!(
            crate::dns_names_of(&der).unwrap(),
            [
                "orders",
                "orders.shop",
                "orders.shop.svc",
                "orders.shop.svc.cluster.local"
            ]
        );
        assert!(!cert.subject().to_string().contains("csr-subject"));
        assert_eq!(eku(&der), (true, true));
        // lifetime: ttl from now, backdated five minutes
        let now = SystemTime::now();
        assert!((secs_between(now, leaf.not_after) - 24 * 3600).abs() <= 5);
        assert!((secs_between(leaf.not_before, now) - 300).abs() <= 5);
        assert!((secs_between(not_after_of(&der).unwrap(), leaf.not_after)).abs() <= 1);
        // a workload certificate is a valid --tls-dir identity
        let id = sole_spiffe_id_of(&der).unwrap().unwrap();
        assert_eq!(
            (id.namespace.as_str(), id.service.as_str()),
            ("shop", "orders")
        );
    }

    #[test]
    fn workload_leaf_in_a_configured_trust_and_cluster_domain() {
        let (_, ca) = ca();
        let (_, csr) = csr_for(&rcgen::PKCS_ECDSA_P256_SHA256);
        let key = verify_csr_p256(&csr).unwrap();
        let leaf = issue_workload_leaf_in(
            &ca,
            &key,
            "prod.example",
            "corp.internal",
            "shop",
            "orders",
            HOUR,
        )
        .unwrap();
        assert_eq!(
            crate::uri_sans_of(&leaf.cert_der).unwrap(),
            ["spiffe://prod.example/ns/shop/svc/orders"]
        );
        assert_eq!(
            crate::dns_names_of(&leaf.cert_der).unwrap()[3],
            "orders.shop.svc.corp.internal"
        );
        let id = sole_spiffe_id_of(&leaf.cert_der).unwrap().unwrap();
        assert_eq!(id.trust_domain, "prod.example");
        for (td, cd) in [("Prod", "cluster.local"), ("agentsc", "a..b")] {
            let e = issue_workload_leaf_in(&ca, &key, td, cd, "shop", "orders", HOUR).unwrap_err();
            assert!(matches!(e, PkiError::Invalid(_)), "{td} {cd}: {e}");
        }
    }

    #[test]
    fn serials_are_random_even_for_the_same_key() {
        let (_, ca) = ca();
        let (_, csr) = csr_for(&rcgen::PKCS_ECDSA_P256_SHA256);
        let key = verify_csr_p256(&csr).unwrap();
        let serial = |c: &IssuedCert| {
            let (_, cert) = parse_x509_certificate(&c.cert_der).unwrap();
            cert.raw_serial().to_vec()
        };
        let a = issue_workload_leaf(&ca, &key, "ns", "svc", HOUR).unwrap();
        let b = issue_workload_leaf(&ca, &key, "ns", "svc", HOUR).unwrap();
        assert_ne!(serial(&a), serial(&b));
        assert_eq!(serial(&a).len(), 16);
    }

    #[test]
    fn csrs_with_other_keys_are_refused() {
        for alg in [&rcgen::PKCS_ECDSA_P384_SHA384, &rcgen::PKCS_ED25519] {
            let (_, csr) = csr_for(alg);
            let e = verify_csr_p256(&csr).unwrap_err().to_string();
            assert!(e.contains("only ECDSA P-256 is accepted"), "{e}");
        }
    }

    #[test]
    fn csrs_whose_signature_does_not_verify_are_refused() {
        let (_, csr) = csr_for(&rcgen::PKCS_ECDSA_P256_SHA256);
        let der = CertificateSigningRequestDer::from_pem_slice(csr.as_bytes()).unwrap();

        // the signature's last byte flipped (still well-formed DER)
        let mut sig = der.as_ref().to_vec();
        if let Some(last) = sig.last_mut() {
            *last ^= 0x01;
        }
        let e = verify_csr_der_p256(&sig).unwrap_err().to_string();
        assert!(e.contains("does not verify"), "{e}");

        // the signed body changed: another subject of the same length
        let mut body = der.as_ref().to_vec();
        let at = body
            .windows(b"csr-subject".len())
            .position(|w| w == b"csr-subject")
            .unwrap();
        body[at] = b'X';
        let e = verify_csr_der_p256(&body).unwrap_err().to_string();
        assert!(e.contains("does not verify"), "{e}");

        // the same request through PEM
        let tampered = pem_block("CERTIFICATE REQUEST", &body);
        let e = verify_csr_p256(&tampered).unwrap_err().to_string();
        assert!(e.contains("does not verify"), "{e}");

        // another key's request info under this request's signature
        let (_, other) = csr_for(&rcgen::PKCS_ECDSA_P256_SHA256);
        let other = CertificateSigningRequestDer::from_pem_slice(other.as_bytes()).unwrap();
        let (_, a) = X509CertificationRequest::from_der(der.as_ref()).unwrap();
        let (_, b) = X509CertificationRequest::from_der(other.as_ref()).unwrap();
        let (info_a, info_b) = (
            a.certification_request_info.raw,
            b.certification_request_info.raw,
        );
        assert_eq!(info_a.len(), info_b.len(), "same shape, different key");
        let mut swapped = der.as_ref().to_vec();
        let at = swapped
            .windows(info_a.len())
            .position(|w| w == info_a)
            .unwrap();
        swapped[at..at + info_b.len()].copy_from_slice(info_b);
        let e = verify_csr_der_p256(&swapped).unwrap_err().to_string();
        assert!(e.contains("does not verify"), "{e}");
    }

    #[test]
    fn malformed_csr_pem_is_refused() {
        let (_, csr) = csr_for(&rcgen::PKCS_ECDSA_P256_SHA256);
        let (bundle, _) = ca();
        let two = format!("{csr}{csr}");
        let junk = pem_block("CERTIFICATE REQUEST", &[0x30, 0x03, 1, 2, 3]);
        for (input, want) in [
            ("", "no CERTIFICATE REQUEST"),
            ("not pem at all", "no CERTIFICATE REQUEST"),
            (bundle.cert_pem.as_str(), "no CERTIFICATE REQUEST"),
            (two.as_str(), "more than one"),
            (junk.as_str(), "not a certificate request"),
        ] {
            let e = verify_csr_p256(input).unwrap_err().to_string();
            assert!(e.contains(want), "{input:?}: {e}");
        }
        // trailing bytes after the DER
        let mut der = CertificateSigningRequestDer::from_pem_slice(csr.as_bytes())
            .unwrap()
            .as_ref()
            .to_vec();
        der.push(0);
        let e = verify_csr_der_p256(&der).unwrap_err().to_string();
        assert!(e.contains("trailing"), "{e}");
        // the original still passes
        verify_csr_p256(&csr).unwrap();
    }

    #[test]
    fn workload_leaf_refuses_bad_names_and_lifetimes() {
        let (_, ca) = ca();
        let (_, csr) = csr_for(&rcgen::PKCS_ECDSA_P256_SHA256);
        let key = verify_csr_p256(&csr).unwrap();
        let long = "x".repeat(64);
        for (ns, svc) in [
            ("", "orders"),
            ("shop", ""),
            ("Shop", "orders"),
            ("shop", "orders/../x"),
            ("shop", "-orders"),
            ("shop", "orders-"),
            ("a.b", "orders"),
            ("shop", long.as_str()),
        ] {
            let e = issue_workload_leaf(&ca, &key, ns, svc, HOUR).unwrap_err();
            assert!(e.to_string().contains("DNS-1123 label"), "{ns}/{svc}: {e}");
        }
        let e = issue_workload_leaf(&ca, &key, "shop", "orders", StdDuration::ZERO).unwrap_err();
        assert!(e.to_string().contains("lifetime is zero"), "{e}");
    }

    #[test]
    fn leaves_never_outlive_the_ca() {
        // a CA that expires in one hour
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "short CA");
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.not_before = OffsetDateTime::now_utc() - ::time::Duration::minutes(5);
        params.not_after = OffsetDateTime::now_utc() + ::time::Duration::hours(1);
        let cert = params.self_signed(&key).unwrap();
        let ca = CaKeyPair::from_pems(&cert.pem(), &key.serialize_pem()).unwrap();
        let (_, csr) = csr_for(&rcgen::PKCS_ECDSA_P256_SHA256);
        let csr = verify_csr_p256(&csr).unwrap();
        let leaf = issue_workload_leaf(&ca, &csr, "a", "b", 24 * HOUR).unwrap();
        assert!(leaf.not_after <= ca.not_after());
        assert!(secs_between(SystemTime::now(), leaf.not_after) <= 3600);
        let control_plane = "spiffe://agentsc/control-plane";
        let server = issue_server_leaf(&ca, &[], control_plane, 720 * HOUR).unwrap();
        assert!(server.not_after <= ca.not_after());

        // an expired CA signs nothing
        params.not_before = OffsetDateTime::now_utc() - ::time::Duration::hours(2);
        params.not_after = OffsetDateTime::now_utc() - ::time::Duration::hours(1);
        let cert = params.self_signed(&key).unwrap();
        let expired = CaKeyPair::from_pems(&cert.pem(), &key.serialize_pem()).unwrap();
        let e = issue_server_leaf(&expired, &[], control_plane, HOUR).unwrap_err();
        assert!(e.to_string().contains("expired"), "{e}");
        let e = issue_workload_leaf(&expired, &csr, "a", "b", HOUR).unwrap_err();
        assert!(e.to_string().contains("expired"), "{e}");
    }

    #[test]
    fn server_leaf_is_server_auth_only() {
        let (bundle, ca) = ca();
        let control_plane = "spiffe://agentsc/control-plane";
        let dns = vec![
            "embassy.agentsc-system.svc".to_string(),
            "localhost".to_string(),
        ];
        let leaf = issue_server_leaf(&ca, &dns, control_plane, 720 * HOUR).unwrap();
        let der = der_of(&leaf.cert_pem);
        assert_signed_by(&der, &der_of(&bundle.cert_pem));
        assert_eq!(eku(&der), (true, false));
        assert_eq!(uri_sans_of(&der).unwrap(), [control_plane]);
        assert_eq!(crate::dns_names_of(&der).unwrap(), dns);
        // not a workload identity
        assert_eq!(sole_spiffe_id_of(&der).unwrap(), None);
        // the key is the certificate's
        let key = KeyPair::from_pem(&leaf.key_pem).unwrap();
        let (_, cert) = parse_x509_certificate(&der).unwrap();
        assert_eq!(
            cert.public_key().raw,
            key.subject_public_key_info().as_slice()
        );
        assert!(!format!("{leaf:?}").contains("PRIVATE"));
        // two leaves get two keys
        let again = issue_server_leaf(&ca, &dns, control_plane, HOUR).unwrap();
        assert_ne!(again.key_pem, leaf.key_pem);
        // no DNS names is fine (sidecars check the URI SAN); bad input is not
        issue_server_leaf(&ca, &[], control_plane, HOUR).unwrap();
        assert!(issue_server_leaf(&ca, &[], "", HOUR).is_err());
        assert!(issue_server_leaf(&ca, &[String::new()], control_plane, HOUR).is_err());
        assert!(issue_server_leaf(&ca, &["é.example".into()], control_plane, HOUR).is_err());
        assert!(issue_server_leaf(&ca, &dns, control_plane, StdDuration::ZERO).is_err());
    }

    #[test]
    fn the_signer_is_the_first_ca_certificate_matching_the_key() {
        let old = ca_init().unwrap();
        let new = ca_init().unwrap();
        // a rotation bundle: the old root first, then the new one; a stray key block is skipped
        let roots = format!("{}{}{}", old.cert_pem, new.key_pem, new.cert_pem);
        let certs = certs_from_pem(&roots).unwrap();
        assert_eq!(certs.len(), 2);
        let clean = certs_to_pem(&certs);
        assert!(!clean.contains("PRIVATE KEY"));
        assert_eq!(certs_from_pem(&clean).unwrap(), certs);

        let signer = CaKeyPair::from_pems(&roots, &new.key_pem).unwrap();
        assert_eq!(signer.cert_der(), &der_of(&new.cert_pem));
        assert_eq!(der_of(signer.cert_pem()), der_of(&new.cert_pem));
        assert!(!format!("{signer:?}").contains("PRIVATE"));
        let (_, csr) = csr_for(&rcgen::PKCS_ECDSA_P256_SHA256);
        let csr = verify_csr_p256(&csr).unwrap();
        let leaf = issue_workload_leaf(&signer, &csr, "a", "b", HOUR).unwrap();
        assert_signed_by(&leaf.cert_der, &der_of(&new.cert_pem));

        // the old key picks the old root
        let signer = CaKeyPair::from_pems(&roots, &old.key_pem).unwrap();
        assert_eq!(signer.cert_der(), &der_of(&old.cert_pem));

        // a key no root matches
        let stranger = ca_init().unwrap();
        let e = CaKeyPair::from_pems(&roots, &stranger.key_pem).unwrap_err();
        assert!(
            e.to_string().contains("none of the 2 certificate(s)"),
            "{e}"
        );

        // a matching certificate that is not a CA cannot sign
        let leaf = crate::issue_leaf(&old, "a", "b", 1).unwrap();
        let e = CaKeyPair::from_pems(&leaf.cert_pem, &leaf.key_pem).unwrap_err();
        assert!(e.to_string().contains("none of the 1"), "{e}");

        // no certificates, a bad key, a corrupt certificate
        assert!(CaKeyPair::from_pems("", &new.key_pem).is_err());
        assert!(CaKeyPair::from_pems(&new.cert_pem, "nope").is_err());
        let corrupt = pem_block("CERTIFICATE", &[0x30, 0x01, 0x00]);
        let e = certs_from_pem(&corrupt).unwrap_err().to_string();
        assert!(e.contains("certificate 1"), "{e}");
        let e = certs_from_pem(&new.key_pem).unwrap_err().to_string();
        assert!(e.contains("no CERTIFICATE block"), "{e}");
    }

    #[test]
    fn pem_blocks_are_rfc7468() {
        let der: Vec<u8> = (0..=255u8).collect();
        let text = pem_block("CERTIFICATE", &der);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.first(), Some(&"-----BEGIN CERTIFICATE-----"));
        assert_eq!(lines.last(), Some(&"-----END CERTIFICATE-----"));
        assert!(text.ends_with("-----\n") && !text.contains('\r'));
        assert!(lines.iter().all(|l| l.len() <= 64));
        // 256 bytes are 344 base64 characters: five full lines and one of 24
        assert_eq!(lines.len(), 2 + 6);
        assert_eq!(lines[6].len(), 24);
        let back = CertificateDer::from_pem_slice(text.as_bytes()).unwrap();
        assert_eq!(back.as_ref(), der.as_slice());
        assert_eq!(pem_block("X", &[]), "-----BEGIN X-----\n-----END X-----\n");
    }

    #[test]
    fn sole_spiffe_id_needs_exactly_one_uri() {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = vec![
            SanType::URI(Ia5String::try_from("spiffe://agentsc/ns/a/svc/b").unwrap()),
            SanType::URI(Ia5String::try_from("spiffe://agentsc/ns/kube-system/svc/x").unwrap()),
        ];
        let two = params.self_signed(&key).unwrap();
        assert_eq!(sole_spiffe_id_of(two.der()).unwrap(), None);
        // the lenient v0.1 parser takes the first
        assert!(crate::spiffe_id_of(two.der()).unwrap().is_some());

        params.subject_alt_names.truncate(1);
        let one = params.self_signed(&key).unwrap();
        let id = sole_spiffe_id_of(one.der()).unwrap().unwrap();
        assert_eq!(id.uri(), "spiffe://agentsc/ns/a/svc/b");

        params.subject_alt_names = vec![SanType::DnsName(Ia5String::try_from("b.a").unwrap())];
        let none = params.self_signed(&key).unwrap();
        assert_eq!(sole_spiffe_id_of(none.der()).unwrap(), None);
        assert!(sole_spiffe_id_of(&[0x30, 0x00]).is_err());
    }
}
