//! rustls for the mesh and the control plane (CONTRACT.md §5, design §6.3).
//!
//! The workload certificate lives in an [`ArcSwapOption<WorkloadTls>`]: the mesh server and the
//! mesh and control-plane clients get it through rustls `ResolvesServerCert` /
//! `ResolvesClientCert`, so a renewal takes effect without a restart. The control plane (and its
//! CA) is verified against the trust roots and its URI SAN `spiffe://attache/control-plane`, never
//! by DNS name.
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use arc_swap::ArcSwapOption;
use attache_pki::TlsMaterial;
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ResolvesClientCert, WebPkiServerVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ParsedCertificate, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, RootCertStore, ServerConfig,
    SignatureScheme,
};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use tokio::net::TcpStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

/// The URI SAN of the control plane's serving certificate (design §7).
pub const CONTROL_PLANE_URI: &str = "spiffe://attache/control-plane";

pub type TlsCell = Arc<ArcSwapOption<WorkloadTls>>;

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The workload's certificate, key and trust roots, parsed once.
pub struct WorkloadTls {
    pub material: TlsMaterial,
    pub certified: Arc<CertifiedKey>,
    pub roots: Arc<RootCertStore>,
    client_verifier: Arc<dyn ClientCertVerifier>,
    /// Validity of the leaf, Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
    /// SHA-256 of the leaf's DER.
    pub cert_sha256: String,
}

impl std::fmt::Debug for WorkloadTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkloadTls")
            .field("identity", &self.material.identity.uri())
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .finish()
    }
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A root store from a PEM bundle (several roots allowed); an error when it holds none.
pub fn roots_from_pem(pem: &str) -> anyhow::Result<RootCertStore> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<_, _>>()
        .context("parse CA PEM")?;
    let mut roots = RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(certs);
    anyhow::ensure!(added > 0, "no usable CA certificate in the PEM");
    Ok(roots)
}

/// `(not_before, not_after)` of a DER certificate, Unix seconds.
pub fn validity(der: &[u8]) -> anyhow::Result<(i64, i64)> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| anyhow::anyhow!("parse certificate: {e}"))?;
    let v = cert.validity();
    Ok((v.not_before.timestamp(), v.not_after.timestamp()))
}

/// The URI SANs of a DER certificate.
pub fn uri_sans(der: &[u8]) -> Vec<String> {
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) else {
        return Vec::new();
    };
    let Ok(Some(san)) = cert.subject_alternative_name() else {
        return Vec::new();
    };
    san.value
        .general_names
        .iter()
        .filter_map(|g| match g {
            x509_parser::extensions::GeneralName::URI(u) => Some(u.to_string()),
            _ => None,
        })
        .collect()
}

impl WorkloadTls {
    pub fn from_material(material: TlsMaterial) -> anyhow::Result<Self> {
        let provider = provider();
        let chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(material.cert_pem.as_bytes())
                .collect::<Result<_, _>>()
                .context("parse tls.crt")?;
        let leaf = chain
            .first()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("tls.crt holds no certificate"))?;
        let key =
            PrivateKeyDer::from_pem_slice(material.key_pem.as_bytes()).context("parse tls.key")?;
        let certified = CertifiedKey::from_der(chain, key, &provider)
            .context("tls.key does not match tls.crt")?;
        let roots = Arc::new(roots_from_pem(&material.ca_pem).context("ca.crt")?);
        let client_verifier = WebPkiClientVerifier::builder_with_provider(roots.clone(), provider)
            .build()
            .context("client verifier")?;
        let (not_before, not_after) = validity(&leaf)?;
        Ok(Self {
            cert_sha256: attache_common::audit::sha256_hex(&leaf),
            material,
            certified: Arc::new(certified),
            roots,
            client_verifier,
            not_before,
            not_after,
        })
    }

    pub fn from_pems(ca_pem: &str, cert_pem: &str, key_pem: &str) -> anyhow::Result<Self> {
        let material = TlsMaterial::from_pems(
            ca_pem.to_string(),
            cert_pem.to_string(),
            key_pem.to_string(),
        )
        .context("load TLS material")?;
        Self::from_material(material)
    }

    /// Seconds until the leaf expires (negative once expired).
    pub fn expires_in_s(&self) -> i64 {
        self.not_after - now_unix()
    }

    pub fn expired(&self) -> bool {
        self.expires_in_s() <= 0
    }

    /// When to renew: two thirds into the lifetime (design §6.3).
    pub fn renew_at(&self) -> SystemTime {
        let life = (self.not_after - self.not_before).max(0);
        let at = self.not_before + life * 2 / 3;
        UNIX_EPOCH + Duration::from_secs(at.max(0) as u64)
    }
}

/// The current workload certificate, for the mesh server and every client that presents it.
#[derive(Debug, Clone)]
pub struct CurrentCert(pub TlsCell);

impl ResolvesServerCert for CurrentCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.load().as_ref().map(|t| t.certified.clone())
    }
}

impl ResolvesClientCert for CurrentCert {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.0.load().as_ref().map(|t| t.certified.clone())
    }

    fn has_certs(&self) -> bool {
        self.0.load().is_some()
    }
}

/// Mesh clients must chain to the current trust roots (which a renewal may replace).
#[derive(Debug)]
struct CurrentClientVerifier {
    tls: TlsCell,
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for CurrentClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let current = self.tls.load();
        let Some(tls) = current.as_ref() else {
            return Err(rustls::Error::General("no workload certificate yet".into()));
        };
        tls.client_verifier
            .verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The mesh server: the current certificate, client certificates required and chained to the
/// current trust roots.
pub fn mesh_server_config(tls: &TlsCell) -> anyhow::Result<Arc<ServerConfig>> {
    let provider = provider();
    let verifier = Arc::new(CurrentClientVerifier {
        tls: tls.clone(),
        provider: provider.clone(),
    });
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(CurrentCert(tls.clone())));
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(cfg))
}

/// A mesh client: verifies the peer against `roots` by DNS name and presents the current
/// certificate.
pub fn mesh_client_config(
    roots: Arc<RootCertStore>,
    cert: Arc<dyn ResolvesClientCert>,
) -> anyhow::Result<Arc<ClientConfig>> {
    let provider = provider();
    let verifier = WebPkiServerVerifier::builder_with_provider(roots, provider.clone()).build()?;
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_webpki_verifier(verifier)
        .with_client_cert_resolver(cert);
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(cfg))
}

/// Verifies a server certificate chains to `roots` and carries the URI SAN `uri` (DNS names are
/// not looked at).
#[derive(Debug)]
pub struct UriSanVerifier {
    roots: Arc<RootCertStore>,
    uri: String,
    provider: Arc<CryptoProvider>,
}

impl UriSanVerifier {
    pub fn new(roots: Arc<RootCertStore>, uri: &str) -> Self {
        Self {
            roots,
            uri: uri.to_string(),
            provider: provider(),
        }
    }
}

impl ServerCertVerifier for UriSanVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            self.provider.signature_verification_algorithms.all,
        )?;
        if uri_sans(end_entity).iter().any(|u| u == &self.uri) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A client for the control plane or its CA: the server must chain to `roots` and carry
/// [`CONTROL_PLANE_URI`]; `cert` (the workload certificate) is presented when given.
pub fn control_plane_client_config(
    roots: Arc<RootCertStore>,
    cert: Option<Arc<dyn ResolvesClientCert>>,
) -> anyhow::Result<Arc<ClientConfig>> {
    let provider = provider();
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(UriSanVerifier::new(roots, CONTROL_PLANE_URI)));
    let mut cfg = match cert {
        Some(c) => builder.with_client_cert_resolver(c),
        None => builder.with_no_client_auth(),
    };
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(cfg))
}

/// The host of a `host:port` address, as a TLS server name.
pub fn server_name_of(addr: &str) -> anyhow::Result<ServerName<'static>> {
    let host = match addr.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => h,
        _ => addr,
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    ServerName::try_from(host.to_string()).map_err(|e| anyhow::anyhow!("server name {host:?}: {e}"))
}

/// A lazily connected gRPC channel to `addr` over TLS with `cfg`, checked as `server_name`.
pub fn tls_channel(
    addr: &str,
    server_name: ServerName<'static>,
    cfg: Arc<ClientConfig>,
    timeout: Option<Duration>,
) -> anyhow::Result<Channel> {
    let connector = tokio_rustls::TlsConnector::from(cfg);
    let target = addr.to_string();
    // HTTP/2 pings notice a peer that vanished without closing the connection.
    let mut endpoint = Endpoint::from_shared(format!("http://{addr}"))?
        .connect_timeout(Duration::from_secs(5))
        .http2_keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(20));
    if let Some(t) = timeout {
        endpoint = endpoint.timeout(t);
    }
    Ok(
        endpoint.connect_with_connector_lazy(service_fn(move |_: Uri| {
            let connector = connector.clone();
            let target = target.clone();
            let name = server_name.clone();
            async move {
                let tcp = TcpStream::connect(&target).await?;
                let tls = connector.connect(name, tcp).await?;
                Ok::<_, std::io::Error>(TokioIo::new(tls))
            }
        })),
    )
}

/// A mesh channel with fixed material: verifies the peer against `tls.ca_pem` with
/// `server_name` and presents `tls`'s certificate. Kept for tools and tests; the sidecar itself
/// uses [`mesh_client_config`] with the current certificate.
pub fn client_channel(tls: &TlsMaterial, addr: &str, server_name: &str) -> anyhow::Result<Channel> {
    let workload = Arc::new(WorkloadTls::from_pems(
        &tls.ca_pem,
        &tls.cert_pem,
        &tls.key_pem,
    )?);
    let roots = workload.roots.clone();
    let cell: TlsCell = Arc::new(ArcSwapOption::from(Some(workload)));
    let cfg = mesh_client_config(roots, Arc::new(CurrentCert(cell)))?;
    tls_channel(
        addr,
        ServerName::try_from(server_name.to_string())?,
        cfg,
        Some(crate::deadline::RUN_TIMEOUT),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workload_material_parses_and_renews_at_two_thirds() {
        let ca = attache_pki::ca_init().unwrap();
        let leaf = attache_pki::issue_leaf(&ca, "shop", "orders", 3).unwrap();
        let t = WorkloadTls::from_pems(&ca.cert_pem, &leaf.cert_pem, &leaf.key_pem).unwrap();
        assert_eq!(
            t.material.identity.uri(),
            "spiffe://attache/ns/shop/svc/orders"
        );
        assert!(t.expires_in_s() > 2 * 86400 && t.expires_in_s() <= 3 * 86400);
        let renew = t.renew_at().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        assert_eq!(renew, t.not_before + (t.not_after - t.not_before) * 2 / 3);
        assert!(!t.expired());
        // a key that does not match the certificate is refused
        let other = attache_pki::issue_leaf(&ca, "shop", "orders", 3).unwrap();
        assert!(WorkloadTls::from_pems(&ca.cert_pem, &leaf.cert_pem, &other.key_pem).is_err());
    }

    /// A server certificate signed by `ca` whose only SAN is the URI `uri`.
    fn served_by(ca: &attache_pki::PemBundle, uri: &str) -> CertificateDer<'static> {
        let issuer = rcgen::Issuer::from_ca_cert_pem(
            &ca.cert_pem,
            rcgen::KeyPair::from_pem(&ca.key_pem).unwrap(),
        )
        .unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names.push(rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(uri).unwrap(),
        ));
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        params.signed_by(&key, &issuer).unwrap().der().clone()
    }

    #[test]
    fn the_control_plane_is_checked_by_its_uri_san_not_its_name() {
        let ca = attache_pki::ca_init().unwrap();
        let roots = Arc::new(roots_from_pem(&ca.cert_pem).unwrap());
        let v = UriSanVerifier::new(roots, CONTROL_PLANE_URI);
        let any_name = ServerName::try_from("whatever.example").unwrap();
        let check = |der: &CertificateDer<'_>| {
            v.verify_server_cert(der, &[], &any_name, &[], UnixTime::now())
        };
        assert!(check(&served_by(&ca, CONTROL_PLANE_URI)).is_ok());
        // a workload certificate from the same CA is not the control plane
        let workload = served_by(&ca, "spiffe://attache/ns/shop/svc/embassy");
        assert!(matches!(
            check(&workload),
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName
            ))
        ));
        // the right URI from another CA does not chain to the trust roots
        let other = attache_pki::ca_init().unwrap();
        assert!(check(&served_by(&other, CONTROL_PLANE_URI)).is_err());
    }

    #[test]
    fn server_names_from_addresses() {
        assert!(matches!(
            server_name_of("embassy.attache-system.svc:15012").unwrap(),
            ServerName::DnsName(_)
        ));
        assert!(matches!(
            server_name_of("127.0.0.1:15012").unwrap(),
            ServerName::IpAddress(_)
        ));
        assert!(matches!(
            server_name_of("[::1]:15012").unwrap(),
            ServerName::IpAddress(_)
        ));
    }
}
