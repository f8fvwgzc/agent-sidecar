//! The control-plane serving certificate (docs/design/agent-platform.md §7).
//!
//! One certificate serves `Connect` and `IssueCertificate` (`--grpc-addr`), the admission
//! webhooks (`--webhook-addr`) and, with `--http-tls`, the REST API: URI SAN
//! [`CONTROL_PLANE_SPIFFE_ID`] (sidecars verify that, not a DNS name), DNS SANs from
//! `--dns-name`, EKU serverAuth only, a 30-day lifetime, renewed at two thirds.
//!
//! [`ServingCertSource`] holds the current certificate and its CA bundle and hands out rustls
//! server configurations whose certificate resolver and client-certificate verifier read the
//! current material on every handshake, so a renewal (or a new CA bundle) applies to existing
//! listeners without a restart. Sources:
//!
//! - [`ServingCertSource::in_memory`]: issued here from the CA (one-process mode, and the `ca`
//!   component), renewed in the background at two thirds of its lifetime;
//! - [`ServingCertSource::from_dir`]: `tls.crt`, `tls.key`, `ca.crt` from `--tls-dir` (the
//!   mounted `embassy-tls` Secret), polled every 10 s and reloaded when they change; a changed
//!   set that does not load (a key that does not fit, say) is logged and the current one kept;
//! - [`ServingCertSource::from_pems`] plus [`ServingCertSource::replace`]: material managed by
//!   the caller (the Kubernetes `--tls-secret` writer).
//!
//! [`ServingCertSource::subscribe`] reports every change (to write `embassy-tls` or re-patch a
//! webhook `caBundle`).
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime};

use anyhow::{Context, anyhow, bail};
use arc_swap::ArcSwap;
use attache_common::identity::SpiffeId;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::CryptoProvider;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{
    ConfigBuilder, DigitallySignedStruct, DistinguishedName, RootCertStore, ServerConfig,
    SignatureScheme, WantsVerifier,
};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use tokio::sync::watch;

use crate::ca::CaMaterial;

/// The URI SAN of the control-plane serving certificate; sidecars check it (design §6.3).
pub const CONTROL_PLANE_SPIFFE_ID: &str = "spiffe://attache/control-plane";
/// Lifetime of an in-memory serving certificate (design §7).
pub const SERVING_CERT_TTL: Duration = Duration::from_secs(30 * 24 * 3600);
/// How often [`ServingCertSource::from_dir`] looks at the files.
pub const DIR_POLL_INTERVAL: Duration = Duration::from_secs(10);
/// How long a failed in-memory renewal waits before the next attempt (at most a third of the
/// lifetime).
pub const RENEW_RETRY_INTERVAL: Duration = Duration::from_secs(60);
/// The shortest lifetime [`ServingCertSource::in_memory_with_ttl`] accepts (renewal after two
/// seconds, retries every second).
pub const MIN_IN_MEMORY_TTL: Duration = Duration::from_secs(3);
/// ALPN protocols of every configuration [`ServingCertSource::rustls_server_config`] returns
/// (gRPC needs `h2`; the API and webhooks also speak HTTP/1.1).
pub const ALPN: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// One serving certificate as PEM: what `embassy-tls` holds.
#[derive(Clone, PartialEq, Eq)]
pub struct ServingCert {
    /// The certificate chain, leaf first (`tls.crt`).
    pub cert_pem: String,
    /// The private key (`tls.key`).
    pub key_pem: String,
    /// The CA bundle (`ca.crt`): the roots that client certificates must chain to, and what
    /// sidecars trust.
    pub ca_pem: String,
    /// When the leaf expires.
    pub not_after: SystemTime,
}

impl fmt::Debug for ServingCert {
    /// Never prints the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServingCert")
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

/// Whether a listener asks for client certificates (always verified against the current CA
/// bundle when presented).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientAuth {
    /// No client certificate is requested (the HTTP API, the webhooks).
    None,
    /// Requested, verified when presented, not required (`IssueCertificate`).
    Optional,
    /// Required and verified (`Connect`).
    Required,
}

/// A validated certificate, key and CA bundle, and what rustls needs from them.
struct Loaded {
    pem: Arc<ServingCert>,
    certified: Arc<CertifiedKey>,
    /// Requires a client certificate chaining to `pem.ca_pem` with EKU clientAuth.
    client_verifier: Arc<dyn ClientCertVerifier>,
}

/// What the resolver, the verifier and the background task share.
struct Shared {
    provider: Arc<CryptoProvider>,
    current: ArcSwap<Loaded>,
    changes: watch::Sender<Arc<ServingCert>>,
}

impl fmt::Debug for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shared")
            .field("current", &self.current.load().pem)
            .finish_non_exhaustive()
    }
}

impl Shared {
    /// Make `loaded` the current material and tell subscribers.
    fn install(&self, loaded: Loaded) {
        let pem = loaded.pem.clone();
        self.current.store(Arc::new(loaded));
        self.changes.send_replace(pem);
    }
}

/// Parse and check one set: a chain whose leaf fits the key, and at least one CA root.
fn load(
    provider: &Arc<CryptoProvider>,
    cert_pem: &str,
    key_pem: &str,
    ca_pem: &str,
) -> anyhow::Result<Loaded> {
    let chain = attache_pki::certs_from_pem(cert_pem).context("the serving certificate")?;
    let leaf = chain
        .first()
        .ok_or_else(|| anyhow!("the serving certificate is empty"))?;
    let not_after = attache_pki::not_after_of(leaf).context("the serving certificate")?;
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|e| anyhow!("the serving key: {e}"))?;
    let certified = CertifiedKey::from_der(chain.clone(), key, provider)
        .context("the serving key does not fit the serving certificate")?;

    let roots_der = attache_pki::certs_from_pem(ca_pem).context("the CA bundle")?;
    let ca_pem = attache_pki::certs_to_pem(&roots_der);
    let mut roots = RootCertStore::empty();
    for (i, root) in roots_der.into_iter().enumerate() {
        roots
            .add(root)
            .with_context(|| format!("CA bundle certificate {}", i + 1))?;
    }
    let client_verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .context("the client-certificate verifier")?;
    Ok(Loaded {
        pem: Arc::new(ServingCert {
            cert_pem: attache_pki::certs_to_pem(&chain),
            key_pem: key_pem.to_string(),
            ca_pem,
            not_after,
        }),
        certified: Arc::new(certified),
        client_verifier,
    })
}

/// A new serving certificate from the CA.
fn issue(ca: &CaMaterial, dns_names: &[String], ttl: Duration) -> anyhow::Result<ServingCert> {
    let leaf = ca.sign_server(dns_names, CONTROL_PLANE_SPIFFE_ID, ttl)?;
    Ok(ServingCert {
        cert_pem: leaf.cert_pem,
        key_pem: leaf.key_pem,
        ca_pem: ca.roots_pem().to_string(),
        not_after: leaf.not_after,
    })
}

/// The current serving certificate; see the module docs.
pub struct ServingCertSource {
    shared: Arc<Shared>,
    /// Provider and protocol versions, checked once at construction.
    builder: ConfigBuilder<ServerConfig, WantsVerifier>,
    /// Where the material comes from, for `Debug`.
    origin: String,
    /// The renewal or polling task; aborted when the source is dropped.
    task: Option<tokio::task::AbortHandle>,
}

impl fmt::Debug for ServingCertSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServingCertSource")
            .field("origin", &self.origin)
            .field("current", &self.shared.current.load().pem)
            .finish_non_exhaustive()
    }
}

impl Drop for ServingCertSource {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

impl ServingCertSource {
    fn build(
        loaded: Loaded,
        provider: Arc<CryptoProvider>,
        origin: String,
    ) -> anyhow::Result<Self> {
        let builder = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .context("TLS protocol versions")?;
        let (changes, _) = watch::channel(loaded.pem.clone());
        Ok(Self {
            shared: Arc::new(Shared {
                provider,
                current: ArcSwap::from_pointee(loaded),
                changes,
            }),
            builder,
            origin,
            task: None,
        })
    }

    fn provider() -> Arc<CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    fn runtime(what: &str) -> anyhow::Result<tokio::runtime::Handle> {
        tokio::runtime::Handle::try_current().map_err(|_| {
            anyhow!("ServingCertSource::{what} needs a tokio runtime (it works in the background)")
        })
    }

    /// Fixed material (`tls.crt` chain, `tls.key`, `ca.crt` text); changes only through
    /// [`Self::replace`]. Needs no runtime.
    pub fn from_pems(cert_pem: &str, key_pem: &str, ca_pem: &str) -> anyhow::Result<Self> {
        let provider = Self::provider();
        let loaded = load(&provider, cert_pem, key_pem, ca_pem)?;
        Self::build(loaded, provider, "fixed material".into())
    }

    /// A certificate issued here by `ca` (URI SAN [`CONTROL_PLANE_SPIFFE_ID`], DNS SANs
    /// `dns_names`, EKU serverAuth, [`SERVING_CERT_TTL`]) and renewed in the background at two
    /// thirds of its lifetime (a failed renewal is retried every [`RENEW_RETRY_INTERVAL`]).
    /// Must be called inside a tokio runtime.
    pub fn in_memory(ca: Arc<CaMaterial>, dns_names: Vec<String>) -> anyhow::Result<Self> {
        Self::in_memory_with_ttl(ca, dns_names, SERVING_CERT_TTL)
    }

    /// [`Self::in_memory`] with another lifetime, at least [`MIN_IN_MEMORY_TTL`] (tests,
    /// short-lived deployments).
    pub fn in_memory_with_ttl(
        ca: Arc<CaMaterial>,
        dns_names: Vec<String>,
        ttl: Duration,
    ) -> anyhow::Result<Self> {
        if ttl < MIN_IN_MEMORY_TTL {
            bail!("the serving certificate lifetime {ttl:?} is shorter than {MIN_IN_MEMORY_TTL:?}");
        }
        let runtime = Self::runtime("in_memory")?;
        let provider = Self::provider();
        let first = issue(&ca, &dns_names, ttl)?;
        let loaded = load(&provider, &first.cert_pem, &first.key_pem, &first.ca_pem)?;
        let origin = format!("in memory, DNS names {dns_names:?}");
        let mut source = Self::build(loaded, provider, origin)?;
        let shared = Arc::downgrade(&source.shared);
        let task = runtime.spawn(renew(shared, ca, dns_names, ttl));
        source.task = Some(task.abort_handle());
        Ok(source)
    }

    /// `tls.crt`, `tls.key` and `ca.crt` in `dir` (`--tls-dir`), polled every
    /// [`DIR_POLL_INTERVAL`] and reloaded when their content changes. Must be called inside a
    /// tokio runtime.
    pub fn from_dir(dir: impl Into<PathBuf>) -> anyhow::Result<Self> {
        Self::from_dir_polling(dir, DIR_POLL_INTERVAL)
    }

    /// [`Self::from_dir`] with another polling interval (at least 10 ms).
    pub fn from_dir_polling(dir: impl Into<PathBuf>, every: Duration) -> anyhow::Result<Self> {
        let every = every.max(Duration::from_millis(10));
        let dir = dir.into();
        let runtime = Self::runtime("from_dir")?;
        let files = DirFiles::read(&dir)?;
        let provider = Self::provider();
        let loaded = load(&provider, &files.cert, &files.key, &files.ca)
            .with_context(|| format!("the serving certificate in {}", dir.display()))?;
        let mut source = Self::build(loaded, provider, format!("directory {}", dir.display()))?;
        let shared = Arc::downgrade(&source.shared);
        let task = runtime.spawn(poll_dir(shared, dir, every, files));
        source.task = Some(task.abort_handle());
        Ok(source)
    }

    /// The current certificate, key and CA bundle.
    pub fn current(&self) -> Arc<ServingCert> {
        self.shared.current.load().pem.clone()
    }

    /// Every change from now on (renewal, reload, [`Self::replace`]); the receiver starts at
    /// the current certificate.
    pub fn subscribe(&self) -> watch::Receiver<Arc<ServingCert>> {
        self.shared.changes.subscribe()
    }

    /// Validate and install new material; on error the current material stays.
    pub fn replace(&self, cert_pem: &str, key_pem: &str, ca_pem: &str) -> anyhow::Result<()> {
        let loaded = load(&self.shared.provider, cert_pem, key_pem, ca_pem)?;
        self.shared.install(loaded);
        Ok(())
    }

    /// A rustls server configuration that always presents the current certificate and, for
    /// [`ClientAuth::Optional`] and [`ClientAuth::Required`], verifies client certificates
    /// against the current CA bundle (chain and EKU clientAuth). Renewals and CA changes apply
    /// to configurations made earlier. ALPN is [`ALPN`]. No certificate-authority hints are sent
    /// to clients. Use [`peer_identity`] on the verified peer certificates.
    pub fn rustls_server_config(&self, auth: ClientAuth) -> Arc<ServerConfig> {
        let builder = self.builder.clone();
        let builder = match auth {
            ClientAuth::None => builder.with_no_client_auth(),
            ClientAuth::Optional | ClientAuth::Required => {
                builder.with_client_cert_verifier(Arc::new(CurrentCaVerifier {
                    shared: self.shared.clone(),
                    mandatory: auth == ClientAuth::Required,
                }))
            }
        };
        let mut config = builder.with_cert_resolver(Arc::new(CurrentCert(self.shared.clone())));
        config.alpn_protocols = ALPN.iter().map(|p| p.to_vec()).collect();
        Arc::new(config)
    }
}

/// The workload identity (`spiffe://attache/ns/<ns>/svc/<svc>`) of a TLS peer, from the
/// certificates the handshake verified (leaf first): `None` without a certificate, or when the
/// leaf does not carry exactly one URI SAN of that form. Only meaningful for certificates a
/// [`ServingCertSource`] configuration verified.
pub fn peer_identity(certs: &[CertificateDer<'_>]) -> Option<SpiffeId> {
    let leaf = certs.first()?;
    attache_pki::sole_spiffe_id_of(leaf).ok().flatten()
}

/// Serves the current certificate on every handshake.
#[derive(Debug)]
struct CurrentCert(Arc<Shared>);

impl ResolvesServerCert for CurrentCert {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.current.load().certified.clone())
    }
}

/// Verifies client certificates against the current CA bundle.
#[derive(Debug)]
struct CurrentCaVerifier {
    shared: Arc<Shared>,
    mandatory: bool,
}

impl ClientCertVerifier for CurrentCaVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // The bundle can change under a running listener; an empty list asks the client for
        // whatever certificate it has.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.shared
            .current
            .load()
            .client_verifier
            .verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.shared.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.shared.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.shared
            .provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Renew an in-memory certificate at two thirds of its lifetime until the source is dropped.
async fn renew(shared: Weak<Shared>, ca: Arc<CaMaterial>, dns_names: Vec<String>, ttl: Duration) {
    let renew_after = ttl / 3 * 2;
    let retry = RENEW_RETRY_INTERVAL.min(ttl / 3);
    let mut wait = renew_after;
    loop {
        tokio::time::sleep(wait).await;
        let Some(shared) = shared.upgrade() else {
            return;
        };
        let renewed = issue(&ca, &dns_names, ttl)
            .and_then(|c| load(&shared.provider, &c.cert_pem, &c.key_pem, &c.ca_pem));
        match renewed {
            Ok(loaded) => {
                let not_after = chrono::DateTime::<chrono::Utc>::from(loaded.pem.not_after);
                shared.install(loaded);
                tracing::info!(%not_after, "renewed the serving certificate");
                wait = renew_after;
            }
            Err(e) => {
                tracing::warn!(
                    error = format!("{e:#}"),
                    retry_in_s = retry.as_secs_f64(),
                    "renewing the serving certificate failed; the current one stays"
                );
                wait = retry;
            }
        }
    }
}

/// The three files of a serving-certificate directory, as read.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DirFiles {
    cert: String,
    key: String,
    ca: String,
}

impl DirFiles {
    const NAMES: [&'static str; 3] = ["tls.crt", "tls.key", "ca.crt"];

    fn read(dir: &Path) -> anyhow::Result<Self> {
        let [cert, key, ca] = Self::NAMES.map(|name| {
            let path = dir.join(name);
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))
        });
        Ok(Self {
            cert: cert?,
            key: key?,
            ca: ca?,
        })
    }

    async fn read_async(dir: &Path) -> anyhow::Result<Self> {
        let read = |name: &'static str| {
            let path = dir.join(name);
            async move {
                tokio::fs::read_to_string(&path)
                    .await
                    .with_context(|| format!("read {}", path.display()))
            }
        };
        Ok(Self {
            cert: read("tls.crt").await?,
            key: read("tls.key").await?,
            ca: read("ca.crt").await?,
        })
    }
}

/// Reload the directory's files when their content changes, until the source is dropped. A
/// set that does not load is reported once and skipped until the files change again.
async fn poll_dir(shared: Weak<Shared>, dir: PathBuf, every: Duration, mut seen: DirFiles) {
    let mut last_error: Option<String> = None;
    loop {
        tokio::time::sleep(every).await;
        let Some(shared) = shared.upgrade() else {
            return;
        };
        let files = match DirFiles::read_async(&dir).await {
            Ok(files) => files,
            Err(e) => {
                let msg = format!("{e:#}");
                if last_error.as_deref() != Some(msg.as_str()) {
                    tracing::warn!(error = %msg, "reading the serving certificate failed; the current one stays");
                    last_error = Some(msg);
                }
                continue;
            }
        };
        if files == seen {
            continue;
        }
        match load(&shared.provider, &files.cert, &files.key, &files.ca) {
            Ok(loaded) => {
                let not_after = chrono::DateTime::<chrono::Utc>::from(loaded.pem.not_after);
                shared.install(loaded);
                tracing::info!(dir = %dir.display(), %not_after, "reloaded the serving certificate");
                last_error = None;
            }
            Err(e) => {
                let msg = format!("{e:#}");
                tracing::warn!(dir = %dir.display(), error = %msg, "the changed serving certificate does not load; the current one stays");
                last_error = Some(msg);
            }
        }
        seen = files;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{ClientConfig, ClientConnection, ServerConnection};
    use rustls_pki_types::ServerName;

    const HOUR: Duration = Duration::from_secs(3600);

    fn ca() -> Arc<CaMaterial> {
        let ca = attache_pki::ca_init().unwrap();
        Arc::new(CaMaterial::from_pems(&ca.cert_pem, &ca.key_pem).unwrap())
    }

    fn dns() -> Vec<String> {
        vec![
            "embassy.attache-system.svc".to_string(),
            "localhost".to_string(),
        ]
    }

    fn der(pem: &str) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(pem.as_bytes()).unwrap()
    }

    /// A workload certificate and key for `ns/svc` from `ca`.
    fn workload(ca: &CaMaterial, ns: &str, svc: &str) -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::default()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap();
        let public = attache_pki::verify_csr_p256(&csr).unwrap();
        let leaf = ca.sign_workload(&public, ns, svc, HOUR).unwrap();
        (leaf.cert_pem, key.serialize_pem())
    }

    fn client(roots_pem: &str, identity: Option<(&str, &str)>) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        for c in attache_pki::certs_from_pem(roots_pem).unwrap() {
            roots.add(c).unwrap();
        }
        let b = ClientConfig::builder_with_provider(ServingCertSource::provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots);
        Arc::new(match identity {
            Some((cert, key)) => b
                .with_client_auth_cert(
                    attache_pki::certs_from_pem(cert).unwrap(),
                    PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap(),
                )
                .unwrap(),
            None => b.with_no_client_auth(),
        })
    }

    /// Move everything `from` wants to send into `to`.
    fn pump(
        from: &mut rustls::Connection,
        to: &mut rustls::Connection,
        side: &str,
    ) -> Result<(), String> {
        let mut buf = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut buf).map_err(|e| e.to_string())?;
        }
        let mut rd = buf.as_slice();
        while !rd.is_empty() {
            to.read_tls(&mut rd).map_err(|e| e.to_string())?;
            to.process_new_packets()
                .map_err(|e| format!("{side}: {e}"))?;
        }
        Ok(())
    }

    /// A full in-memory handshake to `localhost`; the side that failed prefixes the error.
    fn handshake(
        client: Arc<ClientConfig>,
        server: Arc<ServerConfig>,
    ) -> Result<(ClientConnection, ServerConnection), String> {
        let name = ServerName::try_from("localhost").map_err(|e| e.to_string())?;
        let mut c = rustls::Connection::from(
            ClientConnection::new(client, name).map_err(|e| e.to_string())?,
        );
        let mut s =
            rustls::Connection::from(ServerConnection::new(server).map_err(|e| e.to_string())?);
        for _ in 0..10 {
            pump(&mut c, &mut s, "server")?;
            pump(&mut s, &mut c, "client")?;
            if !c.is_handshaking() && !s.is_handshaking() {
                // TLS 1.3: the server judges the client's certificate after the client is done
                pump(&mut c, &mut s, "server")?;
                return match (c, s) {
                    (rustls::Connection::Client(c), rustls::Connection::Server(s)) => Ok((c, s)),
                    _ => Err("connection kinds changed".into()),
                };
            }
        }
        Err("the handshake did not finish".into())
    }

    fn served_cert(c: &ClientConnection) -> CertificateDer<'static> {
        c.peer_certificates().unwrap()[0].clone().into_owned()
    }

    #[test]
    fn source_is_shareable() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ServingCertSource>();
        assert_send_sync::<ServingCert>();
    }

    #[test]
    fn background_sources_need_a_runtime() {
        let e = ServingCertSource::in_memory(ca(), dns()).unwrap_err();
        assert!(e.to_string().contains("tokio runtime"), "{e}");
        let e = ServingCertSource::from_dir("/nonexistent").unwrap_err();
        assert!(e.to_string().contains("tokio runtime"), "{e}");
    }

    #[tokio::test]
    async fn in_memory_certificate_follows_the_design() {
        let ca = ca();
        let source = ServingCertSource::in_memory(ca.clone(), dns()).unwrap();
        let cur = source.current();
        assert_eq!(cur.ca_pem, ca.roots_pem());
        let leaf = der(&cur.cert_pem);
        assert_eq!(
            attache_pki::uri_sans_of(&leaf).unwrap(),
            [CONTROL_PLANE_SPIFFE_ID]
        );
        assert_eq!(attache_pki::dns_names_of(&leaf).unwrap(), dns());
        assert_eq!(peer_identity(std::slice::from_ref(&leaf)), None);
        let days = cur
            .not_after
            .duration_since(SystemTime::now())
            .unwrap()
            .as_secs()
            / 86400;
        assert!((29..=30).contains(&days), "{days}");
        assert!(!format!("{source:?}").contains("PRIVATE"));
        assert!(!format!("{cur:?}").contains("PRIVATE"));

        // EKU serverAuth only: it cannot be used as a client certificate
        let server = source.rustls_server_config(ClientAuth::Required);
        let as_client = client(&cur.ca_pem, Some((&cur.cert_pem, &cur.key_pem)));
        let e = handshake(as_client, server.clone()).unwrap_err();
        assert!(e.starts_with("server:"), "{e}");

        // a client trusting the CA accepts it for its DNS names
        let (wl_cert, wl_key) = workload(&ca, "shop", "orders");
        let (c, _) = handshake(client(ca.roots_pem(), Some((&wl_cert, &wl_key))), server).unwrap();
        assert_eq!(served_cert(&c), leaf);
        assert_eq!(server_alpn(), ALPN.map(<[u8]>::to_vec));
    }

    fn server_alpn() -> Vec<Vec<u8>> {
        let ca = ca();
        let cur = ca
            .sign_server(&dns(), CONTROL_PLANE_SPIFFE_ID, HOUR)
            .unwrap();
        ServingCertSource::from_pems(&cur.cert_pem, &cur.key_pem, ca.roots_pem())
            .unwrap()
            .rustls_server_config(ClientAuth::None)
            .alpn_protocols
            .clone()
    }

    #[tokio::test]
    async fn client_auth_modes() {
        let ca = ca();
        let source = ServingCertSource::in_memory(ca.clone(), dns()).unwrap();
        let roots = ca.roots_pem();
        let (wl_cert, wl_key) = workload(&ca, "shop", "orders");
        let workload_client = || client(roots, Some((&wl_cert, &wl_key)));
        let anonymous = || client(roots, None);
        let foreign_ca = self::ca();
        let (f_cert, f_key) = workload(&foreign_ca, "shop", "orders");
        let foreign = || client(roots, Some((&f_cert, &f_key)));

        // Required: a workload certificate from the CA, nothing else
        let required = source.rustls_server_config(ClientAuth::Required);
        let (_, s) = handshake(workload_client(), required.clone()).unwrap();
        let id = s.peer_certificates().and_then(peer_identity).unwrap();
        assert_eq!(id.uri(), "spiffe://attache/ns/shop/svc/orders");
        let e = handshake(anonymous(), required.clone()).unwrap_err();
        assert!(e.starts_with("server:"), "{e}");
        let e = handshake(foreign(), required).unwrap_err();
        assert!(e.starts_with("server:"), "{e}");

        // Optional: anonymous is fine, a presented certificate must still verify
        let optional = source.rustls_server_config(ClientAuth::Optional);
        let (_, s) = handshake(anonymous(), optional.clone()).unwrap();
        assert!(s.peer_certificates().is_none());
        let (_, s) = handshake(workload_client(), optional.clone()).unwrap();
        let id = s.peer_certificates().and_then(peer_identity).unwrap();
        assert_eq!(
            (id.namespace.as_str(), id.service.as_str()),
            ("shop", "orders")
        );
        let e = handshake(foreign(), optional).unwrap_err();
        assert!(e.starts_with("server:"), "{e}");

        // None: no certificate is asked for
        let none = source.rustls_server_config(ClientAuth::None);
        let (_, s) = handshake(workload_client(), none.clone()).unwrap();
        assert!(s.peer_certificates().is_none());
        handshake(foreign(), none).unwrap();
    }

    #[tokio::test]
    async fn renewal_applies_to_existing_configurations() {
        let ca = ca();
        let source =
            ServingCertSource::in_memory_with_ttl(ca.clone(), dns(), Duration::from_secs(3))
                .unwrap();
        let config = source.rustls_server_config(ClientAuth::Optional);
        let first = source.current();
        let (c, _) = handshake(client(ca.roots_pem(), None), config.clone()).unwrap();
        assert_eq!(served_cert(&c), der(&first.cert_pem));

        let mut changes = source.subscribe();
        assert_eq!(*changes.borrow_and_update(), first);
        // renewed at two thirds of three seconds
        tokio::time::timeout(Duration::from_secs(10), changes.changed())
            .await
            .unwrap()
            .unwrap();
        let second = source.current();
        assert_eq!(*changes.borrow(), second);
        assert_ne!(second.cert_pem, first.cert_pem);
        assert_ne!(second.key_pem, first.key_pem);
        let (c, _) = handshake(client(ca.roots_pem(), None), config).unwrap();
        assert_eq!(served_cert(&c), der(&second.cert_pem));
    }

    #[tokio::test]
    async fn dropping_the_source_stops_its_task() {
        let source =
            ServingCertSource::in_memory_with_ttl(ca(), dns(), Duration::from_secs(3600)).unwrap();
        let mut changes = source.subscribe();
        drop(source);
        // the task held only a weak reference: the sender is gone with the source
        tokio::time::timeout(Duration::from_secs(5), changes.changed())
            .await
            .unwrap()
            .unwrap_err();
    }

    #[tokio::test]
    async fn bad_dns_names_and_lifetimes_are_refused() {
        let e = ServingCertSource::in_memory(ca(), vec![String::new()]).unwrap_err();
        assert!(format!("{e:#}").contains("DNS name"), "{e:#}");
        // a lifetime so short that renewal would spin
        for ttl in [Duration::ZERO, Duration::from_millis(2999)] {
            let e = ServingCertSource::in_memory_with_ttl(ca(), dns(), ttl).unwrap_err();
            assert!(e.to_string().contains("shorter than"), "{e}");
        }
    }

    fn write_dir(dir: &Path, cert: &str, key: &str, ca: &str) {
        std::fs::write(dir.join("tls.crt"), cert).unwrap();
        std::fs::write(dir.join("tls.key"), key).unwrap();
        std::fs::write(dir.join("ca.crt"), ca).unwrap();
    }

    async fn next_change(rx: &mut watch::Receiver<Arc<ServingCert>>) -> Arc<ServingCert> {
        tokio::time::timeout(Duration::from_secs(5), rx.changed())
            .await
            .unwrap()
            .unwrap();
        rx.borrow_and_update().clone()
    }

    #[tokio::test]
    async fn directory_source_reloads_changed_files() {
        let dir = tempfile::tempdir().unwrap();
        let ca1 = ca();
        let one = ca1
            .sign_server(&dns(), CONTROL_PLANE_SPIFFE_ID, HOUR)
            .unwrap();
        write_dir(dir.path(), &one.cert_pem, &one.key_pem, ca1.roots_pem());

        let source =
            ServingCertSource::from_dir_polling(dir.path(), Duration::from_millis(20)).unwrap();
        assert_eq!(der(&source.current().cert_pem), der(&one.cert_pem));
        assert_eq!(source.current().ca_pem, ca1.roots_pem());
        let required = source.rustls_server_config(ClientAuth::Required);
        let (wl1_cert, wl1_key) = workload(&ca1, "shop", "orders");
        let (c, _) = handshake(
            client(ca1.roots_pem(), Some((&wl1_cert, &wl1_key))),
            required.clone(),
        )
        .unwrap();
        assert_eq!(served_cert(&c), der(&one.cert_pem));
        let mut changes = source.subscribe();

        // a renewed certificate is picked up
        let two = ca1
            .sign_server(&dns(), CONTROL_PLANE_SPIFFE_ID, HOUR)
            .unwrap();
        write_dir(dir.path(), &two.cert_pem, &two.key_pem, ca1.roots_pem());
        let cur = next_change(&mut changes).await;
        assert_eq!(der(&cur.cert_pem), der(&two.cert_pem));
        assert_eq!(cur.key_pem, two.key_pem);

        // a key that does not fit is ignored; the current certificate stays
        std::fs::write(dir.path().join("tls.key"), &one.key_pem).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!changes.has_changed().unwrap());
        assert_eq!(der(&source.current().cert_pem), der(&two.cert_pem));
        // so is a missing file
        std::fs::remove_file(dir.path().join("ca.crt")).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!changes.has_changed().unwrap());

        // a new CA: existing listeners verify clients against the new bundle
        let ca2 = ca();
        let three = ca2
            .sign_server(&dns(), CONTROL_PLANE_SPIFFE_ID, HOUR)
            .unwrap();
        write_dir(dir.path(), &three.cert_pem, &three.key_pem, ca2.roots_pem());
        let cur = next_change(&mut changes).await;
        assert_eq!(cur.ca_pem, ca2.roots_pem());
        let (wl2_cert, wl2_key) = workload(&ca2, "shop", "orders");
        let (c, s) = handshake(
            client(ca2.roots_pem(), Some((&wl2_cert, &wl2_key))),
            required.clone(),
        )
        .unwrap();
        assert_eq!(served_cert(&c), der(&three.cert_pem));
        assert!(s.peer_certificates().and_then(peer_identity).is_some());
        let e = handshake(
            client(ca2.roots_pem(), Some((&wl1_cert, &wl1_key))),
            required,
        )
        .unwrap_err();
        assert!(e.starts_with("server:"), "{e}");
    }

    #[tokio::test]
    async fn directory_source_needs_a_valid_set_to_start() {
        let dir = tempfile::tempdir().unwrap();
        let e = format!("{:#}", ServingCertSource::from_dir(dir.path()).unwrap_err());
        assert!(e.contains("tls.crt"), "{e}");
        let ca = ca();
        let leaf = ca
            .sign_server(&dns(), CONTROL_PLANE_SPIFFE_ID, HOUR)
            .unwrap();
        let other = ca
            .sign_server(&dns(), CONTROL_PLANE_SPIFFE_ID, HOUR)
            .unwrap();
        write_dir(dir.path(), &leaf.cert_pem, &other.key_pem, ca.roots_pem());
        let e = format!("{:#}", ServingCertSource::from_dir(dir.path()).unwrap_err());
        assert!(e.contains("does not fit"), "{e}");
        write_dir(dir.path(), &leaf.cert_pem, &leaf.key_pem, "no certificates");
        let e = format!("{:#}", ServingCertSource::from_dir(dir.path()).unwrap_err());
        assert!(e.contains("CA bundle"), "{e}");
        write_dir(dir.path(), &leaf.cert_pem, &leaf.key_pem, ca.roots_pem());
        ServingCertSource::from_dir(dir.path()).unwrap();
    }

    #[test]
    fn replace_validates_and_notifies() {
        let ca = ca();
        let one = ca
            .sign_server(&dns(), CONTROL_PLANE_SPIFFE_ID, HOUR)
            .unwrap();
        let source =
            ServingCertSource::from_pems(&one.cert_pem, &one.key_pem, ca.roots_pem()).unwrap();
        let mut changes = source.subscribe();
        let two = ca
            .sign_server(&dns(), CONTROL_PLANE_SPIFFE_ID, HOUR)
            .unwrap();
        // refused: the key of another certificate, garbage
        assert!(
            source
                .replace(&two.cert_pem, &one.key_pem, ca.roots_pem())
                .is_err()
        );
        assert!(source.replace("x", "y", "z").is_err());
        assert!(!changes.has_changed().unwrap());
        assert_eq!(der(&source.current().cert_pem), der(&one.cert_pem));
        source
            .replace(&two.cert_pem, &two.key_pem, ca.roots_pem())
            .unwrap();
        assert!(changes.has_changed().unwrap());
        assert_eq!(
            der(&changes.borrow_and_update().cert_pem),
            der(&two.cert_pem)
        );
        assert_eq!(der(&source.current().cert_pem), der(&two.cert_pem));
    }

    #[test]
    fn peer_identity_is_strict() {
        let ca = ca();
        let (cert, _) = workload(&ca, "shop", "orders");
        let id = peer_identity(&[der(&cert)]).unwrap();
        assert_eq!(id.uri(), "spiffe://attache/ns/shop/svc/orders");
        assert_eq!(peer_identity(&[]), None);
        assert_eq!(peer_identity(&[der(ca.roots_pem())]), None);
        assert_eq!(peer_identity(&[CertificateDer::from(vec![1, 2, 3])]), None);
    }
}
