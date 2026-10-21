//! In-process fakes of embassy's `ControlPlane` and `CertificateAuthority` (design §7), served
//! over TLS with a serving certificate whose URI SAN is `spiffe://attache/control-plane`, signed
//! by a test CA from attache-pki.
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use attache_pki::PemBundle;
use attache_proto::certificate_authority_server::{
    CertificateAuthority, CertificateAuthorityServer,
};
use attache_proto::control_plane_server::{ControlPlane, ControlPlaneServer};
use attache_proto::{
    CertificateRequest, CertificateResponse, ControlMessage, SidecarMessage, sidecar_message,
};
use rcgen::string::Ia5String;
use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DistinguishedName, ExtendedKeyUsagePurpose,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, Identity, ServerTlsConfig};
use tonic::{Request, Response, Status, Streaming};

pub const JOIN_TOKEN: &str = "join-token-for-orders";
/// The projected service-account token the fake's "TokenReview" accepts.
pub const K8S_TOKEN: &str = "projected-k8s-token-for-orders";

fn issuer(ca: &PemBundle) -> Issuer<'static, KeyPair> {
    let key = KeyPair::from_pem(&ca.key_pem).unwrap();
    Issuer::from_ca_cert_pem(&ca.cert_pem, key).unwrap()
}

/// The control plane's serving certificate: URI SAN `spiffe://attache/control-plane` only.
pub fn serving_cert(ca: &PemBundle, uri: &str) -> PemBundle {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = DistinguishedName::new();
    params
        .subject_alt_names
        .push(SanType::URI(Ia5String::try_from(uri).unwrap()));
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let cert = params.signed_by(&key, &issuer(ca)).unwrap();
    PemBundle {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    }
}

/// Everything the fakes saw, and what the test makes them do.
#[derive(Default)]
pub struct Shared {
    /// Every message from the sidecar, in order, with the index of its stream.
    pub received: Mutex<Vec<(usize, SidecarMessage)>>,
    pub issued: Mutex<Vec<CertificateRequest>>,
    /// The client identities (URI SANs) of the `Connect` streams.
    pub peers: Mutex<Vec<String>>,
    outbound: Mutex<Vec<mpsc::Sender<Result<ControlMessage, Status>>>>,
    pub connections: AtomicUsize,
    pub refuse_issue: AtomicBool,
    /// Lifetime of issued certificates.
    pub ttl: Mutex<Duration>,
}

#[derive(Clone)]
struct Fake {
    ca: PemBundle,
    shared: Arc<Shared>,
}

#[tonic::async_trait]
impl ControlPlane for Fake {
    type ConnectStream = ReceiverStream<Result<ControlMessage, Status>>;

    async fn connect(
        &self,
        request: Request<Streaming<SidecarMessage>>,
    ) -> Result<Response<Self::ConnectStream>, Status> {
        let leaf = request
            .peer_certs()
            .and_then(|c| c.first().cloned())
            .ok_or_else(|| Status::unauthenticated("a workload certificate is required"))?;
        let id = attache_pki::spiffe_id_of(&leaf)
            .ok()
            .flatten()
            .ok_or_else(|| Status::permission_denied("no workload identity"))?;
        self.shared.peers.lock().unwrap().push(id.uri());
        let index = self.shared.connections.fetch_add(1, Ordering::SeqCst);
        let mut inbound = request.into_inner();
        let shared = self.shared.clone();
        tokio::spawn(async move {
            while let Ok(Some(m)) = inbound.message().await {
                shared.received.lock().unwrap().push((index, m));
            }
        });
        let (tx, rx) = mpsc::channel(64);
        self.shared.outbound.lock().unwrap().push(tx);
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[tonic::async_trait]
impl CertificateAuthority for Fake {
    async fn issue_certificate(
        &self,
        request: Request<CertificateRequest>,
    ) -> Result<Response<CertificateResponse>, Status> {
        let req = request.into_inner();
        self.shared.issued.lock().unwrap().push(req.clone());
        if self.shared.refuse_issue.load(Ordering::SeqCst) {
            return Err(Status::unavailable("the CA is refusing for this test"));
        }
        let token_ok = if req.join_token.is_empty() {
            if req.kubernetes_token != K8S_TOKEN {
                return Err(Status::permission_denied(
                    "the TokenReview did not authenticate the Kubernetes token",
                ));
            }
            true
        } else {
            req.kubernetes_token.is_empty() && req.join_token == JOIN_TOKEN
        };
        if !token_ok {
            return Err(Status::permission_denied("unknown join token"));
        }
        let csr = CertificateSigningRequestParams::from_pem(&req.csr_pem)
            .map_err(|e| Status::invalid_argument(format!("csr: {e}")))?;
        if csr.public_key.algorithm() != &rcgen::PKCS_ECDSA_P256_SHA256 {
            return Err(Status::invalid_argument("ECDSA P-256 only"));
        }
        let id = attache_common::identity::SpiffeId {
            namespace: req.namespace.clone(),
            service: req.service.clone(),
        };
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = DistinguishedName::new();
        params
            .subject_alt_names
            .push(SanType::URI(Ia5String::try_from(id.uri()).unwrap()));
        for dns in id.dns_names() {
            params
                .subject_alt_names
                .push(SanType::DnsName(Ia5String::try_from(dns).unwrap()));
        }
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let ttl = *self.shared.ttl.lock().unwrap();
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::seconds(1);
        params.not_after = now + time::Duration::try_from(ttl).unwrap();
        let cert = params
            .signed_by(&csr.public_key, &issuer(&self.ca))
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(CertificateResponse {
            cert_pem: cert.pem(),
            ca_pem: self.ca.cert_pem.clone(),
            expires_at: String::new(),
        }))
    }
}

pub struct FakeCp {
    pub addr: SocketAddr,
    pub ca: PemBundle,
    pub shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

impl FakeCp {
    /// Serve both fakes on one TLS port: client certificates optional (the CA takes none; the
    /// control plane checks for one itself).
    pub async fn start(ca: PemBundle) -> FakeCp {
        Self::start_on("127.0.0.1:0", ca).await
    }

    pub async fn start_on(addr: &str, ca: PemBundle) -> FakeCp {
        Self::start_with(addr, ca, attached::tls::CONTROL_PLANE_URI).await
    }

    /// Serve with a certificate whose only URI SAN is `uri` (an impostor when it is not the
    /// control plane's).
    pub async fn start_with(addr: &str, ca: PemBundle, uri: &str) -> FakeCp {
        // tonic's TLS takes the process-wide provider; the sidecar picks ring the same way
        let _ = rustls::crypto::ring::default_provider().install_default();
        let serving = serving_cert(&ca, uri);
        let shared = Arc::new(Shared {
            ttl: Mutex::new(Duration::from_secs(3600)),
            ..Default::default()
        });
        let fake = Fake {
            ca: ca.clone(),
            shared: shared.clone(),
        };
        // the same port again, once a stopped fake has let go of it
        let mut tries = 0;
        let listener = loop {
            match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => break l,
                Err(e) if tries < 100 => {
                    tries += 1;
                    let _ = e;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(e) => panic!("bind {addr}: {e}"),
            }
        };
        let addr = listener.local_addr().unwrap();
        let tls = ServerTlsConfig::new()
            .identity(Identity::from_pem(&serving.cert_pem, &serving.key_pem))
            .client_ca_root(Certificate::from_pem(&ca.cert_pem))
            .client_auth_optional(true);
        let server = tonic::transport::Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(ControlPlaneServer::new(fake.clone()))
            .add_service(CertificateAuthorityServer::new(fake))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener));
        let task = tokio::spawn(async move {
            let _ = server.await;
        });
        FakeCp {
            addr,
            ca,
            shared,
            task,
        }
    }

    pub fn stop(&self) {
        self.task.abort();
        self.drop_streams();
    }

    /// Send to the newest stream.
    pub async fn push(&self, m: ControlMessage) {
        let tx = self
            .shared
            .outbound
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("a Connect stream");
        tx.send(Ok(m)).await.unwrap();
    }

    /// End every `Connect` stream from the server side.
    pub fn drop_streams(&self) {
        self.shared.outbound.lock().unwrap().clear();
    }

    pub fn connections(&self) -> usize {
        self.shared.connections.load(Ordering::SeqCst)
    }

    pub fn received(&self) -> Vec<(usize, SidecarMessage)> {
        self.shared.received.lock().unwrap().clone()
    }

    pub fn hellos(&self) -> Vec<attache_proto::Hello> {
        self.received()
            .into_iter()
            .filter_map(|(_, m)| match m.msg {
                Some(sidecar_message::Msg::Hello(h)) => Some(h),
                _ => None,
            })
            .collect()
    }

    pub fn acks(&self) -> Vec<attache_proto::ConfigAck> {
        self.received()
            .into_iter()
            .filter_map(|(_, m)| match m.msg {
                Some(sidecar_message::Msg::Ack(a)) => Some(a),
                _ => None,
            })
            .collect()
    }

    pub fn heartbeats(&self) -> Vec<attache_proto::Heartbeat> {
        self.received()
            .into_iter()
            .filter_map(|(_, m)| match m.msg {
                Some(sidecar_message::Msg::Heartbeat(h)) => Some(h),
                _ => None,
            })
            .collect()
    }

    pub fn span_starts(&self) -> Vec<attache_proto::SpanStart> {
        self.received()
            .into_iter()
            .filter_map(|(_, m)| match m.msg {
                Some(sidecar_message::Msg::SpanStart(s)) => Some(s),
                _ => None,
            })
            .collect()
    }

    pub fn proposals(&self) -> Vec<attache_proto::LearningProposal> {
        self.received()
            .into_iter()
            .filter_map(|(_, m)| match m.msg {
                Some(sidecar_message::Msg::Proposal(p)) => Some(p),
                _ => None,
            })
            .collect()
    }

    /// Every audit record received, parsed, in order, with the size of the batch it came in.
    pub fn audit_records(&self) -> Vec<(usize, serde_json::Value)> {
        self.received()
            .into_iter()
            .filter_map(|(_, m)| match m.msg {
                Some(sidecar_message::Msg::Audit(b)) => Some(b),
                _ => None,
            })
            .flat_map(|b| {
                let n = b.records_json.len();
                b.records_json
                    .into_iter()
                    .map(move |j| (n, serde_json::from_str(&j).unwrap()))
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

impl Drop for FakeCp {
    fn drop(&mut self) {
        self.task.abort();
    }
}
