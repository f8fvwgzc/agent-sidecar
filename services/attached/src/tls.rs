//! rustls configuration for the mesh (CONTRACT.md §5).
use attache_pki::TlsMaterial;
use tonic::transport::{
    Certificate, Channel, ClientTlsConfig, Endpoint, Identity, ServerTlsConfig,
};

pub fn server_config(tls: &TlsMaterial) -> ServerTlsConfig {
    ServerTlsConfig::new()
        .identity(Identity::from_pem(&tls.cert_pem, &tls.key_pem))
        .client_ca_root(Certificate::from_pem(&tls.ca_pem))
        .client_auth_optional(false)
}

pub fn client_channel(tls: &TlsMaterial, addr: &str, server_name: &str) -> anyhow::Result<Channel> {
    let cfg = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(&tls.ca_pem))
        .identity(Identity::from_pem(&tls.cert_pem, &tls.key_pem))
        .domain_name(server_name);
    let endpoint = Endpoint::from_shared(format!("https://{addr}"))?
        .tls_config(cfg)?
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(120));
    Ok(endpoint.connect_lazy())
}
