//! `--http3` (docs/adr/0001-http3-for-the-console.md): the API and the console over HTTP/3.
//!
//! QUIC listens on the same address as `--http-addr`, over UDP, with the serving certificate's
//! rustls configuration (ALPN `h3`). Every response of the TCP listener carries
//! `Alt-Svc: h3=":<port>"; ma=86400`, so a browser that fetched the console once over HTTP/1.1
//! or HTTP/2 moves its next connections to QUIC and stays there while the entry is fresh.
//!
//! One `axum::Router` serves every protocol: an HTTP/3 request is read into an `http::Request`
//! (the body collected up to [`crate::api::MAX_BODY`], like the TCP listeners' body limit),
//! given the peer address as `ConnectInfo<ClientAddr>` (the login rate limit reads it), and
//! handed to the router; the response body is streamed back frame by frame, so the SSE stream
//! (`GET /api/v1/events`) works over HTTP/3 as it does over TCP.
//!
//! Connection-specific HTTP/1.1 headers (`Connection`, `Transfer-Encoding`, `Keep-Alive`,
//! `Upgrade`) have no place in HTTP/3 and are dropped from responses. 0-RTT is not enabled:
//! the API has mutating routes and an early-data replay would reach them.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use bytes::{Buf, Bytes};
use h3::server::RequestStream;
use h3_quinn::quinn;
use http_body_util::BodyExt as _;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt as _;

use crate::api::{ClientAddr, MAX_BODY};

/// The ALPN protocol of HTTP/3.
pub const ALPN_H3: &[u8] = b"h3";
/// How long a QUIC connection may stay silent before it is closed.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// How many requests one connection may have in flight.
pub const MAX_CONCURRENT_STREAMS: u32 = 256;
/// How long (seconds) a browser may remember the `Alt-Svc` entry.
pub const ALT_SVC_MAX_AGE: u64 = 86_400;

/// The `Alt-Svc` value that names the HTTP/3 listener on `port`.
pub fn alt_svc_value(port: u16) -> HeaderValue {
    HeaderValue::from_str(&format!("h3=\":{port}\"; ma={ALT_SVC_MAX_AGE}"))
        .expect("an Alt-Svc value is ASCII")
}

/// Middleware for the TCP listener: every response advertises the HTTP/3 listener.
pub async fn alt_svc(State(value): State<HeaderValue>, req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    resp.headers_mut().insert(header::ALT_SVC, value);
    resp
}

/// Bind the QUIC endpoint on `addr` (UDP) with `tls`, the serving certificate's configuration
/// (its certificate resolver follows renewals, so the endpoint does too). Returns the bound
/// address and the endpoint for [`serve`].
pub fn bind(
    addr: SocketAddr,
    tls: Arc<rustls::ServerConfig>,
) -> anyhow::Result<(SocketAddr, quinn::Endpoint)> {
    let mut tls = rustls::ServerConfig::clone(&tls);
    tls.alpn_protocols = vec![ALPN_H3.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .context("the serving certificate's TLS configuration cannot carry QUIC")?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(IDLE_TIMEOUT).context("QUIC idle timeout")?,
    ));
    transport.max_concurrent_bidi_streams(MAX_CONCURRENT_STREAMS.into());
    config.transport_config(Arc::new(transport));
    let endpoint = quinn::Endpoint::server(config, addr)
        .with_context(|| format!("bind --http-addr {addr} for HTTP/3 (UDP)"))?;
    let local = endpoint.local_addr()?;
    Ok((local, endpoint))
}

/// Accept QUIC connections on `endpoint` and serve `app` over HTTP/3 until `shutdown`; then
/// close the endpoint and wait for the connections to drain.
pub async fn serve(
    endpoint: quinn::Endpoint,
    app: Router,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    loop {
        let incoming = tokio::select! {
            i = endpoint.accept() => i,
            () = shutdown.cancelled() => break,
        };
        let Some(incoming) = incoming else {
            break;
        };
        let peer = incoming.remote_address();
        let app = app.clone();
        let stop = shutdown.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(%peer, error = %e, "QUIC handshake failed");
                    return;
                }
            };
            if let Err(e) = connection(conn, peer, app, stop).await {
                tracing::debug!(%peer, error = %e, "HTTP/3 connection ended with an error");
            }
        });
    }
    endpoint.close(0u32.into(), b"shutdown");
    endpoint.wait_idle().await;
    Ok(())
}

/// Serve every request of one connection; each request runs in its own task.
async fn connection(
    conn: quinn::Connection,
    peer: SocketAddr,
    app: Router,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let mut h3: h3::server::Connection<h3_quinn::Connection, Bytes> =
        h3::server::Connection::new(h3_quinn::Connection::new(conn)).await?;
    loop {
        let accepted = tokio::select! {
            r = h3.accept() => r,
            () = shutdown.cancelled() => return Ok(()),
        };
        match accepted {
            Ok(Some(resolver)) => {
                let app = app.clone();
                tokio::spawn(async move {
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => {
                            if let Err(e) = respond(req, stream, peer, app).await {
                                tracing::debug!(%peer, error = %e, "HTTP/3 request failed");
                            }
                        }
                        Err(e) => {
                            tracing::debug!(%peer, error = %e, "HTTP/3 request headers failed")
                        }
                    }
                });
            }
            // the peer closed the connection
            Ok(None) => return Ok(()),
            Err(e) => return Err(e.into()),
        }
    }
}

/// Read the request body (at most [`MAX_BODY`]), run the router, stream the response back.
async fn respond<S>(
    req: http::Request<()>,
    mut stream: RequestStream<S, Bytes>,
    peer: SocketAddr,
    app: Router,
) -> anyhow::Result<()>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let mut body = Vec::new();
    let mut too_large = false;
    while let Some(mut chunk) = stream.recv_data().await? {
        let n = chunk.remaining();
        if body.len() + n > MAX_BODY {
            too_large = true;
            break;
        }
        body.extend_from_slice(&chunk.copy_to_bytes(n));
    }
    let head = req.method() == Method::HEAD;
    let (parts, ()) = req.into_parts();
    let response = if too_large {
        StatusCode::PAYLOAD_TOO_LARGE.into_response()
    } else {
        let mut request = http::Request::from_parts(parts, Body::from(body));
        request
            .extensions_mut()
            .insert(ConnectInfo(ClientAddr(peer)));
        match app.oneshot(request).await {
            Ok(r) => r,
            Err(never) => match never {},
        }
    };
    send(stream, response, head).await
}

/// Headers that belong to an HTTP/1.1 connection, never to an HTTP/3 response.
const CONNECTION_HEADERS: [HeaderName; 5] = [
    header::CONNECTION,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
    HeaderName::from_static("keep-alive"),
    HeaderName::from_static("proxy-connection"),
];

/// Send `response` on `stream`: the head, then every data frame as it comes (an SSE stream
/// stays open as long as the handler keeps it), then the trailers or the end of the stream.
async fn send<S>(
    mut stream: RequestStream<S, Bytes>,
    response: Response,
    head_only: bool,
) -> anyhow::Result<()>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let (mut parts, mut body) = response.into_parts();
    for name in CONNECTION_HEADERS {
        parts.headers.remove(name);
    }
    // like hyper: a 304 or 204 has no content, and we send no Content-Length with it
    let no_content = matches!(
        parts.status,
        StatusCode::NOT_MODIFIED | StatusCode::NO_CONTENT
    ) || parts.status.is_informational();
    if no_content {
        parts.headers.remove(header::CONTENT_LENGTH);
    }
    stream
        .send_response(http::Response::from_parts(parts, ()))
        .await?;
    if head_only || no_content {
        stream.finish().await?;
        return Ok(());
    }
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| anyhow::anyhow!("response body: {e}"))?;
        match frame.into_data() {
            Ok(data) => stream.send_data(data).await?,
            Err(frame) => {
                if let Ok(trailers) = frame.into_trailers() {
                    stream.send_trailers(trailers).await?;
                    return Ok(());
                }
            }
        }
    }
    stream.finish().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alt_svc_names_the_port_and_a_day() {
        assert_eq!(alt_svc_value(8443), "h3=\":8443\"; ma=86400");
    }

    #[test]
    fn connection_headers_are_the_hop_by_hop_ones() {
        let names: Vec<String> = CONNECTION_HEADERS
            .into_iter()
            .map(|h| h.as_str().to_string())
            .collect();
        assert_eq!(
            names,
            [
                "connection",
                "transfer-encoding",
                "upgrade",
                "keep-alive",
                "proxy-connection"
            ]
        );
    }

    #[tokio::test]
    async fn binds_a_quic_endpoint_with_the_serving_certificate() {
        let ca = agentsc_pki::ca_init().unwrap();
        let ca = Arc::new(crate::ca::CaMaterial::from_pems(&ca.cert_pem, &ca.key_pem).unwrap());
        let serving =
            crate::servingcert::ServingCertSource::in_memory(ca, vec!["localhost".into()]).unwrap();
        let tls = serving.rustls_server_config(crate::servingcert::ClientAuth::None);
        let (bound, endpoint) = bind("127.0.0.1:0".parse().unwrap(), tls).unwrap();
        assert_ne!(bound.port(), 0);
        endpoint.close(0u32.into(), b"test");
    }
}
