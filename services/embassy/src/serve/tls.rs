//! TLS listeners with the serving certificate's rustls configuration
//! ([`crate::servingcert::ServingCertSource::rustls_server_config`]): handshakes run in their own
//! tasks (a slow client never holds up the accept loop) and the finished streams are handed to
//! the server (tonic for `Connect`, axum for `--http-tls`).
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;

/// How long a TLS handshake may take.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const QUEUE: usize = 64;

/// A finished TLS connection and its peer address.
pub type Accepted = (TlsStream<TcpStream>, SocketAddr);

/// Accept TCP connections on `listener` and complete TLS handshakes with `config` until
/// `shutdown`; the finished connections come out of the returned channel.
pub fn spawn_acceptor(
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
    shutdown: CancellationToken,
) -> mpsc::Receiver<Accepted> {
    let (tx, rx) = mpsc::channel(QUEUE);
    let acceptor = TlsAcceptor::from(config);
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                r = listener.accept() => r,
                () = shutdown.cancelled() => return,
                () = tx.closed() => return,
            };
            let (tcp, peer) = match accepted {
                Ok(x) => x,
                Err(e) => {
                    tracing::debug!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let _ = tcp.set_nodelay(true);
            let acceptor = acceptor.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                    Ok(Ok(tls)) => {
                        let _ = tx.send((tls, peer)).await;
                    }
                    Ok(Err(e)) => tracing::debug!(%peer, error = %e, "TLS handshake failed"),
                    Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
                }
            });
        }
    });
    rx
}

/// An axum listener over [`spawn_acceptor`] (`--http-tls`).
pub struct TlsListener {
    rx: mpsc::Receiver<Accepted>,
    local: SocketAddr,
}

impl TlsListener {
    pub fn new(
        listener: TcpListener,
        config: Arc<rustls::ServerConfig>,
        shutdown: CancellationToken,
    ) -> std::io::Result<Self> {
        let local = listener.local_addr()?;
        Ok(Self {
            rx: spawn_acceptor(listener, config, shutdown),
            local,
        })
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.rx.recv().await {
            Some(x) => x,
            // the acceptor stopped (shutdown): accept nothing more
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}
