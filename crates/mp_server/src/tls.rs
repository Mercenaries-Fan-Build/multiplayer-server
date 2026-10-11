//! HTTPS listener TLS (OpenSSL) and the connection accept loop.

use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::Router;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use openssl::error::ErrorStack;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{AlpnError, Ssl, SslAcceptor, SslMethod};
use openssl::x509::X509;
use tokio::net::TcpListener;
use tower::ServiceExt;

/// The TCP peer of an HTTPS request (before any proxy attribution).
#[derive(Clone, Copy, Debug)]
pub struct Peer(pub SocketAddr);

/// The acceptor in use; replaced in place when an ACME renewal lands.
pub type SharedAcceptor = Arc<RwLock<Arc<SslAcceptor>>>;

/// TLS 1.2+ (Mozilla "intermediate"), HTTP/1.1 only over ALPN (the WebSocket upgrade needs HTTP/1.1).
pub fn acceptor(chain: &[X509], key: &PKey<Private>) -> Result<SslAcceptor, ErrorStack> {
    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
    let (leaf, rest) = chain.split_first().ok_or_else(ErrorStack::get)?;
    b.set_certificate(leaf)?;
    for cert in rest {
        b.add_extra_chain_cert(cert.clone())?;
    }
    b.set_private_key(key)?;
    b.check_private_key()?;
    b.set_alpn_select_callback(|_, client| {
        openssl::ssl::select_next_proto(b"\x08http/1.1", client).ok_or(AlpnError::NOACK)
    });
    Ok(b.build())
}

#[derive(Debug, thiserror::Error)]
pub enum PemError {
    #[error("reading {path}: {source}")]
    Read { path: String, source: std::io::Error },
    #[error("parsing {path}: {source}")]
    Parse { path: String, source: ErrorStack },
    #[error("{0} contains no certificate")]
    Empty(String),
}

pub fn load_pem(cert: &Path, key: &Path) -> Result<(Vec<X509>, PKey<Private>), PemError> {
    let read = |p: &Path| std::fs::read(p).map_err(|source| PemError::Read { path: p.display().to_string(), source });
    let cert_bytes = read(cert)?;
    let chain = X509::stack_from_pem(&cert_bytes)
        .map_err(|source| PemError::Parse { path: cert.display().to_string(), source })?;
    if chain.is_empty() {
        return Err(PemError::Empty(cert.display().to_string()));
    }
    let key_bytes = read(key)?;
    let key = PKey::private_key_from_pem(&key_bytes)
        .map_err(|source| PemError::Parse { path: key.display().to_string(), source })?;
    Ok((chain, key))
}

/// Accepts TCP connections forever, each served on its own task: TLS handshake (bounded by
/// `handshake_timeout`), then HTTP/1.1 with upgrades. Returns only on a listener failure.
pub async fn serve_https(
    listener: TcpListener,
    acceptor: SharedAcceptor,
    router: Router,
    handshake_timeout: Duration,
) -> std::io::Error {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(conn) => conn,
            // These describe one connection that died between SYN and accept, not the listener.
            Err(e) if matches!(e.kind(), std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::ConnectionReset) => {
                tracing::debug!(error = %e, "connection failed during accept");
                continue;
            }
            Err(e) => return e,
        };
        let acceptor = acceptor.read().expect("acceptor lock poisoned by an earlier panic").clone();
        let router = router.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_connection(tcp, peer, &acceptor, router, handshake_timeout).await {
                tracing::debug!(%peer, error = %e, "HTTPS connection ended with an error");
            }
        });
    }
}

#[derive(Debug, thiserror::Error)]
enum ConnError {
    #[error("TLS setup: {0}")]
    Setup(#[from] ErrorStack),
    #[error("TLS handshake: {0}")]
    Handshake(openssl::ssl::Error),
    #[error("TLS handshake timed out")]
    HandshakeTimeout,
    #[error("HTTP: {0}")]
    Http(Box<dyn std::error::Error + Send + Sync>),
}

async fn serve_connection(
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    acceptor: &SslAcceptor,
    router: Router,
    handshake_timeout: Duration,
) -> Result<(), ConnError> {
    let ssl = Ssl::new(acceptor.context())?;
    let mut tls = tokio_openssl::SslStream::new(ssl, tcp)?;
    match tokio::time::timeout(handshake_timeout, Pin::new(&mut tls).accept()).await {
        Err(_) => return Err(ConnError::HandshakeTimeout),
        Ok(Err(e)) => return Err(ConnError::Handshake(e)),
        Ok(Ok(())) => {}
    }
    let service = router.map_request(move |mut req: http::Request<Incoming>| {
        req.extensions_mut().insert(Peer(peer));
        req
    });
    hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(tls), TowerToHyperService::new(service))
        .with_upgrades()
        .await
        .map_err(|e| ConnError::Http(Box::new(e)))
}
