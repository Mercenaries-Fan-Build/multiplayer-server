//! Mercenaries 2 multiplayer server: accounts and sessions over HTTPS, the lobby over one WebSocket, and a
//! DTLS relay for gameplay datagrams. The wire contract is the `mp_api` crate.

pub mod acme;
pub mod api;
pub mod client_ip;
pub mod config;
pub mod connection;
pub mod db;
pub mod hub;
pub mod passwords;
pub mod ratelimit;
pub mod relay;
pub mod tls;
pub mod util;

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::task::JoinSet;

use crate::api::App;
use crate::client_ip::ClientIpPolicy;
use crate::config::{Config, TlsConfig};
use crate::db::Db;
use crate::hub::Hub;
use crate::passwords::Passwords;
use crate::ratelimit::RateLimiter;
use crate::relay::{RelayHandle, RelayTask};

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error(transparent)]
    Db(#[from] db::DbError),
    #[error(transparent)]
    Passwords(#[from] passwords::PasswordError),
    #[error(transparent)]
    Relay(#[from] relay::RelayError),
    #[error("HTTPS certificate: {0}")]
    Pem(#[from] tls::PemError),
    #[error("TLS: {0}")]
    Tls(#[from] openssl::error::ErrorStack),
    #[error(transparent)]
    Acme(#[from] acme::AcmeError),
    #[error("binding {what} on {addr}: {source}")]
    Bind { what: &'static str, addr: SocketAddr, source: std::io::Error },
    #[error("{0} listener failed: {1}")]
    Listener(&'static str, std::io::Error),
    #[error("{0} stopped unexpectedly")]
    Stopped(&'static str),
    #[error("{0} task panicked")]
    Panicked(String),
}

/// A started server. Its tasks run until [`Running::wait`] reports the first one to fail.
pub struct Running {
    pub https_addr: SocketAddr,
    pub relay_addr: SocketAddr,
    /// Bound address of the ACME HTTP-01 listener (`acme` mode only).
    pub acme_http_addr: Option<SocketAddr>,
    pub relay: RelayHandle,
    tasks: JoinSet<Result<(), ServerError>>,
}

impl Running {
    /// Waits for the first task to end. Every task is meant to run forever, so any end is an error.
    pub async fn wait(mut self) -> ServerError {
        match self.tasks.join_next().await {
            Some(Ok(Err(e))) => e,
            Some(Ok(Ok(()))) => ServerError::Stopped("a server task"),
            Some(Err(join)) => ServerError::Panicked(join.to_string()),
            None => ServerError::Stopped("all server tasks"),
        }
    }
}

async fn bind(what: &'static str, addr: SocketAddr) -> Result<TcpListener, ServerError> {
    TcpListener::bind(addr).await.map_err(|source| ServerError::Bind { what, addr, source })
}

/// Opens the database, binds every listener and starts every task.
pub async fn start(cfg: Config) -> Result<Running, ServerError> {
    let mut tasks = JoinSet::new();
    let db = Db::open(&cfg.database.path).await?;
    let passwords = Passwords::new(&cfg.accounts)?;

    let (relay, relay_task) = RelayTask::bind(&cfg.relay).await?;
    let relay_addr = relay_task.local_addr()?;
    tracing::info!(%relay_addr, cert_sha256 = %relay.public().cert_sha256, "relay listening");
    tasks.spawn(async move { relay_task.run().await.map_err(ServerError::from).and(Err(ServerError::Stopped("relay"))) });

    let hub = Arc::new(Hub::new(db.clone(), relay.clone(), cfg.games.max_players_limit));

    let (shared_acceptor, trusted_proxies, acme_http_addr) = match &cfg.tls {
        TlsConfig::Proxied(p) => {
            let (chain, key) = tls::load_pem(&p.cert_pem, &p.key_pem)?;
            let acceptor = Arc::new(RwLock::new(Arc::new(tls::acceptor(&chain, &key)?)));
            (acceptor, p.trusted_proxies.clone(), None)
        }
        TlsConfig::Acme(a) => {
            let challenges = acme::Challenges::default();
            let listener = bind("ACME HTTP-01 listener", a.http_listen).await?;
            let http_addr = listener.local_addr().map_err(|e| ServerError::Listener("ACME HTTP-01", e))?;
            let router = acme::challenge_router(challenges.clone());
            tasks.spawn(async move {
                axum::serve(listener, router).await.map_err(|e| ServerError::Listener("ACME HTTP-01", e))?;
                Err(ServerError::Stopped("ACME HTTP-01 listener"))
            });
            tracing::info!(%http_addr, "ACME HTTP-01 listener up");
            let (chain, key) = acme::initial_certificate(a, &challenges).await?;
            let acceptor = Arc::new(RwLock::new(Arc::new(tls::acceptor(&chain, &key)?)));
            let renewal = acme::renewal_loop(a.clone(), challenges, acceptor.clone(), chain[0].clone());
            tasks.spawn(async move { Err(ServerError::Acme(renewal.await)) });
            (acceptor, Vec::new(), Some(http_addr))
        }
    };

    let app = Arc::new(App {
        db,
        passwords,
        hub,
        accounts_limit: RateLimiter::new(cfg.rate_limit.accounts),
        sessions_limit: RateLimiter::new(cfg.rate_limit.sessions),
        ip_policy: ClientIpPolicy { trusted_proxies },
        session_ttl: Duration::from_secs(cfg.accounts.session_ttl_secs),
        websocket: cfg.websocket.clone(),
    });
    let listener = bind("HTTPS listener", cfg.server.https_listen).await?;
    let https_addr = listener.local_addr().map_err(|e| ServerError::Listener("HTTPS", e))?;
    let router = api::router(app);
    let handshake_timeout = Duration::from_secs(cfg.server.tls_handshake_timeout_secs);
    tasks.spawn(async move {
        Err(ServerError::Listener("HTTPS", tls::serve_https(listener, shared_acceptor, router, handshake_timeout).await))
    });
    tracing::info!(%https_addr, "HTTPS listening");

    Ok(Running { https_addr, relay_addr, acme_http_addr, relay, tasks })
}
