//! UDP relay terminating one DTLS 1.2 association per client (`mp_api::relay` wire format inside).
//!
//! One tokio `UdpSocket` serves every client. Datagrams are demultiplexed by source address into a
//! per-association OpenSSL `SslStream` over an in-memory datagram queue ([`DgramIo`]): inbound datagrams are
//! queued for OpenSSL to read, and every datagram OpenSSL writes is collected and sent to that address.
//! HelloVerifyRequest cookies (bound to the source address with an HMAC keyed by a per-process secret) are
//! required before the server sends its certificate flight, so a spoofed source gets one small datagram, not
//! an amplified handshake. Associations still handshaking are capped and time out.
//!
//! An association carries data only after its first application datagram, `Hello{token}`, matches a token the
//! lobby issued in a `RelayAssignment`; the token binds it to `(game, user, slot)`. `Data{slot}` is then
//! forwarded to the association bound to that slot in the same game, with `slot` rewritten to the sender's.
//! Anything else is dropped per datagram with a counted, logged reason.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use foreign_types::ForeignTypeRef;
use mp_api::relay::{Datagram, RelayWireError};
use mp_api::{GameId, UserId};
use openssl::error::ErrorStack;
use openssl::ex_data::Index;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::ssl::{ErrorCode, Ssl, SslContext, SslFiletype, SslMethod, SslOptions, SslStream, SslVerifyMode, SslVersion};
use openssl::x509::X509;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

use crate::config::RelayConfig;
use crate::util::{hex, random_bytes};

/// `DTLS_CTRL_HANDLE_TIMEOUT` from OpenSSL's `ssl.h` (`DTLSv1_handle_timeout` is a macro over `SSL_ctrl`,
/// so openssl-sys has no function for it).
const DTLS_CTRL_HANDLE_TIMEOUT: std::os::raw::c_int = 74;

/// Largest UDP payload.
const MAX_DATAGRAM: usize = 65535;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    pub game_id: GameId,
    pub user_id: UserId,
    pub slot: u8,
}

#[derive(Debug)]
enum Command {
    Register { token: Vec<u8>, binding: Binding },
    RevokeUser { game_id: GameId, user_id: UserId },
    RevokeGame { game_id: GameId },
    DropCounts(oneshot::Sender<BTreeMap<&'static str, u64>>),
}

/// What clients are told about the relay.
#[derive(Debug)]
pub struct RelayPublic {
    pub host: String,
    pub port: u16,
    pub cert_sha256: String,
    /// `relay.idle_timeout_secs`: clients must send within this or lose their association.
    pub idle_timeout_secs: u64,
}

#[derive(Debug, thiserror::Error)]
#[error("the relay task is not running")]
pub struct RelayGone;

/// The lobby's side of the relay.
#[derive(Clone)]
pub struct RelayHandle {
    tx: mpsc::UnboundedSender<Command>,
    public: Arc<RelayPublic>,
}

impl RelayHandle {
    pub fn public(&self) -> &RelayPublic {
        &self.public
    }

    pub fn register(&self, token: Vec<u8>, binding: Binding) -> Result<(), RelayGone> {
        self.tx.send(Command::Register { token, binding }).map_err(|_| RelayGone)
    }

    pub fn revoke_user(&self, game_id: GameId, user_id: UserId) -> Result<(), RelayGone> {
        self.tx.send(Command::RevokeUser { game_id, user_id }).map_err(|_| RelayGone)
    }

    pub fn revoke_game(&self, game_id: GameId) -> Result<(), RelayGone> {
        self.tx.send(Command::RevokeGame { game_id }).map_err(|_| RelayGone)
    }

    /// Dropped-datagram counters by reason (diagnostics).
    pub async fn drop_counts(&self) -> Result<BTreeMap<&'static str, u64>, RelayGone> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(Command::DropCounts(tx)).map_err(|_| RelayGone)?;
        rx.await.map_err(|_| RelayGone)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("relay certificate/key: {0}")]
    Tls(#[from] ErrorStack),
    #[error("relay certificate file {path}: {source}")]
    CertFile { path: String, source: io::Error },
    #[error("relay certificate file {0} contains no certificate")]
    NoCert(String),
    #[error("relay socket: {0}")]
    Socket(io::Error),
}

/// In-memory datagram transport under one association's `SslStream`.
#[derive(Default)]
struct DgramIo {
    inbound: VecDeque<Vec<u8>>,
    outbound: Vec<Vec<u8>>,
}

impl Read for DgramIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.inbound.pop_front() {
            None => Err(io::ErrorKind::WouldBlock.into()),
            Some(d) if d.len() > buf.len() => {
                Err(io::Error::new(io::ErrorKind::InvalidData, "datagram larger than the DTLS read buffer"))
            }
            Some(d) => {
                buf[..d.len()].copy_from_slice(&d);
                Ok(d.len())
            }
        }
    }
}

impl Write for DgramIo {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.outbound.push(buf.to_vec());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Assoc {
    stream: SslStream<DgramIo>,
    established: bool,
    binding: Option<Binding>,
    created: Instant,
    last_seen: Instant,
}

pub struct RelayTask {
    socket: UdpSocket,
    ctx: SslContext,
    peer_index: Index<Ssl, SocketAddr>,
    rx: mpsc::UnboundedReceiver<Command>,
    tokens: HashMap<Vec<u8>, Binding>,
    assocs: HashMap<SocketAddr, Assoc>,
    bound: HashMap<(GameId, u8), SocketAddr>,
    handshaking: usize,
    drops: BTreeMap<&'static str, u64>,
    mtu: u32,
    max_pending: usize,
    idle_timeout: Duration,
    handshake_timeout: Duration,
    tick: Duration,
}

/// sha256 (lowercase hex) of the first certificate in a PEM file.
pub fn cert_sha256(path: &Path) -> Result<String, RelayError> {
    let pem = std::fs::read(path).map_err(|source| RelayError::CertFile { path: path.display().to_string(), source })?;
    let certs = X509::stack_from_pem(&pem)?;
    let leaf = certs.first().ok_or_else(|| RelayError::NoCert(path.display().to_string()))?;
    Ok(hex(&leaf.digest(MessageDigest::sha256())?))
}

fn cookie_for(secret: &PKey<openssl::pkey::Private>, peer: &SocketAddr) -> Result<Vec<u8>, ErrorStack> {
    let mut signer = Signer::new(MessageDigest::sha256(), secret)?;
    signer.update(peer.to_string().as_bytes())?;
    signer.sign_to_vec()
}

impl RelayTask {
    pub async fn bind(cfg: &RelayConfig) -> Result<(RelayHandle, RelayTask), RelayError> {
        let fingerprint = cert_sha256(&cfg.cert_pem)?;
        let peer_index = Ssl::new_ex_index::<SocketAddr>()?;
        let secret = PKey::hmac(&random_bytes(32)?)?;
        let verify_secret = secret.clone();

        let mut ctx = SslContext::builder(SslMethod::dtls())?;
        ctx.set_min_proto_version(Some(SslVersion::DTLS1_2))?;
        ctx.set_certificate_chain_file(&cfg.cert_pem)?;
        ctx.set_private_key_file(&cfg.key_pem, SslFiletype::PEM)?;
        ctx.check_private_key()?;
        ctx.set_verify(SslVerifyMode::NONE);
        ctx.set_options(SslOptions::COOKIE_EXCHANGE | SslOptions::NO_QUERY_MTU);
        ctx.set_cookie_generate_cb(move |ssl, buf| {
            let peer = ssl.ex_data(peer_index).ok_or_else(ErrorStack::get)?;
            let cookie = cookie_for(&secret, peer)?;
            buf[..cookie.len()].copy_from_slice(&cookie);
            Ok(cookie.len())
        });
        ctx.set_cookie_verify_cb(move |ssl, cookie| {
            let Some(peer) = ssl.ex_data(peer_index) else {
                return false;
            };
            match cookie_for(&verify_secret, peer) {
                Ok(expected) => expected.len() == cookie.len() && openssl::memcmp::eq(&expected, cookie),
                Err(e) => {
                    tracing::error!(error = %e, "relay cookie HMAC failed");
                    false
                }
            }
        });

        let socket = UdpSocket::bind(cfg.listen).await.map_err(RelayError::Socket)?;
        let (tx, rx) = mpsc::unbounded_channel();
        let handle = RelayHandle {
            tx,
            public: Arc::new(RelayPublic {
                host: cfg.public_host.clone(),
                port: cfg.public_port,
                cert_sha256: fingerprint,
                idle_timeout_secs: cfg.idle_timeout_secs,
            }),
        };
        let task = RelayTask {
            socket,
            ctx: ctx.build(),
            peer_index,
            rx,
            tokens: HashMap::new(),
            assocs: HashMap::new(),
            bound: HashMap::new(),
            handshaking: 0,
            drops: BTreeMap::new(),
            mtu: cfg.mtu,
            max_pending: cfg.max_pending_handshakes,
            idle_timeout: Duration::from_secs(cfg.idle_timeout_secs),
            handshake_timeout: Duration::from_secs(cfg.handshake_timeout_secs),
            tick: Duration::from_millis(cfg.tick_millis),
        };
        Ok((handle, task))
    }

    pub fn local_addr(&self) -> Result<SocketAddr, RelayError> {
        self.socket.local_addr().map_err(RelayError::Socket)
    }

    /// Runs until every [`RelayHandle`] is dropped (Ok) or the socket fails (Err).
    pub async fn run(mut self) -> Result<(), RelayError> {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let mut tick = tokio::time::interval(self.tick);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                // Commands first: a token registered before its RelayAssignment was sent must be known
                // before the client's Hello, which can only arrive after that.
                biased;
                cmd = self.rx.recv() => match cmd {
                    Some(cmd) => self.command(cmd).await,
                    None => return Ok(()),
                },
                received = self.socket.recv_from(&mut buf) => {
                    let (n, from) = received.map_err(RelayError::Socket)?;
                    let datagram = buf[..n].to_vec();
                    self.datagram(datagram, from).await;
                }
                _ = tick.tick() => self.housekeeping().await,
            }
        }
    }

    fn drop_datagram(&mut self, reason: &'static str, from: SocketAddr, detail: &dyn std::fmt::Display) {
        *self.drops.entry(reason).or_insert(0) += 1;
        tracing::warn!(%from, reason, %detail, "relay dropped datagram");
    }

    async fn flush(&mut self, addr: SocketAddr) {
        let Some(assoc) = self.assocs.get_mut(&addr) else {
            return;
        };
        let out = std::mem::take(&mut assoc.stream.get_mut().outbound);
        for datagram in out {
            if let Err(e) = self.socket.send_to(&datagram, addr).await {
                // A send failure loses this one datagram (UDP semantics); the association stays.
                self.drop_datagram("send_failed", addr, &e);
            }
        }
    }

    fn remove_assoc(&mut self, addr: SocketAddr) {
        if let Some(assoc) = self.assocs.remove(&addr) {
            if !assoc.established {
                self.handshaking -= 1;
            }
            if let Some(b) = assoc.binding
                && self.bound.get(&(b.game_id, b.slot)) == Some(&addr)
            {
                self.bound.remove(&(b.game_id, b.slot));
            }
        }
    }

    /// Sends close_notify and removes the association.
    async fn close_assoc(&mut self, addr: SocketAddr) {
        if let Some(assoc) = self.assocs.get_mut(&addr)
            && assoc.established
            && let Err(e) = assoc.stream.shutdown()
            && e.code() != ErrorCode::WANT_READ
        {
            tracing::warn!(%addr, error = %e, "relay close_notify failed");
        }
        self.flush(addr).await;
        self.remove_assoc(addr);
    }

    async fn command(&mut self, cmd: Command) {
        match cmd {
            Command::Register { token, binding } => {
                self.tokens.insert(token, binding);
            }
            Command::RevokeUser { game_id, user_id } => {
                self.revoke(|b| b.game_id == game_id && b.user_id == user_id).await;
            }
            Command::RevokeGame { game_id } => {
                self.revoke(|b| b.game_id == game_id).await;
            }
            Command::DropCounts(reply) => {
                // The requester gave up waiting; there is no one to answer.
                if reply.send(self.drops.clone()).is_err() {
                    tracing::debug!("relay drop-count requester went away");
                }
            }
        }
    }

    async fn revoke(&mut self, matches: impl Fn(&Binding) -> bool) {
        self.tokens.retain(|_, b| !matches(b));
        let doomed: Vec<SocketAddr> =
            self.assocs.iter().filter(|(_, a)| a.binding.as_ref().is_some_and(&matches)).map(|(addr, _)| *addr).collect();
        for addr in doomed {
            self.close_assoc(addr).await;
        }
    }

    fn new_assoc(&mut self, from: SocketAddr, now: Instant) -> Result<(), ErrorStack> {
        let mut ssl = Ssl::new(&self.ctx)?;
        ssl.set_ex_data(self.peer_index, from);
        ssl.set_mtu(self.mtu)?;
        let stream = SslStream::new(ssl, DgramIo::default())?;
        self.assocs.insert(from, Assoc { stream, established: false, binding: None, created: now, last_seen: now });
        self.handshaking += 1;
        Ok(())
    }

    async fn datagram(&mut self, datagram: Vec<u8>, from: SocketAddr) {
        let now = Instant::now();
        if !self.assocs.contains_key(&from) {
            if self.handshaking >= self.max_pending {
                let limit = self.max_pending;
                self.drop_datagram("pending_handshake_limit", from, &limit);
                return;
            }
            if let Err(e) = self.new_assoc(from, now) {
                tracing::error!(%from, error = %e, "relay could not create a DTLS session");
                self.drop_datagram("session_setup_failed", from, &e);
                return;
            }
        }
        let assoc = self.assocs.get_mut(&from).expect("association inserted above");
        assoc.last_seen = now;
        assoc.stream.get_mut().inbound.push_back(datagram);

        if !assoc.established {
            match assoc.stream.accept() {
                Ok(()) => {
                    assoc.established = true;
                    self.handshaking -= 1;
                    tracing::info!(%from, "relay DTLS association established");
                }
                Err(e) if matches!(e.code(), ErrorCode::WANT_READ | ErrorCode::WANT_WRITE) => {}
                Err(e) => {
                    self.flush(from).await;
                    self.remove_assoc(from);
                    self.drop_datagram("handshake_failed", from, &e);
                    return;
                }
            }
            self.flush(from).await;
            if !self.assocs.get(&from).is_some_and(|a| a.established) {
                return;
            }
        }

        let mut plaintexts = Vec::new();
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let mut closed = false;
        let assoc = self.assocs.get_mut(&from).expect("association present");
        loop {
            match assoc.stream.ssl_read(&mut buf) {
                Ok(n) => plaintexts.push(buf[..n].to_vec()),
                Err(e) if e.code() == ErrorCode::WANT_READ => break,
                Err(e) if e.code() == ErrorCode::ZERO_RETURN => {
                    tracing::info!(%from, "relay association closed by peer");
                    closed = true;
                    break;
                }
                Err(e) => {
                    self.drop_datagram("dtls_read_error", from, &e);
                    closed = true;
                    break;
                }
            }
        }
        self.flush(from).await;
        for p in plaintexts {
            self.plaintext(from, &p).await;
        }
        if closed {
            self.remove_assoc(from);
        }
    }

    async fn plaintext(&mut self, from: SocketAddr, bytes: &[u8]) {
        let datagram = match Datagram::decode(bytes) {
            Ok(d) => d,
            Err(e) => {
                let reason = match e {
                    RelayWireError::Empty => "empty",
                    RelayWireError::UnknownTag(_) => "unknown_tag",
                    RelayWireError::UnknownChannel(_) => "unknown_channel",
                    RelayWireError::Truncated(_) => "truncated",
                    RelayWireError::Trailing(_) => "trailing_bytes",
                    RelayWireError::TokenTooLong(_) => "token_too_long",
                };
                self.drop_datagram(reason, from, &e);
                return;
            }
        };
        let Some(binding) = self.assocs.get(&from).map(|a| a.binding) else {
            return;
        };
        match datagram {
            Datagram::Hello { token } => {
                if binding.is_some() {
                    self.drop_datagram("duplicate_hello", from, &"association already bound");
                    return;
                }
                let Some(b) = self.tokens.get(token).copied() else {
                    self.drop_datagram("unknown_token", from, &"hello token was not issued or was revoked");
                    return;
                };
                if let Some(old) = self.bound.insert((b.game_id, b.slot), from)
                    && old != from
                {
                    tracing::info!(%from, %old, game = b.game_id.0, slot = b.slot, "relay slot rebound to a new association");
                    self.close_assoc(old).await;
                    self.bound.insert((b.game_id, b.slot), from);
                }
                if let Some(a) = self.assocs.get_mut(&from) {
                    a.binding = Some(b);
                }
                tracing::info!(%from, game = b.game_id.0, user = b.user_id.0, slot = b.slot, "relay association bound");
            }
            // Its only effect is the `last_seen` update every datagram from a known address gets above.
            Datagram::Keepalive => {
                if binding.is_none() {
                    self.drop_datagram("keepalive_before_hello", from, &"association not bound by hello");
                }
            }
            Datagram::Data { slot, channel, payload } => {
                let Some(sender) = binding else {
                    self.drop_datagram("data_before_hello", from, &"association not bound by hello");
                    return;
                };
                let Some(&dest) = self.bound.get(&(sender.game_id, slot)) else {
                    self.drop_datagram("unknown_slot", from, &slot);
                    return;
                };
                if dest == from {
                    self.drop_datagram("self_addressed", from, &slot);
                    return;
                }
                let out = Datagram::Data { slot: sender.slot, channel, payload }
                    .encode()
                    .expect("data datagrams always encode");
                let dest_assoc = self.assocs.get_mut(&dest).expect("bound slots point at live associations");
                if let Err(e) = dest_assoc.stream.ssl_write(&out) {
                    self.drop_datagram("dtls_write_error", dest, &e);
                    return;
                }
                self.flush(dest).await;
            }
        }
    }

    async fn housekeeping(&mut self) {
        let now = Instant::now();
        let mut expired = Vec::new();
        let mut retransmit = Vec::new();
        for (addr, a) in &self.assocs {
            if !a.established {
                if now.duration_since(a.created) > self.handshake_timeout {
                    expired.push((*addr, "handshake_timeout"));
                } else {
                    retransmit.push(*addr);
                }
            } else if now.duration_since(a.last_seen) > self.idle_timeout {
                expired.push((*addr, "idle_timeout"));
            }
        }
        for (addr, reason) in expired {
            *self.drops.entry(reason).or_insert(0) += 1;
            tracing::info!(%addr, reason, "relay association expired");
            self.close_assoc(addr).await;
        }
        for addr in retransmit {
            let assoc = self.assocs.get_mut(&addr).expect("collected from live associations");
            // SAFETY: the pointer is the live SSL owned by `assoc.stream`; DTLS_CTRL_HANDLE_TIMEOUT takes no
            // argument and only drives OpenSSL's own retransmission timer, writing through our BIO.
            let rc = unsafe {
                openssl_sys::SSL_ctrl(assoc.stream.ssl().as_ptr(), DTLS_CTRL_HANDLE_TIMEOUT, 0, std::ptr::null_mut())
            };
            if rc < 0 {
                tracing::warn!(%addr, "relay DTLS retransmission failed; dropping handshake");
                *self.drops.entry("retransmit_failed").or_insert(0) += 1;
                self.remove_assoc(addr);
                continue;
            }
            self.flush(addr).await;
        }
    }
}
