//! In-process test server (proxied TLS mode with generated self-signed certificates) and clients for its
//! REST, WebSocket and DTLS relay endpoints.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use mp_api::ws::{ClientFrame, Push, Request, Response, ServerFrame};
use mp_api::ApiError;
use mp_server::config::*;
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{ErrorCode, Ssl, SslConnector, SslContext, SslMethod, SslStream, SslVerifyMode};
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::{X509, X509NameBuilder};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

pub const TIMEOUT: Duration = Duration::from_secs(10);

/// A self-signed certificate for `localhost` / `127.0.0.1`.
pub fn self_signed(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key: PKey<Private> = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut subject = X509NameBuilder::new().unwrap();
    subject.append_entry_by_nid(Nid::COMMONNAME, "localhost").unwrap();
    let subject = subject.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    let mut serial = BigNum::new().unwrap();
    serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
    b.set_serial_number(&serial.to_asn1_integer().unwrap()).unwrap();
    b.set_subject_name(&subject).unwrap();
    b.set_issuer_name(&subject).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(30).unwrap()).unwrap();
    let san = SubjectAlternativeName::new().dns("localhost").ip("127.0.0.1").build(&b.x509v3_context(None, None)).unwrap();
    b.append_extension(san).unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    let cert = b.build();
    let cert_path = dir.join(format!("{name}-cert.pem"));
    let key_path = dir.join(format!("{name}-key.pem"));
    std::fs::write(&cert_path, cert.to_pem().unwrap()).unwrap();
    std::fs::write(&key_path, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    (cert_path, key_path)
}

pub fn sha256_hex_of_pem(path: &Path) -> String {
    let cert = X509::from_pem(&std::fs::read(path).unwrap()).unwrap();
    cert.digest(MessageDigest::sha256()).unwrap().iter().map(|b| format!("{b:02x}")).collect()
}

pub struct TestServer {
    pub https: SocketAddr,
    pub relay_addr: SocketAddr,
    pub relay: mp_server::relay::RelayHandle,
    pub https_cert: PathBuf,
    pub relay_fingerprint: String,
    _running: mp_server::Running,
    _dir: tempfile::TempDir,
}

pub fn test_config(dir: &Path) -> Config {
    let (https_cert, https_key) = self_signed(dir, "https");
    let (relay_cert, relay_key) = self_signed(dir, "relay");
    Config {
        log: LogConfig { filter: "info".into(), format: LogFormat::Text },
        server: ServerConfig { https_listen: "127.0.0.1:0".parse().unwrap(), tls_handshake_timeout_secs: 5 },
        database: DatabaseConfig { path: dir.join("mp.sqlite") },
        accounts: AccountsConfig {
            session_ttl_secs: 3600,
            argon2_memory_kib: 256,
            argon2_iterations: 1,
            argon2_parallelism: 1,
        },
        rate_limit: RateLimitConfig {
            accounts: BucketConfig { burst: 1000, refill_per_minute: 1000 },
            sessions: BucketConfig { burst: 1000, refill_per_minute: 1000 },
        },
        websocket: WebSocketConfig {
            max_message_bytes: 65536,
            outbound_queue: 64,
            ping_interval_secs: 5,
            idle_timeout_secs: 30,
        },
        games: GamesConfig { max_players_limit: 4 },
        relay: RelayConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            public_host: "127.0.0.1".into(),
            public_port: 0,
            cert_pem: relay_cert,
            key_pem: relay_key,
            idle_timeout_secs: 30,
            handshake_timeout_secs: 5,
            max_pending_handshakes: 16,
            mtu: 1200,
            tick_millis: 200,
        },
        tls: TlsConfig::Proxied(ProxiedConfig {
            cert_pem: https_cert,
            key_pem: https_key,
            trusted_proxies: vec!["127.0.0.1/32".parse().unwrap()],
        }),
    }
}

impl TestServer {
    pub async fn start() -> TestServer {
        Self::start_with(|_| {}).await
    }

    pub async fn start_with(tweak: impl FnOnce(&mut Config)) -> TestServer {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_config(dir.path());
        // The relay's public port is only known after binding; tests talk to the bound address directly.
        cfg.relay.public_port = 1;
        tweak(&mut cfg);
        cfg.validate().unwrap();
        let https_cert = match &cfg.tls {
            TlsConfig::Proxied(p) => p.cert_pem.clone(),
            TlsConfig::Acme(_) => unreachable!("tests run proxied mode"),
        };
        let relay_fingerprint = sha256_hex_of_pem(&cfg.relay.cert_pem);
        let running = mp_server::start(cfg).await.unwrap();
        TestServer {
            https: running.https_addr,
            relay_addr: running.relay_addr,
            relay: running.relay.clone(),
            https_cert,
            relay_fingerprint,
            _running: running,
            _dir: dir,
        }
    }

    async fn tls(&self) -> tokio_openssl::SslStream<TcpStream> {
        let mut b = SslConnector::builder(SslMethod::tls_client()).unwrap();
        b.set_ca_file(&self.https_cert).unwrap();
        b.set_alpn_protos(b"\x08http/1.1").unwrap();
        let ssl = b.build().configure().unwrap().into_ssl("localhost").unwrap();
        let tcp = TcpStream::connect(self.https).await.unwrap();
        let mut tls = tokio_openssl::SslStream::new(ssl, tcp).unwrap();
        Pin::new(&mut tls).connect().await.unwrap();
        tls
    }

    /// POST JSON as client IP `client_ip` (sent as X-Forwarded-For; the test peer is a trusted proxy).
    pub async fn post(&self, path: &str, body: &str, client_ip: Option<&str>) -> (u16, serde_json::Value) {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(self.tls().await)).await.unwrap();
        tokio::spawn(conn);
        let mut req = http::Request::post(path)
            .header("host", "localhost")
            .header("content-type", "application/json");
        if let Some(ip) = client_ip {
            req = req.header("x-forwarded-for", ip);
        }
        let req = req.body(Full::new(Bytes::from(body.to_string()))).unwrap();
        let rsp = sender.send_request(req).await.unwrap();
        let status = rsp.status().as_u16();
        let bytes = rsp.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("non-JSON body {bytes:?}: {e}"));
        (status, json)
    }

    pub async fn create_account(&self, name: &str) -> i64 {
        let (status, body) = self
            .post("/v1/accounts", &format!(r#"{{"username":"{name}","password":"password-{name}"}}"#), Some("198.51.100.1"))
            .await;
        assert_eq!(status, 201, "{body}");
        body["user_id"].as_i64().unwrap()
    }

    pub async fn login(&self, name: &str) -> (String, i64) {
        let body = format!(
            r#"{{"username":"{name}","password":"password-{name}","client":{{"build_sha256":"{}","asi_version":"test"}}}}"#,
            "ab".repeat(32)
        );
        let (status, body) = self.post("/v1/sessions", &body, Some("198.51.100.1")).await;
        assert_eq!(status, 200, "{body}");
        (body["token"].as_str().unwrap().to_string(), body["user_id"].as_i64().unwrap())
    }

    /// WebSocket upgrade with the given Authorization header; Err carries the HTTP status and body.
    pub async fn ws_raw(&self, authorization: Option<&str>) -> Result<WsClient, (u16, String)> {
        let mut req = format!("wss://localhost:{}/v1/ws", self.https.port()).into_client_request().unwrap();
        if let Some(a) = authorization {
            req.headers_mut().insert("authorization", a.parse().unwrap());
        }
        match tokio_tungstenite::client_async(req, self.tls().await).await {
            Ok((ws, _)) => Ok(WsClient { ws, next_id: 1, pushes: VecDeque::new() }),
            Err(tokio_tungstenite::tungstenite::Error::Http(rsp)) => {
                let body = rsp.body().as_ref().map(|b| String::from_utf8_lossy(b).into_owned()).unwrap_or_default();
                Err((rsp.status().as_u16(), body))
            }
            Err(e) => panic!("websocket connect failed: {e}"),
        }
    }

    /// Creates the account, logs in and connects.
    pub async fn user(&self, name: &str) -> (WsClient, i64) {
        self.create_account(name).await;
        let (token, id) = self.login(name).await;
        (self.ws_raw(Some(&format!("Bearer {token}"))).await.unwrap(), id)
    }
}

pub struct WsClient {
    pub ws: tokio_tungstenite::WebSocketStream<tokio_openssl::SslStream<TcpStream>>,
    next_id: u64,
    pushes: VecDeque<Push>,
}

impl WsClient {
    pub async fn next_frame(&mut self) -> Option<ServerFrame> {
        loop {
            let msg = tokio::time::timeout(TIMEOUT, self.ws.next()).await.expect("timed out waiting for a frame")?;
            match msg.expect("websocket error") {
                Message::Text(t) => return Some(serde_json::from_str(t.as_str()).unwrap()),
                Message::Close(_) => return None,
                Message::Ping(_) | Message::Pong(_) => continue,
                other => panic!("unexpected message {other:?}"),
            }
        }
    }

    pub async fn send_text(&mut self, text: &str) {
        self.ws.send(Message::text(text.to_string())).await.unwrap();
    }

    pub async fn request(&mut self, request: Request) -> Result<Response, ApiError> {
        let id = self.next_id;
        self.next_id += 1;
        let text = serde_json::to_string(&ClientFrame { id, request }).unwrap();
        self.send_text(&text).await;
        loop {
            match self.next_frame().await.expect("connection closed while waiting for a reply") {
                ServerFrame::Reply { id: rid, response } => {
                    assert_eq!(rid, id, "reply for another request");
                    return Ok(response);
                }
                ServerFrame::Error { id: rid, error } => {
                    assert_eq!(rid, id, "error for another request");
                    return Err(error);
                }
                ServerFrame::Push { push } => self.pushes.push_back(push),
            }
        }
    }

    pub async fn push(&mut self) -> Push {
        if let Some(p) = self.pushes.pop_front() {
            return p;
        }
        match self.next_frame().await.expect("connection closed while waiting for a push") {
            ServerFrame::Push { push } => push,
            other => panic!("expected a push, got {other:?}"),
        }
    }

    /// Asserts no push is pending (a Ping round trip flushes everything queued before it).
    pub async fn assert_no_push(&mut self) {
        assert_eq!(self.request(Request::Ping).await.unwrap(), Response::Pong);
        assert!(self.pushes.is_empty(), "unexpected pushes {:?}", self.pushes);
    }
}

/// A blocking UDP transport for a client-side DTLS stream.
#[derive(Debug)]
pub struct UdpIo(pub UdpSocket);

impl Read for UdpIo {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.recv(buf)
    }
}

impl Write for UdpIo {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.send(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// DTLS 1.2 client to the relay that accepts only the certificate with sha256 `fingerprint`.
pub fn dtls_connect(relay: SocketAddr, fingerprint: &str) -> Result<SslStream<UdpIo>, String> {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(relay).unwrap();
    socket.set_read_timeout(Some(Duration::from_millis(1500))).unwrap();
    let mut ctx = SslContext::builder(SslMethod::dtls()).unwrap();
    let expected = fingerprint.to_string();
    ctx.set_verify_callback(SslVerifyMode::PEER, move |_preverified, store| {
        let Some(cert) = store.current_cert() else { return false };
        let digest: String =
            cert.digest(MessageDigest::sha256()).unwrap().iter().map(|b| format!("{b:02x}")).collect();
        store.error_depth() == 0 && digest == expected
    });
    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    ssl.set_mtu(1200).unwrap();
    ssl.connect(UdpIo(socket)).map_err(|e| format!("DTLS handshake failed: {e:?}"))
}

/// Next application datagram, or None when nothing arrives within the socket's read timeout.
pub fn dtls_recv(stream: &mut SslStream<UdpIo>) -> Result<Option<Vec<u8>>, ErrorCode> {
    let mut buf = vec![0u8; 2048];
    match stream.ssl_read(&mut buf) {
        Ok(n) => Ok(Some(buf[..n].to_vec())),
        Err(e) if e.code() == ErrorCode::WANT_READ => Ok(None),
        Err(e) => Err(e.code()),
    }
}
