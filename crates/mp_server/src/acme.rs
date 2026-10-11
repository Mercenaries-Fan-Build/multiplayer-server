//! Certificate issuance and renewal over ACME (RFC 8555) with the HTTP-01 challenge.
//!
//! HTTP-01 was chosen over TLS-ALPN-01: the challenge listener is a plain HTTP route answering one path,
//! while TLS-ALPN-01 would require swapping the certificate per handshake inside OpenSSL's client-hello
//! callback and hand-encoding the critical `acmeIdentifier` extension. HTTP-01 needs port 80 reachable from
//! the CA, which every deployment this mode targets (a VM with a public IP) has.
//!
//! instant-acme drives the protocol; its HTTP transport is supplied here over OpenSSL ([`OpensslHttp`]).
//! The account credentials, certificate chain and key live in `cache_dir`.

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::Router;
use axum::extract::{Path as UrlPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use bytes::Bytes;
use hyper_util::rt::TokioIo;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, BodyWrapper, BytesResponse, ChallengeType, HttpClient,
    Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use openssl::asn1::Asn1Time;
use openssl::ec::{EcGroup, EcKey};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{SslConnector, SslMethod};
use openssl::stack::Stack;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::{X509, X509Req};

use crate::config::AcmeConfig;
use crate::tls::{SharedAcceptor, acceptor, load_pem};
use crate::util::{hex, sha256};

#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    #[error("ACME protocol: {0}")]
    Protocol(#[from] instant_acme::Error),
    #[error("OpenSSL: {0}")]
    Tls(#[from] ErrorStack),
    #[error("ACME cache {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("ACME account file {path}: {source}")]
    Account { path: PathBuf, source: serde_json::Error },
    #[error("cached certificate: {0}")]
    Pem(#[from] crate::tls::PemError),
    #[error("ACME CA offered no http-01 challenge for {0}")]
    NoHttp01(String),
    #[error("authorization for {identifier} is {status:?}")]
    Authorization { identifier: String, status: AuthorizationStatus },
    #[error("order ended in state {0:?} instead of ready")]
    OrderNotReady(OrderStatus),
    #[error("the certificate expired before it could be renewed (last error: {0})")]
    Expired(String),
    #[error("the CA issued a certificate valid for {left_secs}s, inside tls.renew_before_days ({window_secs}s); lower renew_before_days")]
    WindowExceedsValidity { left_secs: i64, window_secs: i64 },
    #[error("the CA returned no certificate in the chain")]
    EmptyChain,
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> AcmeError + '_ {
    move |source| AcmeError::Io { path: path.to_path_buf(), source }
}

/// HTTP-01 key authorizations currently being served, by token.
pub type Challenges = Arc<RwLock<HashMap<String, String>>>;

/// Router for the plain-HTTP challenge listener.
pub fn challenge_router(challenges: Challenges) -> Router {
    Router::new()
        .route("/.well-known/acme-challenge/{token}", get(serve_challenge))
        .fallback(|| async { StatusCode::NOT_FOUND })
        .with_state(challenges)
}

async fn serve_challenge(State(challenges): State<Challenges>, UrlPath(token): UrlPath<String>) -> Response {
    let found = challenges.read().expect("challenge map lock poisoned by an earlier panic").get(&token).cloned();
    match found {
        Some(key_authorization) => key_authorization.into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// instant-acme HTTP transport over OpenSSL: one HTTP/1.1 connection per request.
pub struct OpensslHttp {
    connector: SslConnector,
}

impl OpensslHttp {
    /// `directory_ca` is `"system"` (OpenSSL's default verify paths) or a PEM bundle path.
    pub fn new(directory_ca: &str) -> Result<OpensslHttp, ErrorStack> {
        let mut b = SslConnector::builder(SslMethod::tls_client())?;
        if directory_ca == "system" {
            b.set_default_verify_paths()?;
        } else {
            b.set_ca_file(directory_ca)?;
        }
        Ok(OpensslHttp { connector: b.build() })
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

async fn https_request(connector: SslConnector, req: http::Request<BodyWrapper<Bytes>>) -> Result<BytesResponse, BoxError> {
    let uri = req.uri().clone();
    if uri.scheme_str() != Some("https") {
        return Err(format!("refusing non-https ACME URL {uri}").into());
    }
    let host = uri.host().ok_or_else(|| format!("ACME URL {uri} has no host"))?.to_string();
    // An https URL without an explicit port means 443.
    let port = uri.port_u16().unwrap_or(443);
    let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
    let ssl = connector.configure()?.into_ssl(&host)?;
    let mut tls = tokio_openssl::SslStream::new(ssl, tcp)?;
    Pin::new(&mut tls).connect().await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "ACME HTTP connection ended with an error");
        }
    });
    let (mut parts, body) = req.into_parts();
    // HTTP/1.1 origin-form request target plus Host.
    // An absolute URL with an empty path addresses "/".
    let path = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/").to_string();
    parts.uri = path.parse()?;
    let authority = uri.authority().ok_or_else(|| format!("ACME URL {uri} has no authority"))?.as_str().to_string();
    parts.headers.insert(http::header::HOST, authority.parse()?);
    let response = sender.send_request(http::Request::from_parts(parts, body)).await?;
    Ok(BytesResponse::from(response))
}

impl HttpClient for OpensslHttp {
    fn request(
        &self,
        req: http::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let connector = self.connector.clone();
        Box::pin(async move { https_request(connector, req).await.map_err(instant_acme::Error::Other) })
    }
}

struct CachePaths {
    account: PathBuf,
    cert: PathBuf,
    key: PathBuf,
}

fn cache_paths(cfg: &AcmeConfig) -> CachePaths {
    // One account per directory URL, so switching staging ↔ production never reuses the wrong account.
    let dir_tag = &hex(&sha256(cfg.directory_url.as_bytes()))[..16];
    CachePaths {
        account: cfg.cache_dir.join(format!("account-{dir_tag}.json")),
        cert: cfg.cache_dir.join("cert.pem"),
        key: cfg.cache_dir.join("key.pem"),
    }
}

fn write_private(path: &Path, data: &[u8]) -> Result<(), AcmeError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let mut f =
        std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp).map_err(io_err(&tmp))?;
    f.write_all(data).map_err(io_err(&tmp))?;
    f.sync_all().map_err(io_err(&tmp))?;
    std::fs::rename(&tmp, path).map_err(io_err(path))
}

async fn account(cfg: &AcmeConfig, paths: &CachePaths) -> Result<Account, AcmeError> {
    let http = || OpensslHttp::new(&cfg.directory_ca).map(|h| Box::new(h) as Box<dyn HttpClient>);
    match std::fs::read(&paths.account) {
        Ok(bytes) => {
            let creds: AccountCredentials = serde_json::from_slice(&bytes)
                .map_err(|source| AcmeError::Account { path: paths.account.clone(), source })?;
            Ok(Account::builder_with_http(http()?).from_credentials(creds).await?)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let contact = format!("mailto:{}", cfg.contact_email);
            let (account, creds) = Account::builder_with_http(http()?)
                .create(
                    &NewAccount { contact: &[&contact], terms_of_service_agreed: true, only_return_existing: false },
                    cfg.directory_url.clone(),
                    None,
                )
                .await?;
            let json = serde_json::to_vec(&creds)
                .map_err(|source| AcmeError::Account { path: paths.account.clone(), source })?;
            write_private(&paths.account, &json)?;
            tracing::info!(account = account.id(), "ACME account created");
            Ok(account)
        }
        Err(e) => Err(io_err(&paths.account)(e)),
    }
}

/// Runs one order for all configured domains and stores the result in the cache.
async fn issue(cfg: &AcmeConfig, challenges: &Challenges) -> Result<(Vec<X509>, PKey<Private>), AcmeError> {
    let paths = cache_paths(cfg);
    let account = account(cfg, &paths).await?;
    let identifiers: Vec<Identifier> = cfg.domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;
    let mut served_tokens = Vec::new();
    let result: Result<(String, PKey<Private>), AcmeError> = async {
        let mut authorizations = order.authorizations();
        while let Some(authz) = authorizations.next().await {
            let mut authz = authz?;
            let identifier = authz.identifier().to_string();
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                status => return Err(AcmeError::Authorization { identifier, status }),
            }
            let mut challenge = authz.challenge(ChallengeType::Http01).ok_or(AcmeError::NoHttp01(identifier))?;
            let token = challenge.token.clone();
            challenges
                .write()
                .expect("challenge map lock poisoned by an earlier panic")
                .insert(token.clone(), challenge.key_authorization().as_str().to_string());
            served_tokens.push(token);
            challenge.set_ready().await?;
        }
        let retries = RetryPolicy::new().timeout(Duration::from_secs(120));
        match order.poll_ready(&retries).await? {
            OrderStatus::Ready => {}
            other => return Err(AcmeError::OrderNotReady(other)),
        }
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
        let csr = csr(&cfg.domains, &key)?;
        order.finalize_csr(&csr).await?;
        let chain_pem = order.poll_certificate(&retries).await?;
        Ok((chain_pem, key))
    }
    .await;
    {
        let mut map = challenges.write().expect("challenge map lock poisoned by an earlier panic");
        for t in &served_tokens {
            map.remove(t);
        }
    }
    let (chain_pem, key) = result?;
    let chain = X509::stack_from_pem(chain_pem.as_bytes())?;
    let leaf = chain.first().ok_or(AcmeError::EmptyChain)?;
    // A certificate that is already due for renewal would make the renewal loop reissue without pause.
    let left_secs = seconds_left(leaf)?;
    if left_secs <= renew_window(cfg) {
        return Err(AcmeError::WindowExceedsValidity { left_secs, window_secs: renew_window(cfg) });
    }
    write_private(&paths.key, &key.private_key_to_pem_pkcs8()?)?;
    write_private(&paths.cert, chain_pem.as_bytes())?;
    tracing::info!(domains = ?cfg.domains, "ACME certificate issued");
    Ok((chain, key))
}

fn csr(domains: &[String], key: &PKey<Private>) -> Result<Vec<u8>, ErrorStack> {
    let mut b = X509Req::builder()?;
    b.set_pubkey(key)?;
    let mut san = SubjectAlternativeName::new();
    for d in domains {
        san.dns(d);
    }
    let mut exts = Stack::new()?;
    exts.push(san.build(&b.x509v3_context(None))?)?;
    b.add_extensions(&exts)?;
    b.sign(key, MessageDigest::sha256())?;
    b.build().to_der()
}

/// Seconds until the leaf certificate expires (negative when already expired).
fn seconds_left(leaf: &X509) -> Result<i64, ErrorStack> {
    let now = Asn1Time::days_from_now(0)?;
    let diff = now.diff(leaf.not_after())?;
    Ok(i64::from(diff.days) * 86_400 + i64::from(diff.secs))
}

fn covers(leaf: &X509, domains: &[String]) -> bool {
    // A certificate without a SAN extension names no domains, so it covers none of them.
    let names: Vec<String> = leaf
        .subject_alt_names()
        .map(|sans| sans.iter().filter_map(|n| n.dnsname().map(str::to_ascii_lowercase)).collect())
        .unwrap_or_default();
    domains.iter().all(|d| names.contains(&d.to_ascii_lowercase()))
}

fn renew_window(cfg: &AcmeConfig) -> i64 {
    i64::from(cfg.renew_before_days) * 86_400
}

/// The certificate to start with: the cached one if it covers the domains and is outside the renewal
/// window, otherwise a freshly issued one.
pub async fn initial_certificate(cfg: &AcmeConfig, challenges: &Challenges) -> Result<(Vec<X509>, PKey<Private>), AcmeError> {
    let paths = cache_paths(cfg);
    if paths.cert.exists() {
        let (chain, key) = load_pem(&paths.cert, &paths.key)?;
        let leaf = &chain[0];
        if covers(leaf, &cfg.domains) && seconds_left(leaf)? > renew_window(cfg) {
            tracing::info!(path = %paths.cert.display(), "using cached ACME certificate");
            return Ok((chain, key));
        }
        tracing::info!("cached ACME certificate is due for renewal or does not cover the configured domains");
    }
    issue(cfg, challenges).await
}

/// Renews the certificate before it expires and swaps it into the live acceptor. Retries a failed renewal
/// every `retry_interval_secs`; returns an error only when the certificate in use has expired.
pub async fn renewal_loop(
    cfg: AcmeConfig,
    challenges: Challenges,
    shared: SharedAcceptor,
    mut leaf: X509,
) -> AcmeError {
    loop {
        let left = match seconds_left(&leaf) {
            Ok(s) => s,
            Err(e) => return e.into(),
        };
        let wait = left - renew_window(&cfg);
        if wait > 0 {
            tokio::time::sleep(Duration::from_secs(u64::try_from(wait).expect("positive"))).await;
        }
        loop {
            match issue(&cfg, &challenges).await.and_then(|(chain, key)| Ok((acceptor(&chain, &key)?, chain))) {
                Ok((new_acceptor, chain)) => {
                    *shared.write().expect("acceptor lock poisoned by an earlier panic") = Arc::new(new_acceptor);
                    leaf = chain[0].clone();
                    tracing::info!("ACME certificate renewed and installed");
                    break;
                }
                Err(e) => {
                    let left = match seconds_left(&leaf) {
                        Ok(s) => s,
                        Err(e) => return e.into(),
                    };
                    if left <= 0 {
                        return AcmeError::Expired(e.to_string());
                    }
                    tracing::error!(error = %e, seconds_until_expiry = left, retry_in_secs = cfg.retry_interval_secs, "ACME renewal failed");
                    tokio::time::sleep(Duration::from_secs(cfg.retry_interval_secs)).await;
                }
            }
        }
    }
}
