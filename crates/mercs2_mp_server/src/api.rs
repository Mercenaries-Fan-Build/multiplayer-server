//! HTTP routes: `POST /v1/accounts`, `POST /v1/sessions`, `GET /v1/ws`, and the leaderboards:
//! `PUT /v1/leaderboards/{board}/score`, `GET /v1/leaderboards/{board}/me`, `GET /v1/leaderboards/{board}`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Bytes;
use axum::extract::rejection::{PathRejection, QueryRejection};
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use mercs2_mp_api::rest::{AccountCreated, CreateAccount, CreateSession, PushScore, SessionCreated};
use mercs2_mp_api::{ApiError, ErrorCode, rules};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::client_ip::ClientIpPolicy;
use crate::config::WebSocketConfig;
use crate::db::{Db, DbError, SessionRow};
use crate::hub::Hub;
use crate::passwords::{PasswordError, Passwords};
use crate::ratelimit::RateLimiter;
use crate::tls::Peer;
use crate::util::{hex, now_unix, random_bytes, sha256};

/// Bytes of CSPRNG output in a session token (sent as hex).
const SESSION_TOKEN_BYTES: usize = 32;
/// Rows of `GET /v1/leaderboards/{board}` when `count` is absent, and the most it may ask for.
const LEADERBOARD_PAGE_DEFAULT: u32 = 30;
const LEADERBOARD_PAGE_MAX: u32 = 100;

pub struct App {
    pub db: Db,
    pub passwords: Passwords,
    pub hub: Arc<Hub>,
    pub accounts_limit: RateLimiter,
    pub sessions_limit: RateLimiter,
    pub ip_policy: ClientIpPolicy,
    pub session_ttl: Duration,
    pub websocket: WebSocketConfig,
}

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/v1/accounts", post(create_account))
        .route("/v1/sessions", post(create_session))
        .route("/v1/ws", get(websocket))
        .route("/v1/leaderboards/{board}", get(leaderboard_page))
        .route("/v1/leaderboards/{board}/score", put(push_score))
        .route("/v1/leaderboards/{board}/me", get(my_standing))
        .fallback(|| async { error(StatusCode::NOT_FOUND, ApiError::new(ErrorCode::NotFound, "no such route")) })
        .with_state(app)
}

pub fn status_of(code: ErrorCode) -> StatusCode {
    match code {
        ErrorCode::InvalidField => StatusCode::UNPROCESSABLE_ENTITY,
        ErrorCode::NameTaken | ErrorCode::GameFull | ErrorCode::GameClosed => StatusCode::CONFLICT,
        // Login credentials travel in the JSON body, not an HTTP authentication scheme, so a wrong password is a
        // 400 (RFC 6749 section 5.2) rather than a 401, which RFC 9110 section 15.5.2 ties to a challenge.
        ErrorCode::BadCredentials => StatusCode::BAD_REQUEST,
        ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
        ErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        ErrorCode::NotFound => StatusCode::NOT_FOUND,
        ErrorCode::Forbidden | ErrorCode::JoinDenied => StatusCode::FORBIDDEN,
        ErrorCode::Unsupported => StatusCode::BAD_REQUEST,
        ErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// An error response: HTTP status plus the `mercs2_mp_api::ApiError` JSON body, and the `WWW-Authenticate`
/// challenge of a 401 from a bearer-token route.
pub struct HttpError(StatusCode, ApiError, Option<&'static str>);

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let mut rsp = (self.0, axum::Json(self.1)).into_response();
        if let Some(challenge) = self.2 {
            rsp.headers_mut().insert(http::header::WWW_AUTHENTICATE, HeaderValue::from_static(challenge));
        }
        rsp
    }
}

impl From<ApiError> for HttpError {
    fn from(err: ApiError) -> HttpError {
        HttpError(status_of(err.code), err, None)
    }
}

fn error(status: StatusCode, err: ApiError) -> HttpError {
    HttpError(status, err, None)
}

/// The only message an `internal` error carries to a client, over REST and the WebSocket alike; the detail goes
/// to the server log.
pub const INTERNAL_ERROR_MESSAGE: &str = "internal error";

/// The detail goes to the server log only; the client gets a fixed body.
fn internal(context: &str, e: &dyn std::fmt::Display) -> HttpError {
    tracing::error!(error = %e, "{context}");
    ApiError::new(ErrorCode::Internal, INTERNAL_ERROR_MESSAGE).into()
}

/// 401 `unauthorized` for a bearer-token route, with the RFC 6750 section 3 `WWW-Authenticate` challenge.
fn unauthorized(message: &str, challenge: &'static str) -> HttpError {
    HttpError(StatusCode::UNAUTHORIZED, ApiError::new(ErrorCode::Unauthorized, message), Some(challenge))
}

fn db_failure(e: DbError) -> HttpError {
    internal("database", &e)
}

fn password_failure(e: PasswordError) -> HttpError {
    internal("password hashing", &e)
}

fn parse_body<T: DeserializeOwned>(body: &[u8]) -> Result<T, HttpError> {
    serde_json::from_slice(body).map_err(|e| {
        error(StatusCode::BAD_REQUEST, ApiError::new(ErrorCode::InvalidField, format!("request body: {e}")))
    })
}

/// Client-IP attribution plus the rate-limit check for one endpoint.
fn admit(app: &App, limiter: &RateLimiter, peer: Peer, headers: &HeaderMap) -> Result<(), HttpError> {
    let ip = app.ip_policy.client_ip(peer.0.ip(), headers).map_err(|e| {
        error(StatusCode::BAD_REQUEST, ApiError::new(ErrorCode::InvalidField, format!("X-Forwarded-For: {e}")))
    })?;
    let now = Instant::now();
    limiter.prune(now);
    if !limiter.check(ip, now) {
        return Err(ApiError::new(ErrorCode::RateLimited, "too many attempts; retry later").into());
    }
    Ok(())
}

async fn create_account(
    State(app): State<Arc<App>>,
    Extension(peer): Extension<Peer>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, HttpError> {
    admit(&app, &app.accounts_limit, peer, &headers)?;
    let req: CreateAccount = parse_body(&body)?;
    rules::check_username(&req.username)?;
    rules::check_password(&req.password)?;
    let hash = app.passwords.hash(req.password).await.map_err(password_failure)?;
    match app.db.create_user(&req.username, &hash, now_unix()).await {
        Ok(user_id) => {
            tracing::info!(user = user_id.0, username = %req.username, "account created");
            Ok((StatusCode::CREATED, axum::Json(AccountCreated { user_id, username: req.username })).into_response())
        }
        Err(DbError::NameTaken) => Err(ApiError::new(ErrorCode::NameTaken, "username already registered").into()),
        Err(e) => Err(db_failure(e)),
    }
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

async fn create_session(
    State(app): State<Arc<App>>,
    Extension(peer): Extension<Peer>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, HttpError> {
    admit(&app, &app.sessions_limit, peer, &headers)?;
    let req: CreateSession = parse_body(&body)?;
    rules::check_username(&req.username)?;
    rules::check_password(&req.password)?;
    if !is_sha256_hex(&req.client.build_sha256) {
        return Err(ApiError::new(ErrorCode::InvalidField, "client.build_sha256: must be 64 hex characters").into());
    }
    if req.client.asi_version.trim().is_empty() {
        return Err(ApiError::new(ErrorCode::InvalidField, "client.asi_version: must not be empty").into());
    }
    let stored = app.db.user_by_name(&req.username).await.map_err(db_failure)?;
    // Unknown user and wrong password both run one argon2 verification and give the same answer.
    let ok = app
        .passwords
        .verify(req.password, stored.as_ref().map(|u| u.password_hash.clone()))
        .await
        .map_err(password_failure)?;
    let user = match (ok, stored) {
        (true, Some(user)) => user,
        _ => return Err(ApiError::new(ErrorCode::BadCredentials, "wrong username or password").into()),
    };
    let token = hex(&random_bytes(SESSION_TOKEN_BYTES).map_err(|e| internal("CSPRNG", &e))?);
    let now = now_unix();
    let ttl = i64::try_from(app.session_ttl.as_secs()).expect("session ttl validated to fit i64 seconds");
    let expires_at = now + ttl;
    app.db
        .create_session(&sha256(token.as_bytes()), user.id, now, expires_at, &req.client.build_sha256, &req.client.asi_version)
        .await
        .map_err(db_failure)?;
    tracing::info!(user = user.id.0, build = %req.client.build_sha256, asi = %req.client.asi_version, "session created");
    Ok(no_store(SessionCreated { token, user_id: user.id, display_name: user.username, expires_at }))
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?;
    (!token.is_empty()).then_some(token)
}

/// The live session named by the request's bearer token. Read-only: the session row is not modified.
async fn authenticate(app: &App, headers: &HeaderMap) -> Result<SessionRow, HttpError> {
    let Some(token) = bearer(headers) else {
        return Err(unauthorized("Authorization: Bearer <session token> required", "Bearer"));
    };
    match app.db.session(&sha256(token.as_bytes()), now_unix()).await.map_err(db_failure)? {
        Some(s) => Ok(s),
        None => Err(unauthorized("session token unknown or expired", r#"Bearer error="invalid_token""#)),
    }
}

/// A JSON body that answers for one player's session: never stored by a cache.
fn no_store(body: impl serde::Serialize) -> Response {
    ([(http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"))], axum::Json(body)).into_response()
}

/// The `{board}` path segment, checked by [`rules::check_board_name`].
fn board_name(path: Result<Path<String>, PathRejection>) -> Result<String, HttpError> {
    let Path(board) = path.map_err(|r| HttpError::from(ApiError::new(ErrorCode::InvalidField, format!("board: {}", r.body_text()))))?;
    rules::check_board_name(&board)?;
    Ok(board)
}

/// A score push body: malformed JSON is 400 like every other body; well-formed JSON whose `score` is not a
/// u32 (negative, fractional, too large, missing) is 422, as is a u32 above the score cap.
fn push_score_body(body: &[u8]) -> Result<PushScore, HttpError> {
    let req: PushScore = serde_json::from_slice(body).map_err(|e| match e.classify() {
        serde_json::error::Category::Data => HttpError::from(ApiError::new(ErrorCode::InvalidField, format!("score: {e}"))),
        _ => error(StatusCode::BAD_REQUEST, ApiError::new(ErrorCode::InvalidField, format!("request body: {e}"))),
    })?;
    rules::check_leaderboard_score(req.score)?;
    Ok(req)
}

async fn push_score(
    State(app): State<Arc<App>>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, HttpError> {
    let session = authenticate(&app, &headers).await?;
    let board = board_name(path)?;
    let req = push_score_body(&body)?;
    let uid = session.user.user_id;
    match app.db.push_leaderboard_score(&board, uid, req.score, now_unix()).await.map_err(db_failure)? {
        Some(entry) => {
            tracing::info!(user = uid.0, %board, pushed = req.score, score = entry.score, rank = entry.rank, "leaderboard score pushed");
            Ok(no_store(entry))
        }
        None => {
            tracing::info!(user = uid.0, %board, pushed = req.score, "leaderboard push refused: account is banned");
            Err(ApiError::new(ErrorCode::Forbidden, "this account is banned from leaderboards").into())
        }
    }
}

async fn my_standing(
    State(app): State<Arc<App>>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    let session = authenticate(&app, &headers).await?;
    let board = board_name(path)?;
    let entry = app.db.leaderboard_standing(&board, session.user.user_id).await.map_err(db_failure)?;
    Ok(no_store(entry))
}

#[derive(Deserialize)]
struct PageQuery {
    from: Option<u32>,
    count: Option<u32>,
}

async fn leaderboard_page(
    State(app): State<Arc<App>>,
    path: Result<Path<String>, PathRejection>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Result<Response, HttpError> {
    let board = board_name(path)?;
    let Query(q) =
        query.map_err(|r| HttpError::from(ApiError::new(ErrorCode::InvalidField, format!("query: {}", r.body_text()))))?;
    let from = q.from.unwrap_or(1);
    if from == 0 {
        return Err(ApiError::new(ErrorCode::InvalidField, "from: ranks start at 1").into());
    }
    let count = q.count.unwrap_or(LEADERBOARD_PAGE_DEFAULT);
    if !(1..=LEADERBOARD_PAGE_MAX).contains(&count) {
        return Err(ApiError::new(ErrorCode::InvalidField, format!("count: must be 1-{LEADERBOARD_PAGE_MAX}")).into());
    }
    let page = app.db.leaderboard_page(&board, from, count).await.map_err(db_failure)?;
    Ok(axum::Json(page).into_response())
}

async fn websocket(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Result<Response, HttpError> {
    let session = authenticate(&app, &headers).await?;
    let upgrade = upgrade.map_err(|rejection| {
        error(rejection.status(), ApiError::new(ErrorCode::Unsupported, rejection.body_text()))
    })?;
    Ok(upgrade
        .max_message_size(app.websocket.max_message_bytes)
        .on_upgrade(move |socket| crate::connection::run(app, socket, session)))
}
