//! HTTP routes: `POST /v1/accounts`, `POST /v1/sessions`, `GET /v1/ws`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Bytes;
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use mp_api::rest::{AccountCreated, CreateAccount, CreateSession, SessionCreated};
use mp_api::{ApiError, ErrorCode, rules};
use serde::de::DeserializeOwned;

use crate::client_ip::ClientIpPolicy;
use crate::config::WebSocketConfig;
use crate::db::{Db, DbError};
use crate::hub::Hub;
use crate::passwords::{PasswordError, Passwords};
use crate::ratelimit::RateLimiter;
use crate::tls::Peer;
use crate::util::{hex, now_unix, random_bytes, sha256};

/// Bytes of CSPRNG output in a session token (sent as hex).
const SESSION_TOKEN_BYTES: usize = 32;

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
        .fallback(|| async { error(StatusCode::NOT_FOUND, ApiError::new(ErrorCode::NotFound, "no such route")) })
        .with_state(app)
}

pub fn status_of(code: ErrorCode) -> StatusCode {
    match code {
        ErrorCode::InvalidField => StatusCode::UNPROCESSABLE_ENTITY,
        ErrorCode::NameTaken | ErrorCode::GameFull | ErrorCode::GameClosed => StatusCode::CONFLICT,
        ErrorCode::BadCredentials | ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
        ErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        ErrorCode::NotFound => StatusCode::NOT_FOUND,
        ErrorCode::Forbidden | ErrorCode::JoinDenied => StatusCode::FORBIDDEN,
        ErrorCode::Unsupported => StatusCode::BAD_REQUEST,
        ErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// An error response: HTTP status plus the `mp_api::ApiError` JSON body.
pub struct HttpError(StatusCode, ApiError);

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        (self.0, axum::Json(self.1)).into_response()
    }
}

impl From<ApiError> for HttpError {
    fn from(err: ApiError) -> HttpError {
        HttpError(status_of(err.code), err)
    }
}

fn error(status: StatusCode, err: ApiError) -> HttpError {
    HttpError(status, err)
}

fn internal(context: &str, e: &dyn std::fmt::Display) -> HttpError {
    tracing::error!(error = %e, "{context}");
    ApiError::new(ErrorCode::Internal, format!("{context}: {e}")).into()
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
    Ok(axum::Json(SessionCreated { token, user_id: user.id, display_name: user.username, expires_at }).into_response())
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?;
    (!token.is_empty()).then_some(token)
}

async fn websocket(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Result<Response, HttpError> {
    let Some(token) = bearer(&headers) else {
        return Err(ApiError::new(ErrorCode::Unauthorized, "Authorization: Bearer <session token> required").into());
    };
    let session = match app.db.session(&sha256(token.as_bytes()), now_unix()).await.map_err(db_failure)? {
        Some(s) => s,
        None => return Err(ApiError::new(ErrorCode::Unauthorized, "session token unknown or expired").into()),
    };
    let upgrade = upgrade.map_err(|rejection| {
        error(rejection.status(), ApiError::new(ErrorCode::Unsupported, rejection.body_text()))
    })?;
    Ok(upgrade
        .max_message_size(app.websocket.max_message_bytes)
        .on_upgrade(move |socket| crate::connection::run(app, socket, session)))
}
